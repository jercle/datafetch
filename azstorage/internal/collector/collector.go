// Package collector is the pass itself: for every tenant, list the storage
// accounts, read how much each holds, list and measure their blob
// containers, list the managed disks, and store it all.
package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jercle/datafetch/azstorage/internal/azure"
	"github.com/jercle/datafetch/azstorage/internal/config"
	"github.com/jercle/datafetch/azstorage/internal/model"
	"github.com/jercle/datafetch/azstorage/internal/monitor"
	"github.com/jercle/datafetch/azstorage/internal/store"
)

// AzureAPI is what the collector reads from one tenant.
type AzureAPI interface {
	Subscriptions(ctx context.Context) ([]azure.Subscription, error)
	ResourceGraph(ctx context.Context, query string, subscriptions []string, each func([]azure.Row) error) error
	AccountUsage(ctx context.Context, accountID, kind string, services bool) (usage azure.Usage, warn error, err error)
	Containers(ctx context.Context, accountID string) ([]azure.BlobContainer, error)
	ContainerUsage(ctx context.Context, blobEndpoint, container string, o azure.ListOptions) (azure.ContainerUsage, error)
}

type Collector struct {
	Cfg   *config.Config
	Store store.Store
	Mon   *monitor.Monitor
	Log   *slog.Logger
	// SetRun tags the log sink with the current run.
	SetRun func(id string)
	// NewClient returns the API client for a tenant.
	NewClient func(t config.Tenant) AzureAPI
}

// warnLimit is how many items of one step are logged as warnings before the
// rest go to debug: a missing role fails every account the same way.
const warnLimit = 20

// Run makes one pass and returns its record.
func (c *Collector) Run(ctx context.Context, trigger string, next *time.Time) *model.Run {
	r := c.Mon.StartRun(ctx, trigger, len(c.Cfg.Tenants))
	if c.SetRun != nil {
		c.SetRun(r.ID)
		defer c.SetRun("")
	}
	log := c.Log.With("run", r.ID)
	log.Info("run started", "tenants", len(c.Cfg.Tenants))

	sem := make(chan struct{}, c.Cfg.Concurrency.Tenants)
	var wg sync.WaitGroup
	for _, t := range c.Cfg.Tenants {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
			}
			tr := c.collectTenant(ctx, r, t, log.With("tenantName", t.Name))
			c.Mon.Progress(func() {
				r.Tenants = append(r.Tenants, tr)
				r.TenantsDone++
				if tr.Status == model.StatusFailed {
					r.TenantsFailed++
				}
				r.Counts.Add(tr.Counts)
			})
		}()
	}
	wg.Wait()

	status, errText := model.StatusSuccess, ""
	switch {
	case ctx.Err() != nil:
		status = model.StatusCancelled
	case r.TenantsTotal > 0 && r.TenantsFailed == r.TenantsTotal:
		status, errText = model.StatusFailed, "no tenant could be collected"
	case partial(r.Tenants):
		status = model.StatusPartial
	}
	c.Mon.FinishRun(ctx, r, status, errText, next)
	log.Info("run finished", "status", status, "accounts", r.Counts.Accounts, "usedBytes", r.Counts.UsedBytes,
		"containers", r.Counts.Containers, "containersMeasured", r.Counts.ContainersMeasured,
		"disks", r.Counts.Disks, "diskBytes", r.Counts.DiskBytes,
		"duration", time.Duration(r.DurationMs)*time.Millisecond)
	return r
}

func partial(ts []model.TenantRun) bool {
	for _, t := range ts {
		if t.Status != model.StatusSuccess {
			return true
		}
	}
	return false
}

// each runs fn for every item, n at a time, until ctx ends.
func each[T any](ctx context.Context, n int, items []T, fn func(*T)) {
	sem := make(chan struct{}, max(1, n))
	var wg sync.WaitGroup
	for i := range items {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			fn(&items[i])
		}()
	}
	wg.Wait()
}

func (c *Collector) collectTenant(ctx context.Context, r *model.Run, t config.Tenant, log *slog.Logger) model.TenantRun {
	scope := model.Scope{TenantName: t.Name, TenantID: t.ID}
	started := time.Now().UTC()
	tr := model.TenantRun{Scope: scope, Status: model.StatusSuccess, StartedAt: started, Steps: []model.Step{}}
	var missing []string

	// step runs fn and records it. It returns whether fn succeeded.
	step := func(name string, required bool, fn func() (done, skipped int, err error)) bool {
		if ctx.Err() != nil {
			tr.Steps = append(tr.Steps, model.Step{Name: name, Status: model.StatusCancelled})
			return false
		}
		log.Debug("step started", "step", name)
		t0 := time.Now()
		n, skipped, err := fn()
		st := model.Step{Name: name, Status: model.StatusSuccess, DurationMs: time.Since(t0).Milliseconds(), Count: n, Skipped: skipped}
		if err != nil {
			st.Status, st.Error = model.StatusFailed, err.Error()
			if ctx.Err() != nil {
				st.Status = model.StatusCancelled
			} else if required {
				log.Error("step failed", "step", name, "error", err)
				tr.Status, tr.Error = model.StatusFailed, name+": "+err.Error()
			} else {
				log.Warn("step failed; continuing without it", "step", name, "error", err)
				tr.Status = model.StatusPartial
				tr.Counts.Warnings++
				missing = append(missing, name)
			}
		} else {
			log.Info("step done", "step", name, "count", n, "skipped", skipped, "duration", time.Since(t0).Round(time.Millisecond))
		}
		tr.Steps = append(tr.Steps, st)
		return err == nil
	}

	cli := c.NewClient(t)
	var subs []azure.Subscription
	subNames := map[string]string{}
	var subIDs []string
	var accounts []model.Account
	var disks []model.Disk
	var keepContainers []string // accounts whose containers could not be listed
	accountsListed, disksListed := false, false

	ok := step("subscriptions", true, func() (int, int, error) {
		all, err := cli.Subscriptions(ctx)
		if err != nil {
			return 0, 0, err
		}
		subs = filterSubscriptions(all, t)
		if len(subs) == 0 {
			if len(all) == 0 {
				return 0, 0, errors.New("the service principal can see no subscriptions; it needs Reader on the subscriptions (or a management group above them)")
			}
			return 0, 0, fmt.Errorf("none of the %d visible subscriptions is selected by subscriptions / excludeSubscriptions, or all are disabled", len(all))
		}
		for _, sub := range subs {
			subNames[sub.ID] = sub.Name
			subIDs = append(subIDs, sub.ID)
		}
		return len(subs), 0, nil
	})

	if ok {
		accountsListed = step("accounts", false, func() (int, int, error) {
			bad := 0
			err := cli.ResourceGraph(ctx, azure.QueryAccounts, subIDs, func(rows []azure.Row) error {
				now := time.Now().UTC()
				page := make([]model.Account, 0, len(rows))
				for _, row := range rows {
					a, err := newAccount(scope, r.ID, row, subNames, now)
					if err != nil {
						bad++
						log.Warn("storage account left out: its properties could not be read", "step", "accounts", "account", row.Name, "error", err)
						continue
					}
					page = append(page, a)
				}
				// Stored straight away, so new accounts show up before the
				// slower steps finish. Sizes follow.
				if err := c.Store.SaveAccounts(ctx, page); err != nil {
					return fmt.Errorf("writing to MongoDB: %w", err)
				}
				accounts = append(accounts, page...)
				return nil
			})
			return len(accounts), bad, err
		})
	}

	if accountsListed {
		if c.Cfg.CollectUsage() {
			step("usage", false, func() (int, int, error) {
				known := c.readUsage(ctx, cli, accounts, log.With("step", "usage"))
				if err := c.Store.SaveAccounts(ctx, accounts); err != nil {
					return known, len(accounts) - known, fmt.Errorf("writing to MongoDB: %w", err)
				}
				if known == 0 && len(accounts) > 0 && ctx.Err() == nil {
					return 0, len(accounts), errors.New("no storage account returned a used capacity; see the log for the first errors")
				}
				return known, len(accounts) - known, ctx.Err()
			})
		} else {
			for i := range accounts {
				accounts[i].UsageStatus = model.UsageSkipped
			}
		}
		if c.Cfg.CollectContainers() {
			step("containers", false, func() (int, int, error) {
				n, unmeasured, err := c.readContainers(ctx, cli, scope, r.ID, accounts, log.With("step", "containers"))
				for i := range accounts {
					if accounts[i].ContainersStatus == model.StatusFailed {
						keepContainers = append(keepContainers, accounts[i].ID)
					}
				}
				return n, unmeasured, err
			})
		}
		for i := range accounts {
			if accounts[i].ContainersStatus == "" {
				// Not listed in this pass (switched off, or cancelled):
				// what is stored about its containers stays.
				keepContainers = append(keepContainers, accounts[i].ID)
				if !c.Cfg.CollectContainers() {
					accounts[i].ContainersStatus = "skipped"
				}
			}
		}
	}

	if ok && c.Cfg.CollectDisks() {
		disksListed = step("disks", false, func() (int, int, error) {
			bad := 0
			err := cli.ResourceGraph(ctx, azure.QueryDisks, subIDs, func(rows []azure.Row) error {
				now := time.Now().UTC()
				page := make([]model.Disk, 0, len(rows))
				for _, row := range rows {
					d, err := newDisk(scope, r.ID, row, subNames, now)
					if err != nil {
						bad++
						log.Warn("disk left out: its properties could not be read", "step", "disks", "disk", row.Name, "error", err)
						continue
					}
					page = append(page, d)
				}
				if err := c.Store.SaveDisks(ctx, page); err != nil {
					return fmt.Errorf("writing to MongoDB: %w", err)
				}
				disks = append(disks, page...)
				return nil
			})
			return len(disks), bad, err
		})
	}

	// Totals, per subscription and for the tenant.
	perSub := map[string]*model.Counts{}
	sub := func(id string) *model.Counts {
		if perSub[id] == nil {
			perSub[id] = &model.Counts{}
		}
		return perSub[id]
	}
	for i := range accounts {
		countAccount(sub(accounts[i].SubscriptionID), &accounts[i])
	}
	for i := range disks {
		countDisk(sub(disks[i].SubscriptionID), &disks[i])
	}
	warnings := tr.Counts.Warnings
	tr.Counts = model.Counts{Subscriptions: len(subs), Warnings: warnings}
	for _, cnt := range perSub {
		tr.Counts.Add(*cnt)
	}

	if ok {
		// Recorded even when the run was cancelled part-way: what was
		// collected is stored, nothing is pruned.
		wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
		cancelled := ctx.Err() != nil
		t0 := time.Now()
		err := c.finish(wctx, scope, r.ID, subs, perSub, accounts, keepContainers,
			accountsListed && !cancelled, disksListed && !cancelled)
		cancel()
		st := model.Step{Name: "store", Status: model.StatusSuccess, DurationMs: time.Since(t0).Milliseconds(), Count: len(accounts) + len(disks)}
		if err != nil {
			st.Status, st.Error = model.StatusFailed, err.Error()
			tr.Status, tr.Error = model.StatusFailed, "store: "+err.Error()
			log.Error("step failed", "step", "store", "error", err)
		}
		tr.Steps = append(tr.Steps, st)
	}
	if ctx.Err() != nil && tr.Status != model.StatusFailed {
		tr.Status = model.StatusCancelled
	}

	now := time.Now().UTC()
	tr.DurationMs = now.Sub(started).Milliseconds()
	doc := model.Tenant{
		ID: t.ID, Scope: scope, Counts: tr.Counts, Missing: append([]string{}, missing...),
		LastRunID: r.ID, LastStatus: tr.Status, LastError: tr.Error, LastAttemptAt: now,
	}
	if tr.Status == model.StatusSuccess || tr.Status == model.StatusPartial {
		doc.LastSuccessAt = &now
	}
	if tr.Status != model.StatusCancelled {
		wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		if err := c.Store.SaveTenant(wctx, &doc); err != nil {
			log.Error("tenant record not written", "error", err)
			tr.Counts.Warnings++
		}
		cancel()
	}
	log.Info("tenant done", "status", tr.Status, "subscriptions", tr.Counts.Subscriptions, "accounts", tr.Counts.Accounts,
		"usedBytes", tr.Counts.UsedBytes, "containers", tr.Counts.Containers, "containersMeasured", tr.Counts.ContainersMeasured,
		"disks", tr.Counts.Disks, "diskBytes", tr.Counts.DiskBytes, "duration", time.Duration(tr.DurationMs)*time.Millisecond)
	return tr
}

// finish writes the accounts with their final figures and the subscription
// totals, and removes what is gone.
func (c *Collector) finish(ctx context.Context, scope model.Scope, runID string, subs []azure.Subscription, perSub map[string]*model.Counts,
	accounts []model.Account, keepContainers []string, pruneAccounts, pruneDisks bool) error {
	if err := c.Store.SaveAccounts(ctx, accounts); err != nil {
		return err
	}
	now := time.Now().UTC()
	docs := make([]model.Subscription, 0, len(subs))
	for _, sub := range subs {
		cnt := model.Counts{}
		if p := perSub[sub.ID]; p != nil {
			cnt = *p
		}
		docs = append(docs, model.Subscription{
			ID: model.NewID(scope, "subscription", sub.ID), Scope: scope, RunID: runID,
			SubscriptionID: sub.ID, Name: sub.Name, State: sub.State, Counts: cnt, LastSeenAt: now,
		})
	}
	if err := c.Store.SaveSubscriptions(ctx, scope, runID, docs, pruneAccounts && pruneDisks); err != nil {
		return err
	}
	if pruneAccounts {
		if err := c.Store.PruneAccounts(ctx, scope, runID); err != nil {
			return err
		}
		if err := c.Store.PruneContainers(ctx, scope, runID, keepContainers); err != nil {
			return err
		}
	}
	if pruneDisks {
		return c.Store.PruneDisks(ctx, scope, runID)
	}
	return nil
}

// readUsage fills in each account's used capacity and returns how many have
// one.
func (c *Collector) readUsage(ctx context.Context, cli AzureAPI, accounts []model.Account, log *slog.Logger) int {
	var known, warned atomic.Int64
	services := c.Cfg.ServiceBreakdown()
	each(ctx, c.Cfg.Concurrency.Accounts, accounts, func(a *model.Account) {
		u, warn, err := cli.AccountUsage(ctx, a.ResourceID, a.Kind, services)
		if ctx.Err() != nil {
			return
		}
		l := log.With("account", a.Name)
		switch {
		case err != nil:
			a.UsageStatus, a.UsageError = model.UsageFailed, err.Error()
			logLimited(l, &warned, "used capacity could not be read", "error", err)
			return
		case u.UsedBytes == nil:
			// New accounts have no value for the first day or so.
			a.UsageStatus = model.UsageMissing
			l.Debug("Azure Monitor has no used capacity for the account yet")
			return
		}
		if warn != nil {
			logLimited(l, &warned, "capacity of a service could not be read; the account total is still stored", "error", warn)
		}
		a.UsageStatus, a.UsageAt = model.UsageKnown, u.At
		a.UsedBytes = *u.UsedBytes
		a.BlobBytes, a.FileBytes, a.TableBytes, a.QueueBytes = val(u.BlobBytes), val(u.FileBytes), val(u.TableBytes), val(u.QueueBytes)
		a.BlobCount, a.FileShares = val(u.BlobCount), val(u.FileShares)
		known.Add(1)
	})
	return int(known.Load())
}

func val(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

func logLimited(l *slog.Logger, n *atomic.Int64, msg string, args ...any) {
	switch v := n.Add(1); {
	case v <= warnLimit:
		l.Warn(msg, args...)
	case v == warnLimit+1:
		l.Warn("more of the same follow; they are logged at debug level", args...)
		fallthrough
	default:
		l.Debug(msg, args...)
	}
}

// readContainers lists every account's containers, measures them, and
// stores them account by account. It returns how many containers were found
// and how many of those have no size from this pass.
func (c *Collector) readContainers(ctx context.Context, cli AzureAPI, scope model.Scope, runID string, accounts []model.Account, log *slog.Logger) (int, int, error) {
	var found, unmeasured, warned, listFailed atomic.Int64
	var mu sync.Mutex
	var storeErr error
	measure := c.Cfg.MeasureContainers()
	snapshots, versions, deleted := c.Cfg.BlobIncludes()
	opts := azure.ListOptions{Snapshots: snapshots, Versions: versions, Deleted: deleted, MaxBlobs: c.Cfg.ContainerSizes.MaxBlobs}

	each(ctx, c.Cfg.Concurrency.Accounts, accounts, func(a *model.Account) {
		l := log.With("account", a.Name)
		if strings.EqualFold(a.Kind, "FileStorage") { // has no blob service
			a.ContainersStatus = model.StatusSuccess
			return
		}
		listed, err := cli.Containers(ctx, a.ResourceID)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			a.ContainersStatus, a.ContainersError = model.StatusFailed, err.Error()
			listFailed.Add(1)
			logLimited(l, &warned, "containers could not be listed", "error", err)
			return
		}
		now := time.Now().UTC()
		docs := make([]model.Container, len(listed))
		for i, bc := range listed {
			docs[i] = newContainer(scope, runID, a, bc, now)
		}

		// A reason nothing in the account can be measured.
		var whole atomic.Pointer[sizeFailure]
		switch {
		case !measure:
			whole.Store(&sizeFailure{status: model.SizeSkipped})
		case c.Cfg.SizeExcluded(a.Name):
			whole.Store(&sizeFailure{status: model.SizeSkipped, text: "the account is in containerSizes.excludeAccounts"})
		case a.BlobEndpoint == "":
			whole.Store(&sizeFailure{status: model.SizeFailed, text: "the account has no blob endpoint"})
		}
		each(ctx, c.Cfg.Concurrency.Containers, docs, func(d *model.Container) {
			if f := whole.Load(); f != nil {
				d.SizeStatus, d.SizeError = f.status, f.text
				return
			}
			lctx, cancel := context.WithTimeout(ctx, c.Cfg.ContainerSizes.Timeout.D())
			u, err := cli.ContainerUsage(lctx, a.BlobEndpoint, d.Name, opts)
			timedOut := lctx.Err() != nil && ctx.Err() == nil
			cancel()
			switch {
			case ctx.Err() != nil:
				d.SizeStatus, d.SizeError = model.SizeFailed, "the run was cancelled"
			case err == nil || timedOut:
				d.ContainerSize = containerSize(u, time.Now().UTC())
				d.SizeStatus = model.SizeMeasured
				if timedOut {
					d.SizeStatus = model.SizePartial
					d.SizeError = fmt.Sprintf("listing stopped after %s (containerSizes.timeout); the size is a lower bound", c.Cfg.ContainerSizes.Timeout.D())
				} else if u.Truncated {
					d.SizeStatus = model.SizePartial
					d.SizeError = fmt.Sprintf("listing stopped at %d blobs (containerSizes.maxBlobs); the size is a lower bound", u.Objects)
				}
			default:
				f := classify(err)
				d.SizeStatus, d.SizeError = f.status, f.text
				if f.wholeAccount {
					whole.CompareAndSwap(nil, &f)
				}
			}
		})
		if ctx.Err() != nil {
			return // half-measured: leave what is stored
		}

		a.Containers, a.ContainersStatus = len(docs), model.StatusSuccess
		reasons := map[string]int{}
		for i := range docs {
			if docs[i].Sized() {
				a.ContainersMeasured++
				a.ContainerBytes += docs[i].UsedBytes
			} else {
				reasons[docs[i].SizeStatus]++
			}
		}
		if f := whole.Load(); f != nil && len(docs) > 0 {
			a.SizeStatus = f.status
		}
		found.Add(int64(len(docs)))
		unmeasured.Add(int64(len(docs) - a.ContainersMeasured))
		if n := len(docs) - a.ContainersMeasured; n > 0 && measure && !c.Cfg.SizeExcluded(a.Name) {
			first := ""
			for i := range docs {
				if !docs[i].Sized() {
					first = docs[i].SizeError
					break
				}
			}
			logLimited(l, &warned, "containers could not be measured", "containers", n, "of", len(docs), "reasons", fmt.Sprint(reasons), "error", first)
		} else {
			l.Debug("containers read", "containers", len(docs), "measured", a.ContainersMeasured, "bytes", a.ContainerBytes)
		}
		if err := c.Store.SaveContainers(ctx, docs); err != nil {
			// The totals on the account would not match what is stored.
			a.ContainersStatus, a.ContainersError = model.StatusFailed, "writing to MongoDB: "+err.Error()
			mu.Lock()
			storeErr = err
			mu.Unlock()
		}
	})
	n, un := int(found.Load()), int(unmeasured.Load())
	switch {
	case ctx.Err() != nil:
		return n, un, ctx.Err()
	case storeErr != nil:
		return n, un, fmt.Errorf("writing to MongoDB: %w", storeErr)
	case listFailed.Load() > 0:
		return n, un, fmt.Errorf("the containers of %d of %d storage accounts could not be listed; see the log for the first errors", listFailed.Load(), len(accounts))
	}
	return n, un, nil
}

// sizeFailure is why a container was not measured.
type sizeFailure struct {
	status, text string
	// wholeAccount: the rest of the account's containers will fail the same
	// way, so they are not tried.
	wholeAccount bool
}

func classify(err error) sizeFailure {
	var api *azure.APIError
	if !errors.As(err, &api) {
		return sizeFailure{model.SizeUnreachable, "the blob endpoint could not be reached (a private endpoint or DNS the collector cannot use?): " + err.Error(), true}
	}
	switch {
	case api.Status == http.StatusForbidden && api.Code == "AuthorizationPermissionMismatch", api.Status == http.StatusUnauthorized:
		return sizeFailure{model.SizeDenied, "the service principal may not list blobs here; it needs the Storage Blob Data Reader role (" + api.Error() + ")", false}
	case api.Status == http.StatusForbidden:
		return sizeFailure{model.SizeBlocked, "the storage account refused the request, most likely by its network rules (" + api.Error() + ")", true}
	}
	return sizeFailure{model.SizeFailed, api.Error(), false}
}

func containerSize(u azure.ContainerUsage, at time.Time) model.ContainerSize {
	s := model.ContainerSize{
		UsedBytes: u.Total(), CurrentBytes: u.CurrentBytes, SnapshotBytes: u.SnapshotBytes, VersionBytes: u.VersionBytes,
		DeletedBytes: u.DeletedBytes, Blobs: u.Blobs, Objects: u.Objects, SizedAt: &at,
	}
	if len(u.Tiers) > 0 {
		s.Tiers = make(map[string]model.TierUsage, len(u.Tiers))
		for k, t := range u.Tiers {
			s.Tiers[k] = model.TierUsage{Bytes: t.Bytes, Count: t.Count}
		}
	}
	return s
}

func countAccount(c *model.Counts, a *model.Account) {
	c.Accounts++
	if a.UsageStatus == model.UsageKnown {
		c.UsedBytes += a.UsedBytes
		c.BlobBytes += a.BlobBytes
		c.FileBytes += a.FileBytes
		c.TableBytes += a.TableBytes
		c.QueueBytes += a.QueueBytes
		c.Blobs += a.BlobCount
	} else {
		c.AccountsUnknown++
	}
	if a.ContainersStatus == model.StatusSuccess {
		c.Containers += a.Containers
		c.ContainersMeasured += a.ContainersMeasured
		c.ContainerBytes += a.ContainerBytes
	}
}

func countDisk(c *model.Counts, d *model.Disk) {
	c.Disks++
	c.DiskBytes += d.SizeBytes
	if !d.Attached {
		c.DisksUnattached++
		c.UnattachedBytes += d.SizeBytes
	}
}

func resource(row azure.Row, subNames map[string]string) model.Resource {
	sub := strings.ToLower(row.SubscriptionID)
	return model.Resource{
		ResourceID: row.ID, Name: row.Name, Search: strings.ToLower(row.Name), Location: row.Location,
		ResourceGroup: strings.ToLower(row.ResourceGroup), SubscriptionID: sub, SubscriptionName: subNames[sub], Tags: row.Tags,
	}
}

func newAccount(scope model.Scope, runID string, row azure.Row, subNames map[string]string, now time.Time) (model.Account, error) {
	var p azure.AccountProperties
	if len(row.Properties) > 0 {
		if err := json.Unmarshal(row.Properties, &p); err != nil {
			return model.Account{}, err
		}
	}
	return model.Account{
		ID: model.NewID(scope, "account", row.ID), Scope: scope, RunID: runID, Resource: resource(row, subNames),
		Kind: row.Kind, Sku: row.Sku.Name, AccessTier: p.AccessTier, HNS: p.HNS, CreatedAt: p.CreationTime,
		BlobEndpoint: p.PrimaryEndpoints.Blob, PublicNetworkAccess: p.PublicNetworkAccess,
		NetworkDefaultAction: p.NetworkACLs.DefaultAction,
		// Azure treats an absent value as allowed.
		AllowBlobPublicAccess: p.AllowBlobPublicAccess == nil || *p.AllowBlobPublicAccess,
		MinimumTLS:            p.MinimumTLSVersion,
		FirstSeenAt:           now, LastSeenAt: now,
	}, nil
}

func newContainer(scope model.Scope, runID string, a *model.Account, bc azure.BlobContainer, now time.Time) model.Container {
	id := bc.ID
	if id == "" {
		id = a.ResourceID + "/blobServices/default/containers/" + bc.Name
	}
	access := bc.Properties.PublicAccess
	if access == "" {
		access = "None"
	}
	return model.Container{
		ID: model.NewID(scope, "container", id), Scope: scope, RunID: runID,
		AccountID: a.ID, AccountName: a.Name, ResourceID: id, Name: bc.Name,
		Search:        strings.ToLower(a.Name + "/" + bc.Name),
		ResourceGroup: a.ResourceGroup, SubscriptionID: a.SubscriptionID, SubscriptionName: a.SubscriptionName,
		PublicAccess: access, LeaseState: bc.Properties.LeaseState, LastModifiedAt: bc.Properties.LastModified,
		ImmutablePolicy: bc.Properties.ImmutablePolicy, LegalHold: bc.Properties.LegalHold,
		FirstSeenAt: now, LastSeenAt: now,
	}
}

func newDisk(scope model.Scope, runID string, row azure.Row, subNames map[string]string, now time.Time) (model.Disk, error) {
	var p azure.DiskProperties
	if len(row.Properties) > 0 {
		if err := json.Unmarshal(row.Properties, &p); err != nil {
			return model.Disk{}, err
		}
	}
	bytes := p.SizeBytes
	if bytes == 0 {
		bytes = p.SizeGB << 30
	}
	d := model.Disk{
		ID: model.NewID(scope, "disk", row.ID), Scope: scope, RunID: runID, Resource: resource(row, subNames),
		Sku: row.Sku.Name, Tier: p.Tier, SizeGB: p.SizeGB, SizeBytes: bytes, State: p.State,
		ManagedBy: row.ManagedBy, OSType: p.OSType, IOPS: p.IOPS, MBps: p.MBps, Zones: row.Zones,
		Encryption: p.Encryption.Type, CreateOption: p.CreationData.CreateOption, NetworkAccessPolicy: p.NetworkAccess,
		CreatedAt: p.TimeCreated, OwnershipChangedAt: p.OwnershipTime,
		FirstSeenAt: now, LastSeenAt: now,
	}
	// Reserved is a disk of a deallocated machine: still attached.
	d.Attached = row.ManagedBy != "" || strings.EqualFold(p.State, "Attached") || strings.EqualFold(p.State, "Reserved")
	if i := strings.LastIndexByte(row.ManagedBy, '/'); i >= 0 {
		d.AttachedTo = row.ManagedBy[i+1:]
	}
	return d, nil
}

func filterSubscriptions(all []azure.Subscription, t config.Tenant) []azure.Subscription {
	only, skip := map[string]bool{}, map[string]bool{}
	for _, id := range t.Subscriptions {
		only[id] = true
	}
	for _, id := range t.ExcludeSubscriptions {
		skip[id] = true
	}
	var out []azure.Subscription
	for _, s := range all {
		if skip[s.ID] || (len(only) > 0 && !only[s.ID]) {
			continue
		}
		// Disabled and deleted subscriptions cannot be queried.
		if s.State != "" && !strings.EqualFold(s.State, "Enabled") && !strings.EqualFold(s.State, "Warned") && !strings.EqualFold(s.State, "PastDue") {
			continue
		}
		out = append(out, s)
	}
	return out
}
