// Package collector fetches onboarded machines from every configured Defender
// for Endpoint tenant and stores a merged, per-VM view in MongoDB.
package collector

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/jercle/datafetch/mdetracker/internal/config"
	"github.com/jercle/datafetch/mdetracker/internal/defender"
	"github.com/jercle/datafetch/mdetracker/internal/model"
)

type MachineLister interface {
	ListMachines(ctx context.Context, filter string, pageSize int) ([]defender.Machine, error)
}

type Source struct {
	Tenant config.Tenant
	Lister MachineLister
}

type Store interface {
	StartRun(ctx context.Context, r *model.Run) error
	FinishRun(ctx context.Context, r *model.Run) error
	PreviousState(ctx context.Context) (map[string]Previous, error)
	UpsertVMs(ctx context.Context, vms []model.VM, changes map[string]model.OrgChange) error
	DeactivateMissing(ctx context.Context, runID string) (int64, error)
}

// Previous is what the store held for a VM before this run.
type Previous struct {
	OrgID   string
	Tenant  string
	Tenants []model.TenantContact
}

type Collector struct {
	cfg     *config.Config
	sources []Source
	store   Store
	log     *slog.Logger
	now     func() time.Time
}

func New(cfg *config.Config, sources []Source, store Store, log *slog.Logger) *Collector {
	return &Collector{cfg: cfg, sources: sources, store: store, log: log, now: func() time.Time { return time.Now().UTC() }}
}

type fetchResult struct {
	src     Source
	records []Record
	all     []defender.Machine // everything the API returned, before the mode filter
	fetched int
	dur     time.Duration
	err     error
}

// Run performs one full collection.
func (c *Collector) Run(ctx context.Context) error {
	runID := newRunID()
	log := c.log.With("runId", runID)
	run := &model.Run{ID: runID, StartedAt: c.now(), Status: model.RunRunning, Mode: c.cfg.Mode}
	if err := c.store.StartRun(ctx, run); err != nil {
		log.Error("could not record run start", "error", err.Error())
		return err
	}
	log.Info("collection run started", "tenants", len(c.sources), "mode", c.cfg.Mode)

	err := c.run(ctx, log, run)
	if err != nil {
		run.Error = err.Error()
		if run.Status == model.RunRunning {
			run.Status = model.RunFailed
		}
	}
	fin := c.now()
	run.FinishedAt = &fin
	run.DurationMs = fin.Sub(run.StartedAt).Milliseconds()

	// Record the outcome even if we were cancelled.
	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	if ferr := c.store.FinishRun(fctx, run); ferr != nil {
		log.Error("could not record run result", "error", ferr.Error())
	}

	attrs := []any{"status", run.Status, "durationMs", run.DurationMs, "vms", run.VMs,
		"conflicts", run.Conflicts, "migrated", run.Migrated, "inactive", run.Inactive,
		"orgChanges", run.OrgChanges, "withPreviousOrg", run.WithPreviousOrg, "deactivated", run.Deactivated}
	switch run.Status {
	case model.RunSuccess:
		log.Info("collection run finished", attrs...)
	case model.RunPartial:
		log.Warn("collection run finished with tenant errors", append(attrs, "error", run.Error)...)
	default:
		log.Error("collection run failed", append(attrs, "error", run.Error)...)
	}
	return err
}

func (c *Collector) run(ctx context.Context, log *slog.Logger, run *model.Run) error {
	results := c.fetchAll(ctx, log)
	if c.cfg.HostnameFallbackEnabled() {
		if n := includeByHostname(results, c.cfg.Mode); n > 0 {
			log.Info("kept machines excluded by mode because their computerDnsName matches a collected VM", "count", n)
		}
	}
	dump := newDumper(c.cfg, run.ID, log)
	dump.raw(results)
	defer func() { dump.finish(run) }()

	var recs []Record
	var failed []string
	for _, r := range results {
		tr := model.TenantRun{
			Name: r.src.Tenant.Name, TenantID: r.src.Tenant.TenantID, OrgID: r.src.Tenant.OrgID,
			Fetched: r.fetched, Matched: len(r.records), DurationMs: r.dur.Milliseconds(),
		}
		if r.err != nil {
			tr.Error = r.err.Error()
			failed = append(failed, r.src.Tenant.Name)
		}
		run.Tenants = append(run.Tenants, tr)
		recs = append(recs, r.records...)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(failed) == len(results) {
		return fmt.Errorf("all tenants failed: %s", strings.Join(failed, ", "))
	}
	// Pure in-memory merge; done before the partial check so a debug dump is
	// still complete for the tenants that did respond.
	vms := BuildVMs(recs, BuildOptions{
		Now: c.now(), ActiveWindow: c.cfg.ActiveWindow.Duration, InactiveAfter: c.cfg.InactiveAfter.Duration,
		MatchByHostname: c.cfg.MatchByHostname, HostnameFallback: c.cfg.HostnameFallbackEnabled(), RunID: run.ID,
	})
	byName := 0
	for _, vm := range vms {
		if vm.MergedByHostname {
			byName++
		}
	}
	if byName > 0 {
		log.Info("VMs merged on computerDnsName because their records share no stable ID", "count", byName)
	}
	dump.analysis(results, vms, c.cfg.MatchByHostname)

	var partialErr error
	if len(failed) > 0 {
		run.Status = model.RunPartial
		partialErr = fmt.Errorf("tenants failed: %s", strings.Join(failed, ", "))
		if !c.cfg.WriteOnPartial {
			log.Warn("skipping VM write because some tenants failed (set writeOnPartial to override)", "failedTenants", failed)
			return partialErr
		}
	}

	prev, err := c.store.PreviousState(ctx)
	if err != nil {
		return fmt.Errorf("load previous state: %w", err)
	}
	failedIDs := map[string]bool{}
	for _, r := range results {
		if r.err != nil {
			failedIDs[r.src.Tenant.TenantID] = true
		}
	}
	now := c.now()
	changes := map[string]model.OrgChange{}
	for i := range vms {
		vm := &vms[i]
		// Keep tenants that no longer return this VM so the migration trail survives.
		if p, ok := prev[vm.Key]; ok && len(p.Tenants) > 0 {
			vm.Tenants = MergeTenants(vm.Tenants, p.Tenants, failedIDs)
			Finalize(vm, now, c.cfg.InactiveAfter.Duration)
		}
		if vm.PreviousOrgID != "" {
			run.WithPreviousOrg++
		}
		switch vm.Status {
		case model.StatusConflict:
			run.Conflicts++
			orgs := make([]string, 0, len(vm.Onboardings))
			for _, ob := range vm.Onboardings {
				if ob.State != model.StateSuperseded {
					orgs = append(orgs, ob.TenantName+" ("+ob.OrgID+")")
				}
			}
			log.Warn("VM is reporting to more than one Defender org", "vm", vm.Name, "vmKey", vm.Key, "orgs", orgs)
		case model.StatusMigrated:
			run.Migrated++
		case model.StatusInactive:
			run.Inactive++
		}
		if p, ok := prev[vm.Key]; ok && p.OrgID != "" && p.OrgID != vm.CurrentOrgID {
			ch := model.OrgChange{From: p.OrgID, To: vm.CurrentOrgID, FromTenant: p.Tenant,
				ToTenant: vm.CurrentTenantName, At: now, RunID: run.ID}
			changes[vm.Key] = ch
			log.Info("VM onboarding org changed", "vm", vm.Name, "vmKey", vm.Key,
				"fromOrgId", ch.From, "fromTenant", ch.FromTenant, "toOrgId", ch.To, "toTenant", ch.ToTenant,
				"sameTenant", p.Tenant == vm.CurrentTenantName, "previousLastSeen", timeAttr(vm.PreviousLastSeen))
		}
	}
	run.VMs = len(vms)
	run.OrgChanges = len(changes)
	dump.vms(vms, changes)

	if err := c.store.UpsertVMs(ctx, vms, changes); err != nil {
		return fmt.Errorf("write VMs: %w", err)
	}
	run.VMsWritten = true
	log.Info("VM documents written", "count", len(vms))

	if len(failed) == 0 {
		n, err := c.store.DeactivateMissing(ctx, run.ID)
		if err != nil {
			return fmt.Errorf("deactivate missing VMs: %w", err)
		}
		run.Deactivated = n
		if n > 0 {
			log.Info("marked VMs no longer present in any tenant as inactive", "count", n)
		}
		run.Status = model.RunSuccess
	}
	return partialErr
}

func (c *Collector) fetchAll(ctx context.Context, log *slog.Logger) []fetchResult {
	results := make([]fetchResult, len(c.sources))
	sem := make(chan struct{}, c.cfg.Concurrency)
	var wg sync.WaitGroup
	for i, src := range c.sources {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = c.fetchTenant(ctx, log.With("tenant", src.Tenant.Name, "orgId", src.Tenant.OrgID), src)
		}()
	}
	wg.Wait()
	return results
}

func (c *Collector) fetchTenant(ctx context.Context, log *slog.Logger, src Source) (res fetchResult) {
	res.src = src
	start := time.Now()
	defer func() {
		if p := recover(); p != nil {
			res.err = fmt.Errorf("panic: %v", p)
		}
		res.dur = time.Since(start)
		if res.err != nil {
			log.Error("tenant collection failed", "error", res.err.Error(), "durationMs", res.dur.Milliseconds())
		}
	}()

	log.Info("fetching machines", "filter", src.Tenant.EffectiveFilter())
	machines, err := src.Lister.ListMachines(ctx, src.Tenant.EffectiveFilter(), c.cfg.PageSize)
	if err != nil {
		res.err = err
		return res
	}
	res.fetched = len(machines)
	res.all = machines
	ref := TenantRef{Name: src.Tenant.Name, TenantID: src.Tenant.TenantID, OrgID: src.Tenant.OrgID}
	for _, m := range machines {
		if matchesMode(m, c.cfg.Mode) {
			res.records = append(res.records, Record{Tenant: ref, Machine: m})
		}
	}
	log.Info("tenant collection complete", "fetched", res.fetched, "matched", len(res.records),
		"durationMs", time.Since(start).Milliseconds())
	return res
}

// timeAttr makes an optional time safe to log: nil becomes "".
func timeAttr(t *time.Time) any {
	if t == nil {
		return ""
	}
	return *t
}

// includeByHostname keeps machines the mode filter dropped (typically no Azure
// vmMetadata in a newly onboarded tenant) when their computerDnsName matches a
// machine that was kept in any tenant, so the hostname fallback can merge them.
func includeByHostname(results []fetchResult, mode string) int {
	hostKey := func(m defender.Machine) string { return strings.ToLower(strings.TrimSpace(m.ComputerDNSName)) }
	names := map[string]bool{}
	for _, r := range results {
		for _, rec := range r.records {
			if h := hostKey(rec.Machine); h != "" {
				names[h] = true
			}
		}
	}
	added := 0
	for i := range results {
		r := &results[i]
		ref := TenantRef{Name: r.src.Tenant.Name, TenantID: r.src.Tenant.TenantID, OrgID: r.src.Tenant.OrgID}
		for _, m := range r.all {
			if !matchesMode(m, mode) && names[hostKey(m)] {
				r.records = append(r.records, Record{Tenant: ref, Machine: m})
				added++
			}
		}
	}
	return added
}

var clientPlatforms = map[string]bool{
	"windows7": true, "windows8": true, "windows8blue": true, "windows10": true, "windows11": true,
	"macos": true, "ios": true, "android": true,
}

func matchesMode(m defender.Machine, mode string) bool {
	switch mode {
	case config.ModeAll:
		return true
	case config.ModeServers:
		p := strings.ToLower(m.OSPlatform)
		return m.IsAzureVM() || (p != "" && !clientPlatforms[p])
	default:
		return m.IsAzureVM()
	}
}

func newRunID() string {
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	return time.Now().UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(b)
}
