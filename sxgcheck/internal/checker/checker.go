// Package checker is the pass itself: check every firewall, work out what
// changed since the last pass, and store the state, the history and the
// changes.
package checker

import (
	"context"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jercle/datafetch/sxgcheck/internal/config"
	"github.com/jercle/datafetch/sxgcheck/internal/model"
	"github.com/jercle/datafetch/sxgcheck/internal/monitor"
	"github.com/jercle/datafetch/sxgcheck/internal/probe"
	"github.com/jercle/datafetch/sxgcheck/internal/store"
)

const writeTimeout = 15 * time.Second

type Checker struct {
	Cfg   *config.Config
	Store store.Store
	Mon   *monitor.Monitor
	Log   *slog.Logger
	// Instance owns the firewall documents this checker writes.
	Instance string
	// IntervalSeconds is stored on every firewall; 0 for a single run.
	IntervalSeconds int
	// SetRun tags the log sink with the current run.
	SetRun func(id string)
	// Probe makes the checks on one firewall.
	Probe func(ctx context.Context, fw config.Firewall) probe.Result

	mu sync.Mutex
	// prev is each firewall's state after the last pass, by name.
	prev   map[string]*model.Firewall
	loaded bool
}

// load reads the stored state once, so that "since" survives a restart and
// a restart does not report every problem as new.
func (c *Checker) load(ctx context.Context, log *slog.Logger) {
	if c.loaded {
		return
	}
	if c.prev == nil {
		c.prev = map[string]*model.Firewall{}
	}
	lctx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()
	docs, err := c.Store.LoadFirewalls(lctx, c.Instance)
	if err != nil {
		log.Warn("stored state not read; changes are judged from this run on", "error", err)
		return
	}
	for i := range docs {
		if _, known := c.prev[docs[i].ID]; !known {
			c.prev[docs[i].ID] = &docs[i]
		}
	}
	c.loaded = true
}

// Run makes one pass and returns its record.
func (c *Checker) Run(ctx context.Context, trigger string, next *time.Time) *model.Run {
	fws := c.Cfg.Firewalls
	r := c.Mon.StartRun(ctx, trigger, len(fws))
	if c.SetRun != nil {
		c.SetRun(r.ID)
		defer c.SetRun("")
	}
	log := c.Log.With("run", r.ID)
	log.Debug("run started", "firewalls", len(fws))
	c.load(ctx, log)

	sem := make(chan struct{}, max(1, c.Cfg.Concurrency))
	var wg sync.WaitGroup
	for _, fw := range fws {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			flog := log.With("firewall", fw.Name)
			if fw.TenantName != "" {
				flog = flog.With("tenantName", fw.TenantName)
			}
			fr := c.checkFirewall(ctx, r.ID, fw, flog)
			c.Mon.Progress(func() {
				r.Firewalls = append(r.Firewalls, fr)
				r.FirewallsDone++
				if fr.Error != "" {
					r.FirewallsFailed++
				}
				r.Counts.Add(fr.Health)
				r.Checks.OK += fr.Checks.OK
				r.Checks.Warning += fr.Checks.Warning
				r.Checks.Critical += fr.Checks.Critical
				r.Changes += fr.Changes
			})
		}()
	}
	wg.Wait()

	status, errText := model.StatusSuccess, ""
	switch {
	case ctx.Err() != nil:
		status = model.StatusCancelled
	case r.FirewallsFailed > 0 && r.FirewallsFailed == r.FirewallsDone:
		status, errText = model.StatusFailed, "no result could be stored"
	case r.FirewallsFailed > 0:
		status = model.StatusPartial
	}
	if status != model.StatusCancelled {
		keep := make([]string, len(fws))
		for i, fw := range fws {
			keep[i] = fw.Name
		}
		pctx, cancel := context.WithTimeout(ctx, writeTimeout)
		if err := c.Store.PruneFirewalls(pctx, c.Instance, keep); err != nil {
			log.Warn("firewalls no longer configured were not removed", "error", err)
		}
		cancel()
	}
	c.Mon.Progress(func() {
		sort.Slice(r.Firewalls, func(i, j int) bool { return r.Firewalls[i].Name < r.Firewalls[j].Name })
	})
	c.Mon.FinishRun(ctx, r, status, errText, next)
	// One line per run at info would be 1,440 a day; say something only
	// when there is something to say.
	level := slog.LevelDebug
	if r.Changes > 0 || status != model.StatusSuccess {
		level = slog.LevelInfo
	}
	log.Log(ctx, level, "run finished", "status", status, "firewalls", r.FirewallsDone,
		"ok", r.Counts.OK, "warning", r.Counts.Warning, "critical", r.Counts.Critical,
		"changes", r.Changes, "duration", time.Duration(r.DurationMs)*time.Millisecond)
	return r
}

func search(fw config.Firewall) string {
	return strings.ToLower(strings.Join([]string{fw.Name, fw.Host, fw.Site}, " "))
}

func (c *Checker) checkFirewall(ctx context.Context, runID string, fw config.Firewall, log *slog.Logger) model.FirewallRun {
	started := time.Now().UTC()
	res := c.Probe(ctx, fw)
	now := time.Now().UTC()
	fr := model.FirewallRun{Name: fw.Name, TenantName: fw.TenantName, DurationMs: now.Sub(started).Milliseconds()}
	if ctx.Err() != nil {
		// Checks cut short by shutdown say nothing about the firewall.
		fr.Health, fr.Error = model.HealthOK, "cancelled"
		if p := c.previous(fw.Name); p != nil {
			fr.Health = p.Status
		}
		return fr
	}

	prev := c.previous(fw.Name)
	doc := &model.Firewall{
		ID: fw.Name, Name: fw.Name, Host: fw.Host, Search: search(fw),
		TenantName: fw.TenantName, Site: fw.Site, Tags: fw.Tags,
		Instance: c.Instance, RunID: runID,
		Status: model.HealthOK, StatusSince: now, Checks: res.Checks,
		Device: res.Device, HA: res.HA, Services: res.Services, Licenses: res.Licenses,
		FirstSeenAt: now, LastCheckedAt: now, IntervalSeconds: c.IntervalSeconds,
	}
	if !res.Metrics.Empty() {
		m := res.Metrics
		doc.Metrics = &m
	}
	var events []model.Event
	event := func(checkID, checkName, from, to, message string, since time.Time) {
		e := model.Event{At: now, RunID: runID, Firewall: fw.Name, TenantName: fw.TenantName,
			Check: checkID, CheckName: checkName, From: from, To: to, Severity: model.Rank(to), Message: message}
		if from != "" {
			e.DownForMs = now.Sub(since).Milliseconds()
		}
		events = append(events, e)
	}

	was := map[string]model.Check{}
	if prev != nil {
		doc.FirstSeenAt, doc.LastOKAt = prev.FirstSeenAt, prev.LastOKAt
		for _, k := range prev.Checks {
			was[k.ID] = k
		}
		// What the firewall says about itself outlives a pass in which it
		// could not be asked.
		if doc.Device == nil {
			doc.Device = prev.Device
		} else if prev.Device != nil && doc.Device.Hostname == "" && doc.Device.Firmware == "" {
			api := doc.Device.APIVersion
			d := *prev.Device
			d.APIVersion = api
			doc.Device = &d
		}
	}
	var problems []string
	for i := range doc.Checks {
		k := &doc.Checks[i]
		k.Since = now
		doc.Counts.Add(k.Status)
		if model.Rank(k.Status) > model.Rank(doc.Status) {
			doc.Status = k.Status
		}
		if k.Status != model.HealthOK {
			problems = append(problems, k.Name+": "+k.Message)
		}
		old, seen := was[k.ID]
		switch {
		case seen && old.Status == k.Status:
			k.Since = old.Since
		case seen:
			event(k.ID, k.Name, old.Status, k.Status, k.Message, old.Since)
		case k.Status != model.HealthOK:
			// New check, already failing.
			event(k.ID, k.Name, "", k.Status, k.Message, now)
		}
		if !seen || old.Status != k.Status {
			lvl := slog.LevelInfo
			switch {
			case k.Status == model.HealthCritical:
				lvl = slog.LevelError
			case k.Status == model.HealthWarning:
				lvl = slog.LevelWarn
			case !seen:
				lvl = slog.LevelDebug // a new check that is fine
			}
			log.Log(ctx, lvl, "check is "+k.Status, "check", k.ID, "was", old.Status, "message", k.Message)
		}
	}
	doc.Severity = model.Rank(doc.Status)
	doc.Summary = strings.Join(problems, "; ")
	if len(doc.Summary) > 1000 {
		doc.Summary = strings.ToValidUTF8(doc.Summary[:1000], "") + "…"
	}
	switch {
	case prev != nil && prev.Status == doc.Status:
		doc.StatusSince = prev.StatusSince
	case prev != nil:
		event("", "", prev.Status, doc.Status, doc.Summary, prev.StatusSince)
	case doc.Status != model.HealthOK:
		event("", "", "", doc.Status, doc.Summary, now)
	}
	if doc.Status == model.HealthOK {
		doc.LastOKAt = &now
	}
	if prev == nil || prev.Status != doc.Status {
		lvl := slog.LevelInfo
		if doc.Status == model.HealthCritical {
			lvl = slog.LevelError
		} else if doc.Status == model.HealthWarning {
			lvl = slog.LevelWarn
		}
		wasStatus := ""
		if prev != nil {
			wasStatus = prev.Status
		}
		log.Log(ctx, lvl, "firewall is "+doc.Status, "was", wasStatus, "host", fw.Host, "summary", doc.Summary)
	}

	fr.Health, fr.Checks, fr.Changes, fr.Summary = doc.Status, doc.Counts, len(events), doc.Summary

	result := &model.Result{At: now, RunID: runID, Firewall: fw.Name, TenantName: fw.TenantName, Status: doc.Status, Counts: doc.Counts, Metrics: doc.Metrics}
	for _, k := range doc.Checks {
		if k.Status != model.HealthOK {
			result.Failing = append(result.Failing, model.Failing{ID: k.ID, Name: k.Name, Status: k.Status, Message: k.Message})
		}
	}

	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), writeTimeout)
	defer cancel()
	if err := c.Store.SaveFirewall(wctx, doc); err != nil {
		// Keep the old state as the reference, so the changes are found and
		// recorded again once the store is back.
		fr.Error, fr.Changes = "not stored: "+err.Error(), 0
		log.Error("result not stored", "error", err)
		return fr
	}
	c.mu.Lock()
	c.prev[fw.Name] = doc
	c.mu.Unlock()
	if err := c.Store.SaveEvents(wctx, events); err != nil {
		log.Warn("changes not stored", "error", err, "changes", len(events))
	}
	if err := c.Store.SaveResult(wctx, result); err != nil {
		log.Warn("history entry not stored", "error", err)
	}
	return fr
}

func (c *Checker) previous(name string) *model.Firewall {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.prev[name]
}
