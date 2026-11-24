// Package collector makes one pass: for every tenant it reads the sources
// of every module that is switched on, stores the settings, records what
// changed since the pass before, and marks how each object compares with
// the baseline.
package collector

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/jercle/datafetch/azconfigdrift/internal/catalog"
	"github.com/jercle/datafetch/azconfigdrift/internal/cloud"
	"github.com/jercle/datafetch/azconfigdrift/internal/config"
	"github.com/jercle/datafetch/azconfigdrift/internal/model"
	"github.com/jercle/datafetch/azconfigdrift/internal/monitor"
	"github.com/jercle/datafetch/azconfigdrift/internal/store"
)

type Collector struct {
	Cfg     *config.Config
	Modules []catalog.Module
	Store   store.Store
	Mon     *monitor.Monitor
	Log     *slog.Logger
	// SetRun tells the log sink which run the following lines belong to.
	SetRun  func(string)
	Version string
	// NewClient makes the API client of a tenant; tests replace it.
	NewClient func(config.Tenant, *slog.Logger) *cloud.Client
	// Only, when not empty, limits the pass to these module ids whatever
	// their switches say (-modules).
	Only []string
}

// pass is what stays the same for a whole run.
type pass struct {
	run      *model.Run
	states   map[string]model.ModuleState
	baseline *model.Baseline
	covered  map[string]bool
	claimed  []string
}

const storeTimeout = 2 * time.Minute

// Run makes one pass. next is when the following one is due (nil: none).
func (c *Collector) Run(ctx context.Context, trigger string, next *time.Time) *model.Run {
	now := time.Now().UTC()
	docs := make([]model.Module, len(c.Modules))
	for i, m := range c.Modules {
		docs[i] = m.Doc(i, c.Version, now)
	}
	p := &pass{covered: map[string]bool{}, claimed: catalog.ClaimedTypes(c.Modules)}

	// The switches come from the database, where the dashboard stores
	// them, over the configuration. They and the baseline are read before
	// anything else: without the switches a module that was switched off
	// would be collected, and without the baseline the pass would mislabel
	// all drift, so it does not start.
	sctx, cancel := context.WithTimeout(ctx, storeTimeout)
	switches, err := c.Store.ModuleSwitches(sctx)
	states := states(overlay(c.Cfg.Modules, switches), c.Modules)
	if err == nil {
		err = c.Store.SyncModules(sctx, docs, states)
	}
	if err == nil {
		p.baseline, err = c.Store.ActiveBaseline(sctx)
	}
	cancel()
	p.states = states
	if len(c.Only) > 0 {
		p.states = map[string]model.ModuleState{}
		for _, id := range c.Only {
			p.states[id] = model.ModuleState{Enabled: true, DisabledSources: states[id].DisabledSources}
		}
	}
	var enabled []string
	for _, m := range c.Modules {
		if p.states[m.ID].Enabled {
			enabled = append(enabled, m.ID)
		}
	}
	if p.baseline != nil {
		for _, k := range p.baseline.Covered {
			p.covered[k] = true
		}
	}

	run := c.Mon.StartRun(ctx, trigger, len(c.Cfg.Tenants), enabled)
	p.run = run
	if c.SetRun != nil {
		c.SetRun(run.ID)
		defer c.SetRun("")
	}
	if err != nil {
		c.Log.Error("the pass did not start: the baseline could not be read", "error", err)
		c.Mon.FinishRun(ctx, run, model.StatusFailed, "writing the module catalogue and reading the baseline: "+err.Error(), next)
		return run
	}
	baselineID := ""
	if p.baseline != nil {
		baselineID = p.baseline.ID
	}
	c.Log.Info("pass started", "trigger", trigger, "tenants", len(c.Cfg.Tenants), "modules", len(enabled), "baseline", baselineID)
	if len(enabled) == 0 {
		c.Log.Warn("every module is switched off: nothing to collect")
	}

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
				return
			}
			tr := c.collectTenant(ctx, p, t)
			c.Mon.Progress(func() {
				// The tenant's entry was added when it started.
				for i := range run.Tenants {
					if run.Tenants[i].TenantID == tr.TenantID {
						run.Tenants[i] = tr
					}
				}
				run.TenantsDone++
				if tr.Status == model.StatusFailed {
					run.TenantsFailed++
				}
				run.Counts.Add(tr.Counts)
			})
		}()
	}
	wg.Wait()

	status, errText := model.StatusSuccess, ""
	var partial bool
	c.Mon.Progress(func() {
		for _, t := range run.Tenants {
			if t.Status != model.StatusSuccess {
				partial = true
			}
		}
	})
	switch {
	case ctx.Err() != nil:
		status = model.StatusCancelled
	case len(c.Cfg.Tenants) > 0 && run.TenantsFailed == len(c.Cfg.Tenants):
		status, errText = model.StatusFailed, "no tenant could be collected"
	case partial:
		status = model.StatusPartial
	}
	c.Mon.FinishRun(ctx, run, status, errText, next)
	c.Log.Info("pass finished", "status", status, "duration", time.Since(run.StartedAt).Round(time.Second).String(),
		"items", run.Counts.Items, "added", run.Counts.Added, "changed", run.Counts.Changed, "removed", run.Counts.Removed,
		"drifted", run.Counts.Drifted, "sourcesFailed", run.Counts.SourcesFailed, "sourcesDenied", run.Counts.SourcesDenied)
	return run
}

// overlay lays the switches set in the dashboard over the configuration's,
// switch by switch.
func overlay(cfg map[string]config.ModuleSetting, db []model.ModuleSwitches) map[string]config.ModuleSetting {
	out := make(map[string]config.ModuleSetting, len(cfg)+len(db))
	for id, m := range cfg {
		c := config.ModuleSetting{Enabled: m.Enabled, Sources: make(map[string]config.SourceSetting, len(m.Sources))}
		for sid, s := range m.Sources {
			c.Sources[sid] = s
		}
		out[id] = c
	}
	for _, d := range db {
		m := out[d.ID]
		if m.Sources == nil {
			m.Sources = map[string]config.SourceSetting{}
		}
		if d.Enabled != nil {
			m.Enabled = d.Enabled
		}
		for sid, s := range d.Sources {
			cur := m.Sources[sid]
			if s.Enabled != nil {
				cur.Enabled = s.Enabled
			}
			if s.Beta != nil {
				cur.Beta = s.Beta
			}
			if s.Delegated != nil {
				cur.Delegated = s.Delegated
			}
			m.Sources[sid] = cur
		}
		out[d.ID] = m
	}
	return out
}

// States works out each module's switches from the configuration alone:
// what it sets, and the catalogue's defaults for the rest.
func States(cfg *config.Config, mods []catalog.Module) map[string]model.ModuleState {
	return states(cfg.Modules, mods)
}

func states(set map[string]config.ModuleSetting, mods []catalog.Module) map[string]model.ModuleState {
	modules := set
	out := make(map[string]model.ModuleState, len(mods))
	for _, m := range mods {
		st := model.ModuleState{Enabled: m.DefaultEnabled, SourceBeta: map[string]bool{}, SourceDelegated: map[string]bool{}}
		set := modules[m.ID]
		if set.Enabled != nil {
			st.Enabled = *set.Enabled
		}
		for _, src := range m.Sources {
			ss, ok := set.Sources[src.ID]
			if !ok {
				continue
			}
			if ss.Enabled != nil && !*ss.Enabled {
				st.DisabledSources = append(st.DisabledSources, src.ID)
			}
			// Only Microsoft Graph has a beta version; any source can be
			// read as the service account.
			if ss.Beta != nil && src.Kind == catalog.KindGraph {
				st.SourceBeta[src.ID] = *ss.Beta
			}
			if ss.Delegated != nil {
				st.SourceDelegated[src.ID] = *ss.Delegated
			}
		}
		out[m.ID] = st
	}
	return out
}

// tenantEnv is what the modules of one tenant share.
type tenantEnv struct {
	pass    *pass
	tenant  config.Tenant
	scope   model.Scope
	log     *slog.Logger
	fetcher *fetcher
	prev    *model.Tenant
	// azureErr is set when the subscriptions could not be listed: no Azure
	// source can be read.
	azureErr error

	mu     sync.Mutex
	ignore *catalog.Ignore
}

func (c *Collector) collectTenant(ctx context.Context, p *pass, t config.Tenant) model.TenantRun {
	start := time.Now().UTC()
	scope := model.Scope{TenantID: t.ID, TenantName: t.Name}
	log := c.Log.With("tenantName", t.Name)
	tr := model.TenantRun{Scope: scope, Status: model.StatusRunning, StartedAt: start, Modules: []model.ModuleRun{}}
	c.Mon.Progress(func() { p.run.Tenants = append(p.run.Tenants, tr) })
	finish := func(status, errText string) model.TenantRun {
		tr.Status, tr.Error = status, errText
		tr.DurationMs = time.Since(start).Milliseconds()
		return tr
	}

	newClient := c.NewClient
	if newClient == nil {
		newClient = cloud.NewClient
	}
	env := &tenantEnv{
		pass: p, tenant: t, scope: scope, log: log, ignore: catalog.NewIgnore(c.Cfg),
		fetcher: &fetcher{client: newClient(t, log), tenant: t, log: log, claimed: p.claimed},
	}

	sctx, cancel := context.WithTimeout(ctx, storeTimeout)
	prev, err := c.Store.LoadTenant(sctx, t.ID)
	cancel()
	if err != nil {
		log.Error("tenant not collected: its stored state could not be read", "error", err)
		return finish(model.StatusFailed, "reading the tenant's stored state: "+err.Error())
	}
	if prev == nil {
		prev = &model.Tenant{ID: t.ID}
	}
	env.prev = prev

	var mods []catalog.Module
	azure := false
	for _, m := range c.Modules {
		if p.states[m.ID].Enabled && t.Has(m.Platform) {
			mods = append(mods, m)
			azure = azure || m.Platform == model.PlatformAzure
		}
	}
	if azure {
		if err := env.fetcher.loadSubscriptions(ctx); err != nil {
			env.azureErr = fmt.Errorf("listing subscriptions: %w", err)
			log.Error("Azure modules not collected: subscriptions could not be listed", "error", err)
		} else {
			log.Info("subscriptions listed", "subscriptions", len(env.fetcher.subs))
		}
	}

	// Sources that left the catalogue (a built-in one that was merged into
	// another, an extra source taken out of the configuration) leave their
	// objects behind: forget them.
	keep := map[string][]string{}
	for _, m := range c.Modules {
		for _, s := range m.Sources {
			keep[m.ID] = append(keep[m.ID], s.ID)
		}
	}
	sctx, cancel = context.WithTimeout(ctx, storeTimeout)
	dropped, err := c.Store.DropOtherSources(sctx, t.ID, keep)
	cancel()
	if err != nil {
		log.Warn("objects of sources that no longer exist could not be removed", "error", err)
	} else if dropped > 0 {
		log.Info("objects of sources that no longer exist removed", "objects", dropped)
	}

	// Modules run side by side; the sources of one module one after another.
	results := make([]model.ModuleRun, len(mods))
	entries := make([]model.TenantModule, len(mods))
	sem := make(chan struct{}, c.Cfg.Concurrency.Modules)
	var wg sync.WaitGroup
	for i, m := range mods {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i], entries[i] = c.collectModule(ctx, env, m)
			c.Mon.Progress(func() {
				for j := range p.run.Tenants {
					if p.run.Tenants[j].TenantID == t.ID {
						p.run.Tenants[j].Modules = append(p.run.Tenants[j].Modules, results[i])
					}
				}
			})
		}()
	}
	wg.Wait()

	ok, failed, firstErr := 0, 0, ""
	for _, mr := range results {
		tr.Modules = append(tr.Modules, mr)
		tr.Counts.Add(mr.Counts)
		for _, s := range mr.Sources {
			switch s.Status {
			case model.SourceOK:
				ok++
			case model.SourceDisabled:
			default:
				if s.Status == model.SourceFailed || s.Status == model.SourceCancelled {
					failed++
				}
				if firstErr == "" {
					firstErr = s.Error
				}
			}
		}
	}

	// Keep the entries of modules that did not run this time.
	doc := model.Tenant{ID: t.ID, TenantName: t.Name, Platforms: t.Platforms, LastRunID: p.run.ID, LastAttemptAt: start, LastSuccessAt: prev.LastSuccessAt}
	if len(doc.Platforms) == 0 {
		doc.Platforms = []string{model.PlatformAzure, model.PlatformM365}
	}
	ran := map[string]bool{}
	for _, e := range entries {
		ran[e.Module] = true
	}
	for _, e := range prev.Modules {
		if !ran[e.Module] {
			doc.Modules = append(doc.Modules, e)
		}
	}
	doc.Modules = append(doc.Modules, entries...)
	sort.SliceStable(doc.Modules, func(i, j int) bool { return doc.Modules[i].Module < doc.Modules[j].Module })
	for _, e := range doc.Modules {
		doc.Items += e.Items
	}

	status, errText := model.StatusSuccess, ""
	switch {
	case ctx.Err() != nil:
		status = model.StatusCancelled
	case len(mods) == 0:
		// Nothing is switched on for this tenant: not a failure.
	case ok == 0 && tr.Counts.Sources > 0:
		status, errText = model.StatusFailed, firstErr
	case failed > 0:
		status = model.StatusPartial
	}
	doc.LastStatus, doc.LastError = status, errText
	if status == model.StatusSuccess || status == model.StatusPartial {
		doc.LastSuccessAt = &start
	}
	sctx, cancel = context.WithTimeout(context.WithoutCancel(ctx), storeTimeout)
	err = c.Store.SaveTenant(sctx, &doc)
	cancel()
	if err != nil {
		log.Error("tenant state not stored", "error", err)
		if status == model.StatusSuccess {
			status, errText = model.StatusPartial, "storing the tenant's state: "+err.Error()
		}
	}
	log.Info("tenant finished", "status", status, "duration", time.Since(start).Round(time.Second).String(),
		"items", tr.Counts.Items, "added", tr.Counts.Added, "changed", tr.Counts.Changed, "removed", tr.Counts.Removed,
		"sources", tr.Counts.Sources, "sourcesFailed", tr.Counts.SourcesFailed)
	return finish(status, errText)
}

func (c *Collector) collectModule(ctx context.Context, env *tenantEnv, m catalog.Module) (model.ModuleRun, model.TenantModule) {
	start := time.Now().UTC()
	log := env.log.With("module", m.ID)
	state := env.pass.states[m.ID]
	mr := model.ModuleRun{Module: m.ID, Sources: []model.SourceRun{}}
	entry := model.TenantModule{Module: m.ID, Platform: m.Platform, At: start}
	prev := env.prev.Module(m.ID)
	log.Info("module started", "sources", len(m.Sources))

	worst := model.SourceOK
	rank := map[string]int{model.SourceOK: 0, model.SourceDisabled: 0, model.SourceUnsupported: 1, model.SourceDenied: 2, model.SourceCancelled: 3, model.SourceFailed: 4}
	for _, src := range m.Sources {
		sl := log.With("source", src.ID)
		ts := model.TenantSource{Source: src.ID, At: time.Now().UTC()}
		if old := prev.Source(src.ID); old != nil {
			ts.LastSuccessAt, ts.Items = old.LastSuccessAt, old.Items
		}
		var sr sourceResult
		switch {
		case c.Cfg.Skipped(m.ID, src.ID) || state.SourceDisabled(src.ID):
			sr.SourceRun = model.SourceRun{Source: src.ID, Status: model.SourceDisabled}
		case ctx.Err() != nil:
			sr.SourceRun = model.SourceRun{Source: src.ID, Status: model.SourceCancelled, Error: "the pass was stopped"}
		case m.Platform == model.PlatformAzure && env.azureErr != nil:
			sr.SourceRun = model.SourceRun{Source: src.ID, Status: cloud.Status(env.azureErr), Error: env.azureErr.Error()}
		default:
			// The dashboard's switches: whether to read as the service
			// account and, for Microsoft Graph, which version.
			src.Delegated = state.Delegated(src.ID, src.Delegated)
			sl = sl.With("as", readAs(src.Delegated))
			if src.Kind == catalog.KindGraph {
				src.Beta = state.Beta(src.ID, src.Beta)
				sl = sl.With("graphVersion", graphVersion(src.Beta))
			}
			sctx, cancel := context.WithTimeout(ctx, c.Cfg.Limits.SourceTimeout.D())
			sr = c.collectSource(sctx, env, m, src, ts.LastSuccessAt == nil, sl)
			cancel()
		}
		ts.Status, ts.Error, ts.DurationMs = sr.Status, sr.Error, sr.DurationMs
		if sr.Status == model.SourceOK {
			at := ts.At
			ts.LastSuccessAt, ts.Items = &at, sr.Items
		}
		if sr.Status != model.SourceDisabled {
			mr.Counts.Sources++
			mr.Counts.Items += sr.Items
			mr.Counts.Added += sr.Added
			mr.Counts.Changed += sr.Changed
			mr.Counts.Removed += sr.Removed
			if sr.Status != model.SourceOK {
				mr.Counts.SourcesFailed++
			}
			if sr.Status == model.SourceDenied {
				mr.Counts.SourcesDenied++
			}
		}
		if rank[sr.Status] > rank[worst] {
			worst = sr.Status
		}
		mr.Counts.Drifted += sr.drifted
		mr.Sources = append(mr.Sources, sr.SourceRun)
		entry.Sources = append(entry.Sources, ts)
		entry.Items += ts.Items
	}
	mr.Status, mr.DurationMs = worst, time.Since(start).Milliseconds()
	entry.Status, entry.DurationMs = worst, mr.DurationMs
	log.Info("module finished", "status", worst, "duration", time.Since(start).Round(time.Millisecond).String(),
		"items", mr.Counts.Items, "added", mr.Counts.Added, "changed", mr.Counts.Changed, "removed", mr.Counts.Removed, "sourcesFailed", mr.Counts.SourcesFailed)
	return mr, entry
}

func graphVersion(beta bool) string {
	if beta {
		return "beta"
	}
	return "v1.0"
}

func readAs(delegated bool) string {
	if delegated {
		return "service account"
	}
	return "application"
}

// errText is the message stored for a source that could not be read.
func errText(err error, src catalog.Source, status string) string {
	msg := err.Error()
	if errors.Is(err, context.DeadlineExceeded) {
		msg = "took longer than limits.sourceTimeout: " + msg
	}
	var tok *cloud.TokenError
	noAccount := errors.As(err, &tok) && tok.Code == cloud.ErrNoServiceAccount
	switch {
	case status != model.SourceDenied || src.Permission == "" || noAccount:
	case src.Delegated:
		msg += " (needs " + src.Permission + " as a delegated permission with admin consent, and a role for the service account that may read it)"
	default:
		msg += " (needs " + src.Permission + ")"
	}
	return msg
}
