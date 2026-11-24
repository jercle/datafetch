package collector

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jercle/datafetch/azurecves/pkg/azure"
	"github.com/jercle/datafetch/azurecves/pkg/config"
	"github.com/jercle/datafetch/azurecves/pkg/graph"
	"github.com/jercle/datafetch/azurecves/pkg/monitor"
)

// GlobalTenant is the tenantId used in stage state for stages that are not
// per tenant.
const GlobalTenant = "global"

type Collector struct {
	Cfg      *config.Config
	Store    Store
	Sink     monitor.Sink // may be nil
	Log      *slog.Logger
	Instance string
	Version  string
	// NewClient is replaceable in tests.
	NewClient func(config.Tenant) *azure.Client
	Now       func() time.Time
}

func New(cfg *config.Config, store Store, sink monitor.Sink, log *slog.Logger) *Collector {
	c := &Collector{
		Cfg: cfg, Store: store, Sink: sink, Log: log,
		Now: func() time.Time { return time.Now().UTC() },
	}
	// The endpoints of the configuration in use: Cfg is replaced between
	// passes when the settings change.
	c.NewClient = func(t config.Tenant) *azure.Client { return azure.NewClient(t, c.Cfg.Endpoints, log) }
	return c
}

// pass is the state of one collection run.
type pass struct {
	c   *Collector
	run *monitor.Run
	log *slog.Logger
	// mu guards run (including every stage result in it), clients and devCounts.
	mu      sync.Mutex
	tenants []*tenantRun
	// clients that reached Defender, for the CVE catalogue
	clients []*azure.Client

	// Set by deviceMerge and read-only afterwards.
	merged     bool
	canonical  map[string]string      // machine record -> device node, current records only
	superseded map[string]bool        // the other records of merged devices
	linked     map[string]*graph.Node // device node -> resource it runs on
	devTenant  map[string]string      // device node -> tenant
	devGroup   map[string]string      // device node -> device group

	// CVE counts per device from every tenant's vulnerabilities stage.
	devCounts map[string]*sevCount
	saved     time.Time // when the run record was last written
}

type stageFn func(context.Context, *progress) error

// Run collects every tenant once and returns the run record.
//
// Order: resources and the Defender machine list for every tenant, then one
// merge of all machine records into de-duplicated devices, then software,
// vulnerabilities and containers per tenant, then the stages that span
// tenants. Tenants run in parallel within each per-tenant phase.
func (c *Collector) Run(ctx context.Context, trigger string) *monitor.Run {
	start := c.Now()
	run := &monitor.Run{
		ID: monitor.NewRunID(start), Status: monitor.StatusRunning, Trigger: trigger, Instance: c.Instance, Version: c.Version,
		StartedAt: start, HeartbeatAt: start, TenantsTotal: len(c.Cfg.Tenants), Totals: map[string]int64{},
		Tenants: make([]monitor.TenantResult, len(c.Cfg.Tenants)), Global: []monitor.StageResult{},
	}
	p := &pass{c: c, run: run, log: c.Log.With("runId", run.ID), devCounts: map[string]*sevCount{}}
	for i, t := range c.Cfg.Tenants {
		run.Tenants[i] = monitor.TenantResult{TenantID: t.ID, Name: t.Name, Status: monitor.StatusRunning, Stages: []monitor.StageResult{}}
		tr := &tenantRun{p: p, t: t, cli: c.NewClient(t), log: p.log.With("tenant", t.Name), res: &run.Tenants[i],
			opts: graph.BuildOptions{Via: t.ID, TenantName: t.Name, RunID: run.ID, Now: start, StoreProperties: c.Cfg.StoreProperties}}
		tr.cli.Log = tr.log
		p.tenants = append(p.tenants, tr)
	}
	p.log.Info("collection started", "tenants", len(c.Cfg.Tenants), "trigger", trigger)
	p.save()

	// Keep the run record fresh: its heartbeat shows the process is alive,
	// and the stages in it carry what each is doing right now.
	hbCtx, stop := context.WithCancel(context.Background())
	var hb sync.WaitGroup
	hb.Add(1)
	go func() {
		defer hb.Done()
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-hbCtx.Done():
				return
			case <-t.C:
				p.save()
			}
		}
	}()

	on := c.Cfg.Enabled
	p.phase(ctx, "collecting resources and Defender machine records", []string{"resources", "devices"})
	if on("devices") && ctx.Err() == nil {
		p.global(ctx, "deviceMerge", p.deviceMerge)
	}
	p.phase(ctx, "collecting software, vulnerabilities and container findings", []string{"software", "vulnerabilities", "containers"})

	p.mu.Lock()
	for _, t := range p.tenants {
		t.res.Finish(c.Now().Sub(start))
		run.TenantsDone++
		if t.res.Status == monitor.StatusFailed {
			run.TenantsFailed++
		}
	}
	p.mu.Unlock()
	p.save()

	if ctx.Err() == nil {
		if on("vulnerabilities") {
			p.global(ctx, "vulnRollup", p.vulnRollup)
		}
		if on("cveDetails") {
			p.global(ctx, "cveDetails", p.cveDetails)
		}
		if on("costs") {
			p.global(ctx, "costs", p.costs)
		}
	}
	stop()
	hb.Wait()

	p.mu.Lock()
	end := c.Now()
	run.FinishedAt, run.HeartbeatAt, run.DurationMs = &end, end, end.Sub(start).Milliseconds()
	run.Status = runStatus(run, ctx.Err() != nil)
	run.Totals = totals(run)
	status := run.Status
	p.mu.Unlock()

	if status == monitor.StatusSuccess {
		// CVEs and software nobody has reported for a week are gone everywhere.
		if n, err := c.Store.PruneShared(context.WithoutCancel(ctx), end.Add(-7*24*time.Hour)); err != nil {
			p.log.Warn("pruning unused CVE and software nodes failed", "error", err)
		} else if n > 0 {
			p.log.Info("pruned unused CVE and software nodes", "removed", n)
		}
	}
	p.save()
	lvl := slog.LevelInfo
	if status != monitor.StatusSuccess {
		lvl = slog.LevelWarn
	}
	p.log.Log(ctx, lvl, "collection finished", "status", status, "duration", end.Sub(start).Round(time.Second).String(),
		"tenantsFailed", run.TenantsFailed)
	return run
}

// phase runs the named per-tenant stages, in order, for every tenant;
// TenantConcurrency tenants at a time.
func (p *pass) phase(ctx context.Context, what string, stages []string) {
	started := p.c.Now()
	p.log.Info("phase started: "+what, "stages", strings.Join(stages, ", "), "tenants", len(p.tenants))
	sem := make(chan struct{}, p.c.Cfg.TenantConcurrency)
	var wg sync.WaitGroup
	done := 0
	for _, t := range p.tenants {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			fns := map[string]stageFn{"resources": t.resources, "devices": t.devices, "software": t.software,
				"vulnerabilities": t.vulnerabilities, "containers": t.containers}
			for _, name := range stages {
				if !p.c.Cfg.Enabled(name) || ctx.Err() != nil {
					continue
				}
				p.stage(ctx, t.t.ID, t.t.Name, name, t.log, &t.res.Stages, fns[name])
			}
			p.mu.Lock()
			if t.defenderOK && !hasClient(p.clients, t.cli) {
				p.clients = append(p.clients, t.cli)
			}
			done++
			n := done
			p.mu.Unlock()
			p.log.Info("tenant finished phase", "tenant", t.t.Name, "done", n, "of", len(p.tenants))
		}()
	}
	wg.Wait()
	p.log.Info("phase finished: "+what, "duration", p.c.Now().Sub(started).Round(time.Second).String())
}

func hasClient(list []*azure.Client, c *azure.Client) bool {
	for _, x := range list {
		if x == c {
			return true
		}
	}
	return false
}

func (p *pass) global(ctx context.Context, name string, fn stageFn) {
	p.stage(ctx, GlobalTenant, "All tenants", name, p.log, &p.run.Global, fn)
}

// totals sums what the stages counted into the run's headline figures.
func totals(r *monitor.Run) map[string]int64 {
	out := map[string]int64{}
	take := func(s monitor.StageResult, keys ...string) {
		for _, k := range keys {
			name := k
			if s.Stage == "containers" && (k == "findings" || k == "cves") {
				name = "container" + strings.ToUpper(k[:1]) + k[1:]
			}
			out[name] += s.Counts[k]
		}
	}
	for _, t := range r.Tenants {
		for _, s := range t.Stages {
			switch s.Stage {
			case "resources":
				take(s, "subscriptions", "resources", "nodes", "edges")
			case "devices":
				take(s, "records")
			case "software":
				take(s, "installs")
			case "vulnerabilities":
				take(s, "findings")
			case "containers":
				take(s, "findings", "images", "taggedImages", "containers")
			}
		}
	}
	for _, s := range r.Global {
		if s.Stage == "deviceMerge" {
			take(s, "devices", "duplicateRecords")
		}
	}
	return out
}

func runStatus(r *monitor.Run, cancelled bool) string {
	if cancelled {
		return monitor.StatusCancelled
	}
	ok, bad := 0, 0
	for _, t := range r.Tenants {
		switch t.Status {
		case monitor.StatusSuccess:
			ok++
		case monitor.StatusPartial:
			ok++
			bad++
		default:
			bad++
		}
	}
	for _, s := range r.Global {
		if s.Status == monitor.StatusFailed {
			bad++
		}
	}
	switch {
	case bad == 0:
		return monitor.StatusSuccess
	case ok == 0:
		return monitor.StatusFailed
	}
	return monitor.StatusPartial
}

func copyCounts(in map[string]int64) map[string]int64 {
	out := make(map[string]int64, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// save writes a copy of the run record. Monitoring is best-effort: a
// failure here never stops a run.
func (p *pass) save() {
	if p.c.Sink == nil {
		return
	}
	p.mu.Lock()
	now := p.c.Now()
	p.run.HeartbeatAt, p.saved = now, now
	cp := *p.run
	copyStages := func(in []monitor.StageResult) []monitor.StageResult {
		out := make([]monitor.StageResult, len(in))
		for i, s := range in {
			out[i] = s
			out[i].Counts = copyCounts(s.Counts)
			if s.Status == monitor.StatusRunning {
				out[i].DurationMs = now.Sub(s.StartedAt).Milliseconds()
			}
		}
		return out
	}
	cp.Tenants = make([]monitor.TenantResult, len(p.run.Tenants))
	for i, t := range p.run.Tenants {
		cp.Tenants[i] = t
		cp.Tenants[i].Stages = copyStages(t.Stages)
	}
	cp.Global = copyStages(p.run.Global)
	cp.Totals = totals(&cp)
	p.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := p.c.Sink.SaveRun(ctx, &cp); err != nil {
		p.log.Debug("saving run record failed", "error", err)
	}
}

// errEmpty marks a stage whose API returned nothing: existing data is kept
// rather than swept, because "nothing" is far more often a permissions
// problem than a tenant that really emptied out.
var errEmpty = errors.New("no rows returned")

var errSkip = errors.New("skipped")

func skip(format string, a ...any) error {
	return fmt.Errorf("%w: %s", errSkip, fmt.Sprintf(format, a...))
}

// progress is how a running stage says what it is doing. Every Step is
// logged and shown against the stage in the run record; the counters are
// shown live too. While the stage runs, a reminder with the current step
// and counters is logged every ProgressEvery, so a stage that is waiting
// on a slow API can be told apart from one that is stuck.
type progress struct {
	p     *pass
	log   *slog.Logger
	dst   *[]monitor.StageResult
	i     int
	start time.Time
}

// result must be called with p.mu held.
func (g *progress) result() *monitor.StageResult { return &(*g.dst)[g.i] }

// Step records and logs what the stage has moved on to.
func (g *progress) Step(msg string, args ...any) {
	g.p.mu.Lock()
	first := g.result().Step == ""
	g.result().Step = msg
	stale := g.p.c.Now().Sub(g.p.saved) > 5*time.Second
	g.p.mu.Unlock()
	g.Info(msg, args...)
	// Show it in the run record straight away, but no more often than
	// every few seconds: some stages step once per page.
	if first || stale {
		g.p.save()
	}
}

// Info logs a progress line with the time since the stage started.
func (g *progress) Info(msg string, args ...any) {
	g.log.Info(msg, append(args, "elapsed", g.p.c.Now().Sub(g.start).Round(time.Second).String())...)
}

func (g *progress) Set(key string, v int64) {
	g.p.mu.Lock()
	g.result().Counts[key] = v
	g.p.mu.Unlock()
}

// Add increments a counter and returns its new value.
func (g *progress) Add(key string, n int64) int64 {
	g.p.mu.Lock()
	defer g.p.mu.Unlock()
	g.result().Counts[key] += n
	return g.result().Counts[key]
}

func (g *progress) snapshot() (step, counts string) {
	g.p.mu.Lock()
	defer g.p.mu.Unlock()
	r := g.result()
	keys := make([]string, 0, len(r.Counts))
	for k := range r.Counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s=%d", k, r.Counts[k])
	}
	return r.Step, strings.Join(parts, " ")
}

// write upserts nodes and edges, logging how long large writes take.
func (g *progress) write(ctx context.Context, nodes []graph.Node, edges []graph.Edge) error {
	if len(nodes) == 0 && len(edges) == 0 {
		return nil
	}
	began := time.Now()
	if err := g.p.c.Store.UpsertNodes(ctx, nodes); err != nil {
		return fmt.Errorf("writing %d nodes: %w", len(nodes), err)
	}
	if err := g.p.c.Store.UpsertEdges(ctx, edges); err != nil {
		return fmt.Errorf("writing %d edges: %w", len(edges), err)
	}
	if took := time.Since(began); took > 5*time.Second || len(nodes)+len(edges) >= 5000 {
		g.Info("wrote to MongoDB", "nodes", len(nodes), "edges", len(edges), "took", took.Round(time.Millisecond).String())
	}
	return nil
}

// stage runs fn as a stage: it appears in the run record as running from
// the moment it starts, and its outcome is kept as the per-tenant stage
// state.
func (p *pass) stage(ctx context.Context, tenantID, tenantName, name string, log *slog.Logger, dst *[]monitor.StageResult, fn stageFn) {
	start := p.c.Now()
	log = log.With("stage", name)
	p.mu.Lock()
	*dst = append(*dst, monitor.StageResult{Stage: name, Status: monitor.StatusRunning, StartedAt: start, Counts: map[string]int64{}})
	pg := &progress{p: p, log: log, dst: dst, i: len(*dst) - 1, start: start}
	p.mu.Unlock()
	log.Info("stage started")
	p.save()

	// Remind the log what a long stage is up to.
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(time.Duration(p.c.Cfg.ProgressEvery))
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				step, counts := pg.snapshot()
				pg.Info("stage still running", "doing", step, "counts", counts)
			}
		}
	}()
	err := fn(ctx, pg)
	close(done)
	wg.Wait()

	_, counts := pg.snapshot()
	p.mu.Lock()
	res := pg.result()
	res.DurationMs = p.c.Now().Sub(start).Milliseconds()
	keep := true
	switch {
	case err == nil:
		res.Status, res.Step = monitor.StatusSuccess, ""
	case errors.Is(err, errSkip):
		res.Status, res.Error, res.Step = monitor.StatusSkipped, err.Error(), ""
		keep = false // a skipped stage leaves the previous state untouched
	case errors.Is(err, errEmpty):
		res.Status, res.Error = monitor.StatusEmpty, err.Error()
	case ctx.Err() != nil:
		res.Status, res.Error = monitor.StatusCancelled, "cancelled"
		keep = false
	default:
		res.Status, res.Error = monitor.StatusFailed, err.Error()
	}
	final := *res
	final.Counts = copyCounts(res.Counts)
	p.mu.Unlock()

	took := (time.Duration(final.DurationMs) * time.Millisecond).Round(time.Second).String()
	switch final.Status {
	case monitor.StatusSuccess:
		log.Info("stage finished", "durationMs", final.DurationMs, "took", took, "counts", counts)
	case monitor.StatusSkipped:
		log.Info("stage skipped", "reason", final.Error)
	case monitor.StatusEmpty:
		log.Warn("stage returned no data; existing data kept", "error", final.Error)
	case monitor.StatusCancelled:
		log.Warn("stage cancelled", "doing", final.Step, "took", took, "counts", counts)
	default:
		log.Error("stage failed", "error", final.Error, "doing", final.Step, "durationMs", final.DurationMs, "counts", counts)
	}
	p.save()
	if !keep {
		return
	}
	st := &monitor.StageState{
		ID: tenantID + "|" + name, TenantID: tenantID, TenantName: tenantName, Stage: name, Status: final.Status,
		Error: final.Error, RunID: p.run.ID, At: p.c.Now(), DurationMs: final.DurationMs, Counts: final.Counts,
	}
	if final.Status == monitor.StatusSuccess {
		st.LastSuccessAt = &st.At
	}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	if err := p.c.Store.SaveState(sctx, st); err != nil {
		log.Warn("saving stage state failed", "error", err)
	}
}
