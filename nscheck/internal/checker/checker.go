// Package checker runs the health checks: one pass logs in to every
// appliance, reads its state over NITRO, judges it, and stores the result
// with whatever changed since the pass before.
package checker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jercle/datafetch/nscheck/internal/config"
	"github.com/jercle/datafetch/nscheck/internal/model"
	"github.com/jercle/datafetch/nscheck/internal/monitor"
	"github.com/jercle/datafetch/nscheck/internal/nitro"
	"github.com/jercle/datafetch/nscheck/internal/store"
)

// API is the part of the NITRO client the checks use.
type API interface {
	Login(ctx context.Context) error
	Logout(ctx context.Context)
	Get(ctx context.Context, api, resource string) ([]nitro.Obj, error)
}

type Checker struct {
	Cfg   *config.Config
	Store store.Store
	Mon   *monitor.Monitor
	Log   *slog.Logger
	// SetRun tags the log sink with the running pass.
	SetRun    func(runID string)
	NewClient func(config.Appliance) (API, error)
	// Interval is stored on the appliance documents so a reader can tell
	// when one is overdue. Zero for a single pass.
	Interval time.Duration
	// Now replaces the clock (tests).
	Now func() time.Time

	mu    sync.Mutex
	state map[string]*memory
}

// memory is what the checker remembers of an appliance between passes, to
// tell what changed and to leave unchanged documents alone. It mirrors the
// store: it starts from what is stored and only moves on when a pass has
// been written, so a change is reported by the first pass that can store it.
type memory struct {
	// loaded: the stored state has been read.
	loaded    bool
	appliance *model.Appliance
	objects   map[string]map[string]model.ObjectState
	// logged is the health last written to the log.
	logged string
	// stepErr is the last error logged per step, so a standing failure is
	// logged once and not every pass.
	stepErr map[string]string
	// identity is the appliance's version, model and serial, read hourly.
	identity   *model.System
	identityAt time.Time
}

func (c *Checker) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now().UTC()
}

// Run makes one pass over every appliance. next is when the following pass
// is due, for the heartbeat document.
func (c *Checker) Run(ctx context.Context, trigger string, next *time.Time) *model.Run {
	aps := c.Cfg.Appliances
	run := c.Mon.StartRun(ctx, trigger, len(aps))
	if c.SetRun != nil {
		c.SetRun(run.ID)
		defer c.SetRun("")
	}
	log := c.Log.With("run", run.ID)
	log.Debug("pass started", "appliances", len(aps))

	sem := make(chan struct{}, max(1, c.Cfg.Concurrency))
	var wg sync.WaitGroup
	for _, ap := range aps {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			res, ok := c.checkAppliance(ctx, run.ID, ap)
			if !ok {
				return
			}
			c.Mon.Progress(func() {
				run.Appliances = append(run.Appliances, res.run)
				run.AppliancesDone++
				if res.run.Status == model.StatusFailed {
					run.AppliancesFailed++
				}
				switch res.run.Health {
				case model.HealthCritical:
					run.Counts.Critical++
				case model.HealthWarning:
					run.Counts.Warning++
				case model.HealthUnknown:
					run.Counts.Unknown++
				default:
					run.Counts.OK++
				}
				run.Counts.Events += res.events
			})
		}()
	}
	wg.Wait()

	status, errText := model.StatusSuccess, ""
	c.Mon.Progress(func() {
		sort.Slice(run.Appliances, func(i, j int) bool { return run.Appliances[i].Appliance < run.Appliances[j].Appliance })
		incomplete := 0
		for _, a := range run.Appliances {
			if a.Status != model.StatusSuccess {
				incomplete++
			}
		}
		switch {
		case ctx.Err() != nil && run.AppliancesDone < run.AppliancesTotal:
			status = model.StatusCancelled
		case run.AppliancesDone > 0 && run.AppliancesFailed == run.AppliancesDone:
			status, errText = model.StatusFailed, "no appliance could be reached"
		case incomplete > 0:
			status = model.StatusPartial
		}
	})
	level := slog.LevelInfo
	if status == model.StatusFailed {
		level = slog.LevelError
	}
	log.Log(ctx, level, "pass finished", "status", status,
		"appliances", run.AppliancesDone, "unreachable", run.AppliancesFailed,
		"ok", run.Counts.OK, "warning", run.Counts.Warning, "critical", run.Counts.Critical, "unknown", run.Counts.Unknown,
		"events", run.Counts.Events, "duration", c.now().Sub(run.StartedAt).Round(time.Millisecond))
	c.Mon.FinishRun(ctx, run, status, errText, next)
	return run
}

// remember returns the appliance's memory, merging in the stored state the
// first time the store can be read.
func (c *Checker) remember(ctx context.Context, id string, log *slog.Logger) *memory {
	c.mu.Lock()
	if c.state == nil {
		c.state = map[string]*memory{}
	}
	m := c.state[id]
	if m == nil {
		m = &memory{objects: map[string]map[string]model.ObjectState{}, stepErr: map[string]string{}}
		c.state[id] = m
	}
	c.mu.Unlock()
	if m.loaded {
		return m
	}
	st, err := c.Store.LoadState(ctx, id)
	if err != nil {
		if ctx.Err() == nil {
			log.Warn("the stored state could not be read; nothing is written for this appliance until it can", "error", err)
		}
		return m
	}
	m.loaded = true
	m.appliance = st.Appliance
	if st.Objects != nil {
		m.objects = st.Objects
	}
	if st.Appliance != nil {
		m.logged = st.Appliance.Status
	}
	return m
}

type result struct {
	run    model.ApplianceRun
	events int
}

// objSet is the outcome of a step for one collection: the documents that
// changed, and every _id that still exists.
type objSet struct {
	coll   string
	kinds  []string
	docs   []store.Doc
	keep   []string
	states map[string]model.ObjectState
}

// pass is the state of checking one appliance once.
type pass struct {
	c     *Checker
	ap    config.Appliance
	ref   model.Ref
	runID string
	log   *slog.Logger
	mem   *memory
	prev  *model.Appliance // nil the first time
	now   time.Time
	api   API

	doc    model.Appliance
	checks []model.Check
	steps  []model.Step
	events []model.Event
	sets   []*objSet
	// secondary: this node is the secondary of a pair, where virtual
	// servers and services are not evaluated.
	secondary bool
}

var errSkipped = errors.New("skipped")

func skipped(reason string) error { return fmt.Errorf("%w: %s", errSkipped, reason) }

// stepChecks are the checks a step produces; when the step fails they are
// reported as unknown.
var stepChecks = map[string][]string{
	"system":       {model.CheckCPU, model.CheckMgmtCPU, model.CheckMemory, model.CheckDiskFlash, model.CheckDiskVar},
	"ha":           {model.CheckHA},
	"config":       {model.CheckConfig},
	"interfaces":   {model.CheckInterfaces},
	"vservers":     {model.CheckVservers},
	"services":     {model.CheckServices},
	"certificates": {model.CheckCertificates},
}

// checkAppliance checks one appliance and stores the outcome. ok is false
// when the pass was cancelled before there was an outcome.
func (c *Checker) checkAppliance(ctx context.Context, runID string, ap config.Appliance) (res result, ok bool) {
	started := c.now()
	ref := model.Ref{ApplianceID: model.NewID("appliance", ap.Name), Appliance: ap.Name, TenantName: ap.TenantName}
	log := c.Log.With("run", runID, "appliance", ap.Name)
	if ap.TenantName != "" {
		log = log.With("tenantName", ap.TenantName)
	}
	mem := c.remember(ctx, ref.ApplianceID, log)
	p := &pass{c: c, ap: ap, ref: ref, runID: runID, log: log, mem: mem, prev: mem.appliance, now: started}
	p.doc = model.Appliance{
		ID: ref.ApplianceID, Name: ap.Name, TenantName: ap.TenantName, Address: ap.Address, RunID: runID,
		CheckedAt: started, FirstSeenAt: started, IntervalSeconds: int(c.Interval / time.Second),
	}
	if p.prev != nil {
		p.doc.FirstSeenAt, p.doc.LastSuccessAt = p.prev.FirstSeenAt, p.prev.LastSuccessAt
	}

	client, err := c.NewClient(ap)
	if err == nil {
		t := time.Now()
		err = client.Login(ctx)
		p.doc.LatencyMs = time.Since(t).Milliseconds()
	}
	if ctx.Err() != nil {
		return res, false
	}
	if err != nil {
		p.unreachable(err)
	} else {
		p.api = client
		p.doc.Reachable = true
		p.check(model.Check{Name: model.CheckAPI, Status: model.HealthOK, Message: fmt.Sprintf("The NITRO API answered in %d ms", p.doc.LatencyMs), Value: ptr(float64(p.doc.LatencyMs)), Unit: "ms"})
		cancelled := p.runSteps(ctx)
		// Close the session even when the pass was cancelled.
		lctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		client.Logout(lctx)
		cancel()
		if cancelled {
			return res, false
		}
	}
	return p.finish(ctx, started), true
}

func ptr[T any](v T) *T { return &v }

// unreachable records that the appliance could not be logged in to.
func (p *pass) unreachable(err error) {
	msg := "The NITRO API could not be reached: " + err.Error()
	var ne *nitro.Error
	if errors.As(err, &ne) && ne.Answered() {
		msg = "The NITRO API refused the login: " + err.Error()
	}
	p.doc.Reachable, p.doc.Error = false, err.Error()
	p.check(model.Check{Name: model.CheckAPI, Status: model.HealthCritical, Message: msg})
	p.steps = append(p.steps, model.Step{Name: "login", Status: model.StatusFailed, Error: err.Error(), DurationMs: p.doc.LatencyMs})
	p.logStep("login", err)
}

func (p *pass) check(ch model.Check) { p.checks = append(p.checks, ch) }

// event records a change of state.
func (p *pass) event(kind, name, from, to, severity, message string) {
	p.events = append(p.events, model.Event{
		Time: p.now, Ref: p.ref, RunID: p.runID, Kind: kind, Name: name, From: from, To: to, Severity: severity, Message: message,
	})
}

// logStep logs a step's failure when it is new or has changed, and its
// recovery; a standing failure is at debug level after the first time.
func (p *pass) logStep(step string, err error) {
	last := p.mem.stepErr[step]
	switch {
	case err == nil && last != "":
		p.log.Info("step works again", "step", step)
		delete(p.mem.stepErr, step)
	case err == nil:
	case err.Error() != last:
		p.log.Warn("step failed", "step", step, "error", err)
		p.mem.stepErr[step] = err.Error()
	default:
		p.log.Debug("step still failing", "step", step, "error", err)
	}
}

// runSteps runs the checks in order. It reports whether the pass was
// cancelled.
func (p *pass) runSteps(ctx context.Context) (cancelled bool) {
	cfg := p.c.Cfg
	steps := []struct {
		name string
		on   bool
		fn   func(context.Context) (int, error)
	}{
		{"system", true, p.system},
		// HA comes first of the rest: a secondary node is judged differently.
		{"ha", cfg.CheckHA(), p.ha},
		{"config", cfg.CheckConfig(), p.config},
		{"interfaces", cfg.CheckInterfaces(), p.interfaces},
		{"vservers", cfg.CheckVservers(), p.vservers},
		{"services", cfg.CheckServices(), p.services},
		{"certificates", cfg.CheckCertificates(), p.certificates},
	}
	p.logStep("login", nil)
	lost := false
	for _, s := range steps {
		if !s.on {
			continue
		}
		if lost {
			p.steps = append(p.steps, model.Step{Name: s.name, Status: model.StatusSkipped, Error: "the appliance stopped answering"})
			p.carry(s.name)
			continue
		}
		t := time.Now()
		n, err := s.fn(ctx)
		if ctx.Err() != nil {
			return true
		}
		step := model.Step{Name: s.name, Status: model.StatusSuccess, Count: n, DurationMs: time.Since(t).Milliseconds()}
		switch {
		case errors.Is(err, errSkipped):
			step.Status, step.Error = model.StatusSkipped, strings.TrimPrefix(err.Error(), errSkipped.Error()+": ")
			p.logStep(s.name, nil)
		case err != nil:
			step.Status, step.Error = model.StatusFailed, err.Error()
			p.logStep(s.name, err)
			p.carry(s.name)
			var ne *nitro.Error
			if errors.As(err, &ne) && !ne.Answered() {
				// No reply at all: the rest would only time out one by one.
				lost = true
				p.doc.Reachable, p.doc.Error = false, err.Error()
				p.check(model.Check{Name: model.CheckAPI, Status: model.HealthCritical, Message: "The appliance stopped answering during the pass: " + err.Error()})
			} else {
				for _, name := range stepChecks[s.name] {
					p.check(model.Check{Name: name, Status: model.HealthUnknown, Message: "Could not be read: " + err.Error()})
				}
			}
		default:
			p.logStep(s.name, nil)
		}
		p.steps = append(p.steps, step)
	}
	if lost {
		// The api check was added as ok after the login; drop that one.
		for i, ch := range p.checks {
			if ch.Name == model.CheckAPI && ch.Status == model.HealthOK {
				p.checks = append(p.checks[:i], p.checks[i+1:]...)
				break
			}
		}
	}
	return false
}

// carry keeps what the last good pass read for a step that failed now, so
// the appliance document does not lose it.
func (p *pass) carry(step string) {
	if p.prev == nil {
		return
	}
	old := p.prev
	switch step {
	case "system":
		p.doc.System = old.System
	case "ha":
		p.doc.HA = old.HA
	case "interfaces":
		p.doc.Interfaces = old.Interfaces
		p.doc.Counts.Interfaces, p.doc.Counts.InterfacesDown = old.Counts.Interfaces, old.Counts.InterfacesDown
	case "vservers":
		c, o := &p.doc.Counts, old.Counts
		c.Vservers, c.VserversDown, c.VserversDegraded, c.VserversDisabled = o.Vservers, o.VserversDown, o.VserversDegraded, o.VserversDisabled
	case "services":
		c, o := &p.doc.Counts, old.Counts
		c.Services, c.ServicesDown, c.ServicesDisabled = o.Services, o.ServicesDown, o.ServicesDisabled
	case "certificates":
		c, o := &p.doc.Counts, old.Counts
		c.Certificates, c.CertsExpiring, c.CertsExpired = o.Certificates, o.CertsExpiring, o.CertsExpired
	}
}

// Checks whose changes are reported through the objects or the appliance
// itself, not as an event of their own.
var quietChecks = map[string]bool{
	model.CheckAPI: true, model.CheckVservers: true, model.CheckServices: true, model.CheckCertificates: true,
}

// finish judges the appliance, works out what changed, and stores it all.
func (p *pass) finish(ctx context.Context, started time.Time) result {
	prevChecks := map[string]model.Check{}
	if p.prev != nil {
		for _, ch := range p.prev.Checks {
			prevChecks[ch.Name] = ch
		}
	}
	status := model.HealthOK
	for i := range p.checks {
		ch := &p.checks[i]
		ch.Since = p.now
		if old, ok := prevChecks[ch.Name]; ok {
			if old.Status == ch.Status {
				ch.Since = old.Since
			} else if !quietChecks[ch.Name] {
				p.event(model.EventCheck, ch.Name, old.Status, ch.Status, ch.Status, ch.Message)
			}
		}
		status = model.Worse(status, ch.Status)
	}
	// The worst first, in the order of the checks otherwise.
	var problems []string
	for _, level := range []string{model.HealthCritical, model.HealthWarning, model.HealthUnknown} {
		for _, ch := range p.checks {
			if ch.Status == level {
				problems = append(problems, ch.Message)
			}
		}
	}
	summary := strings.Join(problems, " · ")
	if len(summary) > 600 {
		summary = summary[:600] + "…"
	}

	d := &p.doc
	d.Checks, d.Status, d.Summary, d.StatusSince = p.checks, status, summary, p.now
	if d.Reachable {
		d.LastSuccessAt = &p.now
	}
	changed := p.prev != nil && p.prev.Status != status
	if p.prev != nil && !changed {
		d.StatusSince = p.prev.StatusSince
	}
	if changed {
		msg := "Recovered"
		if status != model.HealthOK {
			msg = summary
		}
		p.event(model.EventAppliance, "", p.prev.Status, status, status, msg)
	}

	switch was := p.mem.logged; {
	case was == status, was == "" && status == model.HealthOK:
		p.log.Debug("appliance checked", "status", status, "latencyMs", d.LatencyMs)
	case model.Rank(status) > model.Rank(was):
		p.log.Warn("appliance is now "+status, "was", was, "summary", summary)
	default:
		p.log.Info("appliance is now "+status, "was", was, "summary", summary)
	}
	p.mem.logged = status

	res := result{events: len(p.events)}
	res.run = model.ApplianceRun{Ref: p.ref, Status: model.StatusSuccess, Health: status, StartedAt: started, Steps: p.steps}
	for _, s := range p.steps {
		if s.Status == model.StatusFailed {
			res.run.Status = model.StatusPartial
			if res.run.Error == "" {
				res.run.Error = s.Error
			}
		}
	}
	if !d.Reachable {
		res.run.Status, res.run.Error = model.StatusFailed, d.Error
	}

	if err := p.store(ctx); err != nil {
		if res.run.Status == model.StatusSuccess {
			res.run.Status = model.StatusPartial
		}
		if res.run.Error == "" {
			res.run.Error = "not stored: " + err.Error()
		}
		p.logStep("store", err)
	} else {
		p.logStep("store", nil)
	}

	res.run.DurationMs = p.c.now().Sub(started).Milliseconds()
	return res
}

// store writes the outcome of the pass.
func (p *pass) store(ctx context.Context) error {
	if !p.mem.loaded {
		return errors.New("the stored state could not be read")
	}
	// A pass that was cancelled right at its end is still stored.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	st := p.c.Store
	var errs []error
	for _, set := range p.sets {
		err := st.SaveObjects(ctx, set.coll, set.docs)
		if err == nil {
			err = st.PruneObjects(ctx, set.coll, p.ref.ApplianceID, set.kinds, set.keep)
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		// Kinds that were not read this pass keep what is remembered.
		m := p.mem.objects[set.coll]
		if m == nil {
			m = map[string]model.ObjectState{}
			p.mem.objects[set.coll] = m
		}
		for id, s := range m {
			if _, ok := set.states[id]; !ok && slices.Contains(set.kinds, s.Kind) {
				delete(m, id)
			}
		}
		for id, s := range set.states {
			m[id] = s
		}
	}
	d := &p.doc
	if err := st.SaveAppliance(ctx, d, d.Reachable); err != nil {
		errs = append(errs, fmt.Errorf("%s: %w", model.CollAppliances, err))
	} else {
		saved := *d
		if !d.Reachable && p.prev != nil {
			// What could not be read stays as the last good pass had it.
			saved.System, saved.HA, saved.Interfaces, saved.Counts = p.prev.System, p.prev.HA, p.prev.Interfaces, p.prev.Counts
		}
		p.mem.appliance = &saved
	}
	s := &model.Sample{
		Time: p.now, Ref: p.ref, Status: d.Status, Reachable: d.Reachable, LatencyMs: d.LatencyMs,
		VserversDown: d.Counts.VserversDown, ServicesDown: d.Counts.ServicesDown,
	}
	if sys := d.System; sys != nil && d.Reachable {
		s.CPU, s.MgmtCPU, s.Memory, s.DiskFlash, s.DiskVar = sys.CPU, sys.MgmtCPU, sys.Memory, sys.DiskFlash, sys.DiskVar
	}
	if err := st.SaveSample(ctx, s); err != nil {
		errs = append(errs, fmt.Errorf("%s: %w", model.CollSamples, err))
	}
	if err := st.SaveEvents(ctx, p.events); err != nil {
		errs = append(errs, fmt.Errorf("%s: %w", model.CollEvents, err))
	}
	return errors.Join(errs...)
}
