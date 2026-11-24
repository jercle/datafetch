package checker

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"slices"
	"sync"
	"testing"

	"github.com/jercle/datafetch/sxgcheck/internal/config"
	"github.com/jercle/datafetch/sxgcheck/internal/model"
	"github.com/jercle/datafetch/sxgcheck/internal/monitor"
	"github.com/jercle/datafetch/sxgcheck/internal/probe"
)

// memStore keeps everything in memory.
type memStore struct {
	mu        sync.Mutex
	firewalls map[string]model.Firewall
	results   []model.Result
	events    []model.Event
	runs      map[string]model.Run
	failSave  map[string]bool
	failLoad  bool
	loads     int
}

func newStore() *memStore {
	return &memStore{firewalls: map[string]model.Firewall{}, runs: map[string]model.Run{}, failSave: map[string]bool{}}
}

func (m *memStore) LoadFirewalls(_ context.Context, instance string) ([]model.Firewall, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.loads++
	if m.failLoad {
		return nil, errors.New("down")
	}
	var out []model.Firewall
	for _, f := range m.firewalls {
		if f.Instance == instance {
			out = append(out, f)
		}
	}
	return out, nil
}
func (m *memStore) SaveFirewall(_ context.Context, f *model.Firewall) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failSave[f.ID] {
		return errors.New("down")
	}
	m.firewalls[f.ID] = *f
	return nil
}
func (m *memStore) SaveResult(_ context.Context, r *model.Result) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.results = append(m.results, *r)
	return nil
}
func (m *memStore) SaveEvents(_ context.Context, e []model.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, e...)
	return nil
}
func (m *memStore) PruneFirewalls(_ context.Context, instance string, keep []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, f := range m.firewalls {
		if f.Instance == instance && !slices.Contains(keep, id) {
			delete(m.firewalls, id)
		}
	}
	return nil
}
func (m *memStore) WriteLogs(context.Context, []model.LogEntry) error { return nil }
func (m *memStore) SaveRun(_ context.Context, r *model.Run) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.runs[r.ID] = *r
	return nil
}
func (m *memStore) Heartbeat(context.Context, *model.Instance) error { return nil }
func (m *memStore) Close(context.Context) error                      { return nil }

type world struct {
	mu     sync.Mutex
	health map[string]map[string]string // firewall -> check id -> status
	device map[string]*model.Device
}

func (w *world) set(fw, check, status string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.health[fw][check] = status
}

func (w *world) probe(_ context.Context, fw config.Firewall) probe.Result {
	w.mu.Lock()
	defer w.mu.Unlock()
	var r probe.Result
	for _, id := range []string{"tcp/4444", "snmp", "snmp/memory"} {
		if st, ok := w.health[fw.Name][id]; ok {
			r.Checks = append(r.Checks, model.Check{ID: id, Kind: "x", Name: "Check " + id, Status: st, Message: id + " is " + st})
		}
	}
	r.Device = w.device[fw.Name]
	v := 50.0
	r.Metrics.MemoryPercent = &v
	return r
}

func setup(t *testing.T, st *memStore, names ...string) (*Checker, *world) {
	t.Helper()
	js := `{"firewalls":[`
	w := &world{health: map[string]map[string]string{}, device: map[string]*model.Device{}}
	for i, n := range names {
		if i > 0 {
			js += ","
		}
		js += `{"name":"` + n + `","host":"10.0.0.1","tenantName":"Prod","tcp":{"ports":[4444]}}`
		w.health[n] = map[string]string{"tcp/4444": model.HealthOK, "snmp": model.HealthOK, "snmp/memory": model.HealthOK}
	}
	cfg, err := config.Parse([]byte(js+`]}`), func(string) string { return "" }, nil)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	c := &Checker{Cfg: cfg, Store: st, Log: log, Instance: "chk1", IntervalSeconds: 60, Probe: w.probe,
		Mon: monitor.New(st, log, model.Instance{ID: "chk1"})}
	return c, w
}

func TestChangesAndSince(t *testing.T) {
	st := newStore()
	c, w := setup(t, st, "fw1", "fw2")
	ctx := context.Background()
	w.device["fw1"] = &model.Device{Hostname: "fw1.local", Firmware: "SFOS 21"}

	r1 := c.Run(ctx, "manual", nil)
	if r1.Status != model.StatusSuccess || r1.Counts.OK != 2 || r1.Checks.OK != 6 || r1.Changes != 0 || len(st.events) != 0 {
		t.Fatalf("first run %+v, events %+v", r1, st.events)
	}
	f := st.firewalls["fw1"]
	if f.Status != model.HealthOK || f.LastOKAt == nil || f.Instance != "chk1" || f.IntervalSeconds != 60 || f.Search != "fw1 10.0.0.1 " || f.Metrics == nil {
		t.Fatalf("%+v", f)
	}
	okSince, firstSeen := f.StatusSince, f.FirstSeenAt

	// A check fails: one event for the check, one for the firewall.
	w.set("fw1", "tcp/4444", model.HealthCritical)
	w.set("fw1", "snmp/memory", model.HealthWarning)
	w.device["fw1"] = nil
	r2 := c.Run(ctx, "manual", nil)
	f = st.firewalls["fw1"]
	if f.Status != model.HealthCritical || f.Severity != 2 || f.Counts != (model.Counts{OK: 1, Warning: 1, Critical: 1}) ||
		f.Summary != "Check tcp/4444: tcp/4444 is critical; Check snmp/memory: snmp/memory is warning" {
		t.Fatalf("%+v", f)
	}
	if r2.Changes != 3 || len(st.events) != 3 || r2.Counts.Critical != 1 || r2.Counts.OK != 1 {
		t.Fatalf("run %+v events %+v", r2, st.events)
	}
	overall := st.events[2]
	if overall.Check != "" || overall.From != model.HealthOK || overall.To != model.HealthCritical || overall.Severity != 2 || overall.TenantName != "Prod" {
		t.Fatalf("%+v", overall)
	}
	if !f.StatusSince.After(okSince) || !f.FirstSeenAt.Equal(firstSeen) || f.LastOKAt == nil || !f.LastOKAt.Equal(okSince) {
		t.Fatalf("times %+v", f)
	}
	// The device is remembered while SNMP is silent; an unchanged check keeps its since.
	if f.Device == nil || f.Device.Firmware != "SFOS 21" || !f.Checks[1].Since.Equal(okSince) || !f.Checks[0].Since.Equal(f.StatusSince) {
		t.Fatalf("%+v", f)
	}
	badSince := f.StatusSince

	// Nothing changes: no events, since stays.
	r3 := c.Run(ctx, "manual", nil)
	f = st.firewalls["fw1"]
	if r3.Changes != 0 || len(st.events) != 3 || !f.StatusSince.Equal(badSince) || !f.LastCheckedAt.After(badSince) {
		t.Fatalf("run %+v", r3)
	}

	// Partial recovery: the worst check clears, the firewall drops to warning.
	w.set("fw1", "tcp/4444", model.HealthOK)
	c.Run(ctx, "manual", nil)
	f = st.firewalls["fw1"]
	if f.Status != model.HealthWarning || len(st.events) != 5 || st.events[3].To != model.HealthOK || st.events[3].Check != "tcp/4444" || st.events[4].To != model.HealthWarning {
		t.Fatalf("%+v %+v", f, st.events[3:])
	}

	if len(st.results) != 8 {
		t.Fatalf("%d history entries", len(st.results))
	}
	last := st.results[len(st.results)-1]
	if last.Metrics == nil || *last.Metrics.MemoryPercent != 50 {
		t.Fatalf("%+v", last)
	}
	// The run record lists the firewalls by name.
	run := st.runs[r2.ID]
	if len(run.Firewalls) != 2 || run.Firewalls[0].Name != "fw1" || run.Firewalls[0].Health != model.HealthCritical || run.Firewalls[0].Changes != 3 || run.FinishedAt == nil {
		t.Fatalf("%+v", run)
	}
}

func TestRestartKeepsState(t *testing.T) {
	st := newStore()
	c, w := setup(t, st, "fw1")
	w.set("fw1", "snmp", model.HealthCritical)
	c.Run(context.Background(), "manual", nil)
	if len(st.events) != 2 { // new and already failing: check + firewall
		t.Fatalf("%+v", st.events)
	}
	if st.events[0].From != "" || st.events[0].DownForMs != 0 {
		t.Fatalf("%+v", st.events[0])
	}
	since := st.firewalls["fw1"].StatusSince

	// A new process, same store: the problem is not reported again.
	c2, w2 := setup(t, st, "fw1")
	w2.set("fw1", "snmp", model.HealthCritical)
	r := c2.Run(context.Background(), "manual", nil)
	if r.Changes != 0 || len(st.events) != 2 || !st.firewalls["fw1"].StatusSince.Equal(since) {
		t.Fatalf("after restart: %+v events %d", r, len(st.events))
	}
	c2.Run(context.Background(), "manual", nil)
	if st.loads != 2 {
		t.Fatalf("state loaded %d times", st.loads)
	}
}

func TestStoreFailures(t *testing.T) {
	st := newStore()
	st.failLoad = true
	c, w := setup(t, st, "fw1", "fw2")
	ctx := context.Background()
	c.Run(ctx, "manual", nil)
	st.failLoad = false

	st.failSave["fw1"] = true
	w.set("fw1", "tcp/4444", model.HealthCritical)
	r := c.Run(ctx, "manual", nil)
	if r.Status != model.StatusPartial || r.FirewallsFailed != 1 || len(st.events) != 0 || st.firewalls["fw1"].Status != model.HealthOK {
		t.Fatalf("%+v", r)
	}
	// When the store is back the change is recorded, once.
	st.failSave["fw1"] = false
	r = c.Run(ctx, "manual", nil)
	if r.Status != model.StatusSuccess || len(st.events) != 2 || st.firewalls["fw1"].Status != model.HealthCritical {
		t.Fatalf("%+v events %+v", r, st.events)
	}

	st.failSave["fw1"], st.failSave["fw2"] = true, true
	if r = c.Run(ctx, "manual", nil); r.Status != model.StatusFailed || r.Error == "" {
		t.Fatalf("%+v", r)
	}
}

func TestPruneAndCancel(t *testing.T) {
	st := newStore()
	st.firewalls["gone"] = model.Firewall{ID: "gone", Instance: "chk1"}
	st.firewalls["other"] = model.Firewall{ID: "other", Instance: "chk2"}
	c, _ := setup(t, st, "fw1")
	c.Run(context.Background(), "manual", nil)
	if _, ok := st.firewalls["gone"]; ok {
		t.Fatal("removed firewall kept")
	}
	if _, ok := st.firewalls["other"]; !ok {
		t.Fatal("another checker's firewall removed")
	}

	// A cancelled run stores no verdicts and removes nothing.
	st.firewalls["gone"] = model.Firewall{ID: "gone", Instance: "chk1"}
	before := st.firewalls["fw1"].LastCheckedAt
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := c.Run(ctx, "manual", nil)
	if r.Status != model.StatusCancelled || !st.firewalls["fw1"].LastCheckedAt.Equal(before) {
		t.Fatalf("%+v", r)
	}
	if _, ok := st.firewalls["gone"]; !ok {
		t.Fatal("pruned on a cancelled run")
	}
}
