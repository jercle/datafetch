package checker_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jercle/datafetch/nscheck/internal/checker"
	"github.com/jercle/datafetch/nscheck/internal/config"
	"github.com/jercle/datafetch/nscheck/internal/model"
	"github.com/jercle/datafetch/nscheck/internal/monitor"
	"github.com/jercle/datafetch/nscheck/internal/nitro"
	"github.com/jercle/datafetch/nscheck/internal/nitrotest"
	"github.com/jercle/datafetch/nscheck/internal/store"
)

// memStore keeps everything in memory and counts the object writes.
type memStore struct {
	mu         sync.Mutex
	appliances map[string]model.Appliance
	objects    map[string]map[string]*model.Object // collection -> _id
	samples    []model.Sample
	events     []model.Event
	runs       map[string]model.Run
	writes     int // object documents written
	down       bool
}

func newStore() *memStore {
	return &memStore{appliances: map[string]model.Appliance{}, objects: map[string]map[string]*model.Object{}, runs: map[string]model.Run{}}
}

var errDown = errors.New("store down")

func (m *memStore) LoadState(_ context.Context, id string) (*model.State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.down {
		return nil, errDown
	}
	st := &model.State{Objects: map[string]map[string]model.ObjectState{}}
	if a, ok := m.appliances[id]; ok {
		st.Appliance = &a
	}
	for coll, docs := range m.objects {
		st.Objects[coll] = map[string]model.ObjectState{}
		for oid, o := range docs {
			if o.ApplianceID == id {
				st.Objects[coll][oid] = model.ObjectState{Kind: o.Kind, Status: o.Status, Since: o.StatusSince, FirstSeen: o.FirstSeenAt, Hash: o.Hash}
			}
		}
	}
	return st, nil
}

func (m *memStore) SaveAppliance(_ context.Context, a *model.Appliance, full bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.down {
		return errDown
	}
	doc := *a
	if old, ok := m.appliances[a.ID]; ok && !full {
		doc.System, doc.HA, doc.Interfaces, doc.Counts, doc.LastSuccessAt, doc.FirstSeenAt = old.System, old.HA, old.Interfaces, old.Counts, old.LastSuccessAt, old.FirstSeenAt
	}
	m.appliances[a.ID] = doc
	return nil
}

func (m *memStore) SaveObjects(_ context.Context, coll string, docs []store.Doc) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.down {
		return errDown
	}
	if m.objects[coll] == nil {
		m.objects[coll] = map[string]*model.Object{}
	}
	for _, d := range docs {
		o := *d.Body.(interface{ Base() *model.Object }).Base()
		m.objects[coll][d.ID] = &o
		m.writes++
	}
	return nil
}

func (m *memStore) PruneObjects(_ context.Context, coll, applianceID string, kinds, keep []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	kept := map[string]bool{}
	for _, id := range keep {
		kept[id] = true
	}
	for id, o := range m.objects[coll] {
		if o.ApplianceID == applianceID && !kept[id] && strings.Contains(" "+strings.Join(kinds, " ")+" ", " "+o.Kind+" ") {
			delete(m.objects[coll], id)
		}
	}
	return nil
}

func (m *memStore) SaveSample(_ context.Context, s *model.Sample) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.down {
		return errDown
	}
	m.samples = append(m.samples, *s)
	return nil
}

func (m *memStore) SaveEvents(_ context.Context, e []model.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.down {
		return errDown
	}
	m.events = append(m.events, e...)
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

// takeEvents returns the events stored since the last call, as "kind name from>to".
func (m *memStore) takeEvents() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, e := range m.events {
		out = append(out, strings.Join(strings.Fields(e.Kind+" "+e.Name), " ")+" "+e.From+">"+e.To)
	}
	m.events = nil
	return out
}

func (m *memStore) object(coll, name string) *model.Object {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, o := range m.objects[coll] {
		if o.Name == name {
			c := *o
			return &c
		}
	}
	return nil
}

func (m *memStore) appliance(name string) model.Appliance {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.appliances[model.NewID("appliance", name)]
}

// healthy fills a fake appliance with a primary node in good order.
func healthy(a *nitrotest.Appliance) {
	a.Set("stat/system", `{"pktcpuusagepcnt": 12, "mgmtcpuusagepcnt": "8.5", "memusagepcnt": 40.1, "memuseinmb": "3200", "disk0perusage": 31, "disk1perusage": 55,
		"numcpus": "4", "starttime": "Mon Nov  2 08:00:00 2026", "powersupply1status": "NORMAL", "powersupply2status": "NORMAL", "powersupply3status": "NOT PRESENT"}`)
	a.Set("config/nsversion", `{"version": "NetScaler NS14.1: Build 25.56.nc"}`)
	a.Set("config/nshardware", `{"hwdescription": "NSMPX-8900", "serialno": "ABC123", "hostid": "0cc47a"}`)
	a.Set("config/nshostname", `[{"hostname": "ns-prod-01"}]`)
	a.Set("config/hanode", `[{"id": "0", "name": "ns-prod-01", "ipaddress": "10.0.0.11", "hastatus": "UP", "state": "Primary", "hasync": "ENABLED"},
		{"id": "1", "name": "ns-prod-02", "ipaddress": "10.0.0.12", "hastatus": "UP", "state": "Secondary", "hasync": "SUCCESS"}]`)
	a.Set("stat/hanode", `{"hacurstatus": "YES", "hacurstate": "UP", "hacurmasterstate": "Primary", "transtime": "Mon Nov  2 08:01:10 2026", "haerrsyncfailure": "0"}`)
	a.Set("config/nsconfig", `{"lastconfigchangedtime": "Tue Nov 17 10:00:00 2026", "lastconfigsavetime": "Tue Nov 17 10:05:00 2026"}`)
	a.Set("config/Interface", `[{"id": "0/1", "state": "ENABLED", "linkstate": 1, "hamonitor": "ON", "actspeed": "1000"},
		{"id": "1/1", "state": "ENABLED", "linkstate": 1, "hamonitor": "ON"}, {"id": "1/2", "state": "DISABLED", "linkstate": 0, "hamonitor": "ON"},
		{"id": "LO/1", "state": "ENABLED", "linkstate": 1, "hamonitor": "OFF"}]`)
	a.Set("stat/lbvserver", `[{"name": "lb_web", "primaryipaddress": "10.1.0.10", "primaryport": 443, "type": "SSL", "state": "UP", "vslbhealth": "100", "actsvcs": "2", "inactsvcs": "0"},
		{"name": "lb_api", "primaryipaddress": "10.1.0.11", "primaryport": 443, "type": "SSL", "state": "UP", "vslbhealth": "100", "actsvcs": "2", "inactsvcs": "0"},
		{"name": "lb_old", "primaryipaddress": "10.1.0.12", "primaryport": 80, "type": "HTTP", "state": "OUT OF SERVICE", "vslbhealth": "0"},
		{"name": "test-lb", "primaryipaddress": "10.1.0.13", "primaryport": 80, "type": "HTTP", "state": "DOWN", "vslbhealth": "0"}]`)
	a.Set("stat/csvserver", `[{"name": "cs_main", "primaryipaddress": "10.1.0.20", "primaryport": 443, "type": "SSL", "state": "UP"}]`)
	a.Set("stat/vpnvserver", `[{"name": "gw_ext", "primaryipaddress": "10.1.0.30", "primaryport": 443, "type": "SSL", "state": "UP"}]`)
	a.Fail("stat/gslbvserver", http.StatusBadRequest) // feature not enabled
	a.Set("stat/service", `[{"name": "svc_web1", "primaryipaddress": "10.2.0.1", "primaryport": 80, "servicetype": "HTTP", "state": "UP"},
		{"name": "svc_web2", "primaryipaddress": "10.2.0.2", "primaryport": 80, "servicetype": "HTTP", "state": "UP"}]`)
	a.Set("config/servicegroup", `[{"servicegroupname": "sg_api", "servicetype": "HTTP", "state": "ENABLED", "servicegroupeffectivestate": "UP"}]`)
	a.Set("config/sslcertkey", `[{"certkey": "wildcard", "subject": "CN=*.example.com", "issuer": "CN=Example CA", "serial": "0A1B", "daystoexpiration": 200,
		"clientcertnotbefore": "Nov 24 02:44:00 2025 GMT", "clientcertnotafter": "Jun 12 02:44:00 2027 GMT", "status": "Valid", "certificatetype": ["CLNT_CERT", "SRVR_CERT"]},
		{"certkey": "ns-server-certificate", "subject": "CN=default", "daystoexpiration": 3, "status": "Valid"}]`)
}

type rig struct {
	t     *testing.T
	ns    *nitrotest.Appliance
	store *memStore
	chk   *checker.Checker
	clock time.Time
}

func cfg(t *testing.T, ns ...*nitrotest.Appliance) *config.Config {
	t.Helper()
	var aps []string
	for i, a := range ns {
		aps = append(aps, fmt.Sprintf(`{"name": "ns-%d", "tenantName": "Contoso", "address": %q, "username": %q, "password": %q, "tlsSkipVerify": true}`, i+1, a.URL, a.User, a.Pass))
	}
	c, err := config.Parse([]byte(`{"mongo": {"uri": "x"}, "timeout": "3s", "ignore": {"vservers": ["test-*"], "certificates": ["ns-server-*"]}, "appliances": [`+strings.Join(aps, ",")+`]}`),
		func(string) string { return "" }, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newChecker(c *config.Config, st store.Store, now func() time.Time) *checker.Checker {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return &checker.Checker{
		Cfg: c, Store: st, Log: log, Now: now, Interval: time.Minute,
		Mon: monitor.New(st, log, model.Instance{ID: "test", Version: "test"}),
		NewClient: func(a config.Appliance) (checker.API, error) {
			return nitro.New(nitro.Options{Address: a.Address, Username: a.Username, Password: a.Password, Timeout: c.Timeout.D(), SkipVerify: a.SkipVerify})
		},
	}
}

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{t: t, ns: nitrotest.New(), store: newStore(), clock: time.Date(2026, 11, 24, 2, 0, 0, 0, time.UTC)}
	t.Cleanup(r.ns.Close)
	healthy(r.ns)
	r.chk = newChecker(cfg(t, r.ns), r.store, func() time.Time { return r.clock })
	return r
}

// pass runs one pass a minute after the last.
func (r *rig) pass() *model.Run {
	r.t.Helper()
	r.clock = r.clock.Add(time.Minute)
	return r.chk.Run(context.Background(), "manual", nil)
}

func checkOf(a model.Appliance, name string) model.Check {
	for _, c := range a.Checks {
		if c.Name == name {
			return c
		}
	}
	return model.Check{Status: "missing"}
}

func wantEvents(t *testing.T, got []string, want ...string) {
	t.Helper()
	have := map[string]bool{}
	for _, g := range got {
		have[g] = true
	}
	for _, w := range want {
		if !have[w] {
			t.Errorf("missing event %q in %q", w, got)
		}
	}
	if len(got) != len(want) {
		t.Errorf("events: got %q, want %q", got, want)
	}
}

func TestHealthyThenUnchanged(t *testing.T) {
	r := newRig(t)
	run := r.pass()
	if run.Status != model.StatusSuccess || run.Counts.OK != 1 || run.AppliancesDone != 1 || len(run.Appliances) != 1 {
		t.Fatalf("run: %+v", run)
	}
	a := r.store.appliance("ns-1")
	if a.Status != model.HealthOK || !a.Reachable || a.Summary != "" || a.LastSuccessAt == nil || a.IntervalSeconds != 60 || a.TenantName != "Contoso" {
		t.Fatalf("appliance: %+v", a)
	}
	for _, name := range []string{"api", "cpu", "mgmt-cpu", "memory", "disk-flash", "disk-var", "hardware", "ha", "config", "interfaces", "vservers", "services", "certificates"} {
		if c := checkOf(a, name); c.Status != model.HealthOK {
			t.Errorf("check %s: %+v", name, c)
		}
	}
	s := a.System
	if s == nil || *s.CPU != 12 || *s.MgmtCPU != 8.5 || *s.DiskVar != 55 || s.Version != "NetScaler NS14.1: Build 25.56.nc" || s.Model != "NSMPX-8900" || s.Hostname != "ns-prod-01" || len(s.PowerSupplies) != 2 || s.ConfigUnsaved {
		t.Fatalf("system: %+v", s)
	}
	if a.HA == nil || !a.HA.Configured || a.HA.MasterState != "Primary" || a.HA.Peer != "10.0.0.12" || a.HA.PeerState != "UP" || len(a.HA.Nodes) != 2 {
		t.Fatalf("ha: %+v", a.HA)
	}
	// The loopback is left out; the ignored test-lb and the disabled lb_old do not count as down.
	want := model.Counts{Vservers: 6, VserversDisabled: 1, Services: 3, Certificates: 2, Interfaces: 3}
	if a.Counts != want {
		t.Fatalf("counts: %+v", a.Counts)
	}
	if v := r.store.object(model.CollVservers, "lb_web"); v == nil || v.Status != model.HealthOK || v.Kind != "lb" || v.TenantName != "Contoso" {
		t.Fatalf("lb_web: %+v", v)
	}
	if v := r.store.object(model.CollVservers, "test-lb"); v == nil || v.Status != model.HealthCritical || !v.Ignored {
		t.Fatalf("test-lb: %+v", v)
	}
	if v := r.store.object(model.CollVservers, "lb_old"); v.Status != model.HealthDisabled {
		t.Fatalf("lb_old: %+v", v)
	}
	if c := r.store.object(model.CollCertificates, "ns-server-certificate"); c.Status != model.HealthCritical || !c.Ignored {
		t.Fatalf("ignored certificate: %+v", c)
	}
	if got := r.store.takeEvents(); len(got) != 0 {
		t.Fatalf("a first pass reports no changes, got %q", got)
	}
	if r.ns.OpenSessions() != 0 {
		t.Fatal("the session was left open")
	}
	calls := strings.Join(r.ns.Calls(), " ")
	if !strings.Contains(calls, "config/nsversion") {
		t.Fatalf("calls: %s", calls)
	}

	// Nothing changed: no object is rewritten, nothing is reported, and the
	// identity is not read again within the hour.
	writes, since := r.store.writes, a.StatusSince
	run = r.pass()
	if r.store.writes != writes {
		t.Fatalf("%d unchanged objects were rewritten", r.store.writes-writes)
	}
	a = r.store.appliance("ns-1")
	if !a.StatusSince.Equal(since) || !a.CheckedAt.After(since) || len(r.store.samples) != 2 || len(r.store.takeEvents()) != 0 {
		t.Fatalf("second pass: since %v checked %v samples %d", a.StatusSince, a.CheckedAt, len(r.store.samples))
	}
	if calls := strings.Join(r.ns.Calls(), " "); strings.Contains(calls, "nsversion") || !strings.Contains(calls, "stat/system") {
		t.Fatalf("second pass calls: %s", calls)
	}
	if got := r.store.runs[run.ID]; got.Status != model.StatusSuccess || got.FinishedAt == nil || len(got.Appliances[0].Steps) != 7 {
		t.Fatalf("stored run: %+v", got)
	}
}

func TestProblemsAndRecovery(t *testing.T) {
	r := newRig(t)
	r.pass()
	first := r.store.object(model.CollVservers, "lb_web")

	r.ns.Set("stat/system", `{"pktcpuusagepcnt": 93, "mgmtcpuusagepcnt": 82, "memusagepcnt": 40, "disk0perusage": 31, "disk1perusage": 55, "starttime": "Mon Nov  2 08:00:00 2026", "powersupply1status": "NORMAL", "powersupply2status": "FAILED"}`)
	r.ns.Set("stat/lbvserver", `[{"name": "lb_web", "primaryipaddress": "10.1.0.10", "primaryport": 443, "type": "SSL", "state": "DOWN", "vslbhealth": "0", "actsvcs": "0", "inactsvcs": "2"},
		{"name": "lb_api", "primaryipaddress": "10.1.0.11", "primaryport": 443, "type": "SSL", "state": "UP", "vslbhealth": "50", "actsvcs": "1", "inactsvcs": "1"},
		{"name": "test-lb", "primaryipaddress": "10.1.0.13", "primaryport": 80, "type": "HTTP", "state": "UP", "vslbhealth": "100"}]`)
	r.ns.Set("stat/service", `[{"name": "svc_web1", "state": "DOWN"}, {"name": "svc_web2", "state": "OUT OF SERVICE"}]`)
	r.ns.Set("config/servicegroup", `[{"servicegroupname": "sg_api", "state": "ENABLED", "servicegroupeffectivestate": "PARTIAL-UP"}]`)
	r.ns.Set("config/sslcertkey", `[{"certkey": "wildcard", "daystoexpiration": 21, "status": "Valid"}, {"certkey": "old", "daystoexpiration": 0, "status": "Expired"}, {"certkey": "soon", "daystoexpiration": 5}]`)
	r.ns.Set("config/nsconfig", `{"lastconfigchangedtime": "Tue Nov 24 10:00:00 2026", "lastconfigsavetime": "Tue Nov 17 10:05:00 2026"}`)
	r.ns.Set("config/Interface", `[{"id": "0/1", "state": "ENABLED", "linkstate": 1, "hamonitor": "ON"}, {"id": "1/1", "state": "ENABLED", "linkstate": 0, "hamonitor": "ON"}, {"id": "1/3", "state": "ENABLED", "linkstate": 0, "hamonitor": "OFF"}]`)
	run := r.pass()

	a := r.store.appliance("ns-1")
	if a.Status != model.HealthCritical || run.Counts.Critical != 1 || run.Status != model.StatusSuccess {
		t.Fatalf("status %s, run %+v", a.Status, run)
	}
	for name, want := range map[string]string{
		"cpu": model.HealthCritical, "mgmt-cpu": model.HealthWarning, "memory": model.HealthOK, "hardware": model.HealthCritical,
		"config": model.HealthWarning, "interfaces": model.HealthWarning, "vservers": model.HealthCritical,
		"services": model.HealthWarning, "certificates": model.HealthCritical, "ha": model.HealthOK,
	} {
		if c := checkOf(a, name); c.Status != want {
			t.Errorf("check %s is %s, want %s: %s", name, c.Status, want, c.Message)
		}
	}
	if !strings.HasPrefix(a.Summary, "Packet CPU is at 93%") || !strings.Contains(a.Summary, "1 virtual server of 5 down: lb_web") ||
		!strings.Contains(a.Summary, "1 certificate has expired: old") || !strings.Contains(a.Summary, "wildcard (21 days)") ||
		!strings.Contains(a.Summary, "1 interface is enabled and HA-monitored but down: 1/1") || !strings.Contains(a.Summary, "Power supply 2 is FAILED") {
		t.Fatalf("summary: %s", a.Summary)
	}
	want := model.Counts{Vservers: 5, VserversDown: 1, VserversDegraded: 1, Services: 3, ServicesDown: 2, ServicesDisabled: 1, Certificates: 3, CertsExpiring: 2, CertsExpired: 1, Interfaces: 3, InterfacesDown: 1}
	if a.Counts != want {
		t.Fatalf("counts: %+v", a.Counts)
	}
	if !a.System.ConfigUnsaved {
		t.Fatal("the unsaved configuration is not on the document")
	}
	web := r.store.object(model.CollVservers, "lb_web")
	if web.Status != model.HealthCritical || !web.StatusSince.After(first.StatusSince) || !web.FirstSeenAt.Equal(first.FirstSeenAt) {
		t.Fatalf("lb_web: %+v", web)
	}
	// Gone from the appliance, gone from the store.
	if r.store.object(model.CollVservers, "lb_old") != nil || r.store.object(model.CollCertificates, "ns-server-certificate") != nil {
		t.Fatal("removed objects were kept")
	}
	// The gateway was not in this pass's fixture change, so it is unchanged and kept.
	if r.store.object(model.CollVservers, "gw_ext") == nil {
		t.Fatal("gw_ext was dropped")
	}
	// The ignored test-lb came up: stored, not reported. New objects are not reported either.
	wantEvents(t, r.store.takeEvents(),
		"appliance ok>critical", "check cpu ok>critical", "check mgmt-cpu ok>warning", "check hardware ok>critical",
		"check config ok>warning", "check interfaces ok>warning",
		"vserver lb_web ok>critical", "vserver lb_api ok>warning",
		"service svc_web1 ok>warning", "service svc_web2 ok>disabled", "service sg_api ok>warning",
		"certificate wildcard ok>warning")
	if s := r.store.samples[len(r.store.samples)-1]; *s.CPU != 93 || s.VserversDown != 1 || s.ServicesDown != 2 || s.Status != model.HealthCritical {
		t.Fatalf("sample: %+v", s)
	}

	// A restart of the checker starts from what is stored: nothing new to report.
	since := a.StatusSince
	r.chk = newChecker(r.chk.Cfg, r.store, func() time.Time { return r.clock })
	r.pass()
	if got := r.store.takeEvents(); len(got) != 0 {
		t.Fatalf("after a restart: %q", got)
	}
	if a = r.store.appliance("ns-1"); !a.StatusSince.Equal(since) || !checkOf(a, "cpu").Since.Equal(since) {
		t.Fatalf("since was reset: %v, want %v", a.StatusSince, since)
	}

	healthy(r.ns)
	r.pass()
	if a = r.store.appliance("ns-1"); a.Status != model.HealthOK || !a.StatusSince.After(since) {
		t.Fatalf("not recovered: %s %s", a.Status, a.Summary)
	}
	got := r.store.takeEvents()
	for _, w := range []string{"appliance critical>ok", "vserver lb_web critical>ok", "check cpu critical>ok", "service svc_web2 disabled>ok", "certificate wildcard warning>ok"} {
		if !strings.Contains(strings.Join(got, "|"), w) {
			t.Errorf("missing %q in %q", w, got)
		}
	}
}

func TestUnreachableKeepsLastGoodData(t *testing.T) {
	r := newRig(t)
	r.pass()
	r.ns.Pass = "changed"
	run := r.pass()
	a := r.store.appliance("ns-1")
	if run.Status != model.StatusFailed || run.AppliancesFailed != 1 || run.Appliances[0].Status != model.StatusFailed || run.Appliances[0].Steps[0].Name != "login" {
		t.Fatalf("run: %+v", run)
	}
	if a.Status != model.HealthCritical || a.Reachable || !strings.Contains(a.Summary, "refused the login") || !strings.Contains(a.Error, "Invalid username or password") {
		t.Fatalf("appliance: %s %q %q", a.Status, a.Summary, a.Error)
	}
	// What the last good pass read is still there, and so are the objects.
	if a.System == nil || a.System.Model != "NSMPX-8900" || a.Counts.Vservers != 6 || a.LastSuccessAt == nil || !a.LastSuccessAt.Before(a.CheckedAt) || len(a.Checks) != 1 {
		t.Fatalf("kept data: %+v", a)
	}
	if r.store.object(model.CollVservers, "lb_web") == nil {
		t.Fatal("objects were removed while unreachable")
	}
	wantEvents(t, r.store.takeEvents(), "appliance ok>critical")
	if s := r.store.samples[len(r.store.samples)-1]; s.Reachable || s.CPU != nil {
		t.Fatalf("sample: %+v", s)
	}

	// Still down: one event only.
	r.pass()
	wantEvents(t, r.store.takeEvents())

	r.ns.Pass = "secret"
	r.pass()
	if a = r.store.appliance("ns-1"); a.Status != model.HealthOK || !a.Reachable || a.Error != "" || a.System.Model != "NSMPX-8900" {
		t.Fatalf("back: %+v", a)
	}
	wantEvents(t, r.store.takeEvents(), "appliance critical>ok")

	// Nothing listening at all.
	r.ns.Close()
	run = r.pass()
	if a = r.store.appliance("ns-1"); a.Status != model.HealthCritical || !strings.Contains(a.Summary, "could not be reached") || run.Status != model.StatusFailed {
		t.Fatalf("closed: %s %q", a.Status, a.Summary)
	}
}

func TestFailedStepIsUnknownNotDown(t *testing.T) {
	r := newRig(t)
	r.pass()
	writes := r.store.writes
	r.ns.Fail("stat/lbvserver", http.StatusForbidden)
	r.ns.Fail("config/sslcertkey", http.StatusInternalServerError)
	run := r.pass()
	a := r.store.appliance("ns-1")
	if run.Status != model.StatusPartial || run.Appliances[0].Status != model.StatusPartial || !strings.Contains(run.Appliances[0].Error, "lbvserver") {
		t.Fatalf("run: %+v", run.Appliances[0])
	}
	if a.Status != model.HealthUnknown || !a.Reachable || checkOf(a, "vservers").Status != model.HealthUnknown || checkOf(a, "certificates").Status != model.HealthUnknown || checkOf(a, "services").Status != model.HealthOK {
		t.Fatalf("appliance: %s %s", a.Status, a.Summary)
	}
	// The counts and documents of the parts that could not be read are kept.
	if a.Counts.Vservers != 6 || a.Counts.Certificates != 2 || r.store.object(model.CollVservers, "lb_web") == nil || r.store.writes != writes {
		t.Fatalf("counts %+v, writes %d", a.Counts, r.store.writes-writes)
	}
	steps := map[string]string{}
	for _, s := range run.Appliances[0].Steps {
		steps[s.Name] = s.Status
	}
	if steps["vservers"] != model.StatusFailed || steps["certificates"] != model.StatusFailed || steps["services"] != model.StatusSuccess {
		t.Fatalf("steps: %v", steps)
	}
	wantEvents(t, r.store.takeEvents(), "appliance ok>unknown")
}

func TestSecondaryNode(t *testing.T) {
	r := newRig(t)
	r.pass()
	if r.store.object(model.CollVservers, "lb_web") == nil {
		t.Fatal("no virtual servers stored as primary")
	}
	r.ns.Calls()
	// A failover: this node is now the secondary, where everything shows as down.
	r.ns.Set("config/hanode", `[{"id": 0, "ipaddress": "10.0.0.11", "hastatus": "UP", "state": "Secondary", "hasync": "SUCCESS"}, {"id": 1, "ipaddress": "10.0.0.12", "hastatus": "UP", "state": "Primary", "hasync": "ENABLED"}]`)
	r.ns.Set("stat/hanode", `{"hacurstatus": "YES", "hacurstate": "UP", "hacurmasterstate": "Secondary"}`)
	r.ns.Set("stat/lbvserver", `[{"name": "lb_web", "state": "DOWN"}]`)
	r.ns.Set("config/nsconfig", `{"lastconfigchangedtime": "Tue Nov 24 10:00:00 2026", "lastconfigsavetime": "Tue Nov 17 10:05:00 2026"}`)
	run := r.pass()
	a := r.store.appliance("ns-1")
	if a.Status != model.HealthOK || a.HA.MasterState != "Secondary" || a.Counts.Vservers != 0 || a.Counts.Services != 0 || a.Counts.Certificates != 2 {
		t.Fatalf("secondary: %s %q %+v", a.Status, a.Summary, a.Counts)
	}
	if !strings.Contains(checkOf(a, "vservers").Message, "Secondary node") || checkOf(a, "config").Status != model.HealthOK {
		t.Fatalf("checks: %+v", a.Checks)
	}
	if r.store.object(model.CollVservers, "lb_web") != nil || r.store.object(model.CollServices, "svc_web1") != nil || r.store.object(model.CollCertificates, "wildcard") == nil {
		t.Fatal("a secondary keeps its certificates and nothing else")
	}
	if calls := strings.Join(r.ns.Calls(), " "); strings.Contains(calls, "lbvserver") || strings.Contains(calls, "stat/service") || strings.Contains(calls, "nsconfig") {
		t.Fatalf("a secondary's virtual servers were read: %s", calls)
	}
	wantEvents(t, r.store.takeEvents(), "ha Primary>Secondary")
	if run.Status != model.StatusSuccess {
		t.Fatalf("run: %+v", run)
	}

	// The peer goes away, and the appliance restarts.
	r.ns.Set("config/hanode", `[{"id": 0, "ipaddress": "10.0.0.11", "hastatus": "UP", "state": "Primary", "hasync": "ENABLED"}, {"id": 1, "ipaddress": "10.0.0.12", "hastatus": "UNKNOWN", "state": "UNKNOWN", "hasync": "FAILED"}]`)
	r.ns.Set("stat/hanode", `{"hacurstatus": "YES", "hacurstate": "UP", "hacurmasterstate": "Primary"}`)
	r.ns.Set("stat/system", `{"pktcpuusagepcnt": 5, "mgmtcpuusagepcnt": 5, "memusagepcnt": 30, "disk0perusage": 31, "disk1perusage": 55, "starttime": "Tue Nov 24 01:59:00 2026"}`)
	r.ns.Set("stat/lbvserver", `[{"name": "lb_web", "state": "UP", "vslbhealth": 100}]`)
	r.ns.Set("config/nsconfig", `{"configchanged": false}`)
	r.pass()
	a = r.store.appliance("ns-1")
	if c := checkOf(a, "ha"); c.Status != model.HealthCritical || !strings.Contains(c.Message, "the peer 10.0.0.12 is UNKNOWN") || !strings.Contains(c.Message, "synchronisation failed") {
		t.Fatalf("ha: %+v", c)
	}
	if checkOf(a, "hardware").Message != "No power supply sensors (a virtual appliance)" {
		t.Fatalf("hardware: %+v", checkOf(a, "hardware"))
	}
	wantEvents(t, r.store.takeEvents(), "ha Secondary>Primary", "check ha ok>critical", "appliance ok>critical", "restart Mon Nov  2 08:00:00 2026>Tue Nov 24 01:59:00 2026")
}

func TestStandaloneAndRequireHA(t *testing.T) {
	r := newRig(t)
	r.ns.Set("config/hanode", `[{"id": 0, "ipaddress": "10.0.0.11", "hastatus": "UP", "state": "Primary"}]`)
	r.ns.Set("stat/hanode", `{"hacurstatus": "NO", "hacurstate": "UP", "hacurmasterstate": "Primary"}`)
	r.pass()
	if a := r.store.appliance("ns-1"); a.Status != model.HealthOK || a.HA.Configured || !strings.Contains(checkOf(a, "ha").Message, "Standalone") {
		t.Fatalf("standalone: %+v", checkOf(a, "ha"))
	}
	r.chk.Cfg.Appliances[0].RequireHA = true
	r.pass()
	if a := r.store.appliance("ns-1"); checkOf(a, "ha").Status != model.HealthCritical {
		t.Fatalf("requireHA: %+v", checkOf(a, "ha"))
	}
}

func TestStoreAwayThenBack(t *testing.T) {
	r := newRig(t)
	r.store.down = true
	run := r.pass()
	if run.Appliances[0].Status != model.StatusPartial || !strings.Contains(run.Appliances[0].Error, "not stored") || run.Appliances[0].Health != model.HealthOK {
		t.Fatalf("run while the store is away: %+v", run.Appliances[0])
	}
	if len(r.store.appliances) != 0 || r.store.writes != 0 {
		t.Fatal("something was written without the stored state")
	}
	r.store.down = false
	r.ns.Set("stat/lbvserver", `[{"name": "lb_web", "state": "DOWN"}]`)
	run = r.pass()
	if a := r.store.appliance("ns-1"); a.Status != model.HealthCritical || run.Appliances[0].Status != model.StatusSuccess || r.store.object(model.CollVservers, "lb_web") == nil {
		t.Fatalf("after the store came back: %+v", run.Appliances[0])
	}
	// Nothing was stored before, so there is nothing to compare with.
	wantEvents(t, r.store.takeEvents())

	// A write that fails later is reported again by the next pass that can store it.
	r.ns.Set("stat/lbvserver", `[{"name": "lb_web", "state": "UP", "vslbhealth": 100}]`)
	r.store.down = true
	r.pass()
	r.store.down = false
	r.pass()
	wantEvents(t, r.store.takeEvents(), "appliance critical>ok", "vserver lb_web critical>ok")
}

func TestTwoAppliancesAndCancel(t *testing.T) {
	a, b := nitrotest.New(), nitrotest.New()
	defer a.Close()
	healthy(a)
	healthy(b)
	st := newStore()
	clock := time.Date(2026, 11, 24, 2, 0, 0, 0, time.UTC)
	chk := newChecker(cfg(t, a, b), st, func() time.Time { return clock })
	b.Close() // the second cannot be reached
	run := chk.Run(context.Background(), "schedule", nil)
	if run.Status != model.StatusPartial || run.AppliancesDone != 2 || run.AppliancesFailed != 1 || run.Counts.OK != 1 || run.Counts.Critical != 1 ||
		run.Appliances[0].Appliance != "ns-1" || run.Appliances[1].Status != model.StatusFailed {
		t.Fatalf("run: %+v", run)
	}
	// The same names on two appliances are two documents.
	n := 0
	for _, o := range st.objects[model.CollVservers] {
		if o.Name == "lb_web" {
			n++
		}
	}
	if n != 1 || st.appliance("ns-2").Status != model.HealthCritical {
		t.Fatalf("lb_web documents: %d", n)
	}

	// A cancelled pass stores nothing new and does not call anything down.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	samples := len(st.samples)
	run = chk.Run(ctx, "schedule", nil)
	if run.Status != model.StatusCancelled || run.AppliancesDone != 0 || len(st.samples) != samples || st.appliance("ns-1").Status != model.HealthOK {
		t.Fatalf("cancelled run: %+v", run)
	}
	if got := st.runs[run.ID]; got.Status != model.StatusCancelled || got.FinishedAt == nil {
		t.Fatalf("stored cancelled run: %+v", got)
	}
}
