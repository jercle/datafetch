package collector

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jercle/datafetch/mdetracker/internal/config"
	"github.com/jercle/datafetch/mdetracker/internal/defender"
	"github.com/jercle/datafetch/mdetracker/internal/model"
)

type fakeLister []defender.Machine

func (f fakeLister) ListMachines(context.Context, string, int) ([]defender.Machine, error) {
	return f, nil
}

type fakeStore struct{}

func (fakeStore) StartRun(context.Context, *model.Run) error  { return nil }
func (fakeStore) FinishRun(context.Context, *model.Run) error { return nil }
func (fakeStore) PreviousState(context.Context) (map[string]Previous, error) {
	return nil, nil
}
func (fakeStore) UpsertVMs(context.Context, []model.VM, map[string]model.OrgChange) error {
	return nil
}
func (fakeStore) DeactivateMissing(context.Context, string) (int64, error) { return 0, nil }

func TestDump(t *testing.T) {
	dir := t.TempDir()
	// An old run folder that should be pruned, and an unrelated folder that must survive.
	old := filepath.Join(dir, "20200101T000000Z-abcdef")
	keepMe := filepath.Join(dir, "notes")
	for _, p := range []string{old, keepMe} {
		if err := os.MkdirAll(p, 0o750); err != nil {
			t.Fatal(err)
		}
	}

	off := false // hostname fallback off: the Fabrikam record stays excluded
	cfg := &config.Config{Mode: config.ModeVMs, Concurrency: 2, PageSize: 100, DumpDir: dir, DumpKeep: 1, HostnameFallback: &off}
	cfg.ActiveWindow.Duration = 48 * time.Hour
	cfg.InactiveAfter.Duration = 7 * 24 * time.Hour

	// Same host in both tenants; the new tenant's record has no vmMetadata yet,
	// so mode=vms drops it and the VM never shows up in Fabrikam.
	inA := azm("a1", ago(100*24*time.Hour), ago(5*24*time.Hour), rid, "g")
	inB := defender.Machine{ID: "b1", ComputerDNSName: "VM-APP-01.corp.local", OSPlatform: "WindowsServer2022",
		OnboardingStatus: "Onboarded", LastSeen: ago(time.Hour)}
	sources := []Source{
		{Tenant: config.Tenant{Name: "Contoso Prod", TenantID: "tid-a", OrgID: "org-a"}, Lister: fakeLister{inA}},
		{Tenant: config.Tenant{Name: "Fabrikam", TenantID: "tid-b", OrgID: "org-b"}, Lister: fakeLister{inB}},
	}
	c := New(cfg, sources, fakeStore{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := c.Run(context.Background()); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatal("old run folder should have been pruned")
	}
	if _, err := os.Stat(keepMe); err != nil {
		t.Fatal("unrelated folder must not be removed")
	}
	runs, _ := filepath.Glob(filepath.Join(dir, "2*Z-*"))
	if len(runs) != 1 {
		t.Fatalf("want 1 run folder, got %v", runs)
	}
	for _, f := range []string{"run.json", "vms.json", "org-changes.json", "unlinked-hostnames.json",
		"tenants/contoso-prod.machines.json", "tenants/contoso-prod.records.json",
		"tenants/fabrikam.machines.json", "tenants/fabrikam.records.json"} {
		if _, err := os.Stat(filepath.Join(runs[0], f)); err != nil {
			t.Fatalf("missing %s: %v", f, err)
		}
	}

	var unlinked []unlinkedHost
	b, _ := os.ReadFile(filepath.Join(runs[0], "unlinked-hostnames.json"))
	if err := json.Unmarshal(b, &unlinked); err != nil {
		t.Fatal(err)
	}
	if len(unlinked) != 1 || unlinked[0].Hostname != "vm-app-01" || len(unlinked[0].Records) != 2 {
		t.Fatalf("unlinked: %+v", unlinked)
	}

	var recs []recordDump
	b, _ = os.ReadFile(filepath.Join(runs[0], "tenants/fabrikam.records.json"))
	if err := json.Unmarshal(b, &recs); err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].Included || recs[0].ExcludedReason == "" {
		t.Fatalf("fabrikam record should be excluded with a reason: %+v", recs)
	}

	var vms []map[string]any
	b, _ = os.ReadFile(filepath.Join(runs[0], "vms.json"))
	if err := json.Unmarshal(b, &vms); err != nil {
		t.Fatal(err)
	}
	if len(vms) != 1 || vms[0]["currentOrgId"] != "org-a" || vms[0]["key"] == "" {
		t.Fatalf("vms.json: %+v", vms)
	}
}

func TestHostnameFallbackRescuesExcluded(t *testing.T) {
	cfg := &config.Config{Mode: config.ModeVMs, Concurrency: 2, PageSize: 100}
	cfg.ActiveWindow.Duration = 48 * time.Hour
	cfg.InactiveAfter.Duration = 7 * 24 * time.Hour
	inA := azm("a1", ago(100*24*time.Hour), ago(5*24*time.Hour), rid, "g")
	inB := defender.Machine{ID: "b1", ComputerDNSName: "VM-APP-01", OnboardingStatus: "Onboarded", LastSeen: ago(time.Hour)}
	other := defender.Machine{ID: "b2", ComputerDNSName: "laptop-7", OSPlatform: "Windows11", LastSeen: ago(time.Hour)}
	st := &captureStore{}
	c := New(cfg, []Source{
		{Tenant: config.Tenant{Name: "Contoso", TenantID: "tid-a", OrgID: "org-a"}, Lister: fakeLister{inA}},
		{Tenant: config.Tenant{Name: "Fabrikam", TenantID: "tid-b", OrgID: "org-b"}, Lister: fakeLister{inB, other}},
	}, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	c.now = func() time.Time { return now }
	if err := c.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(st.vms) != 1 || st.vms[0].CurrentOrgID != "org-b" || !st.vms[0].MergedByHostname || len(st.vms[0].Tenants) != 2 {
		t.Fatalf("want one VM now in org-b, merged by hostname: %+v", st.vms)
	}
}

type captureStore struct {
	fakeStore
	vms []model.VM
}

func (s *captureStore) UpsertVMs(_ context.Context, vms []model.VM, _ map[string]model.OrgChange) error {
	s.vms = vms
	return nil
}
