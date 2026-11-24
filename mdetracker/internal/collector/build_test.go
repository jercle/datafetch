package collector

import (
	"testing"
	"time"

	"github.com/jercle/datafetch/mdetracker/internal/defender"
	"github.com/jercle/datafetch/mdetracker/internal/model"
)

var now = time.Date(2026, 11, 13, 6, 0, 0, 0, time.UTC)

func ago(d time.Duration) *time.Time { t := now.Add(-d); return &t }

var (
	tA = TenantRef{Name: "Contoso", TenantID: "tid-a", OrgID: "org-a"}
	tB = TenantRef{Name: "Fabrikam", TenantID: "tid-b", OrgID: "org-b"}
)

const rid = "/subscriptions/1111/resourceGroups/RG-App/providers/Microsoft.Compute/virtualMachines/vm-app-01"

func azm(id string, first, last *time.Time, resID, vmID string) defender.Machine {
	return defender.Machine{
		ID: id, ComputerDNSName: "vm-app-01", FirstSeen: first, LastSeen: last,
		OnboardingStatus: "Onboarded", HealthStatus: "Active", OSPlatform: "WindowsServer2022",
		VMMetadata: &defender.VMMetadata{ResourceID: resID, VMID: vmID, CloudProvider: "Azure", SubscriptionID: "1111"},
	}
}

func opts() BuildOptions {
	return BuildOptions{Now: now, ActiveWindow: 48 * time.Hour, InactiveAfter: 7 * 24 * time.Hour, RunID: "r1"}
}

func TestSingleTenant(t *testing.T) {
	vms := BuildVMs([]Record{{tA, azm("m1", ago(90*24*time.Hour), ago(time.Hour), rid, "vm-guid")}}, opts())
	if len(vms) != 1 {
		t.Fatalf("want 1 vm, got %d", len(vms))
	}
	v := vms[0]
	if v.Status != model.StatusOK || v.CurrentOrgID != "org-a" || v.ResourceGroup != "RG-App" || v.SubscriptionID != "1111" {
		t.Fatalf("unexpected vm: %+v", v)
	}
	if v.Key != "res:"+normResourceID(rid) {
		t.Fatalf("key = %s", v.Key)
	}
}

func TestMigratedAcrossOrgs(t *testing.T) {
	// Old record in org A stopped reporting before the org B onboarding began.
	// The new record only shares the vmId (resourceId casing differs, still merges).
	recs := []Record{
		{tA, azm("old", ago(200*24*time.Hour), ago(10*24*time.Hour), rid, "VM-GUID")},
		{tB, azm("new", ago(9*24*time.Hour), ago(2*time.Hour), "", "vm-guid")},
	}
	vms := BuildVMs(recs, opts())
	if len(vms) != 1 {
		t.Fatalf("records should merge, got %d vms", len(vms))
	}
	v := vms[0]
	if v.CurrentOrgID != "org-b" || v.Status != model.StatusMigrated || v.OrgCount != 2 {
		t.Fatalf("unexpected: org=%s status=%s orgs=%d", v.CurrentOrgID, v.Status, v.OrgCount)
	}
	if v.AzureResourceID != rid {
		t.Fatalf("azure metadata should come from the old record when the current lacks it")
	}
	if v.Onboardings[0].State != model.StateCurrent || v.Onboardings[1].State != model.StateSuperseded {
		t.Fatalf("states: %+v", v.Onboardings)
	}
}

func TestConflictWhenBothReporting(t *testing.T) {
	recs := []Record{
		{tA, azm("a", ago(100*24*time.Hour), ago(3*time.Hour), rid, "g")},
		{tB, azm("b", ago(5*24*time.Hour), ago(1*time.Hour), rid, "g")},
	}
	v := BuildVMs(recs, opts())[0]
	if v.Status != model.StatusConflict || v.CurrentOrgID != "org-b" {
		t.Fatalf("want conflict on org-b, got %s on %s", v.Status, v.CurrentOrgID)
	}
}

func TestInactive(t *testing.T) {
	v := BuildVMs([]Record{{tA, azm("m", ago(60*24*time.Hour), ago(20*24*time.Hour), rid, "g")}}, opts())[0]
	if v.Status != model.StatusInactive {
		t.Fatalf("want inactive, got %s", v.Status)
	}
}

func TestDistinctVMsStaySeparate(t *testing.T) {
	recs := []Record{
		{tA, azm("1", ago(time.Hour), ago(time.Hour), rid, "g1")},
		{tA, azm("2", ago(time.Hour), ago(time.Hour), rid+"x", "g2")},
	}
	if n := len(BuildVMs(recs, opts())); n != 2 {
		t.Fatalf("want 2 vms, got %d", n)
	}
}

func TestMatchesMode(t *testing.T) {
	laptop := defender.Machine{OSPlatform: "Windows11"}
	server := defender.Machine{OSPlatform: "WindowsServer2019"}
	azure := azm("x", nil, nil, rid, "")
	if matchesMode(laptop, "vms") || matchesMode(server, "vms") || !matchesMode(azure, "vms") {
		t.Fatal("vms mode")
	}
	if matchesMode(laptop, "servers") || !matchesMode(server, "servers") {
		t.Fatal("servers mode")
	}
}

func TestTenantContactsAggregate(t *testing.T) {
	// Two records in org A (re-onboarded once), one current in org B.
	recs := []Record{
		{tA, azm("a1", ago(300*24*time.Hour), ago(200*24*time.Hour), rid, "g")},
		{tA, azm("a2", ago(190*24*time.Hour), ago(12*24*time.Hour), rid, "g")},
		{tB, azm("b1", ago(11*24*time.Hour), ago(time.Hour), rid, "g")},
	}
	v := BuildVMs(recs, opts())[0]
	if len(v.Tenants) != 2 {
		t.Fatalf("want 2 tenant entries, got %d", len(v.Tenants))
	}
	cur, old := v.Tenants[0], v.Tenants[1]
	if cur.TenantID != "tid-b" || cur.State != model.StateCurrent || !cur.Present {
		t.Fatalf("current entry: %+v", cur)
	}
	if old.Records != 2 || !old.LastSeen.Equal(*ago(12 * 24 * time.Hour)) || !old.FirstSeen.Equal(*ago(300 * 24 * time.Hour)) {
		t.Fatalf("old entry should aggregate both records: %+v", old)
	}
	if v.PreviousOrgID != "org-a" || v.Status != model.StatusMigrated {
		t.Fatalf("previous org: %s status %s", v.PreviousOrgID, v.Status)
	}
}

func TestMergeKeepsVanishedTenant(t *testing.T) {
	// This run only org B returns the VM; org A's record has aged out of Defender.
	v := BuildVMs([]Record{{tB, azm("b1", ago(30*24*time.Hour), ago(time.Hour), rid, "g")}}, opts())[0]
	if v.Status != model.StatusOK {
		t.Fatalf("before merge want ok, got %s", v.Status)
	}
	prev := []model.TenantContact{
		{TenantID: "tid-a", TenantName: "Contoso", OrgID: "org-a", LastSeen: ago(40 * 24 * time.Hour), State: model.StateCurrent, Present: true},
		{TenantID: "tid-b", TenantName: "Fabrikam", OrgID: "org-b", LastSeen: ago(2 * time.Hour), State: model.StateSuperseded, Present: true},
	}
	v.Tenants = MergeTenants(v.Tenants, prev, nil)
	Finalize(&v, now, 7*24*time.Hour)
	if len(v.Tenants) != 2 {
		t.Fatalf("want 2 tenants, got %d", len(v.Tenants))
	}
	a := v.Tenants[1]
	if a.TenantID != "tid-a" || a.Present || a.State != model.StateSuperseded {
		t.Fatalf("vanished tenant entry: %+v", a)
	}
	if v.Status != model.StatusMigrated || v.PreviousOrgID != "org-a" || v.OrgCount != 2 {
		t.Fatalf("after merge: status=%s prev=%s orgs=%d", v.Status, v.PreviousOrgID, v.OrgCount)
	}
	if !v.Tenants[0].LastSeen.Equal(*ago(time.Hour)) {
		t.Fatal("this run's contact must win over the stored one")
	}

	// A tenant that failed this run keeps its stored Present flag.
	v2 := v
	v2.Tenants = MergeTenants(v.Tenants[:1], prev, map[string]bool{"tid-a": true})
	if !v2.Tenants[1].Present {
		t.Fatal("failed tenant should not be marked absent")
	}
}

func TestHostnameFallback(t *testing.T) {
	o := opts()
	o.HostnameFallback = true
	// New tenant's record has no Azure metadata at all: only the name links it.
	noMeta := defender.Machine{ID: "b1", ComputerDNSName: "VM-APP-01", OnboardingStatus: "Onboarded",
		FirstSeen: ago(3 * 24 * time.Hour), LastSeen: ago(time.Hour)}
	recs := []Record{
		{tA, azm("a1", ago(100*24*time.Hour), ago(5*24*time.Hour), rid, "g1")},
		{tB, noMeta},
	}
	vms := BuildVMs(recs, o)
	if len(vms) != 1 || !vms[0].MergedByHostname || vms[0].CurrentOrgID != "org-b" || vms[0].Status != model.StatusMigrated {
		t.Fatalf("want one VM merged by hostname, current in org-b: %+v", vms)
	}
	if vms[0].Key != "res:"+normResourceID(rid) {
		t.Fatalf("key should stay the Azure resource ID, got %s", vms[0].Key)
	}

	// Same name but different Azure VM IDs: two machines, never merged.
	recs = []Record{
		{tA, azm("a1", ago(time.Hour), ago(time.Hour), rid, "g1")},
		{tB, azm("b1", ago(time.Hour), ago(time.Hour), rid+"-other", "g2")},
	}
	if n := len(BuildVMs(recs, o)); n != 2 {
		t.Fatalf("different VM IDs must stay separate, got %d", n)
	}

	// IDs already link them: not flagged as a hostname merge.
	recs = []Record{
		{tA, azm("a1", ago(9*24*time.Hour), ago(8*24*time.Hour), rid, "g1")},
		{tB, azm("b1", ago(time.Hour), ago(time.Hour), rid, "g1")},
	}
	if vms := BuildVMs(recs, o); len(vms) != 1 || vms[0].MergedByHostname {
		t.Fatalf("ID match should not be flagged: %+v", vms)
	}

	// Off: stays separate.
	o.HostnameFallback = false
	if n := len(BuildVMs([]Record{{tA, azm("a1", nil, ago(time.Hour), rid, "g1")}, {tB, noMeta}}, o)); n != 2 {
		t.Fatalf("fallback off: want 2, got %d", n)
	}
}

// Issue #2: a tenant's orgId is changed in config (the tenant moved to a new Defender org).
func TestTenantOrgIDChanged(t *testing.T) {
	tNew := TenantRef{Name: "Contoso", TenantID: "tid-a", OrgID: "org-a2"}
	v := BuildVMs([]Record{{tNew, azm("m1", ago(90*24*time.Hour), ago(time.Hour), rid, "g")}}, opts())[0]
	prev := []model.TenantContact{{TenantID: "tid-a", TenantName: "Contoso", OrgID: "org-a",
		LastSeen: ago(26 * time.Hour), State: model.StateCurrent, Present: true}}
	v.Tenants = MergeTenants(v.Tenants, prev, nil)
	Finalize(&v, now, 7*24*time.Hour)
	if len(v.Tenants) != 2 || v.Tenants[0].OrgID != "org-a2" || v.Tenants[0].State != model.StateCurrent {
		t.Fatalf("tenants: %+v", v.Tenants)
	}
	old := v.Tenants[1]
	if old.OrgID != "org-a" || old.Present || old.State != model.StateSuperseded {
		t.Fatalf("old org entry should be kept as history: %+v", old)
	}
	if v.CurrentOrgID != "org-a2" || v.PreviousOrgID != "org-a" || v.Status != model.StatusMigrated || v.OrgCount != 2 {
		t.Fatalf("vm: cur=%s prev=%s status=%s orgs=%d", v.CurrentOrgID, v.PreviousOrgID, v.Status, v.OrgCount)
	}
}
