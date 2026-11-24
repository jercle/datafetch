package graph

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestParentID(t *testing.T) {
	for id, want := range map[string]string{
		"/subscriptions/s":                  "",
		"/subscriptions/s/resourcegroups/g": "/subscriptions/s",
		"/subscriptions/s/resourcegroups/g/providers/microsoft.compute/virtualmachines/vm":                                                      "/subscriptions/s/resourcegroups/g",
		"/subscriptions/s/providers/microsoft.authorization/policyassignments/p":                                                                "/subscriptions/s",
		"/subscriptions/s/resourcegroups/g/providers/microsoft.sql/servers/a/databases/b":                                                       "/subscriptions/s/resourcegroups/g/providers/microsoft.sql/servers/a",
		"/subscriptions/s/resourcegroups/g/providers/microsoft.network/loadbalancers/l/backendaddresspools":                                     "/subscriptions/s/resourcegroups/g/providers/microsoft.network/loadbalancers/l",
		"/subscriptions/s/resourcegroups/g/providers/microsoft.compute/virtualmachines/vm/providers/microsoft.guestconfiguration/assignments/x": "/subscriptions/s/resourcegroups/g/providers/microsoft.compute/virtualmachines/vm",
	} {
		if got := ParentID(id); got != want {
			t.Errorf("ParentID(%s) = %s, want %s", id, got, want)
		}
	}
}

func TestResolveScaleSetInstance(t *testing.T) {
	vmss := "/subscriptions/s/resourceGroups/g/providers/Microsoft.Compute/virtualMachineScaleSets/Web"
	_, edges, ix := Build(BuildOptions{Via: "T"}, nil, []Resource{
		{ID: vmss, Name: "Web", Type: "Microsoft.Compute/virtualMachineScaleSets", SubscriptionID: "s", ResourceGroup: "g"},
		{ID: "/subscriptions/s/resourceGroups/g/providers/Microsoft.Network/loadBalancers/lb", Type: "Microsoft.Network/loadBalancers", SubscriptionID: "s",
			Properties: map[string]any{"backendAddressPools": []any{map[string]any{"properties": map[string]any{"backendIPConfigurations": []any{
				map[string]any{"id": vmss + "/virtualMachines/0/networkInterfaces/nic/ipConfigurations/ip"}}}}}}},
	})
	if n := ix.Resolve(vmss + "/virtualMachines/3"); n == nil || n.ID != ARMID(vmss) {
		t.Fatalf("resolve: %+v", n)
	}
	found := false
	for _, e := range edges {
		found = found || (e.Rel == RelBackend && e.To == ARMID(vmss))
	}
	if !found {
		t.Error("load balancer not linked to the scale set behind it")
	}
	// The subscription was never listed, so it is synthesised under the tenant.
	if ix.Node("/subscriptions/s") == nil || ix.Node("/tenants/t") == nil {
		t.Error("missing synthesised subscription or tenant")
	}
}

func TestBuildDevicesLinksByName(t *testing.T) {
	_, _, ix := Build(BuildOptions{Via: "t"}, nil, []Resource{
		{ID: "/subscriptions/s/resourceGroups/g/providers/Microsoft.HybridCompute/machines/SRV01", Name: "SRV01", Type: "Microsoft.HybridCompute/machines", SubscriptionID: "s", ResourceGroup: "g"},
	})
	g := BuildDevices(DeviceOptions{}, []*Index{ix}, []Device{{Tenant: "t", ID: "a", Name: "srv01.corp.example"}, {Tenant: "t", ID: "b", Name: "other"}})
	a := g.Canonical[RecordKey("t", "a")]
	if g.Linked[a] == nil || len(g.Linked) != 1 || g.LinkedByName != 1 {
		t.Fatalf("linked: %v", g.Linked)
	}
	for _, e := range g.Edges {
		if e.From == a && (e.Rel != RelRunsOn || e.Attrs["match"] != "name") {
			t.Errorf("edge: %+v", e)
		}
	}
}

func TestBuildDevicesMergesAcrossTenants(t *testing.T) {
	day := func(d int) time.Time { return time.Date(2026, 11, d, 0, 0, 0, 0, time.UTC) }
	vm := "/subscriptions/s/resourceGroups/g/providers/Microsoft.Compute/virtualMachines/app01"
	_, _, ix := Build(BuildOptions{Via: "tenant-a"}, nil, []Resource{{ID: vm, Name: "app01", Type: "Microsoft.Compute/virtualMachines", SubscriptionID: "s", ResourceGroup: "g", TenantID: "tenant-a"}})
	recs := []Device{
		// The same VM in two Defender orgs: the old record went quiet, the new one is live.
		{Tenant: "tenant-a", ID: "old", Name: "app01", ResourceID: vm, VMID: "11111111-1111-1111-1111-111111111111", LastSeen: day(1)},
		{Tenant: "tenant-b", ID: "new", Name: "app01.corp", VMID: "{11111111-1111-1111-1111-111111111111}", LastSeen: day(15), OSPlatform: "Windows11"},
		// Entra device ID in common.
		{Tenant: "tenant-a", ID: "l1", Name: "laptop", AADDeviceID: "AAAAAAAA-0000-0000-0000-000000000001", LastSeen: day(2)},
		{Tenant: "tenant-b", ID: "l2", Name: "laptop-renamed", AADDeviceID: "aaaaaaaa-0000-0000-0000-000000000001", LastSeen: day(3), OnboardingStatus: "InsufficientInfo"},
		// Same name, different VM IDs: two machines, never merged.
		{Tenant: "tenant-a", ID: "w1", Name: "web", VMID: "22222222-2222-2222-2222-222222222222", LastSeen: day(4)},
		{Tenant: "tenant-b", ID: "w2", Name: "WEB", VMID: "33333333-3333-3333-3333-333333333333", LastSeen: day(5)},
		// Same name, nothing else known: merged by the hostname fallback.
		{Tenant: "tenant-a", ID: "h1", Name: "Legacy", LastSeen: day(6)},
		{Tenant: "tenant-b", ID: "h2", Name: "legacy", LastSeen: day(7)},
		// An all-zero Entra ID is no identifier at all.
		{Tenant: "tenant-a", ID: "z1", Name: "z-one", AADDeviceID: "00000000-0000-0000-0000-000000000000"},
		{Tenant: "tenant-b", ID: "z2", Name: "z-two", AADDeviceID: "00000000-0000-0000-0000-000000000000"},
	}
	g := BuildDevices(DeviceOptions{HostnameFallback: true}, []*Index{ix}, recs)
	if len(g.Nodes) != 7 || g.Merged != 3 || g.MergedByHostname != 1 || len(g.Superseded) != 3 {
		t.Fatalf("%d devices, %d merged (%d by hostname), %d superseded", len(g.Nodes), g.Merged, g.MergedByHostname, len(g.Superseded))
	}
	node := func(id string) Node {
		for _, n := range g.Nodes {
			if n.ID == id {
				return n
			}
		}
		t.Fatalf("no node %s", id)
		return Node{}
	}
	// Keyed by the Azure resource ID, current record from tenant-b, linked to the VM in tenant-a.
	app := g.Canonical[RecordKey("tenant-b", "new")]
	if n := node(app); app != "device:res:"+ARMID(vm) || n.Via != "tenant-b" || n.Type != "windows11" || n.ResourceGroup != "g" || g.Linked[app] == nil {
		t.Errorf("app01: %s %+v", app, n)
	}
	if !g.Superseded[RecordKey("tenant-a", "old")] || g.Canonical[RecordKey("tenant-a", "old")] != "" {
		t.Error("the old record of app01 should be superseded")
	}
	// The onboarded record wins over a more recent one that is not onboarded.
	if g.Canonical[RecordKey("tenant-a", "l1")] != "device:aad:aaaaaaaa-0000-0000-0000-000000000001" || !g.Superseded[RecordKey("tenant-b", "l2")] {
		t.Errorf("laptop: %v", g.Canonical)
	}
	if g.Canonical[RecordKey("tenant-a", "w1")] == g.Canonical[RecordKey("tenant-b", "w2")] {
		t.Error("machines with different Azure VM IDs were merged because they share a name")
	}
	if g.Canonical[RecordKey("tenant-b", "h2")] == "" || !g.Superseded[RecordKey("tenant-a", "h1")] {
		t.Error("hostname fallback did not merge legacy")
	}
	if g.Canonical[RecordKey("tenant-a", "z1")] == g.Canonical[RecordKey("tenant-b", "z2")] {
		t.Error("all-zero Entra device IDs were treated as a shared identifier")
	}
	if n := len(BuildDevices(DeviceOptions{}, nil, recs).Nodes); n != 8 {
		t.Errorf("without the hostname fallback: %d devices, want 8", n)
	}
}

func TestGrouper(t *testing.T) {
	g, err := NewGrouper([]GroupDef{
		{Name: "GCP", Hidden: true, CIDRs: []string{"10.128.0.0/9"}, Names: []string{"gke-*", "*.c.my-project.internal"}, CloudProviders: []string{"gcp"}},
		{Name: "AWS", Hidden: true, CIDRs: []string{"172.31.0.0/16", "192.168.50.7"}, NameRegex: []string{`^ip-\d+-\d+-\d+-\d+`}},
		{Name: "Lab", Names: []string{"lab-??"}},
	}, "Azure", false)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		d    Device
		want string
	}{
		{Device{Name: "web01", LastIP: "10.130.4.2"}, "GCP"},
		{Device{Name: "GKE-pool-1-abc", LastIP: "192.168.1.1"}, "GCP"},
		{Device{Name: "db.c.my-project.internal"}, "GCP"},
		{Device{Name: "plain", CloudProvider: "GCP"}, "GCP"},
		{Device{Name: "app", LastIP: "172.31.9.9"}, "AWS"},
		{Device{Name: "app", LastIP: "192.168.50.7"}, "AWS"},
		{Device{Name: "app", LastIP: "192.168.50.8"}, "Azure"},
		{Device{Name: "ip-10-0-3-4.ec2.internal"}, "AWS"},
		{Device{Name: "lab-01"}, "Lab"},
		{Device{Name: "lab-001"}, "Azure"},
		// First match wins: the address says GCP even though the name says AWS.
		{Device{Name: "ip-10-0-3-4", LastIP: "10.128.0.1"}, "GCP"},
		{Device{Name: "vm1", LastIP: "10.0.0.4", CloudProvider: "Azure"}, "Azure"},
		{Device{Name: "vm2", LastIP: "not an address"}, "Azure"},
	} {
		if got := g.Group(c.d); got != c.want {
			t.Errorf("%+v: group %q, want %q", c.d, got, c.want)
		}
	}
	if defs := g.Defs(); len(defs) != 4 || defs[3].Name != "Azure" || !defs[0].Hidden || defs[3].Hidden {
		t.Errorf("defs: %+v", defs)
	}
	var none *Grouper
	if none.Group(Device{Name: "x"}) != "" || none.Defs() != nil {
		t.Error("no groups configured should mean no group")
	}
	if g, err := NewGrouper(nil, "Other", false); g != nil || err != nil {
		t.Errorf("empty config: %v %v", g, err)
	}
	_, err = NewGrouper([]GroupDef{{Name: "a", CIDRs: []string{"10.0.0.0/33"}}, {Name: "A", Names: []string{"x"}}, {Name: "b"}, {Name: "all", Names: []string{"x"}}, {Name: "re", NameRegex: []string{"("}}}, "Other", false)
	if err == nil || strings.Count(err.Error(), "\n") != 4 {
		t.Errorf("want five configuration errors, got: %v", err)
	}
}

func TestParseContainerFindingShapes(t *testing.T) {
	d := "sha256:" + strings.Repeat("a", 64)
	parse := func(name string, extra map[string]any) ContainerFinding {
		f, ok := ParseContainerFinding("/subscriptions/s/resourceGroups/g/providers/Microsoft.ContainerRegistry/registries/MyReg/providers/Microsoft.Security/securityEntityData/e1/providers/Microsoft.Security/assessments/a",
			map[string]any{"resourceDetails": map[string]any{"ResourceType": ".containerimage", "ResourceName": name}, "resourceAdditionalData": extra})
		if !ok {
			t.Fatal("not parsed")
		}
		return f
	}
	for _, c := range []struct {
		name               string
		extra              map[string]any
		host, repo, digest string
		tags               string
	}{
		// Identity only in the resource name.
		{"team/app:1.2@" + d, nil, "", "team/app", d, "[1.2]"},
		{"myreg.azurecr.io/team/app:1.2", map[string]any{"ImageDigest": d}, "myreg.azurecr.io", "team/app", d, "[1.2]"},
		{d, map[string]any{"RepositoryName": "team/app"}, "", "team/app", d, "[]"},
		// Tags under assorted keys, as an array, a string and a comma-separated string.
		{"team/app", map[string]any{"Digest": d, "RepoTags": []any{"1.2", "latest"}}, "", "team/app", d, "[1.2 latest]"},
		{"team/app", map[string]any{"Digest": d, "ImageTag": "1.2"}, "", "team/app", d, "[1.2]"},
		{"team/app", map[string]any{"Digest": d, "tagList": "1.2, stable"}, "", "team/app", d, "[1.2 stable]"},
		// An ETag is not a tag, and a tag-less reference still gives host and repository.
		{"x", map[string]any{"etag": "W/abc", "Image": "MyReg.azurecr.io/Team/App@" + d}, "myreg.azurecr.io", "team/app", d, "[]"},
		{"x", map[string]any{"Digest": d, "ImageReference": "myreg.azurecr.io/team/app:v3"}, "myreg.azurecr.io", "team/app", d, "[v3]"},
	} {
		f := parse(c.name, c.extra)
		if f.Host != c.host || f.Repo != c.repo || f.Digest != c.digest || fmt.Sprint(f.Tags) != c.tags {
			t.Errorf("%q %v: host %q repo %q digest %q tags %v", c.name, c.extra, f.Host, f.Repo, f.Digest, f.Tags)
		}
	}

	// The registry's login server replaces a missing host or a bare registry name.
	_, _, ix := Build(BuildOptions{Via: "t"}, nil, []Resource{{ID: "/subscriptions/s/resourceGroups/g/providers/Microsoft.ContainerRegistry/registries/MyReg", Name: "MyReg",
		Type: "Microsoft.ContainerRegistry/registries", SubscriptionID: "s", ResourceGroup: "g", Properties: map[string]any{"loginServer": "MyReg.azurecr.io"}}})
	fs := []ContainerFinding{parse("team/app@"+d, nil), parse("team/app", map[string]any{"Registry": "myreg", "Digest": d}), parse("myreg.azurecr.io/team/app@"+d, map[string]any{"RepositoryName": "myreg.azurecr.io/team/app"})}
	NormaliseFindings(ix, fs)
	for i, f := range fs {
		if f.Host != "myreg.azurecr.io" || f.Repo != "team/app" || f.ImageID() != "image:myreg.azurecr.io/team/app@"+d {
			t.Errorf("finding %d: host %q repo %q id %q", i, f.Host, f.Repo, f.ImageID())
		}
	}
	if r := ReposWithoutTags(fs); len(r) != 1 || r[0] != (ImageRepo{"myreg.azurecr.io", "team/app"}) {
		t.Errorf("repositories to ask: %v", r)
	}
}
