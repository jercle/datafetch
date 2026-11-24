package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jercle/datafetch/azurecves/pkg/azure"
	"github.com/jercle/datafetch/azurecves/pkg/config"
	"github.com/jercle/datafetch/azurecves/pkg/graph"
	"github.com/jercle/datafetch/azurecves/pkg/monitor"
)

// memStore is an in-memory Store with the same semantics as mongostore.
type memStore struct {
	mu       sync.Mutex
	nodes    map[string]graph.Node
	fields   map[string]map[string]map[string]any // node -> field -> value
	edges    map[string]graph.Edge
	exposure map[string]Exposure
	software map[string]SoftwareSummary
	details  map[string]map[string]any
	state    map[string]*monitor.StageState
	costs    []CostRow
	groups   []DeviceGroup
}

func newMem() *memStore {
	return &memStore{nodes: map[string]graph.Node{}, fields: map[string]map[string]map[string]any{}, edges: map[string]graph.Edge{},
		exposure: map[string]Exposure{}, software: map[string]SoftwareSummary{}, details: map[string]map[string]any{}, state: map[string]*monitor.StageState{}}
}

func (m *memStore) UpsertNodes(_ context.Context, n []graph.Node) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, x := range n {
		m.nodes[x.ID] = x
	}
	return nil
}
func (m *memStore) UpsertEdges(_ context.Context, e []graph.Edge) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, x := range e {
		m.edges[x.ID] = x
	}
	return nil
}
func (m *memStore) Sweep(_ context.Context, via, source, run string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var n int64
	for id, x := range m.nodes {
		if x.Via == via && x.Source == source && x.RunID != run {
			delete(m.nodes, id)
			delete(m.fields, id)
			n++
		}
	}
	for id, x := range m.edges {
		if x.Via == via && x.Source == source && x.RunID != run {
			delete(m.edges, id)
			n++
		}
	}
	return n, nil
}
func (m *memStore) SetNodeField(_ context.Context, via, field, run string, values map[string]map[string]any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, v := range values {
		if _, ok := m.nodes[id]; !ok {
			continue
		}
		if m.fields[id] == nil {
			m.fields[id] = map[string]map[string]any{}
		}
		m.fields[id][field] = v
	}
	for id, f := range m.fields {
		if v, ok := f[field]; ok && v["run"] != run && (via == "" || m.nodes[id].Via == via) {
			delete(f, field)
		}
	}
	return nil
}
func (m *memStore) ReplaceExposure(_ context.Context, via, source, run string, docs []Exposure) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, d := range m.exposure {
		if d.TenantID == via && d.Source == source {
			delete(m.exposure, id)
		}
	}
	for _, d := range docs {
		m.exposure[d.ID] = d
	}
	return nil
}
func (m *memStore) ReplaceSoftware(_ context.Context, via, run string, docs []SoftwareSummary) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, d := range m.software {
		if d.TenantID == via {
			delete(m.software, id)
		}
	}
	for _, d := range docs {
		m.software[d.ID] = d
	}
	return nil
}
func (m *memStore) SaveDeviceGroups(_ context.Context, g []DeviceGroup) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.groups = g
	return nil
}
func (m *memStore) CVEIDs(context.Context) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var ids []string
	for id, n := range m.nodes {
		if n.Kind == graph.KindCVE {
			ids = append(ids, id)
		}
	}
	return ids, nil
}
func (m *memStore) SetCVEDetails(_ context.Context, d map[string]map[string]any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, v := range d {
		m.details[k] = v
	}
	return nil
}
func (m *memStore) PruneShared(context.Context, time.Time) (int64, error) { return 0, nil }
func (m *memStore) ResourceCosts(context.Context, string, time.Time, time.Time) ([]CostRow, error) {
	return m.costs, nil
}
func (m *memStore) SaveState(_ context.Context, s *monitor.StageState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if prev := m.state[s.ID]; prev != nil && s.LastSuccessAt == nil {
		s.LastSuccessAt = prev.LastSuccessAt
	}
	m.state[s.ID] = s
	return nil
}
func (m *memStore) State(_ context.Context, t, stage string) (*monitor.StageState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state[t+"|"+stage], nil
}

func (m *memStore) hasEdge(from, rel, to string) bool {
	for _, e := range m.edges {
		if e.From == from && e.Rel == rel && e.To == to {
			return true
		}
	}
	return false
}

const (
	tenant = "11111111-1111-1111-1111-111111111111"
	sub    = "/subscriptions/22222222-2222-2222-2222-222222222222"
	rg     = sub + "/resourceGroups/RG-App"
	net    = rg + "/providers/Microsoft.Network"
	acr    = rg + "/providers/Microsoft.ContainerRegistry/registries/acr1"
	aks    = rg + "/providers/Microsoft.ContainerService/managedClusters/aks1"
)

var digestA, digestB = "sha256:" + strings.Repeat("a", 64), "sha256:" + strings.Repeat("b", 64)
var digestIndex = "sha256:" + strings.Repeat("e", 64)

// containerFindings are shaped like Defender for Cloud's individual
// recommendations: the documented fields, plus two different ways an image
// might be described, since that part is not documented.
func containerFindings() []map[string]any {
	finding := func(scope, entity, kind, name, severity, software, version, fixed string, extra map[string]any, cves any) map[string]any {
		return map[string]any{
			"id": scope + "/providers/Microsoft.Security/securityEntityData/" + entity + "/providers/Microsoft.Security/assessments/" + entity + software,
			"properties": map[string]any{
				"displayName":            "Update " + software,
				"status":                 map[string]any{"code": "Unhealthy"},
				"metadata":               map[string]any{"recommendationCategory": "SoftwareUpdate", "severity": severity},
				"resourceDetails":        map[string]any{"ResourceType": kind, "Source": "Azure", "ResourceName": name},
				"resourceAdditionalData": extra,
				"additionalData": map[string]any{"SoftwareName": software, "SoftwareVendor": "vendor", "DetectedSoftwareVersions": []string{version},
					"FixedVersion": fixed, "CvesDetails": cves},
			},
		}
	}
	return []map[string]any{
		// CvesDetails as a JSON string, image named by repository details and digest, no tags.
		finding(acr, "img1", ".containerimage", "team/app", "Critical", "openssl", "3.0.1", "3.0.9",
			map[string]any{"RepositoryDetails": map[string]any{"Registry": "acr1", "RepositoryName": "team/app"}, "Digest": digestA}, // registry by name, not login server
			`[{"CveId":"CVE-2024-0001","Severity":"Critical","Cvss":{"3":{"Base":9.8}},"ExploitabilityDetails":{"IsInExploitKit":true}},{"CveId":"CVE-2024-0100","Severity":"Medium"}]`),
		// CvesDetails as an array, image named only by a full reference with a tag.
		finding(acr, "img2", ".containerimage", "acr1.azurecr.io/team/api:2.0@"+digestB, "High", "curl", "8.0", "",
			nil, []map[string]any{{"CveId": "CVE-2024-0200", "Severity": "High", "Cvss": []map[string]any{{"Key": "3", "Value": map[string]any{"Base": 7.5}}}}}),
		// A running container that knows its image only by digest.
		finding(aks, "ctr1", "K8s-container", "app", "Critical", "openssl", "3.0.1", "3.0.9",
			map[string]any{"Namespace": "prod", "ControllerName": "app-deploy", "ControllerType": "Deployment", "PodName": "app-1", "ContainerName": "app", "ImageDigest": digestA},
			`[{"CveId":"CVE-2024-0001","Severity":"Critical"}]`),
	}
}

func res(id, typ string, props string) map[string]any {
	var p map[string]any
	if props != "" {
		if err := json.Unmarshal([]byte(props), &p); err != nil {
			panic(err)
		}
	}
	name := id[strings.LastIndex(id, "/")+1:]
	return map[string]any{"id": id, "name": name, "type": typ, "location": "australiaeast", "resourceGroup": "rg-app",
		"subscriptionId": "22222222-2222-2222-2222-222222222222", "tenantId": tenant, "tags": map[string]any{"env": "prod"}, "properties": p}
}

// fakeAzure serves the token endpoint, Resource Graph and the Defender API.
type fakeAzure struct {
	mu        sync.Mutex
	withVM    bool
	throttled bool
	acrDenied bool
	srv       *httptest.Server
}

func (f *fakeAzure) resources() []map[string]any {
	vm := rg + "/providers/Microsoft.Compute/virtualMachines/VM1"
	nic := net + "/networkInterfaces/nic1"
	out := []map[string]any{
		res(net+"/virtualNetworks/vnet1", "Microsoft.Network/virtualNetworks", `{"subnets":[{"id":"`+net+`/virtualNetworks/vnet1/subnets/default","name":"default","properties":{"addressPrefix":"10.0.0.0/24"}}]}`),
		res(net+"/publicIPAddresses/pip1", "Microsoft.Network/publicIPAddresses", `{"ipAddress":"20.1.2.3"}`),
		res(rg+"/providers/Microsoft.Compute/disks/disk1", "Microsoft.Compute/disks", `{}`),
		res(net+"/networkInterfaces/nic1", "Microsoft.Network/networkInterfaces", `{"virtualMachine":{"id":"`+vm+`"},"ipConfigurations":[{"properties":{
			"privateIPAddress":"10.0.0.4","subnet":{"id":"`+net+`/virtualNetworks/vnet1/subnets/default"},"publicIPAddress":{"id":"`+net+`/publicIPAddresses/pip1"}}}]}`),
		res(net+"/loadBalancers/lb1", "Microsoft.Network/loadBalancers", `{"frontendIPConfigurations":[{"properties":{"privateIPAddress":"10.0.0.10","subnet":{"id":"`+net+`/virtualNetworks/vnet1/subnets/default"}}}],
			"backendAddressPools":[{"id":"`+net+`/loadBalancers/lb1/backendAddressPools/pool1","properties":{"backendIPConfigurations":[{"id":"`+nic+`/ipConfigurations/ipconfig1"}]}}]}`),
		res(net+"/applicationGateways/agw1", "Microsoft.Network/applicationGateways", `{"backendAddressPools":[{"id":"x/backendAddressPools/web","properties":{"backendAddresses":[{"fqdn":"App1.azurewebsites.net"},{"ipAddress":"10.0.0.4"}]}}]}`),
		res(rg+"/providers/Microsoft.Web/serverFarms/plan1", "Microsoft.Web/serverFarms", `{}`),
		res(acr, "Microsoft.ContainerRegistry/registries", `{"loginServer":"acr1.azurecr.io"}`),
		res(aks, "Microsoft.ContainerService/managedClusters", `{}`),
		res(rg+"/providers/Microsoft.Web/sites/app1", "Microsoft.Web/sites", `{"defaultHostName":"app1.azurewebsites.net","serverFarmId":"`+rg+`/providers/Microsoft.Web/serverfarms/plan1"}`),
	}
	if f.withVM {
		out = append(out, res(vm, "Microsoft.Compute/virtualMachines", `{"hardwareProfile":{"vmSize":"Standard_D2s_v5"},"osProfile":{"computerName":"vm1"},
			"networkProfile":{"networkInterfaces":[{"id":"`+nic+`"}]},"storageProfile":{"osDisk":{"osType":"Linux","managedDisk":{"id":"`+rg+`/providers/Microsoft.Compute/disks/disk1"}}}}`))
	}
	return out
}

func (f *fakeAzure) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	reply := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	if strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token") {
		reply(map[string]any{"access_token": "tok", "expires_in": 3600})
		return
	}
	// Azure Container Registry: token exchange, then the tag list.
	switch r.URL.Path {
	case "/oauth2/exchange":
		_ = r.ParseForm()
		if r.Form.Get("access_token") != "tok" || r.Form.Get("service") != "acr1.azurecr.io" {
			http.Error(w, "bad exchange", http.StatusUnauthorized)
			return
		}
		reply(map[string]any{"refresh_token": "refresh"})
		return
	case "/oauth2/token":
		_ = r.ParseForm()
		if f.acrDenied {
			http.Error(w, `{"errors":[{"code":"UNAUTHORIZED","message":"authentication required"}]}`, http.StatusUnauthorized)
			return
		}
		if r.Form.Get("refresh_token") != "refresh" || r.Form.Get("scope") != "repository:team/app:metadata_read,pull" {
			http.Error(w, "bad scope", http.StatusBadRequest)
			return
		}
		reply(map[string]any{"access_token": "acrtok"})
		return
	case "/acr/v1/team/app/_manifests":
		// team/app is multi-platform: its tags point at an index, and the
		// image Defender scanned (digestA) is one platform under it.
		if r.Header.Get("Authorization") != "Bearer acrtok" {
			http.Error(w, "no registry token", http.StatusUnauthorized)
			return
		}
		reply(map[string]any{"manifests": []map[string]any{
			{"digest": digestIndex, "tags": []string{"latest", "1.4.2"}, "mediaType": "application/vnd.oci.image.index.v1+json"},
			{"digest": digestA, "mediaType": "application/vnd.oci.image.manifest.v1+json"},
			{"digest": "sha256:" + strings.Repeat("c", 64), "tags": []string{"old"}, "mediaType": "application/vnd.oci.image.manifest.v1+json"},
		}})
		return
	case "/v2/team/app/manifests/" + digestIndex:
		if !strings.Contains(r.Header.Get("Accept"), "image.index") {
			http.Error(w, "index not accepted", http.StatusNotAcceptable)
			return
		}
		reply(map[string]any{"manifests": []map[string]any{{"digest": digestA}, {"digest": "sha256:" + strings.Repeat("d", 64)}}})
		return
	}
	if r.Header.Get("Authorization") != "Bearer tok" {
		http.Error(w, "no token", http.StatusUnauthorized)
		return
	}
	switch r.URL.Path {
	case "/providers/Microsoft.ResourceGraph/resources":
		var body struct {
			Query   string         `json:"query"`
			Options map[string]any `json:"options"`
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		if strings.HasPrefix(body.Query, "resourcecontainers") {
			reply(map[string]any{"data": []map[string]any{
				{"id": sub, "name": "Production", "type": "microsoft.resources/subscriptions", "subscriptionId": sub[15:], "tenantId": tenant, "properties": map[string]any{"state": "Enabled"}},
				{"id": rg, "name": "RG-App", "type": "microsoft.resources/subscriptions/resourcegroups", "subscriptionId": sub[15:], "tenantId": tenant, "location": "australiaeast"},
			}})
			return
		}
		if strings.HasPrefix(body.Query, "securityresources") {
			reply(map[string]any{"data": containerFindings()})
			return
		}
		all := f.resources()
		if body.Options["$skipToken"] == nil { // two pages
			reply(map[string]any{"data": all[:3], "$skipToken": "next"})
		} else {
			reply(map[string]any{"data": all[3:]})
		}
	case "/api/machines":
		reply(map[string]any{"value": []map[string]any{
			{"id": "m1", "computerDnsName": "vm1.corp.example", "osPlatform": "Ubuntu", "healthStatus": "Active", "lastIpAddress": "10.0.0.4",
				"lastSeen": "2026-11-17T00:00:00Z", "vmMetadata": map[string]any{"resourceId": strings.ToUpper(rg + "/providers/Microsoft.Compute/virtualMachines/VM1")}},
			{"id": "m2", "computerDnsName": "onprem01", "osPlatform": "WindowsServer2022", "lastSeen": "2026-11-17T00:00:00Z"},
			// An older record of the same VM (re-onboarded), and an older record of onprem01 with nothing but its name in common.
			{"id": "m3", "computerDnsName": "vm1", "osPlatform": "Ubuntu", "healthStatus": "Inactive", "lastSeen": "2026-08-01T00:00:00Z",
				"vmMetadata": map[string]any{"resourceId": rg + "/providers/Microsoft.Compute/virtualMachines/vm1"}},
			{"id": "m4", "computerDnsName": "ONPREM01", "osPlatform": "WindowsServer2019", "lastSeen": "2026-06-01T00:00:00Z"},
		}})
	case "/api/machines/SoftwareVulnerabilitiesByMachine":
		if !f.throttled {
			f.throttled = true
			w.Header().Set("Retry-After", "0")
			http.Error(w, "slow down", http.StatusTooManyRequests)
			return
		}
		row := func(dev, cve, sev, sw, ver string) map[string]any {
			return map[string]any{"deviceId": dev, "deviceName": dev, "cveId": cve, "vulnerabilitySeverityLevel": sev, "softwareVendor": "openssl",
				"softwareName": sw, "softwareVersion": ver, "cvssScore": 9.8, "firstSeenTimestamp": "2026-10-01 10:13:34.8476880", "lastSeenTimestamp": "2026-11-01T00:00:00Z"}
		}
		if r.URL.Query().Get("$skiptoken") == "" {
			reply(map[string]any{"value": []map[string]any{row("m1", "CVE-2024-0001", "Critical", "openssl", "1.1.1"), row("m1", "CVE-2024-0001", "Critical", "openssl", "3.0.0")},
				"@odata.nextLink": f.srv.URL + r.URL.Path + "?pageSize=2&$skiptoken=p2"})
		} else {
			reply(map[string]any{"value": []map[string]any{row("m1", "CVE-2024-0002", "High", "curl", "8.0"), row("m2", "cve-2024-0001", "Critical", "openssl", "1.1.1"), row("m2", "", "", "notepad", "1"),
				row("m3", "CVE-2024-0999", "High", "bash", "4.0")}}) // from the superseded record: must not be counted
		}
	case "/api/machines/SoftwareInventoryByMachine":
		row := func(dev, sw, ver string) map[string]any {
			return map[string]any{"deviceId": dev, "softwareVendor": "openssl", "softwareName": sw, "softwareVersion": ver, "numberOfWeaknesses": 3}
		}
		reply(map[string]any{"value": []map[string]any{row("m1", "openssl", "1.1.1"), row("m1", "openssl", "3.0.0"), row("m2", "openssl", "1.1.1")}})
	case "/api/Vulnerabilities":
		reply(map[string]any{"value": []map[string]any{
			{"id": "CVE-2024-0001", "name": "CVE-2024-0001", "description": "Buffer overflow", "severity": "Critical", "cvssV3": 9.8, "publicExploit": true, "publishedOn": "2024-01-02T00:00:00Z"},
			{"id": "CVE-1999-0001", "description": "not present here"},
		}})
	default:
		http.NotFound(w, r)
	}
}

func setup(t *testing.T) (*Collector, *memStore, *fakeAzure) {
	t.Helper()
	f := &fakeAzure{withVM: true}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	cfg := &config.Config{
		Tenants:   []config.Tenant{{Name: "Contoso", ID: tenant, ClientID: "c", ClientSecret: "s"}},
		Mongo:     config.Mongo{URI: "mongodb://unused"},
		Endpoints: config.Endpoints{Authority: f.srv.URL, ARM: f.srv.URL, Defender: f.srv.URL},
	}
	// dev1 (10.0.0.4) lands in "Internal" by address, onprem01 in the hidden "On-prem" by name.
	cfg.DeviceGroups = []graph.GroupDef{
		{Name: "On-prem", Hidden: true, Names: []string{"onprem*"}},
		{Name: "Internal", CIDRs: []string{"10.0.0.0/24"}},
	}
	cfg.Defaults()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	st := newMem()
	c := New(cfg, st, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	c.NewClient = func(tn config.Tenant) *azure.Client {
		cli := azure.NewClient(tn, cfg.Endpoints, nil)
		cli.Backoff = time.Millisecond
		cli.ACRBase = func(string) string { return f.srv.URL }
		return cli
	}
	return c, st, f
}

func TestRunBuildsGraph(t *testing.T) {
	c, st, _ := setup(t)
	vm := graph.ARMID(rg + "/providers/Microsoft.Compute/virtualMachines/VM1")
	rgID, subID, netID := graph.ARMID(rg), graph.ARMID(sub), graph.ARMID(net)
	st.costs = []CostRow{
		{TenantID: tenant, ResourceID: vm, Currency: "AUD", Last30: 10, Last30USD: 6.5, MTD: 4},
		{TenantID: tenant, ResourceID: rgID + "/providers/microsoft.compute/disks/disk1", Currency: "AUD", Last30: 5, Last30USD: 3.25, MTD: 2},
	}
	run := c.Run(context.Background(), "test")
	if run.Status != monitor.StatusSuccess {
		b, _ := json.MarshalIndent(run, "", " ")
		t.Fatalf("status %s\n%s", run.Status, b)
	}

	nic, ip := netID+"/networkinterfaces/nic1", "ip:"+strings.TrimPrefix(netID, "/")+"/virtualnetworks/vnet1/10.0.0.4"
	dev1, dev2, cve := "device:res:"+vm, "device:mde:"+tenant+":m2", "cve:CVE-2024-0001"
	for _, e := range [][3]string{
		{graph.TenantID(tenant), graph.RelContains, subID},
		{subID, graph.RelContains, rgID},
		{rgID, graph.RelContains, vm},
		{netID + "/virtualnetworks/vnet1", graph.RelContains, netID + "/virtualnetworks/vnet1/subnets/default"},
		{netID + "/virtualnetworks/vnet1/subnets/default", graph.RelContains, ip},
		{vm, graph.RelAttached, nic},
		{vm, graph.RelAttached, rgID + "/providers/microsoft.compute/disks/disk1"},
		{nic, graph.RelInSubnet, netID + "/virtualnetworks/vnet1/subnets/default"},
		{nic, graph.RelHasIP, ip},
		{nic, graph.RelAttached, netID + "/publicipaddresses/pip1"},
		{netID + "/publicipaddresses/pip1", graph.RelHasIP, "ip:public/20.1.2.3"},
		{vm, graph.RelHasIP, ip},
		{vm, graph.RelHasIP, "ip:public/20.1.2.3"},
		{netID + "/loadbalancers/lb1", graph.RelBackend, nic},
		{netID + "/loadbalancers/lb1", graph.RelBackend, vm},
		{netID + "/applicationgateways/agw1", graph.RelBackend, rgID + "/providers/microsoft.web/sites/app1"},
		{netID + "/applicationgateways/agw1", graph.RelBackend, ip},
		{netID + "/applicationgateways/agw1", graph.RelBackend, vm},
		{rgID + "/providers/microsoft.web/sites/app1", graph.RelReferences, rgID + "/providers/microsoft.web/serverfarms/plan1"},
		{dev1, graph.RelRunsOn, vm},
		{graph.TenantID(tenant), graph.RelContains, dev2},
		{dev1, graph.RelAffectedBy, cve},
		{dev2, graph.RelAffectedBy, cve},
		{dev1, graph.RelHasSoftware, "software:openssl/openssl"},
	} {
		if !st.hasEdge(e[0], e[1], e[2]) {
			t.Errorf("missing edge %s -%s-> %s", e[0], e[1], e[2])
		}
	}
	if st.hasEdge(vm, graph.RelReferences, nic) || st.hasEdge(nic, graph.RelReferences, vm) {
		t.Error("references edge duplicates a typed edge")
	}
	if n := st.nodes[vm]; n.Attrs["vmSize"] != "Standard_D2s_v5" || !strings.Contains(n.Q, "10.0.0.4") || len(n.Tags) != 1 {
		t.Errorf("vm node: %+v", n)
	}
	if n := st.nodes[dev1]; n.ResourceGroup != "rg-app" || n.SubscriptionID == "" {
		t.Errorf("device not placed in its resource's scope: %+v", n)
	}

	check := func(id, field, key string, want any) {
		t.Helper()
		if got := st.fields[id][field][key]; fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("%s %s.%s = %v, want %v", id, field, key, got, want)
		}
	}
	check(dev1, "vuln", "critical", 1)
	check(dev1, "vuln", "high", 1)
	check(vm, "vulnRollup", "total", 2)
	check(rgID, "vulnRollup", "critical", 1)
	check(graph.TenantID(tenant), "vulnRollup", "critical", 2)
	check(graph.TenantID(tenant), "vulnRollup", "devices", 2)
	check(dev1, "software", "products", 1)
	check(vm, "cost", "last30d", 10)
	check(rgID, "cost", "last30d", 15)
	check(subID, "cost", "mtd", 6)
	check(graph.TenantID(tenant), "cost", "last30dUsd", 9.75)

	// Exposure and software summaries are kept per device group.
	if e := st.exposure[tenant+"|Internal|CVE-2024-0001"]; e.Devices != 1 || e.Group != "Internal" || e.Severity != "critical" || e.FirstSeen.IsZero() || len(e.Software) != 1 {
		t.Errorf("exposure: %+v", e)
	}
	if e := st.exposure[tenant+"|On-prem|CVE-2024-0001"]; e.Devices != 1 || e.Group != "On-prem" {
		t.Errorf("exposure: %+v", e)
	}
	if e := st.exposure[tenant+"|Internal|CVE-2024-0002"]; e.Devices != 1 || e.SeverityRank != 3 {
		t.Errorf("exposure: %+v", e)
	}
	if _, ok := st.exposure[tenant+"|On-prem|CVE-2024-0002"]; ok {
		t.Error("CVE-2024-0002 is not on any On-prem device")
	}
	if s := st.software[tenant+"|Internal|openssl/openssl"]; s.Devices != 1 || len(s.Versions) != 2 || s.Weaknesses != 3 {
		t.Errorf("software summary: %+v", s)
	}
	if s := st.software[tenant+"|On-prem|openssl/openssl"]; s.Devices != 1 || len(s.Versions) != 1 || s.Versions[0].Version != "1.1.1" {
		t.Errorf("software summary: %+v", s)
	}
	if st.nodes[dev1].Group != "Internal" || st.nodes[dev2].Group != "On-prem" {
		t.Errorf("device groups: %q, %q", st.nodes[dev1].Group, st.nodes[dev2].Group)
	}
	for _, e := range st.edges {
		if want := st.nodes[e.From].Group; (e.Rel == graph.RelAffectedBy || e.Rel == graph.RelHasSoftware || e.Rel == graph.RelRunsOn) && e.FromKind == graph.KindDevice && e.Group != want {
			t.Errorf("edge %s -%s-> %s has group %q, want %q", e.From, e.Rel, e.To, e.Group, want)
		}
		if e.Rel == graph.RelContains && e.To == dev2 && e.Group != "On-prem" {
			t.Errorf("tenant -> device edge has group %q", e.Group)
		}
	}
	// Roll-ups carry a breakdown per group next to the total.
	byGroup := map[string]any{}
	for _, g := range st.fields[graph.TenantID(tenant)]["vulnRollup"]["groups"].([]map[string]any) {
		byGroup[g["group"].(string)] = fmt.Sprint(g["critical"], g["high"], g["devices"])
	}
	if fmt.Sprint(byGroup) != "map[Internal:1 1 1 On-prem:1 0 1]" {
		t.Errorf("tenant roll-up by group: %v", byGroup)
	}
	// The dashboard's list of groups: in order, default last, with what is hidden.
	var list []string
	for _, g := range st.groups {
		list = append(list, fmt.Sprintf("%s hidden=%v default=%v devices=%d", g.Name, g.Hidden, g.Default, g.Devices))
	}
	if strings.Join(list, "; ") != "On-prem hidden=true default=false devices=1; Internal hidden=false default=false devices=1; Other hidden=false default=true devices=0" {
		t.Errorf("device groups: %v", list)
	}
	if d := st.details[cve]; d["description"] != "Buffer overflow" || d["publicExploit"] != true {
		t.Errorf("cve details: %+v", d)
	}
	if len(st.details) != 1 {
		t.Errorf("details stored for CVEs nobody has: %v", st.details)
	}
	if s := st.state[tenant+"|vulnerabilities"]; s == nil || s.LastSuccessAt == nil || s.Counts["findings"] != 4 || s.Counts["duplicateRecordRows"] != 1 {
		t.Errorf("stage state: %+v", s)
	}

	// Four machine records, two machines: one pair merged by Azure resource ID, one by hostname.
	devices := 0
	for _, n := range st.nodes {
		if n.Kind == graph.KindDevice {
			devices++
		}
	}
	if s := st.state[GlobalTenant+"|deviceMerge"]; devices != 2 || s == nil || s.Counts["records"] != 4 || s.Counts["devices"] != 2 ||
		s.Counts["duplicateRecords"] != 2 || s.Counts["mergedByHostname"] != 1 {
		t.Errorf("%d device nodes; merge state: %+v", devices, s)
	}
	if n := st.nodes[dev1]; n.Attrs["machineId"] != "m1" || n.Name != "vm1.corp.example" || len(n.Attrs["records"].([]map[string]any)) != 2 {
		t.Errorf("merged device should take its details from the newest record: %+v", n)
	}
	if n := st.nodes[dev2]; n.Attrs["mergedByHostname"] != true || n.Attrs["osPlatform"] != "WindowsServer2022" {
		t.Errorf("hostname-merged device: %+v", n)
	}
	if _, ok := st.nodes["cve:CVE-2024-0999"]; ok {
		t.Error("a CVE reported only for a superseded machine record was recorded")
	}
	if run.Totals["devices"] != 2 || run.Totals["records"] != 4 {
		t.Errorf("run totals: %v", run.Totals)
	}
}

func TestSecondRunSweepsRemovedResources(t *testing.T) {
	c, st, f := setup(t)
	vm := graph.ARMID(rg + "/providers/Microsoft.Compute/virtualMachines/VM1")
	c.Run(context.Background(), "test")
	if _, ok := st.nodes[vm]; !ok {
		t.Fatal("vm missing after first run")
	}
	f.mu.Lock()
	f.withVM = false
	f.mu.Unlock()
	run := c.Run(context.Background(), "test")
	if _, ok := st.nodes[vm]; ok {
		t.Error("deleted VM still in graph")
	}
	for _, e := range st.edges {
		if e.Source == graph.SourceARM && (e.From == vm || e.To == vm) {
			t.Errorf("stale edge %s -%s-> %s", e.From, e.Rel, e.To)
		}
	}
	if _, ok := st.fields[graph.ARMID(rg)]["vulnRollup"]; ok {
		t.Error("resource group kept CVE counts from a VM that is gone")
	}
	if st.fields[graph.TenantID(tenant)]["vulnRollup"]["devices"] != int64(2) {
		t.Errorf("tenant roll-up: %v", st.fields[graph.TenantID(tenant)]["vulnRollup"])
	}
	// The catalogue was refreshed in the first run, so it is skipped now.
	for _, g := range run.Global {
		if g.Stage == "cveDetails" && g.Status != monitor.StatusSkipped {
			t.Errorf("cveDetails status %s", g.Status)
		}
	}
}

func TestFailedStageKeepsDataAndIsReported(t *testing.T) {
	c, st, f := setup(t)
	c.Run(context.Background(), "test")
	before := len(st.edges)
	// Break Defender only.
	f.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.Error(w, `{"error":{"code":"Forbidden","message":"Missing application roles"}}`, http.StatusForbidden)
			return
		}
		f.handle(w, r)
	})
	run := c.Run(context.Background(), "test")
	if run.Status != monitor.StatusPartial || run.Tenants[0].Status != monitor.StatusPartial {
		t.Fatalf("status %s / %s", run.Status, run.Tenants[0].Status)
	}
	if len(st.edges) != before {
		t.Errorf("edges %d -> %d: a failed stage must not remove data", before, len(st.edges))
	}
	s := st.state[tenant+"|devices"]
	if s.Status != monitor.StatusFailed || !strings.Contains(s.Error, "Missing application roles") || s.LastSuccessAt == nil {
		t.Errorf("state: %+v", s)
	}
}

func TestContainerImagesAndTags(t *testing.T) {
	c, st, _ := setup(t)
	run := c.Run(context.Background(), "test")
	if run.Status != monitor.StatusSuccess {
		b, _ := json.MarshalIndent(run, "", " ")
		t.Fatalf("status %s\n%s", run.Status, b)
	}
	acrID, aksID := graph.ARMID(acr), graph.ARMID(aks)
	imgA, imgB := "image:acr1.azurecr.io/team/app@"+digestA, "image:acr1.azurecr.io/team/api@"+digestB
	ctr := "container:" + strings.TrimPrefix(aksID, "/") + "/ctr1"
	for _, e := range [][3]string{
		{acrID, graph.RelContains, imgA},
		{acrID, graph.RelContains, imgB},
		{imgA, graph.RelAffectedBy, "cve:CVE-2024-0001"},
		{imgA, graph.RelAffectedBy, "cve:CVE-2024-0100"},
		{imgB, graph.RelAffectedBy, "cve:CVE-2024-0200"},
		{aksID, graph.RelContains, ctr},
		{ctr, graph.RelRunsImage, imgA},
		{ctr, graph.RelAffectedBy, "cve:CVE-2024-0001"},
	} {
		if !st.hasEdge(e[0], e[1], e[2]) {
			t.Errorf("missing edge %s -%s-> %s", e[0], e[1], e[2])
		}
	}
	a := st.nodes[imgA]
	if tags := fmt.Sprint(a.Attrs["tags"]); tags != "[1.4.2 latest]" || a.Attrs["tagsFrom"] != "registry" {
		t.Errorf("image A tags %v from %v, want the registry's [1.4.2 latest]", a.Attrs["tags"], a.Attrs["tagsFrom"])
	}
	if !strings.Contains(a.Q, "team/app:latest") || a.ResourceGroup != "rg-app" || fmt.Sprint(a.Vuln["critical"], a.Vuln["medium"], a.Vuln["total"]) != "1 1 2" {
		t.Errorf("image A: q=%q rg=%q vuln=%v", a.Q, a.ResourceGroup, a.Vuln)
	}
	if b := st.nodes[imgB]; fmt.Sprint(b.Attrs["tags"]) != "[2.0]" || b.Attrs["tagsFrom"] != "defender" || b.Vuln["high"] != 1 {
		t.Errorf("image B: %+v", b)
	}
	if n := st.nodes[ctr]; n.Name != "app" || n.Attrs["namespace"] != "prod" || n.Attrs["workload"] != "app-deploy" || n.Vuln["critical"] != 1 {
		t.Errorf("container: %+v", n)
	}
	for id := range st.nodes {
		if strings.HasPrefix(id, "image:@") {
			t.Errorf("container was linked to a nameless copy of its image: %s", id)
		}
	}
	var fix any
	for _, e := range st.edges {
		if e.From == imgA && e.To == "cve:CVE-2024-0001" {
			fix = e.Attrs["fixedVersion"]
		}
	}
	if fix != "3.0.9" {
		t.Errorf("fixed version on image edge = %v", fix)
	}
	// Each CVE is tied to every tag of the image it is in.
	for _, e := range st.edges {
		if e.From == imgA && e.Rel == graph.RelAffectedBy && (fmt.Sprint(e.Attrs["tags"]) != "[1.4.2 latest]" || e.Attrs["repository"] != "team/app") {
			t.Errorf("image edge to %s carries tags %v", e.To, e.Attrs["tags"])
		}
	}
	if e := st.exposure["containers:"+tenant+"|CVE-2024-0001"]; e.Tags != 2 {
		t.Errorf("CVE-2024-0001 is in two tags of one image, exposure says %d", e.Tags)
	}
	// The same CVE is on devices and in containers; each source keeps its own exposure.
	if e := st.exposure["containers:"+tenant+"|CVE-2024-0001"]; e.Images != 1 || e.Containers != 1 || e.Severity != "critical" || e.Cvss != 9.8 || !e.FixAvailable {
		t.Errorf("container exposure: %+v", e)
	}
	if e := st.exposure[tenant+"|Internal|CVE-2024-0001"]; e.Devices != 1 || e.Source != "devices" {
		t.Errorf("device exposure lost: %+v", e)
	}
	if v := st.fields[acrID]["containerVuln"]; fmt.Sprint(v["critical"], v["high"], v["medium"], v["images"]) != "1 1 1 2" {
		t.Errorf("registry roll-up: %v", v)
	}
	if v := st.fields[graph.TenantID(tenant)]["containerVuln"]; fmt.Sprint(v["critical"], v["images"], v["containers"]) != "2 2 1" {
		t.Errorf("tenant roll-up: %v", v)
	}
	if s := st.state[tenant+"|containers"]; s == nil || s.Counts["images"] != 2 || s.Counts["taggedImages"] != 2 || s.Counts["containers"] != 1 || s.Counts["tagLookups"] != 1 {
		t.Errorf("stage state: %+v", s)
	}
}

// recorder captures run records and log lines the way the monitor would see them.
type recorder struct {
	mu    sync.Mutex
	steps map[string]bool
	logs  []monitor.LogEntry
}

func (r *recorder) SaveRun(_ context.Context, run *monitor.Run) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, t := range run.Tenants {
		for _, s := range t.Stages {
			if s.Status == monitor.StatusRunning && s.Step != "" {
				r.steps[s.Stage] = true
			}
		}
	}
	return nil
}
func (r *recorder) SaveInstance(context.Context, *monitor.Instance) error { return nil }
func (r *recorder) InsertLogs(_ context.Context, e []monitor.LogEntry) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.logs = append(r.logs, e...)
	return nil
}

func TestProgressIsVisibleWhileStagesRun(t *testing.T) {
	c, _, _ := setup(t)
	rec := &recorder{steps: map[string]bool{}}
	h, flush := monitor.NewHandler(slog.NewTextHandler(io.Discard, nil), rec, slog.LevelInfo, "test")
	c.Sink, c.Log = rec, slog.New(h)
	c.Cfg.ProgressEvery = config.Duration(time.Millisecond)
	c.Run(context.Background(), "test")
	flush()

	seen := map[string]bool{}
	for _, e := range rec.logs {
		seen[e.Stage+": "+e.Msg] = true
		if e.Stage != "" && (e.RunID == "" || (e.Tenant == "" && e.Stage != "deviceMerge" && e.Stage != "vulnRollup" && e.Stage != "cveDetails" && e.Stage != "costs")) {
			t.Errorf("stage log line without run or tenant: %+v", e)
		}
	}
	for _, want := range []string{
		"resources: stage started",
		"resources: listing resources from Azure Resource Graph",
		"vulnerabilities: requesting the software vulnerabilities export from Defender",
		"vulnerabilities: vulnerabilities: page received, writing it",
		"vulnerabilities: stage finished",
		"deviceMerge: merging machine records that are the same machine",
		"containers: reading image tags from container registries",
	} {
		if !seen[want] {
			t.Errorf("no log line %q", want)
		}
	}
	// The vulnerabilities export is throttled once by the fake API, so the
	// stage is alive for at least one reminder interval.
	if !seen["vulnerabilities: stage still running"] {
		t.Error("no reminder was logged for a stage that was waiting")
	}
	if !rec.steps["resources"] && !rec.steps["vulnerabilities"] {
		t.Errorf("the run record never showed a running stage with its current step: %v", rec.steps)
	}
}

func TestUntaggedImagesSayWhy(t *testing.T) {
	c, st, f := setup(t)
	f.acrDenied = true
	run := c.Run(context.Background(), "test")
	if run.Status != monitor.StatusSuccess {
		t.Fatalf("a registry refusing tags must not fail the run: %s", run.Status)
	}
	a := st.nodes["image:acr1.azurecr.io/team/app@"+digestA]
	if len(a.Attrs["tags"].([]string)) != 0 || a.Attrs["untaggedReason"] != graph.UntaggedDenied {
		t.Errorf("image A: tags %v, reason %v", a.Attrs["tags"], a.Attrs["untaggedReason"])
	}
	// The other image got its tag from the finding and is unaffected.
	if b := st.nodes["image:acr1.azurecr.io/team/api@"+digestB]; fmt.Sprint(b.Attrs["tags"]) != "[2.0]" || b.Attrs["untaggedReason"] != nil {
		t.Errorf("image B: %+v", b.Attrs)
	}
	if s := st.state[tenant+"|containers"]; s.Counts["untaggedImages"] != 1 || s.Counts["tagLookupsFailed"] != 1 || s.Counts["taggedImages"] != 1 {
		t.Errorf("stage counts: %v", s.Counts)
	}
}
