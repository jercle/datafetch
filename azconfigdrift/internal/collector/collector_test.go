package collector

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jercle/datafetch/azconfigdrift/internal/catalog"
	"github.com/jercle/datafetch/azconfigdrift/internal/cloud"
	"github.com/jercle/datafetch/azconfigdrift/internal/config"
	"github.com/jercle/datafetch/azconfigdrift/internal/model"
	"github.com/jercle/datafetch/azconfigdrift/internal/monitor"
	"github.com/jercle/datafetch/azconfigdrift/internal/store"
)

const (
	tenantID = "00000000-0000-0000-0000-00000000000a"
	sub1     = "11111111-1111-1111-1111-111111111111"
	sub2     = "22222222-2222-2222-2222-222222222222"
)

type obj = map[string]any

// api is a stand-in for Entra ID, Resource Manager, Resource Graph, Graph
// and Exchange Online on one server.
type api struct {
	t  *testing.T
	mu sync.Mutex
	// graphRows: Resource Graph rows by table.
	graphRows map[string][]obj
	// lists and objects: GET answers by path (without the query).
	lists   map[string][]obj
	objects map[string]obj
	// status: an HTTP status to answer a path with instead.
	status map[string]int
	// cmdlets: Exchange Online answers by cmdlet.
	cmdlets map[string][]obj
	// pageSize splits lists and Resource Graph results into pages.
	pageSize int
	// tooLarge makes Resource Graph refuse pages of more rows than this.
	tooLarge int
	// raw: a GET answer by path, sent as it is (for shapes that are not
	// an object or a {"value": []} list).
	raw map[string]string
	// userOnly: paths that refuse the application's own token.
	userOnly map[string]bool
	// logins: the form of every token request.
	logins   []map[string]string
	requests []string
	bodies   []obj
	srv      *httptest.Server
}

func newAPI(t *testing.T) *api {
	a := &api{t: t, graphRows: map[string][]obj{}, lists: map[string][]obj{}, objects: map[string]obj{}, status: map[string]int{}, cmdlets: map[string][]obj{}, raw: map[string]string{}, userOnly: map[string]bool{}, pageSize: 1000}
	a.lists["/subscriptions"] = []obj{
		{"subscriptionId": sub1, "displayName": "Production", "state": "Enabled"},
		{"subscriptionId": sub2, "displayName": "Sandbox", "state": "Enabled"},
	}
	a.srv = httptest.NewServer(http.HandlerFunc(a.serve))
	t.Cleanup(a.srv.Close)
	return a
}

func (a *api) set(fn func()) {
	a.mu.Lock()
	defer a.mu.Unlock()
	fn()
}

func (a *api) fail(w http.ResponseWriter, status int, code string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(obj{"error": obj{"code": code, "message": "refused by the test"}})
}

func (a *api) serve(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	path := r.URL.Path
	a.requests = append(a.requests, r.Method+" "+r.URL.RequestURI())
	w.Header().Set("Content-Type", "application/json")
	if strings.HasSuffix(path, "/oauth2/v2.0/token") {
		_ = r.ParseForm()
		if st := a.status["token:"+r.Form.Get("scope")]; st != 0 {
			w.WriteHeader(st)
			_ = json.NewEncoder(w).Encode(obj{"error": "unauthorized_client", "error_description": "no consent\nTrace ID: x"})
			return
		}
		login := map[string]string{}
		for k := range r.Form {
			login[k] = r.Form.Get(k)
		}
		a.logins = append(a.logins, login)
		tok := "tok"
		if r.Form.Get("grant_type") == "password" {
			if r.Form.Get("password") != "pw" {
				w.WriteHeader(400)
				_ = json.NewEncoder(w).Encode(obj{"error": "invalid_grant", "error_description": "AADSTS50126: wrong user name or password"})
				return
			}
			tok = "usertok"
		}
		_ = json.NewEncoder(w).Encode(obj{"access_token": tok, "expires_in": 3600})
		return
	}
	switch auth := r.Header.Get("Authorization"); {
	case auth != "Bearer tok" && auth != "Bearer usertok":
		a.fail(w, 401, "NoToken")
		return
	case a.userOnly[path] && auth != "Bearer usertok":
		a.fail(w, 403, "ApplicationPermissionsNotSupported")
		return
	}
	if st := a.status[path]; st != 0 {
		a.fail(w, st, "Refused")
		return
	}
	var body obj
	if r.Method == http.MethodPost {
		_ = json.NewDecoder(r.Body).Decode(&body)
		a.bodies = append(a.bodies, body)
	}
	switch {
	case path == "/providers/Microsoft.ResourceGraph/resources":
		query := body["query"].(string)
		table, _, _ := strings.Cut(query, " ")
		opts := body["options"].(obj)
		top := int(opts["$top"].(float64))
		if a.tooLarge > 0 && top > a.tooLarge {
			w.WriteHeader(400)
			_ = json.NewEncoder(w).Encode(obj{"error": obj{"code": "BadRequest", "message": "bad", "details": []obj{{"code": "ResponsePayloadTooLarge", "message": "too large"}}}})
			return
		}
		var rows []obj
		for _, row := range a.graphRows[table] {
			typ := strings.ToLower(row["type"].(string))
			keep := true
			if i := strings.Index(query, "where not("); i >= 0 {
				keep = !matchesTypes(query[i:], typ)
			} else if strings.Contains(query, "type startswith") {
				keep = matchesTypes(query, typ)
			}
			if strings.Contains(query, "policyType =~ 'Custom'") {
				keep = keep && row["properties"].(obj)["policyType"] == "Custom"
			}
			if subs, ok := body["subscriptions"].([]any); ok && keep {
				keep = false
				for _, s := range subs {
					keep = keep || s == row["subscriptionId"]
				}
			}
			if keep {
				rows = append(rows, row)
			}
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i]["id"].(string) < rows[j]["id"].(string) })
		from := 0
		if s, ok := opts["$skipToken"].(string); ok {
			from = atoi(s)
		}
		size := min(top, a.pageSize)
		to := min(len(rows), from+size)
		out := obj{"data": rows[from:to], "count": to - from}
		if to < len(rows) {
			out["$skipToken"] = itoa(to)
		}
		_ = json.NewEncoder(w).Encode(out)
	case strings.HasSuffix(path, "/InvokeCommand"):
		if !strings.HasPrefix(r.Header.Get("X-AnchorMailbox"), "UPN:SystemMailbox{") || !strings.HasSuffix(r.Header.Get("X-AnchorMailbox"), "@contoso.onmicrosoft.com") {
			a.fail(w, 400, "NoAnchor")
			return
		}
		name := body["CmdletInput"].(obj)["CmdletName"].(string)
		_ = json.NewEncoder(w).Encode(obj{"value": a.cmdlets[name]})
	default:
		if body, ok := a.raw[path]; ok {
			_, _ = w.Write([]byte(body))
			return
		}
		if o, ok := a.objects[path]; ok {
			_ = json.NewEncoder(w).Encode(o)
			return
		}
		list, ok := a.lists[path]
		if !ok {
			a.fail(w, 404, "NotFound")
			return
		}
		from := atoi(r.URL.Query().Get("page"))
		to := min(len(list), from+a.pageSize)
		out := obj{"value": list[from:to], "@odata.context": "ctx"}
		if to < len(list) {
			next := a.srv.URL + path + "?page=" + itoa(to)
			out["nextLink"], out["@odata.nextLink"] = next, next
		}
		_ = json.NewEncoder(w).Encode(out)
	}
}

func matchesTypes(query, typ string) bool {
	for _, part := range strings.Split(query, "type startswith '")[1:] {
		prefix, _, _ := strings.Cut(part, "'")
		if strings.HasPrefix(typ, prefix) {
			return true
		}
	}
	return false
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for ; n > 0; n /= 10 {
		s = string(rune('0'+n%10)) + s
	}
	return s
}

type harness struct {
	api *api
	st  *store.Memory
	c   *Collector
	log *strings.Builder
}

func testModules() []catalog.Module {
	return []catalog.Module{
		{ID: "azure-network", Platform: model.PlatformAzure, Name: "Networking", DefaultEnabled: true, Sources: []catalog.Source{
			{ID: "resources", Name: "Resources", Kind: catalog.KindARG, Table: "resources", Types: []string{"microsoft.network/"}, Permission: "Reader"},
		}},
		{ID: "azure-governance", Platform: model.PlatformAzure, Name: "Governance", DefaultEnabled: true, Sources: []catalog.Source{
			{ID: "policy-definitions", Name: "Custom policies", Kind: catalog.KindARG, Table: "policyresources", Types: []string{"microsoft.authorization/policydefinitions"}, Where: "properties.policyType =~ 'Custom'", Permission: "Reader"},
			{ID: "locks", Name: "Locks", Kind: catalog.KindARM, Path: "/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/locks?api-version=2020-05-01", Permission: "Reader"},
		}},
		{ID: "azure-other", Platform: model.PlatformAzure, Name: "Other", DefaultEnabled: true, Sources: []catalog.Source{
			{ID: "resources", Name: "Resources", Kind: catalog.KindARG, Table: "resources", Other: true, Permission: "Reader"},
		}},
		{ID: "m365-identity", Platform: model.PlatformM365, Name: "Identity", DefaultEnabled: true, Sources: []catalog.Source{
			{ID: "authorization-policy", Name: "Authorisation policy", Kind: catalog.KindGraph, Path: "/policies/authorizationPolicy", Single: true, Type: "authorization-policy", Permission: "Policy.Read.All"},
			{ID: "branding", Name: "Branding", Kind: catalog.KindGraph, Path: "/organization/{tenantId}/branding", Single: true, Type: "branding", Permission: "Organization.Read.All"},
			{ID: "ca-policies", Name: "Policies", Kind: catalog.KindGraph, Path: "/identity/conditionalAccess/policies", Type: "ca-policies", Permission: "Policy.Read.All"},
			{ID: "settings-catalog", Name: "Settings catalogue", Kind: catalog.KindGraph, Path: "/deviceManagement/configurationPolicies", Beta: true, Type: "settings-catalog",
				Children: []catalog.Child{{Field: "settings", Suffix: "settings"}}, Ignore: []string{"settingCount"}, Permission: "DeviceManagementConfiguration.Read.All"},
		}},
		{ID: "m365-exchange", Platform: model.PlatformM365, Name: "Exchange", DefaultEnabled: false, Sources: []catalog.Source{
			{ID: "transport-rules", Name: "Mail flow rules", Kind: catalog.KindEXO, Cmdlet: "Get-TransportRule", Type: "transport-rules", KeyField: "Guid", Ignore: []string{"isValid"}, Permission: "Exchange.ManageAsApp"},
		}},
	}
}

func seed(a *api) {
	rg := "/subscriptions/" + sub1 + "/resourceGroups/rg-net"
	a.graphRows["resources"] = []obj{
		{"id": rg + "/providers/Microsoft.Network/virtualNetworks/vnet-hub", "name": "vnet-hub", "type": "microsoft.network/virtualnetworks", "tenantId": tenantID,
			"subscriptionId": sub1, "resourceGroup": "rg-net", "location": "australiaeast", "kind": "", "sku": nil, "tags": obj{"env": "prod"},
			"properties": obj{"provisioningState": "Succeeded", "addressSpace": obj{"addressPrefixes": []any{"10.1.0.0/16", "10.0.0.0/16"}}, "enableDdosProtection": false}},
		{"id": rg + "/providers/Microsoft.Network/networkSecurityGroups/nsg-web", "name": "nsg-web", "type": "microsoft.network/networksecuritygroups", "tenantId": tenantID,
			"subscriptionId": sub1, "resourceGroup": "rg-net", "location": "australiaeast",
			"properties": obj{"securityRules": []any{obj{"name": "allow-https", "properties": obj{"access": "Allow", "destinationPortRange": "443"}}}}},
		{"id": "/subscriptions/" + sub2 + "/resourceGroups/rg-x/providers/Microsoft.Quantum/workspaces/q1", "name": "q1", "type": "microsoft.quantum/workspaces", "tenantId": tenantID,
			"subscriptionId": sub2, "resourceGroup": "rg-x", "location": "westus", "properties": obj{"usable": "Yes"}},
	}
	a.graphRows["policyresources"] = []obj{
		{"id": "/providers/Microsoft.Management/managementGroups/root/providers/Microsoft.Authorization/policyDefinitions/custom-1", "name": "custom-1", "type": "microsoft.authorization/policydefinitions",
			"properties": obj{"policyType": "Custom", "mode": "All", "displayName": "Deny public IPs"}},
		{"id": "/providers/Microsoft.Authorization/policyDefinitions/builtin-1", "name": "builtin-1", "type": "microsoft.authorization/policydefinitions",
			"properties": obj{"policyType": "BuiltIn", "mode": "All"}},
	}
	a.lists["/subscriptions/"+sub1+"/providers/Microsoft.Authorization/locks"] = []obj{
		{"id": rg + "/providers/Microsoft.Authorization/locks/no-delete", "name": "no-delete", "type": "Microsoft.Authorization/locks", "properties": obj{"level": "CanNotDelete"}},
	}
	// sub2 has no locks list at all: 404, read as "none".
	a.objects["/v1.0/policies/authorizationPolicy"] = obj{"@odata.context": "ctx", "id": "authorizationPolicy", "allowInvitesFrom": "adminsAndGuestInviters",
		"guestUserRoleId": "2af84b1e", "defaultUserRolePermissions": obj{"allowedToCreateApps": false, "allowedToCreateTenants": nil}}
	a.lists["/v1.0/identity/conditionalAccess/policies"] = []obj{
		{"id": "ca-1", "displayName": "Require MFA for admins", "state": "enabled", "modifiedDateTime": "2026-01-01T00:00:00Z", "conditions": obj{"users": obj{"includeRoles": []any{"b", "a"}}}},
		{"id": "ca-2", "displayName": "Block legacy authentication", "state": "enabled", "modifiedDateTime": "2026-01-01T00:00:00Z", "conditions": obj{"clientAppTypes": []any{"other", "exchangeActiveSync"}}},
		{"id": "ca-3", "displayName": "Require compliant device", "state": "enabledForReportingButNotEnforced", "modifiedDateTime": "2026-01-01T00:00:00Z"},
	}
	a.lists["/beta/deviceManagement/configurationPolicies"] = []obj{{"id": "pol-1", "name": "Windows baseline", "platforms": "windows10", "settingCount": 2}}
	a.lists["/beta/deviceManagement/configurationPolicies/pol-1/settings"] = []obj{
		{"id": "0", "settingInstance": obj{"settingDefinitionId": "device_vendor_msft_bitlocker_requiredeviceencryption", "choiceSettingValue": obj{"value": "1"}}},
		{"id": "1", "settingInstance": obj{"settingDefinitionId": "device_vendor_msft_firewall_enable", "choiceSettingValue": obj{"value": "true"}}},
	}
	a.lists["/v1.0/organization"] = []obj{{"id": tenantID, "verifiedDomains": []any{obj{"name": "contoso.com"}, obj{"name": "contoso.onmicrosoft.com", "isInitial": true}}}}
	a.cmdlets["Get-TransportRule"] = []obj{{"Guid": "rule-1", "Name": "Block executables", "State": "Enabled", "Priority": 0, "IsValid": true, "WhenChanged": "2026-01-01"}}
}

func newHarness(t *testing.T, mods []catalog.Module) *harness {
	a := newAPI(t)
	seed(a)
	cfg, err := config.Parse([]byte(`{"mongo": {"uri": "x"}, "tenants": [{"tenantName": "Contoso", "tenantId": "`+tenantID+`", "clientId": "c", "clientSecret": "s"}]}`),
		func(string) string { return "" }, nil)
	if err != nil {
		t.Fatal(err)
	}
	u := a.srv.URL
	cfg.Tenants[0].Endpoints = config.Endpoints{Authority: u, ARM: u, ARMScope: "arm", Graph: u, GraphScope: "graph", Exchange: u, ExchangeScope: "exo", Defender: u, DefenderScope: "defender", PowerPlatform: u, PowerPlatformScope: "pp", SharePoint: u}
	st := store.NewMemory()
	out := &strings.Builder{}
	var mu sync.Mutex
	log := slog.New(slog.NewTextHandler(writerFunc(func(p []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		return out.Write(p)
	}), &slog.HandlerOptions{Level: slog.LevelDebug}))
	c := &Collector{
		Cfg: cfg, Modules: mods, Store: st, Log: log, Version: "test",
		Mon: monitor.New(st, log, model.Instance{ID: "host", Version: "test", Mode: "once"}),
		NewClient: func(tn config.Tenant, l *slog.Logger) *cloud.Client {
			cl := cloud.NewClient(tn, l)
			cl.Backoff = time.Millisecond
			return cl
		},
	}
	return &harness{api: a, st: st, c: c, log: out}
}

func flag(b bool) *bool { return &b }

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

func (h *harness) run(t *testing.T) *model.Run {
	t.Helper()
	return h.c.Run(context.Background(), "manual", nil)
}

// items returns the stored items by "module/source/name".
func (h *harness) items() map[string]model.Item {
	out := map[string]model.Item{}
	for _, it := range h.st.Items {
		out[it.Module+"/"+it.Source+"/"+it.Name] = it
	}
	return out
}

func (h *harness) source(t *testing.T, module, source string) model.TenantSource {
	t.Helper()
	tn := h.st.Tenants[tenantID]
	s := tn.Module(module).Source(source)
	if s == nil {
		t.Fatalf("no entry for %s/%s", module, source)
	}
	return *s
}

func TestFirstPassStoresEverythingAndRecordsNoChanges(t *testing.T) {
	h := newHarness(t, testModules())
	r := h.run(t)
	if r.Status != model.StatusSuccess || r.TenantsDone != 1 || r.Counts.Items != 10 || r.Counts.Added != 0 || r.Counts.Sources != 8 || r.Counts.SourcesFailed != 0 {
		t.Fatalf("run: %s %+v\n%s", r.Status, r.Counts, h.log)
	}
	if strings.Join(r.Modules, ",") != "azure-network,azure-governance,azure-other,m365-identity" {
		t.Errorf("enabled modules: %v", r.Modules)
	}
	if len(h.st.Changes) != 0 {
		t.Errorf("a first pass records no changes, got %d", len(h.st.Changes))
	}
	items := h.items()
	want := []string{
		"azure-network/resources/vnet-hub", "azure-network/resources/nsg-web", "azure-other/resources/q1",
		"azure-governance/policy-definitions/custom-1", "azure-governance/locks/no-delete",
		"m365-identity/authorization-policy/Authorisation policy", "m365-identity/ca-policies/Require MFA for admins",
		"m365-identity/ca-policies/Block legacy authentication", "m365-identity/ca-policies/Require compliant device",
		"m365-identity/settings-catalog/Windows baseline",
	}
	for _, k := range want {
		if _, ok := items[k]; !ok {
			t.Errorf("missing item %s", k)
		}
	}
	if len(items) != len(want) {
		t.Errorf("%d items, want %d", len(items), len(want))
	}

	v := items["azure-network/resources/vnet-hub"]
	if v.Config != `{"location":"australiaeast","properties":{"addressSpace":{"addressPrefixes":["10.0.0.0/16","10.1.0.0/16"]},"enableDdosProtection":false},"tags":{"env":"prod"}}` {
		t.Errorf("vnet settings: %s", v.Config)
	}
	if v.Type != "microsoft.network/virtualnetworks" || v.SubscriptionName != "Production" || v.ResourceGroup != "rg-net" || !v.Present || v.Props != 5 ||
		v.Drift.Status != model.DriftUntracked || len(v.ID) != 32 || len(v.Hash) != 64 || v.SortName != "vnet-hub" ||
		v.Text != "vnet-hub microsoft.network/virtualnetworks rg-net production australiaeast resources\taddressprefixes enableddosprotection env location" {
		t.Errorf("vnet: %+v", v)
	}
	if !strings.HasPrefix(v.Key, "/subscriptions/"+sub1+"/resourcegroups/rg-net/") {
		t.Errorf("key: %s", v.Key)
	}
	ap := items["m365-identity/authorization-policy/Authorisation policy"]
	if ap.Config != `{"allowInvitesFrom":"adminsAndGuestInviters","defaultUserRolePermissions":{"allowedToCreateApps":false},"guestUserRoleId":"2af84b1e"}` || ap.Key != "authorization-policy" {
		t.Errorf("authorisation policy: %+v", ap)
	}
	if ca := items["m365-identity/ca-policies/Require MFA for admins"]; strings.Contains(ca.Config, "modifiedDateTime") || !strings.Contains(ca.Config, `"includeRoles":["a","b"]`) || ca.Key != "ca-1" {
		t.Errorf("CA policy: %s", ca.Config)
	}
	if sc := items["m365-identity/settings-catalog/Windows baseline"]; !strings.Contains(sc.Config, "device_vendor_msft_firewall_enable") || strings.Contains(sc.Config, "settingCount") {
		t.Errorf("settings catalogue: %s", sc.Config)
	}
	if lk := items["azure-governance/locks/no-delete"]; lk.Type != "microsoft.authorization/locks" || lk.ResourceGroup != "rg-net" || lk.SubscriptionID != sub1 {
		t.Errorf("lock: %+v", lk)
	}

	tn := h.st.Tenants[tenantID]
	if tn.LastStatus != model.StatusSuccess || tn.LastSuccessAt == nil || tn.Items != 10 || len(tn.Modules) != 4 {
		t.Errorf("tenant: %+v", tn)
	}
	// Branding answered 404: not configured, read as nothing.
	if s := h.source(t, "m365-identity", "branding"); s.Status != model.SourceOK || s.Items != 0 || s.LastSuccessAt == nil {
		t.Errorf("branding: %+v", s)
	}
	if h.st.States["m365-exchange"].Enabled || !h.st.States["azure-network"].Enabled || len(h.st.Modules) != 5 {
		t.Errorf("module switches: %+v", h.st.States)
	}
	run := h.st.Runs[r.ID]
	if run.Status != model.StatusSuccess || len(run.Tenants) != 1 || len(run.Tenants[0].Modules) != 4 {
		t.Errorf("stored run: %+v", run)
	}
}

func TestSecondPassRecordsChangesAndDrift(t *testing.T) {
	h := newHarness(t, testModules())
	h.run(t)
	first := h.items()
	h.st.SaveBaseline("b1")
	if b := h.st.Baselines[0]; len(b.Covered) != 8 {
		t.Fatalf("covered: %v", b.Covered)
	}

	// Nothing changed: nothing recorded, everything matches the baseline.
	r := h.run(t)
	if r.Counts.Changed+r.Counts.Added+r.Counts.Removed+r.Counts.Drifted != 0 || len(h.st.Changes) != 0 {
		t.Fatalf("an unchanged tenant gave %+v, %d changes", r.Counts, len(h.st.Changes))
	}
	for k, it := range h.items() {
		if it.Drift != (model.Drift{BaselineID: "b1", Status: model.DriftSame}) || it.RunID != r.ID {
			t.Errorf("%s: %+v", k, it.Drift)
		}
	}

	h.api.set(func() {
		rows := h.api.graphRows["resources"]
		// Changed: DDoS protection on. Volatile only: provisioningState.
		rows[0]["properties"].(obj)["enableDdosProtection"] = true
		rows[0]["properties"].(obj)["provisioningState"] = "Updating"
		// Removed: the NSG. Added: a public IP.
		rows[1] = obj{"id": "/subscriptions/" + sub1 + "/resourceGroups/rg-net/providers/Microsoft.Network/publicIPAddresses/pip-1", "name": "pip-1",
			"type": "microsoft.network/publicipaddresses", "subscriptionId": sub1, "resourceGroup": "rg-net", "properties": obj{"publicIPAllocationMethod": "Static"}}
		pol := h.api.lists["/v1.0/identity/conditionalAccess/policies"]
		pol[1]["state"] = "disabled"
		pol[1]["modifiedDateTime"] = "2026-02-02T00:00:00Z"
		pol[0]["modifiedDateTime"] = "2026-02-02T00:00:00Z" // volatile only
		h.api.lists["/beta/deviceManagement/configurationPolicies/pol-1/settings"][1]["settingInstance"].(obj)["choiceSettingValue"].(obj)["value"] = "false"
	})
	r = h.run(t)
	if r.Status != model.StatusSuccess || r.Counts.Changed != 3 || r.Counts.Added != 1 || r.Counts.Removed != 1 || r.Counts.Drifted != 5 {
		t.Fatalf("run: %s %+v\n%s", r.Status, r.Counts, h.log)
	}
	got := map[string]model.Change{}
	for _, c := range h.st.Changes {
		got[c.Kind+" "+c.Name] = c
	}
	if len(got) != 5 {
		t.Fatalf("changes: %v", got)
	}
	c := got["changed vnet-hub"]
	if c.PathCount != 1 || c.Paths[0] != (model.PathChange{Path: "properties.enableDdosProtection", Kind: model.ChangeChanged, Before: "false", After: "true"}) ||
		c.HashBefore == c.HashAfter || c.Module != "azure-network" || c.RunID != r.ID || c.TenantName != "Contoso" {
		t.Errorf("vnet change: %+v", c)
	}
	if c := got["changed Block legacy authentication"]; c.PathCount != 1 || c.Paths[0].Path != "state" || c.Paths[0].After != `"disabled"` {
		t.Errorf("CA change: %+v", c)
	}
	if c := got["changed Windows baseline"]; c.PathCount != 1 || c.Paths[0].Path != "settings[1].settingInstance.choiceSettingValue.value" {
		t.Errorf("settings catalogue change: %+v", c)
	}
	if c := got["removed nsg-web"]; c.Type != "microsoft.network/networksecuritygroups" || c.HashBefore == "" {
		t.Errorf("removal: %+v", c)
	}
	if _, ok := got["added pip-1"]; !ok {
		t.Error("no record of the added public IP")
	}

	items := h.items()
	drift := map[string]string{}
	for k, it := range items {
		drift[k] = it.Drift.Status
	}
	for k, want := range map[string]string{
		"azure-network/resources/vnet-hub": model.DriftChanged, "azure-network/resources/pip-1": model.DriftAdded, "azure-network/resources/nsg-web": model.DriftRemoved,
		"m365-identity/ca-policies/Block legacy authentication": model.DriftChanged, "m365-identity/ca-policies/Require MFA for admins": model.DriftSame,
		"azure-other/resources/q1": model.DriftSame,
	} {
		if drift[k] != want {
			t.Errorf("%s: drift %q, want %q", k, drift[k], want)
		}
	}
	nsg := items["azure-network/resources/nsg-web"]
	if nsg.Present || nsg.RemovedAt == nil || !strings.Contains(nsg.Config, "allow-https") {
		t.Errorf("a removed item that is in the baseline is kept: %+v", nsg)
	}
	v := items["azure-network/resources/vnet-hub"]
	if !v.FirstSeenAt.Equal(first["azure-network/resources/vnet-hub"].FirstSeenAt) || !v.ChangedAt.After(v.FirstSeenAt) {
		t.Errorf("first seen %v, changed %v", v.FirstSeenAt, v.ChangedAt)
	}

	// The same again: the drift stays, nothing new is recorded.
	n := len(h.st.Changes)
	r = h.run(t)
	if len(h.st.Changes) != n || r.Counts.Drifted != 5 || r.Counts.Changed+r.Counts.Removed != 0 || h.items()["azure-network/resources/nsg-web"].Present {
		t.Errorf("a repeat pass: %+v, %d changes", r.Counts, len(h.st.Changes)-n)
	}

	// Back to the baseline: the NSG returns, the vnet setting is restored.
	h.api.set(func() {
		rows := h.api.graphRows["resources"]
		rows[0]["properties"].(obj)["enableDdosProtection"] = false
		h.api.graphRows["resources"] = append(rows, obj{"id": "/subscriptions/" + sub1 + "/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/nsg-web", "name": "nsg-web",
			"type": "microsoft.network/networksecuritygroups", "subscriptionId": sub1, "resourceGroup": "rg-net", "location": "australiaeast",
			"properties": obj{"securityRules": []any{obj{"name": "allow-https", "properties": obj{"access": "Allow", "destinationPortRange": "443"}}}}})
	})
	h.run(t)
	items = h.items()
	if it := items["azure-network/resources/nsg-web"]; !it.Present || it.Drift.Status != model.DriftSame || it.RemovedAt != nil {
		t.Errorf("returned NSG: %+v", it)
	}
	if items["azure-network/resources/vnet-hub"].Drift.Status != model.DriftSame {
		t.Error("restored vnet still drifted")
	}

	// A new baseline accepts the rest; an object removed after it that the
	// baseline does not hold is forgotten.
	h.st.SaveBaseline("b2")
	h.api.set(func() { h.api.graphRows["resources"] = h.api.graphRows["resources"][:1] })
	r = h.run(t)
	items = h.items()
	if _, ok := items["azure-network/resources/vnet-hub"]; !ok || r.Counts.Removed != 3 {
		t.Fatalf("after removing rows: %+v", r.Counts)
	}
	if it := items["azure-network/resources/pip-1"]; it.Present || it.Drift != (model.Drift{BaselineID: "b2", Status: model.DriftRemoved}) {
		t.Errorf("pip-1 is in baseline b2 and gone: %+v", it)
	}
}

func TestFailuresKeepWhatIsStored(t *testing.T) {
	h := newHarness(t, testModules())
	h.run(t)
	h.st.SaveBaseline("b1")
	h.api.set(func() {
		h.api.status["/v1.0/identity/conditionalAccess/policies"] = 403
		h.api.status["/beta/deviceManagement/configurationPolicies"] = 400
		h.api.status["/providers/Microsoft.ResourceGraph/resources"] = 500
	})
	r := h.run(t)
	if r.Status != model.StatusPartial || r.Counts.SourcesFailed != 5 || r.Counts.SourcesDenied != 1 || len(h.st.Changes) != 0 || len(h.st.Items) != 10 {
		t.Fatalf("run: %s %+v, %d items\n%s", r.Status, r.Counts, len(h.st.Items), h.log)
	}
	ca := h.source(t, "m365-identity", "ca-policies")
	if ca.Status != model.SourceDenied || !strings.Contains(ca.Error, "needs Policy.Read.All") || ca.LastSuccessAt == nil || ca.Items != 3 {
		t.Errorf("denied source: %+v", ca)
	}
	if s := h.source(t, "m365-identity", "settings-catalog"); s.Status != model.SourceUnsupported {
		t.Errorf("unsupported source: %+v", s)
	}
	if s := h.source(t, "azure-network", "resources"); s.Status != model.SourceFailed || !strings.Contains(s.Error, "HTTP 500") {
		t.Errorf("failed source: %+v", s)
	}
	tn := h.st.Tenants[tenantID]
	if tn.LastStatus != model.StatusPartial || tn.Module("m365-identity").Status != model.SourceDenied || tn.Module("azure-network").Status != model.SourceFailed {
		t.Errorf("tenant: %+v", tn)
	}

	// Permissions alone do not make a pass partial.
	h.api.set(func() { delete(h.api.status, "/providers/Microsoft.ResourceGraph/resources") })
	if r := h.run(t); r.Status != model.StatusSuccess || r.Counts.SourcesFailed != 2 {
		t.Errorf("run with only permission problems: %s %+v", r.Status, r.Counts)
	}

	// A list that stops half way removes nothing.
	h.api.set(func() {
		h.api.status = map[string]int{}
		h.api.pageSize = 2
		h.api.lists["/v1.0/identity/conditionalAccess/policies"][0]["state"] = "disabled"
	})
	orig := h.api.srv.Config.Handler
	h.api.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1.0/identity/conditionalAccess/policies" && r.URL.Query().Get("page") == "2" {
			w.WriteHeader(403)
			return
		}
		orig.ServeHTTP(w, r)
	})
	r = h.run(t)
	items := h.items()
	if s := h.source(t, "m365-identity", "ca-policies"); s.Status != model.SourceDenied {
		t.Errorf("half-read source: %+v", s)
	}
	if !items["m365-identity/ca-policies/Require compliant device"].Present || !strings.Contains(items["m365-identity/ca-policies/Require MFA for admins"].Config, "disabled") || r.Counts.Removed != 0 {
		t.Errorf("a half-read list must keep unseen items and store seen ones: %+v", r.Counts)
	}

	// No token at all: every source denied, the tenant failed.
	h.api.srv.Config.Handler = orig
	h.api.set(func() { h.api.status["token:arm"], h.api.status["token:graph"] = 401, 401 })
	r = h.run(t)
	if r.Status != model.StatusFailed || r.TenantsFailed != 1 || len(h.st.Items) != 10 {
		t.Errorf("no token: %s %+v", r.Status, r)
	}
	if tn := h.st.Tenants[tenantID]; tn.LastStatus != model.StatusFailed || !strings.Contains(tn.LastError, "no consent") || strings.Contains(tn.LastError, "Trace ID") {
		t.Errorf("tenant after token failure: %+v", tn)
	}

	// The store is down: the pass does not start.
	h.st.Fail = errors.New("mongo is down")
	if r := h.run(t); r.Status != model.StatusFailed || !strings.Contains(r.Error, "mongo is down") {
		t.Errorf("store down: %+v", r)
	}
}

func TestSwitchesDecideWhatIsRead(t *testing.T) {
	h := newHarness(t, testModules())
	h.run(t)
	// The settings turn Exchange on, networking off, and one source off.
	h.c.Cfg.Modules = map[string]config.ModuleSetting{
		"m365-exchange": {Enabled: flag(true)},
		"azure-network": {Enabled: flag(false)},
		"m365-identity": {Sources: map[string]config.SourceSetting{"ca-policies": {Enabled: flag(false)}}},
	}
	h.c.Cfg.SkipSources = []string{"azure-governance/locks"}
	h.api.set(func() { h.api.requests = nil })
	r := h.run(t)
	if r.Status != model.StatusSuccess || strings.Join(r.Modules, ",") != "azure-governance,azure-other,m365-identity,m365-exchange" {
		t.Fatalf("run: %s %v\n%s", r.Status, r.Modules, h.log)
	}
	for _, req := range h.api.requests {
		if strings.Contains(req, "conditionalAccess") || strings.Contains(req, "locks") {
			t.Errorf("a switched-off source was read: %s", req)
		}
	}
	for _, b := range h.api.bodies[len(h.api.bodies)-3:] {
		if q, _ := b["query"].(string); strings.Contains(q, "resources | where type startswith 'microsoft.network/'") {
			t.Errorf("a switched-off module was read: %s", q)
		}
	}
	items := h.items()
	rule := items["m365-exchange/transport-rules/Block executables"]
	if rule.Config != `{"Guid":"rule-1","Name":"Block executables","Priority":0,"State":"Enabled"}` || rule.Key != "rule-1" {
		t.Errorf("transport rule: %+v", rule)
	}
	// What a switched-off module or source stored stays, with its entry.
	if !items["azure-network/resources/vnet-hub"].Present || !items["m365-identity/ca-policies/Require MFA for admins"].Present {
		t.Error("switching off must not remove what is stored")
	}
	tn := h.st.Tenants[tenantID]
	if m := tn.Module("azure-network"); m == nil || m.Status != model.SourceOK || m.Items != 2 {
		t.Errorf("entry of the switched-off module: %+v", m)
	}
	if s := h.source(t, "m365-identity", "ca-policies"); s.Status != model.SourceDisabled || s.LastSuccessAt == nil || s.Items != 3 {
		t.Errorf("switched-off source: %+v", s)
	}
	if s := h.source(t, "azure-governance", "locks"); s.Status != model.SourceDisabled {
		t.Errorf("skipped source: %+v", s)
	}
	if tn.Items != 11 {
		t.Errorf("tenant items: %d", tn.Items)
	}

	// -modules overrides the switches.
	h.c.Only = []string{"azure-network"}
	if r := h.run(t); strings.Join(r.Modules, ",") != "azure-network" || r.Counts.Items != 2 {
		t.Errorf("only: %v %+v", r.Modules, r.Counts)
	}

	// A tenant limited to Microsoft 365 reads no Azure module.
	h.c.Only = nil
	h.c.Cfg.Modules["azure-network"] = config.ModuleSetting{Enabled: flag(true)}
	h.c.Cfg.Tenants[0].Platforms = []string{"m365"}
	h.api.set(func() { h.api.requests = nil })
	h.run(t)
	for _, req := range h.api.requests {
		if strings.Contains(req, "/subscriptions") || strings.Contains(req, "ResourceGraph") {
			t.Errorf("Azure was read for a Microsoft 365 only tenant: %s", req)
		}
	}
}

func TestResourceGraphPagingAndScope(t *testing.T) {
	h := newHarness(t, testModules())
	h.api.set(func() {
		for i := 0; i < 25; i++ {
			h.api.graphRows["resources"] = append(h.api.graphRows["resources"], obj{
				"id": "/subscriptions/" + sub2 + "/resourceGroups/rg-x/providers/Microsoft.Network/routeTables/rt-" + itoa(i), "name": "rt-" + itoa(i),
				"type": "microsoft.network/routetables", "subscriptionId": sub2, "resourceGroup": "rg-x", "properties": obj{"n": i}})
		}
		h.api.pageSize = 10
		h.api.tooLarge = 300
	})
	r := h.run(t)
	if r.Status != model.StatusSuccess || h.source(t, "azure-network", "resources").Items != 27 {
		t.Fatalf("paged read: %s %+v\n%s", r.Status, h.source(t, "azure-network", "resources"), h.log)
	}
	var other string
	for _, b := range h.api.bodies {
		if q, _ := b["query"].(string); strings.Contains(q, "where not(") {
			other = q
		}
		if _, ok := b["subscriptions"]; ok {
			t.Error("an unrestricted tenant is queried without naming subscriptions")
		}
	}
	if other != "resources | where not(type startswith 'microsoft.network/') | order by id asc" {
		t.Errorf("catch-all query: %s", other)
	}

	// Restricted to one subscription: only its resources remain.
	h.c.Cfg.Tenants[0].ExcludeSubscriptions = []string{sub2}
	h.api.set(func() { h.api.bodies = nil })
	r = h.run(t)
	if s := h.source(t, "azure-network", "resources"); s.Items != 2 || r.Counts.Removed != 27 { // 25 route tables, q1, and the policy above subscriptions
		t.Errorf("restricted read: %+v %+v", s, r.Counts)
	}
	for _, b := range h.api.bodies {
		if subs, _ := b["subscriptions"].([]any); len(subs) != 1 || subs[0] != sub1 {
			t.Errorf("subscriptions sent: %v", b["subscriptions"])
		}
	}
}

// Every built-in source must make a request the stand-in understands, and
// an empty tenant must give a clean pass.
func TestWholeCatalogueAgainstAnEmptyTenant(t *testing.T) {
	mods, err := catalog.Build(&config.Config{ModuleDefaults: map[string]bool{"m365-exchange": true, "m365-groups": true}})
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, mods)
	// Some sources are read as a service account by default.
	h.c.Cfg.Tenants[0].Username, h.c.Cfg.Tenants[0].Password = "svc-drift@contoso.com", "pw"
	h.api.set(func() {
		h.api.graphRows, h.api.cmdlets = map[string][]obj{}, map[string][]obj{}
		keep := h.api.lists
		h.api.lists = map[string][]obj{"/subscriptions": keep["/subscriptions"], "/v1.0/organization": keep["/v1.0/organization"]}
		h.api.objects = map[string]obj{}
	})
	orig := h.api.srv.Config.Handler
	h.api.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Everything that is not otherwise known is an empty list.
		p := r.URL.Path
		if (r.Method == http.MethodGet || strings.Contains(p, "listTenantSettings")) && p != "/subscriptions" && p != "/v1.0/organization" {
			h.api.set(func() { h.api.requests = append(h.api.requests, "GET "+r.URL.RequestURI()) })
			_, _ = io.WriteString(w, `{"value": []}`)
			return
		}
		orig.ServeHTTP(w, r)
	})
	r := h.run(t)
	sources, singles := 0, 0
	for _, m := range mods {
		if !m.DefaultEnabled {
			continue // Teams: needs PowerShell, and is off unless switched on
		}
		sources += len(m.Sources)
		for _, s := range m.Sources {
			// The stand-in answers each with an object; those read per
			// resource have no resource to be read for.
			if s.Single && len(s.Each) == 0 {
				singles++
			}
		}
	}
	if r.Status != model.StatusSuccess || r.Counts.Sources != sources || r.Counts.SourcesFailed != 0 || r.Counts.Items != singles+1 { // and the organisation
		t.Fatalf("run: %s %+v (want %d sources, %d items)", r.Status, r.Counts, sources, singles)
	}
	all := strings.Join(h.api.requests, "\n")
	for _, want := range []string{
		"GET /v1.0/policies/roleManagementPolicies?$filter=scopeId%20eq%20%27/%27%20and%20scopeType%20eq%20%27DirectoryRole%27&$expand=rules",
		"GET /v1.0/organization/" + tenantID + "/branding",
		"GET /beta/deviceManagement/configurationPolicies\n",
		"GET /subscriptions/" + sub2 + "/providers/Microsoft.Security/pricings?api-version=2024-01-01",
		"POST /adminapi/beta/" + tenantID + "/InvokeCommand",
	} {
		if !strings.Contains(all+"\n", want) {
			t.Errorf("no request %q", want)
		}
	}
	for _, req := range h.api.requests {
		if _, uri, _ := strings.Cut(req, " "); strings.ContainsAny(uri, " '") {
			t.Errorf("unescaped request: %s", req)
		}
	}
}

// Resource Manager lists come as {"value": []}, as a bare array, or as the
// one object there is.
func TestResourceManagerAnswerShapes(t *testing.T) {
	contacts := "/providers/Microsoft.Security/securityContacts"
	h := newHarness(t, []catalog.Module{{ID: "azure-security", Platform: model.PlatformAzure, Name: "Security", DefaultEnabled: true, Sources: []catalog.Source{
		{ID: "security-contacts", Name: "Security contacts", Kind: catalog.KindARM, Path: "/subscriptions/{subscriptionId}" + contacts + "?api-version=2020-01-01-preview", Permission: "Reader"},
		{ID: "locks", Name: "Locks", Kind: catalog.KindARM, Path: "/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/locks?api-version=2020-05-01", Permission: "Reader"},
	}}})
	contact := func(sub, name, email string) string {
		return `{"id": "/subscriptions/` + sub + contacts + `/` + name + `", "name": "` + name + `", "type": "Microsoft.Security/securityContacts", "properties": {"emails": "` + email + `"}}`
	}
	h.api.set(func() {
		h.api.raw["/subscriptions/"+sub1+contacts] = "[" + contact(sub1, "default", "a@contoso.com") + ", " + contact(sub1, "second", "b@contoso.com") + "]"
		h.api.raw["/subscriptions/"+sub2+contacts] = contact(sub2, "default", "c@contoso.com")
	})
	r := h.run(t)
	if s := h.source(t, "azure-security", "security-contacts"); r.Status != model.StatusSuccess || s.Status != model.SourceOK || s.Items != 3 {
		t.Fatalf("security contacts: %s %+v\n%s", r.Status, s, h.log)
	}
	if s := h.source(t, "azure-security", "locks"); s.Status != model.SourceOK || s.Items != 1 {
		t.Errorf("an ordinary list: %+v", s)
	}
	emails := map[string]string{}
	for _, it := range h.st.Items {
		if it.Source == "security-contacts" {
			emails[it.SubscriptionName+"/"+it.Name] = it.Config
		}
	}
	want := map[string]string{
		"Production/default": `{"properties":{"emails":"a@contoso.com"}}`, "Production/second": `{"properties":{"emails":"b@contoso.com"}}`,
		"Sandbox/default": `{"properties":{"emails":"c@contoso.com"}}`,
	}
	for k, v := range want {
		if emails[k] != v {
			t.Errorf("%s: %s", k, emails[k])
		}
	}

	// The shape changing from one pass to the next is not a change, and an
	// empty array or object is "none".
	h.api.set(func() {
		h.api.raw["/subscriptions/"+sub2+contacts] = "[" + contact(sub2, "default", "c@contoso.com") + "]"
		h.api.raw["/subscriptions/"+sub1+contacts] = `{"value": [` + contact(sub1, "default", "a@contoso.com") + ", " + contact(sub1, "second", "b@contoso.com") + `]}`
	})
	if r := h.run(t); r.Counts.Changed+r.Counts.Added+r.Counts.Removed != 0 {
		t.Errorf("another shape of the same answer gave %+v", r.Counts)
	}
	h.api.set(func() {
		h.api.raw["/subscriptions/"+sub1+contacts] = "[]"
		h.api.raw["/subscriptions/"+sub2+contacts] = "{}"
	})
	if r := h.run(t); r.Counts.Removed != 3 || h.source(t, "azure-security", "security-contacts").Status != model.SourceOK {
		t.Errorf("empty answers: %+v", r.Counts)
	}
}

// The dashboard chooses, per Graph source, the version to read and whether
// to read as the service account.
func TestGraphVersionAndServiceAccountSwitches(t *testing.T) {
	mods := []catalog.Module{{ID: "m365-governance", Platform: model.PlatformM365, Name: "Governance", DefaultEnabled: true, Sources: []catalog.Source{
		{ID: "terms-of-use", Name: "Terms of use", Kind: catalog.KindGraph, Path: "/identityGovernance/termsOfUse/agreements", Type: "terms-of-use", Delegated: true, Permission: "Agreement.Read.All"},
		{ID: "settings-catalog", Name: "Settings catalogue", Kind: catalog.KindGraph, Path: "/deviceManagement/configurationPolicies", Beta: true, Type: "settings-catalog",
			Children: []catalog.Child{{Field: "settings", Suffix: "settings"}}, Permission: "DeviceManagementConfiguration.Read.All"},
		{ID: "forms", Name: "Forms", Kind: catalog.KindGraph, Path: "/admin/forms", Beta: true, Single: true, Type: "forms", Permission: "OrgSettings-Forms.Read.All"},
	}}}
	h := newHarness(t, mods)
	tou := "/v1.0/identityGovernance/termsOfUse/agreements"
	h.api.set(func() {
		h.api.lists[tou] = []obj{{"id": "tou-1", "displayName": "Guest terms", "isViewingBeforeAcceptanceRequired": true}}
		h.api.userOnly[tou], h.api.userOnly["/beta/admin/forms"] = true, true
		h.api.objects["/beta/admin/forms"] = obj{"settings": obj{"isExternalSendFormEnabled": false}}
		h.api.lists["/v1.0/deviceManagement/configurationPolicies"] = []obj{{"id": "pol-1", "name": "Windows baseline (v1.0)"}}
		h.api.lists["/v1.0/deviceManagement/configurationPolicies/pol-1/settings"] = []obj{}
	})
	requested := func(prefix string) bool {
		for _, r := range h.api.requests {
			if strings.HasPrefix(r, "GET "+prefix) {
				return true
			}
		}
		return false
	}

	// No service account: the delegated source says so; the others are read
	// as the application, and Forms is refused.
	r := h.run(t)
	s := h.source(t, "m365-governance", "terms-of-use")
	if s.Status != model.SourceDenied || !strings.Contains(s.Error, "no username and password") || strings.Contains(s.Error, "needs Agreement") || requested(tou) {
		t.Fatalf("delegated source without a service account: %+v", s)
	}
	if s := h.source(t, "m365-governance", "forms"); s.Status != model.SourceDenied || !strings.Contains(s.Error, "(needs OrgSettings-Forms.Read.All)") {
		t.Errorf("forms as the application: %+v", s)
	}
	if s := h.source(t, "m365-governance", "settings-catalog"); s.Status != model.SourceOK || !requested("/beta/deviceManagement/configurationPolicies/pol-1/settings") || r.Status != model.StatusSuccess {
		t.Errorf("beta by default: %+v", s)
	}

	// With a service account, and the dashboard switching Forms to it and
	// the settings catalogue to v1.0.
	h.c.Cfg.Tenants[0].Username, h.c.Cfg.Tenants[0].Password = "svc-drift@contoso.com", "pw"
	h.c.Cfg.Modules = map[string]config.ModuleSetting{"m365-governance": {Sources: map[string]config.SourceSetting{
		"settings-catalog": {Beta: flag(false)}, "forms": {Delegated: flag(true)},
		// Not a source: ignored.
		"nope": {Beta: flag(true)},
	}}}
	h.api.set(func() { h.api.requests, h.api.logins = nil, nil })
	r = h.run(t)
	if r.Status != model.StatusSuccess || r.Counts.SourcesFailed != 0 {
		t.Fatalf("run: %s %+v\n%s", r.Status, r.Counts, h.log)
	}
	items := h.items()
	if it := items["m365-governance/terms-of-use/Guest terms"]; it.Config != `{"displayName":"Guest terms","isViewingBeforeAcceptanceRequired":true}` {
		t.Errorf("terms of use: %+v", it)
	}
	if it := items["m365-governance/forms/Forms"]; !strings.Contains(it.Config, "isExternalSendFormEnabled") {
		t.Errorf("forms as the service account: %+v", it)
	}
	if _, ok := items["m365-governance/settings-catalog/Windows baseline (v1.0)"]; !ok || !requested("/v1.0/deviceManagement/configurationPolicies/pol-1/settings") || requested("/beta/deviceManagement") {
		t.Errorf("the settings catalogue was not read from v1.0: %v", h.api.requests)
	}
	var user map[string]string
	for _, l := range h.api.logins {
		if l["grant_type"] == "password" {
			if user != nil {
				t.Error("the service account signed in more than once in a pass")
			}
			user = l
		}
	}
	if user["username"] != "svc-drift@contoso.com" || user["password"] != "pw" || user["client_id"] != "c" || user["client_secret"] != "s" || user["scope"] != "graph" {
		t.Errorf("sign-in: %v", user)
	}
	if strings.Contains(h.log.String(), "pw\"") || strings.Contains(h.log.String(), "password=") {
		t.Error("the password is in the log")
	}
	if !strings.Contains(h.log.String(), `as="service account"`) || !strings.Contains(h.log.String(), "graphVersion=v1.0") {
		t.Errorf("the log does not say how sources were read")
	}

	// A public client application: no secret is sent.
	h.c.Cfg.Tenants[0].DelegatedClientID = "public-app"
	h.api.set(func() { h.api.logins = nil })
	h.run(t)
	for _, l := range h.api.logins {
		if _, secret := l["client_secret"]; l["grant_type"] == "password" && (l["client_id"] != "public-app" || secret) {
			t.Errorf("public client sign-in: %v", l)
		}
	}

	// A wrong password: denied, with the account named and what is stored kept.
	h.c.Cfg.Tenants[0].Password = "wrong"
	h.run(t)
	s = h.source(t, "m365-governance", "terms-of-use")
	if s.Status != model.SourceDenied || !strings.Contains(s.Error, "signing in as svc-drift@contoso.com") || !strings.Contains(s.Error, "AADSTS50126") || strings.Contains(s.Error, "wrong\"") {
		t.Errorf("wrong password: %+v", s)
	}
	if !h.items()["m365-governance/terms-of-use/Guest terms"].Present {
		t.Error("a failed sign-in must not remove what is stored")
	}

	// Switched back to the application: refused again by the endpoint.
	h.c.Cfg.Modules = map[string]config.ModuleSetting{"m365-governance": {Sources: map[string]config.SourceSetting{"terms-of-use": {Delegated: flag(false)}}}}
	h.run(t)
	if s := h.source(t, "m365-governance", "terms-of-use"); s.Status != model.SourceDenied || !strings.Contains(s.Error, "(needs Agreement.Read.All)") {
		t.Errorf("terms of use as the application: %+v", s)
	}
}

// Any kind of source can be read as the service account, not only Graph's.
func TestServiceAccountForAzureSources(t *testing.T) {
	locks := "/providers/Microsoft.Authorization/locks"
	h := newHarness(t, []catalog.Module{{ID: "azure-governance", Platform: model.PlatformAzure, Name: "Governance", DefaultEnabled: true, Sources: []catalog.Source{
		{ID: "locks", Name: "Locks", Kind: catalog.KindARM, Path: "/subscriptions/{subscriptionId}" + locks + "?api-version=2020-05-01", Permission: "Reader"},
	}}})
	h.api.set(func() { h.api.userOnly["/subscriptions/"+sub1+locks] = true })
	// As the application the list is refused.
	h.run(t)
	if s := h.source(t, "azure-governance", "locks"); s.Status != model.SourceDenied {
		t.Fatalf("as the application: %+v", s)
	}
	// Switched to the service account, with beta set too: only Graph has a
	// beta version, so that part is ignored.
	h.c.Cfg.Tenants[0].Username, h.c.Cfg.Tenants[0].Password = "svc-drift@contoso.com", "pw"
	h.c.Cfg.Modules = map[string]config.ModuleSetting{"azure-governance": {Sources: map[string]config.SourceSetting{"locks": {Delegated: flag(true), Beta: flag(true)}}}}
	st := States(h.c.Cfg, h.c.Modules)["azure-governance"]
	if !st.SourceDelegated["locks"] || len(st.SourceBeta) != 0 {
		t.Errorf("states: %+v", st)
	}
	h.api.set(func() { h.api.logins = nil })
	if r := h.run(t); r.Status != model.StatusSuccess {
		t.Fatalf("run: %s\n%s", r.Status, h.log)
	}
	if s := h.source(t, "azure-governance", "locks"); s.Status != model.SourceOK || s.Items != 1 {
		t.Errorf("as the service account: %+v", s)
	}
	signedIn := false
	for _, l := range h.api.logins {
		signedIn = signedIn || (l["grant_type"] == "password" && l["scope"] == "arm")
	}
	if !signedIn {
		t.Errorf("the service account did not sign in for Resource Manager: %v", h.api.logins)
	}
}

// Identifiers are shown with what they stand for, permission grants are
// stored with the application they were granted to, managed identities are
// a type of their own, and the configuration can leave objects out.
func TestNamesGrantsIdentitiesAndExclusions(t *testing.T) {
	const (
		alice   = "aaaaaaaa-0000-0000-0000-000000000001"
		spApp   = "b50f4398-2fa6-4884-b936-011b7ce18f68"
		spGraph = "f5116e97-f94d-46af-a68e-0d7c109a53e0"
		spMI    = "cccccccc-0000-0000-0000-000000000003"
		roleID  = "/subscriptions/" + sub1 + "/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c"
		raID    = "/subscriptions/" + sub1 + "/providers/Microsoft.Authorization/roleAssignments/11112222-0000-0000-0000-000000000009"
		admin   = "62e90394-69f5-4237-9190-012177145e10"
	)
	var mods []catalog.Module
	all, err := catalog.Build(&config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range all {
		keep := map[string][]string{"azure-access": {"role-assignments"}, "m365-roles": {"role-assignments"}, "m365-applications": {"service-principals", "managed-identities"}, "azure-network": {"resources"}}[m.ID]
		if keep == nil {
			continue
		}
		var srcs []catalog.Source
		for _, s := range m.Sources {
			if slices.Contains(keep, s.ID) {
				srcs = append(srcs, s)
			}
		}
		m.Sources = srcs
		mods = append(mods, m)
	}
	if len(mods) != 4 {
		t.Fatalf("modules: %d", len(mods))
	}
	h := newHarness(t, mods)
	h.api.set(func() {
		h.api.graphRows["authorizationresources"] = []obj{
			{"id": raID, "name": "11112222-0000-0000-0000-000000000009", "type": "microsoft.authorization/roleassignments", "subscriptionId": sub1,
				"properties": obj{"principalId": alice, "roleDefinitionId": roleID, "scope": "/subscriptions/" + sub1, "principalType": "User"}},
			{"id": roleID, "name": "b24988ac-6180-42a0-ab88-20f7382dd24c", "type": "microsoft.authorization/roledefinitions", "roleName": "Contributor", "properties": obj{"roleName": "Contributor"}},
		}
		h.api.graphRows["resources"] = []obj{
			{"id": "/subscriptions/" + sub1 + "/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet-a", "name": "vnet-a", "type": "microsoft.network/virtualnetworks", "subscriptionId": sub1, "resourceGroup": "rg-net", "location": "westeurope", "properties": obj{"x": 1}},
			{"id": "/subscriptions/" + sub1 + "/resourceGroups/rg-net/providers/Microsoft.Network/networkWatchers/nw", "name": "nw", "type": "microsoft.network/networkwatchers", "subscriptionId": sub1, "resourceGroup": "rg-net", "location": "westeurope", "properties": obj{"x": 1}},
			{"id": "/subscriptions/" + sub1 + "/resourceGroups/MC_aks/providers/Microsoft.Network/loadBalancers/lb", "name": "lb", "type": "microsoft.network/loadbalancers", "subscriptionId": sub1, "resourceGroup": "MC_aks", "location": "westeurope", "properties": obj{"x": 1}},
		}
		h.api.lists["/v1.0/directoryObjects/getByIds"] = []obj{
			{"id": alice, "displayName": "Alice Smith"}, {"id": spGraph, "displayName": "Microsoft Graph"}, {"id": spApp, "displayName": "Intranet"},
		}
		h.api.lists["/v1.0/roleManagement/directory/roleDefinitions"] = []obj{{"id": admin, "templateId": admin, "displayName": "Global Administrator"}}
		h.api.lists["/v1.0/roleManagement/directory/roleAssignments"] = []obj{{"id": "ra-1", "principalId": alice, "roleDefinitionId": admin, "directoryScopeId": "/"}}
		h.api.lists["/v1.0/servicePrincipals"] = []obj{
			{"id": spApp, "displayName": "Intranet", "servicePrincipalType": "Application"},
			{"id": spGraph, "displayName": "Microsoft Graph", "servicePrincipalType": "Application"},
			{"id": spMI, "displayName": "vm-build", "servicePrincipalType": "ManagedIdentity"},
		}
		h.api.lists["/v1.0/oauth2PermissionGrants"] = []obj{{"id": "g-1", "clientId": spApp, "consentType": "AllPrincipals", "resourceId": spGraph, "scope": "AllSites.FullControl"}}
	})
	if r := h.run(t); r.Status != model.StatusSuccess {
		t.Fatalf("run: %s\n%s", r.Status, h.log)
	}
	items := h.items()

	// Role assignments are named after the principal and the role, and
	// carry the names of the identifiers in them.
	az := items["azure-access/role-assignments/Alice Smith · Contributor · Production"]
	if az.Refs[alice] != "Alice Smith" || az.Refs[roleID] != "Contributor" || !strings.Contains(az.Text, "alice smith") {
		t.Errorf("Azure role assignment: %+v\n%v", az, keys(items))
	}
	if strings.Contains(az.Config, "Alice") {
		t.Error("names must not be part of the settings")
	}
	if e := items["m365-roles/role-assignments/Alice Smith · Global Administrator"]; e.Refs[admin] != "Global Administrator" {
		t.Errorf("Entra role assignment: %+v", e)
	}

	// The grant is inside the application it was granted to, with the
	// resource named; it is not an object of its own.
	app := items["m365-applications/service-principals/Intranet"]
	if !strings.Contains(app.Config, `"oauth2PermissionGrants":[{"consentType":"AllPrincipals","resourceId":"`+spGraph+`","scope":"AllSites.FullControl"}]`) || app.Refs[spGraph] != "Microsoft Graph" {
		t.Errorf("grants of the application: %s %v", app.Config, app.Refs)
	}
	if g := items["m365-applications/service-principals/Microsoft Graph"]; !strings.Contains(g.Config, `"oauth2PermissionGrants":[]`) {
		t.Errorf("an application without grants: %s", g.Config)
	}
	// Managed identities are apart from enterprise applications.
	mi := items["m365-applications/managed-identities/vm-build"]
	if mi.Type != "managed-identities" || !mi.Present {
		t.Errorf("managed identity: %+v", mi)
	}
	if _, ok := items["m365-applications/service-principals/vm-build"]; ok {
		t.Error("a managed identity is listed as an enterprise application")
	}

	// A principal renamed: the item is relabelled, and no change recorded.
	before := len(h.st.Changes)
	changedAt := az.ChangedAt
	h.api.set(func() {
		h.api.lists["/v1.0/directoryObjects/getByIds"][0] = obj{"id": alice, "displayName": "Alice Jones"}
	})
	h.run(t)
	items = h.items()
	if it := items["azure-access/role-assignments/Alice Jones · Contributor · Production"]; it.Refs[alice] != "Alice Jones" || !it.ChangedAt.Equal(changedAt) || len(h.st.Changes) != before {
		t.Errorf("renamed principal: %+v, %d changes more\n%v", it, len(h.st.Changes)-before, keys(items))
	}

	// Leave out a type everywhere, and a resource group by pattern.
	cfg, err := config.Parse([]byte(`{"mongo": {"uri": "x"}, "tenants": [{"tenantName": "Contoso", "tenantId": "`+tenantID+`", "clientId": "c", "clientSecret": "s"}],
		"exclude": [{"module": "azure-network", "type": "Microsoft.Network/networkWatchers"}, {"resourceGroup": "mc_*"}]}`), func(string) string { return "" }, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.c.Cfg.Exclude = cfg.Exclude
	r := h.run(t)
	items = h.items()
	if _, ok := items["azure-network/resources/vnet-a"]; !ok || len(itemsOf(items, "azure-network")) != 1 || r.Counts.Removed != 0 || len(h.st.Changes) != before {
		t.Errorf("excluded objects: %v, removed %d, %d changes more", keys(itemsOf(items, "azure-network")), r.Counts.Removed, len(h.st.Changes)-before)
	}
	for _, bad := range []string{`[{"module": "azure-network"}]`, `[{"type": "*"}]`} {
		if _, err := config.Parse([]byte(`{"mongo": {"uri": "x"}, "tenants": [{"tenantName": "C", "tenantId": "`+tenantID+`", "clientId": "c", "clientSecret": "s"}], "exclude": `+bad+`}`), func(string) string { return "" }, nil); err == nil {
			t.Errorf("exclude %s should be refused", bad)
		}
	}

	// A source that left the catalogue takes its objects with it.
	h.c.Modules = mods[:1]
	h.run(t)
	for k := range h.items() {
		if !strings.HasPrefix(k, mods[0].ID+"/") {
			t.Errorf("left behind: %s", k)
		}
	}
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func itemsOf(items map[string]model.Item, module string) map[string]model.Item {
	out := map[string]model.Item{}
	for k, v := range items {
		if v.Module == module && v.Present {
			out[k] = v
		}
	}
	return out
}

// The switches the dashboard stores in the database win over the
// configuration, switch by switch.
func TestSwitchesFromTheDatabase(t *testing.T) {
	h := newHarness(t, []catalog.Module{{ID: "azure-governance", Platform: model.PlatformAzure, Name: "Governance", DefaultEnabled: true, Sources: []catalog.Source{
		{ID: "locks", Name: "Locks", Kind: catalog.KindARM, Path: "/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/locks?api-version=2020-05-01", Permission: "Reader"},
		{ID: "containers", Name: "Containers", Kind: catalog.KindARG, Table: "resourcecontainers", Permission: "Reader"},
	}}})
	// The configuration switches locks off and containers to the service account.
	h.c.Cfg.Modules = map[string]config.ModuleSetting{"azure-governance": {Sources: map[string]config.SourceSetting{"locks": {Enabled: flag(false)}, "containers": {Delegated: flag(true)}}}}
	h.st.Switches = []model.ModuleSwitches{
		{ID: "azure-governance", Sources: map[string]model.SourceSwitches{"locks": {Enabled: flag(true)}}},
		{ID: "not-a-module", Enabled: flag(false)},
	}
	h.run(t)
	if s := h.source(t, "azure-governance", "locks"); s.Status != model.SourceOK {
		t.Errorf("the database switched locks back on: %+v", s)
	}
	// What the database does not set stays as the configuration has it.
	if st := h.st.States["azure-governance"]; !st.Enabled || len(st.DisabledSources) != 0 || !st.SourceDelegated["containers"] {
		t.Errorf("states: %+v", st)
	}
	if h.c.Cfg.Modules["azure-governance"].Sources["locks"].Enabled == nil || *h.c.Cfg.Modules["azure-governance"].Sources["locks"].Enabled {
		t.Error("the configuration itself must not be changed")
	}
	// The module switched off in the database: nothing is read.
	h.st.Switches = []model.ModuleSwitches{{ID: "azure-governance", Enabled: flag(false)}}
	h.api.set(func() { h.api.requests = nil })
	h.run(t)
	for _, r := range h.api.requests {
		if strings.Contains(r, "locks") {
			t.Errorf("read although the module is off: %s", r)
		}
	}
	// The switches cannot be read: the pass does not start.
	h.st.Fail = errors.New("database down")
	if r := h.run(t); r.Status != model.StatusFailed {
		t.Errorf("without the switches the pass must not run: %s", r.Status)
	}
}

// Extensions are stored inside their machine, role definitions are named
// by their role name, and principals carry the roles they hold.
func TestNestingAndRolesByPrincipal(t *testing.T) {
	const (
		alice = "aaaaaaaa-0000-0000-0000-000000000001"
		sp    = "b50f4398-2fa6-4884-b936-011b7ce18f68"
		appID = "99999999-0000-0000-0000-00000000000a"
		admin = "62e90394-69f5-4237-9190-012177145e10"
		vm    = "/subscriptions/" + sub1 + "/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1"
		role  = "/subscriptions/" + sub1 + "/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c"
	)
	all, err := catalog.Build(&config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{"azure-compute": {"resources"}, "azure-access": {"role-definitions"}, "m365-roles": {"principal-roles"}, "m365-applications": {"applications", "service-principals"}}
	var mods []catalog.Module
	for _, m := range all {
		var srcs []catalog.Source
		for _, s := range m.Sources {
			if slices.Contains(want[m.ID], s.ID) {
				srcs = append(srcs, s)
			}
		}
		if m.Sources = srcs; len(srcs) > 0 {
			mods = append(mods, m)
		}
	}
	h := newHarness(t, mods)
	h.api.set(func() {
		h.api.graphRows["resources"] = []obj{
			{"id": vm, "name": "vm1", "type": "microsoft.compute/virtualmachines", "subscriptionId": sub1, "resourceGroup": "rg", "location": "westeurope", "properties": obj{"vmSize": "D2"}},
			{"id": vm + "/extensions/AzureMonitor", "name": "AzureMonitor", "type": "microsoft.compute/virtualmachines/extensions", "subscriptionId": sub1, "resourceGroup": "rg", "location": "westeurope", "properties": obj{"publisher": "Microsoft.Azure.Monitor"}},
			{"id": strings.Replace(vm, "vm1", "vm2", 1), "name": "vm2", "type": "microsoft.compute/virtualmachines", "subscriptionId": sub1, "resourceGroup": "rg", "location": "westeurope", "properties": obj{"vmSize": "D2"}},
		}
		h.api.graphRows["authorizationresources"] = []obj{
			{"id": role, "name": "b24988ac-6180-42a0-ab88-20f7382dd24c", "type": "microsoft.authorization/roledefinitions", "roleName": "Contributor", "properties": obj{"roleName": "Contributor", "type": "CustomRole"}},
			{"id": "/subscriptions/" + sub1 + "/providers/Microsoft.Authorization/roleAssignments/ra1", "name": "ra1", "type": "microsoft.authorization/roleassignments",
				"principalId": sp, "roleDefinitionId": role, "scope": "/subscriptions/" + sub1, "properties": obj{"principalId": sp, "roleDefinitionId": role, "scope": "/subscriptions/" + sub1}},
		}
		h.api.lists["/v1.0/directoryObjects/getByIds"] = []obj{{"id": alice, "displayName": "Alice Smith", "@odata.type": "#microsoft.graph.user"}, {"id": sp, "displayName": "Intranet", "@odata.type": "#microsoft.graph.servicePrincipal"}}
		h.api.lists["/v1.0/roleManagement/directory/roleDefinitions"] = []obj{{"id": admin, "templateId": admin, "displayName": "Global Administrator"}}
		h.api.lists["/v1.0/roleManagement/directory/roleAssignments"] = []obj{{"id": "d1", "principalId": alice, "roleDefinitionId": admin, "directoryScopeId": "/"}}
		h.api.lists["/v1.0/servicePrincipals"] = []obj{{"id": sp, "appId": appID, "displayName": "Intranet", "servicePrincipalType": "Application"}}
		h.api.lists["/v1.0/applications"] = []obj{{"id": "app-object", "appId": appID, "displayName": "Intranet"}, {"id": "app-2", "appId": "none", "displayName": "No principal"}}
		h.api.lists["/v1.0/oauth2PermissionGrants"] = []obj{}
	})
	if r := h.run(t); r.Status != model.StatusSuccess {
		t.Fatalf("run: %s\n%s", r.Status, h.log)
	}
	items := h.items()
	if v := items["azure-compute/resources/vm1"]; !strings.Contains(v.Config, `"extensions":[{`) || !strings.Contains(v.Config, `"name":"AzureMonitor"`) {
		t.Errorf("the extension is not inside its machine: %s", v.Config)
	}
	if v := items["azure-compute/resources/vm2"]; !strings.Contains(v.Config, `"extensions":[]`) {
		t.Errorf("a machine without extensions: %s", v.Config)
	}
	if n := len(itemsOf(items, "azure-compute")); n != 2 {
		t.Errorf("an extension is stored as an object of its own: %v", keys(itemsOf(items, "azure-compute")))
	}
	if _, ok := items["azure-access/role-definitions/Contributor"]; !ok {
		t.Errorf("role definition not named by its role name: %v", keys(itemsOf(items, "azure-access")))
	}
	// The service principal and its app registration both carry its Azure role, named.
	azRole := `"azureRoles":[{"roleDefinitionId":"` + role + `","scope":"/subscriptions/` + sub1 + `"}]`
	for _, k := range []string{"m365-applications/service-principals/Intranet", "m365-applications/applications/Intranet"} {
		if it := items[k]; !strings.Contains(it.Config, azRole) || !strings.Contains(it.Config, `"directoryRoles":[]`) || it.Refs[role] != "Contributor" {
			t.Errorf("%s: %s %v", k, it.Config, it.Refs)
		}
	}
	if it := items["m365-applications/applications/No principal"]; !strings.Contains(it.Config, `"azureRoles":[]`) {
		t.Errorf("an application without a service principal has no roles: %s", it.Config)
	}
	// One object per principal that holds a role: the user and the application.
	u := items["m365-roles/principal-roles/Alice Smith"]
	if !strings.Contains(u.Config, `"directoryRoles":[{"directoryScopeId":"/","roleDefinitionId":"`+admin+`"}]`) || !strings.Contains(u.Config, `"principalType":"user"`) || u.Refs[admin] != "Global Administrator" {
		t.Errorf("roles of the user: %s %v\n%v", u.Config, u.Refs, keys(itemsOf(items, "m365-roles")))
	}
	if a := items["m365-roles/principal-roles/Intranet"]; !strings.Contains(a.Config, azRole) {
		t.Errorf("roles of the application: %s", a.Config)
	}
	// A role granted to the user shows as a change to that user.
	before := len(h.st.Changes)
	h.api.set(func() {
		h.api.graphRows["authorizationresources"] = append(h.api.graphRows["authorizationresources"], obj{"id": "/subscriptions/" + sub1 + "/providers/Microsoft.Authorization/roleAssignments/ra2", "name": "ra2",
			"type": "microsoft.authorization/roleassignments", "principalId": alice, "roleDefinitionId": role, "scope": "/subscriptions/" + sub1, "properties": obj{}})
	})
	h.run(t)
	found := false
	for _, c := range h.st.Changes[before:] {
		found = found || (c.Source == "principal-roles" && c.Name == "Alice Smith" && c.Kind == model.ChangeChanged)
	}
	if !found {
		t.Errorf("the new role is not a change to the user: %+v", h.st.Changes[before:])
	}
}

// A tenant can have switches and exclusions of its own; a default that is
// enforced wins over them.
func TestTenantLevelSwitchesAndExclusions(t *testing.T) {
	h := newHarness(t, []catalog.Module{{ID: "azure-governance", Platform: model.PlatformAzure, Name: "Governance", DefaultEnabled: true, Sources: []catalog.Source{
		{ID: "containers", Name: "Containers", Kind: catalog.KindARG, Table: "resourcecontainers", Permission: "Reader"},
	}}})
	h.st.Switches = []model.ModuleSwitches{
		{ID: "azure-governance", Enabled: flag(true)},
		{ID: tenantID + "/azure-governance", TenantID: tenantID, Module: "azure-governance", Enabled: flag(false)},
		{ID: "other-tenant/azure-governance", TenantID: "other-tenant", Module: "azure-governance", Sources: map[string]model.SourceSwitches{"containers": {Enabled: flag(false)}}},
	}
	h.api.set(func() {
		h.api.graphRows["resourcecontainers"] = []obj{{"id": "/subscriptions/" + sub1 + "/resourceGroups/rg-a", "name": "rg-a", "type": "microsoft.resources/subscriptions/resourcegroups", "subscriptionId": sub1, "location": "westeurope", "properties": obj{"x": 1}}}
	})
	h.run(t)
	if len(itemsOf(h.items(), "azure-governance")) != 0 {
		t.Error("the tenant switched the module off for itself, and it was collected")
	}
	if !h.st.States["azure-governance"].Enabled {
		t.Error("the default stays on for the other tenants")
	}
	// Enforced: the tenant's own switch no longer counts.
	h.st.Switches[0].Enforced = true
	h.run(t)
	if len(itemsOf(h.items(), "azure-governance")) == 0 {
		t.Error("an enforced default must win over the tenant's switch")
	}

	c := &config.Config{Exclude: []config.ExcludeRule{
		{Type: "microsoft.network/networkwatchers"},
		{Type: "microsoft.insights/", Enforced: true},
		{Tenant: "t1", Type: "microsoft.network/networkwatchers", Include: true},
		{Tenant: "t1", Type: "microsoft.insights/", Include: true},
		{Tenant: "t2", ResourceGroup: "rg-lab"},
	}}
	for _, x := range []struct {
		tenant, typ, rg string
		want            bool
	}{
		{"t9", "microsoft.network/networkwatchers", "rg", true},  // the rule for everyone
		{"t1", "microsoft.network/networkwatchers", "rg", false}, // the tenant keeps it
		{"t1", "microsoft.insights/components", "rg", true},      // enforced: the tenant cannot
		{"t2", "microsoft.compute/disks", "rg-lab", true},        // the tenant leaves out more
		{"t9", "microsoft.compute/disks", "rg-lab", false},
	} {
		if got := c.Excluded(x.tenant, "m", x.typ, x.rg, "n"); got != x.want {
			t.Errorf("%s %s %s: excluded %v, want %v", x.tenant, x.typ, x.rg, got, x.want)
		}
	}
	if _, err := config.Parse([]byte(`{"mongo": {"uri": "x"}, "tenants": [{"tenantName": "C", "tenantId": "`+tenantID+`", "clientId": "c", "clientSecret": "s"}], "exclude": [{"tenant": "`+tenantID+`", "type": "x", "enforced": true}]}`), func(string) string { return "" }, nil); err == nil {
		t.Error("a tenant's rule cannot be enforced")
	}
}

// Replicas never read the same tenant at once, nor one after the other in
// the same round; every completed run leaves a snapshot, and the history
// of a setting keeps when it first changed and every value since.
func TestReplicasSnapshotsAndHistory(t *testing.T) {
	h := newHarness(t, []catalog.Module{{ID: "azure-governance", Platform: model.PlatformAzure, Name: "Governance", DefaultEnabled: true, Sources: []catalog.Source{
		{ID: "containers", Name: "Containers", Kind: catalog.KindARG, Table: "resourcecontainers", Permission: "Reader"},
	}}})
	rg := func(tag string) []obj {
		return []obj{{"id": "/subscriptions/" + sub1 + "/resourceGroups/rg-a", "name": "rg-a", "type": "microsoft.resources/subscriptions/resourcegroups", "subscriptionId": sub1, "location": "westeurope", "tags": obj{"env": tag}}}
	}
	h.api.set(func() { h.api.graphRows["resourcecontainers"] = rg("dev") })
	ctx := context.Background()
	h.c.Owner = "replica-a"

	// Another replica holds the tenant: this one leaves it alone.
	if ok, _ := h.st.AcquireTenant(ctx, tenantID, "replica-b", time.Minute, time.Now()); !ok {
		t.Fatal("the lease was free")
	}
	r := h.run(t)
	if r.Status != model.StatusSuccess || len(r.Tenants) != 1 || r.Tenants[0].Status != model.StatusSkipped || len(h.items()) != 0 || len(h.st.Snapshots) != 0 {
		t.Fatalf("a held tenant must be skipped: %s %+v", r.Status, r.Tenants)
	}
	// It finished a moment ago: still not ours in this round, with a gap set.
	h.st.ReleaseTenant(ctx, tenantID, "replica-b", true)
	h.c.MinGap = time.Hour
	if r = h.run(t); r.Tenants[0].Status != model.StatusSkipped {
		t.Errorf("a tenant another replica just finished: %+v", r.Tenants[0])
	}
	// Asked for from the dashboard, it is read all the same.
	if r = h.c.Run(ctx, "request", nil); r.Tenants[0].Status != model.StatusSuccess || len(h.items()) != 1 {
		t.Fatalf("a requested pass: %+v\n%s", r.Tenants, h.log)
	}
	if l := h.st.Leases[tenantID]; l.Owner != "" || l.DoneBy != "replica-a" {
		t.Errorf("the lease is given up when the tenant is done: %+v", l)
	}
	// What this replica finished itself does not hold it back.
	if r = h.run(t); r.Tenants[0].Status != model.StatusSuccess {
		t.Errorf("own tenant on the next pass: %+v", r.Tenants[0])
	}
	// A lease whose holder died is taken over once it has expired.
	h.st.Leases[tenantID] = store.Lease{Owner: "replica-dead", ExpiresAt: time.Now().Add(-time.Second)}
	if r = h.run(t); r.Tenants[0].Status != model.StatusSuccess {
		t.Errorf("an expired lease: %+v", r.Tenants[0])
	}

	// Two changes of the same setting in two runs: one history, two entries.
	snaps := len(h.st.Snapshots)
	h.api.set(func() { h.api.graphRows["resourcecontainers"] = rg("test") })
	first := h.run(t)
	h.api.set(func() { h.api.graphRows["resourcecontainers"] = rg("prod") })
	second := h.run(t)
	h.run(t) // nothing changes
	var hist []model.SettingHistory
	for _, x := range h.st.History {
		hist = append(hist, x)
	}
	if len(hist) != 1 || hist[0].Path != "tags.env" || len(hist[0].Changes) != 2 {
		t.Fatalf("history: %+v", hist)
	}
	c := hist[0].Changes
	if c[0].RunID != first.ID || c[0].Before != `"dev"` || c[0].After != `"test"` || c[1].RunID != second.ID || c[1].After != `"prod"` || !hist[0].FirstAt.Equal(c[0].At) || !hist[0].LastAt.Equal(c[1].At) {
		t.Errorf("the entries keep the run each value was first seen in: %+v", hist[0])
	}
	got := h.st.Snapshots[snaps:]
	if len(got) != 3 || got[0].ID != first.ID || got[0].Settings != 1 || got[0].Objects != 1 || got[2].Settings != 0 || len(got[0].Tenants) != 1 {
		t.Errorf("one snapshot per completed run: %+v", got)
	}
}

// Sentinel's content is read per workspace that Sentinel is enabled on,
// and named by its display name.
func TestSentinelPerWorkspace(t *testing.T) {
	all, err := catalog.Build(&config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	var mods []catalog.Module
	for _, m := range all {
		if m.ID == "azure-sentinel" {
			mods = append(mods, m)
		}
	}
	if len(mods) != 1 || len(mods[0].Sources) != 11 {
		t.Fatalf("the Sentinel module: %+v", mods)
	}
	ws := func(name string) string {
		return "/subscriptions/" + sub1 + "/resourceGroups/rg-sec/providers/Microsoft.OperationalInsights/workspaces/" + name
	}
	si := "/providers/Microsoft.SecurityInsights/"
	// Requests carry the workspace as Resource Graph gave it: in lower case.
	at := func(name string) string { return strings.ToLower(ws(name)) }
	h := newHarness(t, mods)
	h.api.set(func() {
		h.api.graphRows["resources"] = []obj{
			{"id": ws("law-sentinel"), "name": "law-sentinel", "type": "microsoft.operationalinsights/workspaces", "subscriptionId": sub1, "resourceGroup": "rg-sec"},
			{"id": ws("law-plain"), "name": "law-plain", "type": "microsoft.operationalinsights/workspaces", "subscriptionId": sub1, "resourceGroup": "rg-sec"},
		}
		h.api.lists[at("law-sentinel")+si+"onboardingStates"] = []obj{{"id": ws("law-sentinel") + si + "onboardingStates/default", "name": "default", "type": "Microsoft.SecurityInsights/onboardingStates", "properties": obj{"customerManagedKey": false}}}
		h.api.lists[at("law-plain")+si+"onboardingStates"] = []obj{}
		h.api.lists[at("law-sentinel")+si+"alertRules"] = []obj{{"id": ws("law-sentinel") + si + "alertRules/1111", "name": "1111", "type": "Microsoft.SecurityInsights/alertRules", "kind": "Scheduled", "etag": "\"a\"",
			"properties": obj{"displayName": "Brute force", "enabled": true, "severity": "High", "query": "SigninLogs | take 1", "lastModifiedUtc": "2026-01-01T00:00:00Z"}}}
		h.api.lists[at("law-sentinel")+si+"automationRules"] = []obj{{"id": ws("law-sentinel") + si + "automationRules/2222", "name": "2222", "type": "Microsoft.SecurityInsights/automationRules",
			"properties": obj{"displayName": "Close noise", "order": 1}}}
		h.api.lists[at("law-sentinel")+"/tables"] = []obj{{"id": ws("law-sentinel") + "/tables/SecurityEvent", "name": "SecurityEvent", "type": "Microsoft.OperationalInsights/workspaces/tables",
			"properties": obj{"retentionInDays": 90, "totalRetentionInDays": 730, "plan": "Analytics", "provisioningState": "Succeeded", "schema": obj{"name": "SecurityEvent", "columns": []obj{{"name": "Account"}}}}}}
		// A workspace without Sentinel must never be asked for rules.
		h.api.lists[at("law-plain")+si+"alertRules"] = []obj{{"id": ws("law-plain") + si + "alertRules/x", "name": "x", "type": "Microsoft.SecurityInsights/alertRules", "properties": obj{"displayName": "Must not appear"}}}
	})
	if r := h.run(t); r.Status != model.StatusSuccess {
		t.Fatalf("run: %s\n%s", r.Status, h.log)
	}
	items := h.items()
	rule := items["azure-sentinel/alert-rules/Brute force"]
	if rule.Type != "microsoft.securityinsights/alertrules" || rule.ResourceGroup != "rg-sec" || rule.SubscriptionID != sub1 || !strings.Contains(rule.Key, "/workspaces/law-sentinel/") ||
		!strings.Contains(rule.Config, `"severity":"High"`) || strings.Contains(rule.Config, "etag") || strings.Contains(rule.Config, "lastModifiedUtc") {
		t.Errorf("analytics rule: %+v\n%v", rule, keys(items))
	}
	if _, ok := items["azure-sentinel/automation-rules/Close noise"]; !ok {
		t.Errorf("automation rule missing: %v", keys(items))
	}
	if tb := items["azure-sentinel/table-retention/SecurityEvent"]; !strings.Contains(tb.Config, `"totalRetentionInDays":730`) || !strings.Contains(tb.Config, `"plan":"Analytics"`) || strings.Contains(tb.Config, "schema") || strings.Contains(tb.Config, "provisioningState") {
		t.Errorf("table retention: %s", tb.Config)
	}
	if _, ok := items["azure-sentinel/alert-rules/Must not appear"]; ok {
		t.Error("a workspace without Sentinel was read")
	}
	// A rule edited in the portal is a change to that rule.
	before := len(h.st.Changes)
	h.api.set(func() {
		h.api.lists[at("law-sentinel")+si+"alertRules"][0]["properties"] = obj{"displayName": "Brute force", "enabled": false, "severity": "High", "query": "SigninLogs | take 1", "lastModifiedUtc": "2026-02-02T00:00:00Z"}
	})
	h.run(t)
	if got := h.st.Changes[before:]; len(got) != 1 || got[0].Name != "Brute force" || len(got[0].Paths) != 1 || got[0].Paths[0].Path != "properties.enabled" {
		t.Errorf("a disabled rule: %+v", got)
	}
}

// Defender XDR: custom detections and identity sensors from Graph, and
// indicators from the Defender for Endpoint API with its own token.
func TestDefenderModule(t *testing.T) {
	all, err := catalog.Build(&config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	var mods []catalog.Module
	for _, m := range all {
		if m.ID == "m365-defender" {
			mods = append(mods, m)
		}
	}
	if len(mods) != 1 {
		t.Fatal("no Defender module")
	}
	h := newHarness(t, mods)
	h.api.set(func() {
		h.api.lists["/beta/security/rules/detectionRules"] = []obj{{"id": "35079", "displayName": "LOLBin to rare TLD", "isEnabled": true,
			"queryCondition": obj{"queryText": "DeviceNetworkEvents | take 1"}, "schedule": obj{"period": "24H"}, "lastRunDetails": obj{"lastRunDateTime": "2026-01-01T00:00:00Z", "status": "completed"}}}
		h.api.lists["/v1.0/security/identities/sensors"] = []obj{{"id": "s-1", "displayName": "DC1", "sensorType": "domainControllerIntegrated", "healthStatus": "healthy", "version": "2.240.1",
			"settings": obj{"description": "", "isDelayedDeploymentEnabled": false}}}
		h.api.lists["/api/indicators"] = []obj{{"id": "17", "indicatorValue": "evil.example", "indicatorType": "DomainName", "action": "Block", "title": "Block evil.example", "severity": "High"}}
		h.api.logins = nil
	})
	if r := h.run(t); r.Status != model.StatusSuccess {
		t.Fatalf("run: %s\n%s", r.Status, h.log)
	}
	items := h.items()
	if d := items["m365-defender/detection-rules/LOLBin to rare TLD"]; !strings.Contains(d.Config, `"period":"24H"`) || strings.Contains(d.Config, "lastRunDetails") {
		t.Errorf("custom detection: %s\n%v", d.Config, keys(items))
	}
	if s := items["m365-defender/identity-sensors/DC1"]; !strings.Contains(s.Config, `"sensorType":"domainControllerIntegrated"`) || strings.Contains(s.Config, "healthStatus") || strings.Contains(s.Config, `"version"`) {
		t.Errorf("sensor: %s", s.Config)
	}
	if i := items["m365-defender/indicators/Block evil.example"]; i.Type != "indicators" || !strings.Contains(i.Config, `"action":"Block"`) {
		t.Errorf("indicator: %+v", i)
	}
	// The indicators were asked for with a token for the Defender API, not Graph's.
	scopes := map[string]bool{}
	for _, l := range h.api.logins {
		scopes[l["scope"]] = true
	}
	if len(scopes) < 2 {
		t.Errorf("the Defender API needs a token of its own: %v", h.api.logins)
	}
}
