package collector

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/jercle/datafetch/azconfigdrift/internal/config"

	"github.com/jercle/datafetch/azconfigdrift/internal/catalog"
	"github.com/jercle/datafetch/azconfigdrift/internal/model"
)

// A cloud without a Defender for Endpoint API: the source is not
// supported there, rather than failed.
func TestDefenderAPIMissingInACloud(t *testing.T) {
	h := newHarness(t, []catalog.Module{{ID: "m365-defender", Platform: model.PlatformM365, Name: "Defender", DefaultEnabled: true, Sources: []catalog.Source{
		{ID: "indicators", Name: "Indicators", Kind: catalog.KindMDE, Path: "/api/indicators", Type: "indicators"},
	}}})
	e := h.c.Cfg.Tenants[0].Endpoints
	e.Defender, e.DefenderScope = "", ""
	h.c.Cfg.Tenants[0].Endpoints = e
	h.run(t)
	if s := h.source(t, "m365-defender", "indicators"); s.Status != model.SourceUnsupported {
		t.Errorf("source %+v", s)
	}
}

// Settings Resource Graph does not have are read per resource and named
// after it; SharePoint and Power Platform have APIs of their own; Teams
// policies come from the embedded PowerShell script.
func TestPerResourceAndOtherAPIs(t *testing.T) {
	all, err := catalog.Build(&config.Config{ModuleDefaults: map[string]bool{"m365-teams": true}})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{"azure-data": {"storage-blob-settings", "sql-firewall-rules"}, "azure-monitoring": {"resource-diagnostics"}, "azure-governance": {"budgets"},
		"m365-sharepoint": {"tenant"}, "m365-power-platform": {"tenant-settings", "dlp-policies", "environments"}, "m365-teams": {"meeting-policies", "federation", "guest-calling"}}
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
	// A stand-in for pwsh: prints what the script would, and what it was given.
	dir := t.TempDir()
	fake := filepath.Join(dir, "pwsh")
	script := "#!/bin/sh\nprintf '%s %s %s' \"$ACD_GRAPH_TOKEN\" \"$ACD_TEAMS_TOKEN\" \"$ACD_CMDLETS\" > " + dir + "/seen\necho \"$@\" > " + dir + "/args\n" +
		`echo 'WARNING: noise {"Get-CsTeamsMeetingPolicy":{"items":[{"Identity":"Global","AllowCloudRecording":true},{"Identity":"Tag:Restricted","AllowCloudRecording":false}]},` +
		`"Get-CsTenantFederationConfiguration":{"items":[{"Identity":"Global","AllowFederatedUsers":true}]},"Get-CsTeamsGuestCallingConfiguration":{"error":"Access Denied."}}'` + "\n"
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	old := pwshCommand
	pwshCommand = fake
	defer func() { pwshCommand = old }()

	st := "/subscriptions/" + sub1 + "/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/stprod"
	sql := "/subscriptions/" + sub1 + "/resourceGroups/rg/providers/Microsoft.Sql/servers/sqlprod"
	low := strings.ToLower
	h := newHarness(t, mods)
	h.c.Cfg.Tenants[0].Username, h.c.Cfg.Tenants[0].Password = "svc@contoso.com", "pw"
	h.api.set(func() {
		h.api.graphRows["resources"] = []obj{
			{"id": st, "name": "stprod", "type": "microsoft.storage/storageaccounts", "subscriptionId": sub1},
			{"id": sql, "name": "sqlprod", "type": "microsoft.sql/servers", "subscriptionId": sub1},
		}
		h.api.objects[low(st)+"/blobServices/default"] = obj{"id": st + "/blobServices/default", "name": "default", "type": "Microsoft.Storage/storageAccounts/blobServices",
			"properties": obj{"deleteRetentionPolicy": obj{"enabled": true, "days": 14}}}
		h.api.lists[low(sql)+"/firewallRules"] = []obj{{"id": sql + "/firewallRules/AllowAll", "name": "AllowAll", "type": "Microsoft.Sql/servers/firewallRules", "properties": obj{"startIpAddress": "0.0.0.0", "endIpAddress": "255.255.255.255"}}}
		h.api.lists[low(st)+"/providers/Microsoft.Insights/diagnosticSettings"] = []obj{{"id": st + "/providers/microsoft.insights/diagnosticSettings/to-law", "name": "to-law", "type": "Microsoft.Insights/diagnosticSettings",
			"properties": obj{"workspaceId": "/subscriptions/x/law"}}}
		h.api.lists["/subscriptions/"+sub1+"/providers/Microsoft.Consumption/budgets"] = []obj{{"id": "/subscriptions/" + sub1 + "/providers/Microsoft.Consumption/budgets/monthly", "name": "monthly", "type": "Microsoft.Consumption/budgets",
			"properties": obj{"amount": 1000, "currentSpend": obj{"amount": 12.5}}}}
		h.api.objects["/_api/SPO.Tenant"] = obj{"SharingCapability": 1, "LegacyAuthProtocolsEnabled": false, "StorageQuotaAllocated": 99}
		h.api.objects["/providers/Microsoft.BusinessAppPlatform/listTenantSettings"] = obj{"disableTrialEnvironmentCreationByNonAdminUsers": true}
		h.api.lists["/providers/PowerPlatform.Governance/v2/policies"] = []obj{{"name": "p-1", "displayName": "Block social"}}
		h.api.lists["/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments"] = []obj{{"name": "env-1", "properties": obj{"displayName": "Production", "environmentSku": "Production"}}}
	})
	h.run(t)
	items := h.items()
	for key, has := range map[string]string{
		"azure-data/storage-blob-settings/stprod":               `"days":14`,
		"azure-data/sql-firewall-rules/sqlprod / AllowAll":      `"endIpAddress":"255.255.255.255"`,
		"azure-monitoring/resource-diagnostics/stprod / to-law": `"workspaceId"`,
		"azure-governance/budgets/monthly":                      `"amount":1000`,
		"m365-sharepoint/tenant/Tenant settings":                `"SharingCapability":1`,
		"m365-power-platform/tenant-settings/Tenant settings":   `"disableTrialEnvironmentCreationByNonAdminUsers":true`,
		"m365-power-platform/dlp-policies/Block social":         `"displayName":"Block social"`,
		"m365-power-platform/environments/Production":           `"environmentSku":"Production"`,
		"m365-teams/meeting-policies/Tag:Restricted":            `"AllowCloudRecording":false`,
		"m365-teams/federation/Global":                          `"AllowFederatedUsers":true`,
	} {
		if it, ok := items[key]; !ok || !strings.Contains(it.Config, has) {
			t.Errorf("%s: %q not in %s\n%v", key, has, it.Config, keys(items))
		}
	}
	if b := items["azure-governance/budgets/monthly"]; strings.Contains(b.Config, "currentSpend") {
		t.Error("what was spent is not a setting")
	}
	if s := items["m365-sharepoint/tenant/Tenant settings"]; strings.Contains(s.Config, "StorageQuotaAllocated") {
		t.Error("what is used is not a setting")
	}
	// One cmdlet refused: that source is denied, the others are read.
	if s := h.source(t, "m365-teams", "guest-calling"); s.Status != model.SourceDenied {
		t.Errorf("a refused cmdlet: %+v", s)
	}
	// The script ran once for all three cmdlets, with tokens in its environment and none on its command line.
	seen, _ := os.ReadFile(filepath.Join(dir, "seen"))
	args, _ := os.ReadFile(filepath.Join(dir, "args"))
	got := strings.Fields(string(seen))
	if len(got) != 3 || got[0] == "" || got[1] == "" || got[2] != "Get-CsTeamsMeetingPolicy,Get-CsTenantFederationConfiguration,Get-CsTeamsGuestCallingConfiguration" {
		t.Errorf("what the script was given: %q", seen)
	}
	// What the script is given never appears among its arguments.
	if strings.Contains(string(args), got[2]) || !strings.Contains(string(args), "-NonInteractive") {
		t.Errorf("the script's input was passed on the command line: %.200s", args)
	}
	// Without PowerShell the Teams sources are unsupported, not failed.
	pwshCommand = filepath.Join(dir, "no-such-pwsh")
	h.run(t)
	if s := h.source(t, "m365-teams", "meeting-policies"); s.Status != model.SourceUnsupported {
		t.Errorf("without pwsh: %+v", s)
	}
}
