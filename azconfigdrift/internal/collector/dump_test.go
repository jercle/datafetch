package collector

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/jercle/datafetch/azconfigdrift/internal/config"
	"github.com/jercle/datafetch/azconfigdrift/internal/model"
)

// TestDumpForDashboard writes what the collector stores after one pass and
// after a second one against a baseline, as the fixtures of the dashboard's
// tests. It only runs when asked to:
//
//	ACD_DUMP=$PWD/dashboard/test/fixtures go test ./internal/collector -run TestDumpForDashboard
//
// The baseline's id is the text BASELINE; the dashboard's test puts the id
// of the baseline it saved itself in its place.
func TestDumpForDashboard(t *testing.T) {
	dir := os.Getenv("ACD_DUMP")
	if dir == "" {
		t.Skip("ACD_DUMP is not set")
	}
	h := newHarness(t, testModules())
	dump := func(name string) {
		mods := []map[string]any{}
		for _, m := range testModules() {
			b, _ := json.Marshal(h.st.Modules[m.ID])
			var d map[string]any
			_ = json.Unmarshal(b, &d)
			st := h.st.States[m.ID]
			d["enabled"], d["disabledSources"], d["sourceBeta"], d["sourceDelegated"] = st.Enabled, append([]string{}, st.DisabledSources...), st.SourceBeta, st.SourceDelegated
			mods = append(mods, d)
		}
		out := map[string]any{
			model.CollModules: mods, model.CollItems: h.st.Items, model.CollTenants: h.st.Tenants, model.CollChanges: h.st.Changes,
			model.CollRuns: h.st.Runs, model.CollInstances: h.st.Instances,
		}
		b, _ := json.MarshalIndent(out, "", " ")
		if err := os.WriteFile(dir+"/"+name, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	h.run(t)
	dump("pass1.json")

	h.st.SaveBaseline("BASELINE")
	h.api.set(func() {
		rows := h.api.graphRows["resources"]
		// Changed: three settings of the virtual network.
		rows[0]["properties"].(obj)["enableDdosProtection"] = true
		rows[0]["properties"].(obj)["addressSpace"].(obj)["addressPrefixes"] = []any{"10.0.0.0/16"}
		rows[0]["tags"].(obj)["owner"] = "network team"
		// Removed: the NSG. Added: a public IP.
		rows[1] = obj{"id": "/subscriptions/" + sub1 + "/resourceGroups/rg-net/providers/Microsoft.Network/publicIPAddresses/pip-1", "name": "pip-1",
			"type": "microsoft.network/publicipaddresses", "subscriptionId": sub1, "resourceGroup": "rg-net", "properties": obj{"publicIPAllocationMethod": "Static"}}
		h.api.lists["/v1.0/identity/conditionalAccess/policies"][1]["state"] = "disabled"
		// A source that lost its permission.
		h.api.status["/beta/deviceManagement/configurationPolicies"] = 403
	})
	// A module switched on after the baseline.
	h.c.Cfg.Modules = map[string]config.ModuleSetting{"m365-exchange": {Enabled: flag(true)}}
	h.run(t)
	dump("pass2.json")
}
