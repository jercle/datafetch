package azurecves

import (
	"os"
	"strings"
	"testing"

	"github.com/jercle/datafetch/azurecves/pkg/config"

	"github.com/jercle/datafetch/internal/settings"
)

// merged lays settings over a configuration file and expects every one of
// them to be taken.
func merged(t *testing.T, file []byte, flat map[string]any, applied int) []byte {
	t.Helper()
	keyed := map[string]any{}
	for k, v := range flat {
		keyed[settings.Key(Spec.Tool)+"."+k] = v
	}
	r, err := settings.Merge(file, settings.Nest(keyed), Spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Warnings) != 0 || r.Applied != applied {
		t.Fatalf("applied %d of %d settings; warnings:\n%s", r.Applied, applied, strings.Join(r.Warnings, "\n"))
	}
	return r.Config
}

func none(string) string { return "" }

const tenant = "aaaaaaaa-0000-0000-0000-000000000001"

func TestSettingsAlone(t *testing.T) {
	b := merged(t, []byte("{}"), map[string]any{
		"mongo.uri":                           "mongodb://db",
		"mongo.database":                      "cves",
		"interval":                            "1d",
		"tenantConcurrency":                   "2",
		"disable":                             "costs, containers",
		"hostnameFallback":                    "false",
		"costs.enabled":                       false,
		"monitoring.logRetentionDays":         "14",
		"deviceGroups":                        `[{"name": "Servers", "hidden": true, "names": ["srv*"]}]`,
		"tenants." + tenant + ".tenantName":   "Contoso",
		"tenants." + tenant + ".clientId":     "client",
		"tenants." + tenant + ".clientSecret": "secret",
	}, 12)
	c, err := config.Parse(b, none)
	if err != nil {
		t.Fatal(err)
	}
	if c.Mongo.Database != "cves" || time24(c) != 24 || c.TenantConcurrency != 2 || c.Enabled("costs") || c.Enabled("containers") || !c.Enabled("devices") ||
		c.HostnameFallback == nil || *c.HostnameFallback || c.Monitoring.LogRetentionDays != 14 || len(c.DeviceGroups) != 1 {
		t.Errorf("%+v", c)
	}
	if len(c.Tenants) != 1 || c.Tenants[0].ID != tenant || c.Tenants[0].Name != "Contoso" || c.Tenants[0].ClientSecret != "secret" {
		t.Errorf("%+v", c.Tenants)
	}
}

func time24(c *config.Config) float64 { return float64(c.Interval) / 3.6e12 }

func TestSettingsOverTheExampleFile(t *testing.T) {
	file, err := os.ReadFile("deploy/config.example.json")
	if err != nil {
		t.Fatal(err)
	}
	before, err := config.Parse(merged(t, file, nil, 0), none)
	if err != nil {
		t.Fatalf("the file alone, through the merge: %v", err)
	}
	first := before.Tenants[0]
	c, err := config.Parse(merged(t, file, map[string]any{
		"tenants." + first.ID + ".clientSecret": "from-app-config",
		"tenants." + tenant + ".clientId":       "c",
		"tenants." + tenant + ".clientSecret":   "s",
		"interval":                              "90m",
	}, 4), none)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Tenants) != len(before.Tenants)+1 || c.Tenants[0].Name != first.Name || c.Tenants[0].ClientSecret != "from-app-config" ||
		len(c.DeviceGroups) != len(before.DeviceGroups) || time24(c) != 1.5 {
		t.Errorf("%+v", c)
	}
	// The environment still overrides both.
	c, err = config.Parse(merged(t, file, map[string]any{"mongo.database": "x"}, 1), func(k string) string {
		return map[string]string{"AZCVES_DB": "from-env"}[k]
	})
	if err != nil || c.Mongo.Database != "from-env" {
		t.Errorf("%+v %v", c, err)
	}
}
