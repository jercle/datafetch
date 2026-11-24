package azstorage

import (
	"os"
	"strings"
	"testing"

	"github.com/jercle/datafetch/azstorage/internal/config"

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

// Everything can come from App Configuration: no file at all.
func TestSettingsAlone(t *testing.T) {
	b := merged(t, nil, map[string]any{
		"mongo.uri":                            "mongodb://db",
		"interval":                             "12h",
		"concurrency.accounts":                 "16",
		"collect.disks":                        "false",
		"containerSizes.excludeAccounts":       "stdiag*, TMP*",
		"containerSizes.maxBlobs":              "-1",
		"containerSizes.timeout":               "10m",
		"tenants." + tenant + ".tenantName":    "Contoso",
		"tenants." + tenant + ".clientId":      "client",
		"tenants." + tenant + ".clientSecret":  "secret",
		"tenants." + tenant + ".subscriptions": "aaaaaaaa-0000-0000-0000-00000000000a",
	}, 11)
	c, err := config.Parse(b, none, os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	if c.Mongo.URI != "mongodb://db" || c.Interval.D().Hours() != 12 || c.Concurrency.Accounts != 16 || c.CollectDisks() || !c.CollectUsage() ||
		!c.SizeExcluded("tmp1") || c.ContainerSizes.MaxBlobs != -1 || c.ContainerSizes.Timeout.D().Minutes() != 10 {
		t.Errorf("%+v", c)
	}
	if len(c.Tenants) != 1 || c.Tenants[0].ID != tenant || c.Tenants[0].Name != "Contoso" || c.Tenants[0].ClientSecret != "secret" || len(c.Tenants[0].Subscriptions) != 1 {
		t.Errorf("%+v", c.Tenants)
	}
}

// The settings are laid over the example file, tenant by tenant.
func TestSettingsOverTheExampleFile(t *testing.T) {
	file, err := os.ReadFile("deploy/config.example.json")
	if err != nil {
		t.Fatal(err)
	}
	env := func(k string) string {
		// The secrets the file names variables for; none of the tool's own
		// overrides of the database, the list and its file.
		for _, own := range []string{"_MONGO_URI", "_MONGO_DATABASE", "_FILE", "_TENANTS", "_APPLIANCES", "_FIREWALLS"} {
			if strings.HasSuffix(k, own) {
				return ""
			}
		}
		return "from-" + k
	}
	before, err := config.Parse(merged(t, file, nil, 0), env, os.ReadFile)
	if err != nil {
		t.Fatalf("the file alone, through the merge: %v", err)
	}
	first := before.Tenants[0]
	c, err := config.Parse(merged(t, file, map[string]any{
		"retention.logsDays": 7,
		"tenants." + strings.ToUpper(first.ID) + ".clientSecret": "from-app-config",
		"tenants." + tenant + ".tenantName":                      "New",
		"tenants." + tenant + ".clientId":                        "c",
		"tenants." + tenant + ".clientSecret":                    "s",
	}, 5), env, os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	if c.Retention.LogsDays != 7 || len(c.Tenants) != len(before.Tenants)+1 || c.Mongo.Database != before.Mongo.Database {
		t.Errorf("%+v", c)
	}
	// A secret given in App Configuration replaces the variable the file names.
	if got := c.Tenants[0]; got.Name != first.Name || got.ClientID != first.ClientID || got.ClientSecret != "from-app-config" {
		t.Errorf("%+v", got)
	}
}
