package mdetracker

import (
	"os"
	"strings"
	"testing"

	"github.com/jercle/datafetch/mdetracker/internal/config"

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

func TestSettingsAlone(t *testing.T) {
	b := merged(t, nil, map[string]any{
		"mongo.uri":                         "mongodb://db",
		"mongo.logRetentionDays":            "-1",
		"interval":                          "6h",
		"activeWindow":                      "2d",
		"mode":                              "servers",
		"hostnameFallback":                  "false",
		"concurrency":                       "2",
		"tenants.Contoso.tenantId":          "t1",
		"tenants.Contoso.orgId":             "ORG1",
		"tenants.Contoso.auth.clientId":     "client",
		"tenants.Contoso.auth.clientSecret": "it${is}literal",
		"tenants.Fabrikam.tenantId":         "t2",
		"tenants.Fabrikam.orgId":            "org2",
		"tenants.Fabrikam.auth.type":        "workload",
		"tenants.Fabrikam.filter":           "onboardingStatus eq 'Onboarded'",
		"tenants.Old.enabled":               "false",
	}, 16)
	c, err := config.ParseExpanded(b)
	if err != nil {
		t.Fatal(err)
	}
	if c.Interval.Hours() != 6 || c.ActiveWindow.Hours() != 48 || c.Mode != config.ModeServers || c.HostnameFallbackEnabled() || c.Concurrency != 2 || c.Mongo.LogRetentionDays != -1 {
		t.Errorf("%+v", c)
	}
	ts := c.EnabledTenants()
	if len(c.Tenants) != 3 || len(ts) != 2 {
		t.Fatalf("%+v", c.Tenants)
	}
	// A secret from App Configuration is taken as it is.
	if ts[0].Name != "Contoso" || ts[0].OrgID != "org1" || ts[0].Auth.ClientSecret != "it${is}literal" || ts[0].Auth.Type != config.AuthSecret {
		t.Errorf("%+v", ts[0])
	}
	if ts[1].Name != "Fabrikam" || ts[1].Auth.Type != config.AuthWorkload || ts[1].EffectiveFilter() == "" {
		t.Errorf("%+v", ts[1])
	}
}

func TestSettingsOverTheExampleFile(t *testing.T) {
	file, err := os.ReadFile("deploy/config.example.json")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("MONGODB_URI", "mongodb://env")
	t.Setenv("CONTOSO_MDE_SECRET", "from-env")
	// The ${...} references are the file's, expanded before the merge.
	if file, err = config.Expand(file); err != nil {
		t.Fatal(err)
	}
	before, err := config.ParseExpanded(merged(t, file, nil, 0))
	if err != nil {
		t.Fatalf("the file alone, through the merge: %v", err)
	}
	first := before.Tenants[0]
	if first.Auth.ClientSecret != "from-env" {
		t.Fatalf("%+v", first)
	}
	c, err := config.ParseExpanded(merged(t, file, map[string]any{
		"tenants." + first.Name + ".auth.clientSecret": "from-app-config",
		"tenants." + first.Name + ".enabled":           "true",
		"inactiveAfter":                                "14d",
	}, 3))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Tenants) != len(before.Tenants) || c.Tenants[0].Auth.ClientSecret != "from-app-config" || c.Tenants[0].Auth.ClientID != first.Auth.ClientID ||
		c.InactiveAfter.Hours() != 14*24 || c.Mongo.URI != "mongodb://env" {
		t.Errorf("%+v", c)
	}
}
