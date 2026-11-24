package config

import (
	"os"
	"strings"
	"testing"
	"time"
)

const tenant = `{"tenantName": "Contoso", "tenantId": "00000000-0000-0000-0000-00000000000A", "clientId": "c", "clientSecretEnv": "SECRET"}`

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestDefaults(t *testing.T) {
	c, err := Parse([]byte(`{"mongo": {"uri": "mongodb://x"}, "tenants": [`+tenant+`]}`), env(map[string]string{"SECRET": "s"}), nil)
	if err != nil {
		t.Fatal(err)
	}
	tn := c.Tenants[0]
	if c.Mongo.Database != "azconfigdrift" || c.Interval.D() != 6*time.Hour || c.Concurrency.Modules != 3 ||
		c.Retention.ChangesDays != 365 || c.Limits.MaxItemBytes != 4<<20 || c.Limits.ChangePaths != 100 || !c.EnsureIndexes() {
		t.Errorf("defaults: %+v", c)
	}
	if tn.HasServiceAccount() {
		t.Error("no service account was configured")
	}
	withUser, err := Parse([]byte(`{"tenants": [{"tenantName": "x", "tenantId": "00000000-0000-0000-0000-000000000009", "clientId": "c", "clientSecret": "s", "username": " svc@x ", "passwordEnv": "PW"}]}`),
		env(map[string]string{"PW": "secret"}), nil)
	if err != nil || !withUser.Tenants[0].HasServiceAccount() || withUser.Tenants[0].Username != "svc@x" || withUser.Tenants[0].Password != "secret" {
		t.Errorf("service account: %v %+v", err, withUser)
	}
	if tn.ID != "00000000-0000-0000-0000-00000000000a" || tn.ClientSecret != "s" || tn.Cloud != "public" ||
		tn.Endpoints.Graph != "https://graph.microsoft.com" || !tn.Has("azure") || !tn.Has("m365") {
		t.Errorf("tenant: %+v", tn)
	}
}

func TestOverridesAndValidation(t *testing.T) {
	c, err := Parse([]byte(`{
		"interval": "30m", "skipSources": ["m365-identity/domains"],
		"ignore": [{"type": "Microsoft.Web/Sites", "paths": ["properties.state"]}],
		"extraSources": [{"module": "custom", "id": "budgets", "kind": "arm", "path": "/subscriptions/{subscriptionId}/providers/Microsoft.Consumption/budgets?api-version=2023-05-01"}]
	}`), env(map[string]string{
		"AZCONFIGDRIFT_MONGO_URI": "mongodb://env", "AZCONFIGDRIFT_MONGO_DATABASE": "other",
		"AZCONFIGDRIFT_TENANTS": `[{"tenantName": "Gov", "tenantId": "00000000-0000-0000-0000-000000000001", "clientId": "c", "clientSecret": "s", "cloud": "USGovernment", "platforms": ["M365"]}]`,
	}), nil)
	if err != nil {
		t.Fatal(err)
	}
	tn := c.Tenants[0]
	if c.Mongo.URI != "mongodb://env" || c.Mongo.Database != "other" || tn.Endpoints.Graph != "https://graph.microsoft.us" || tn.Has("azure") || !tn.Has("m365") {
		t.Errorf("%+v %+v", c.Mongo, tn)
	}
	if !c.Skipped("m365-identity", "domains") || c.Skipped("m365-identity", "organization") || c.Ignore[0].Type != "microsoft.web/sites" || c.ExtraSources[0].Name != "budgets" {
		t.Errorf("%+v", c)
	}

	bad := map[string]string{
		`{"tenants": [` + tenant + `], "nonsense": 1}`: "unknown field",
		`{"tenants": []}`: "no tenants",
		`{"interval": "1m", "tenants": [` + tenant + `]}`:                                                                                                        "at least 5m",
		`{"tenants": [` + tenant + `, ` + tenant + `]}`:                                                                                                          "twice",
		`{"tenants": [{"tenantName": "x", "tenantId": "nope", "clientId": "c"}]}`:                                                                                "GUID",
		`{"tenants": [` + tenant + `], "ignore": [{"module": "x"}]}`:                                                                                             "paths is empty",
		`{"tenants": [` + tenant + `], "extraSources": [{"module": "m", "id": "x", "kind": "x"}]}`:                                                               "kind must be",
		`{"tenants": [` + tenant + `], "extraSources": [{"module": "M", "id": "x", "kind": "arg"}]}`:                                                             "lower-case",
		`{"tenants": [` + tenant + `], "limits": {"maxItemBytes": 99999999}}`:                                                                                    "12 MiB",
		`{"tenants": [{"tenantName": "x", "tenantId": "00000000-0000-0000-0000-000000000009", "clientId": "c", "clientSecret": "s", "username": "u@x"}]}`:        "go together",
		`{"tenants": [{"tenantName": "x", "tenantId": "00000000-0000-0000-0000-000000000009", "clientId": "c", "clientSecret": "s", "password": "p"}]}`:          "go together",
		`{"tenants": [{"tenantName": "x", "tenantId": "00000000-0000-0000-0000-000000000009", "clientId": "c", "clientSecret": "s", "delegatedClientId": "d"}]}`: "delegatedClientId needs",
	}
	for in, want := range bad {
		_, err := Parse([]byte(in), env(map[string]string{"SECRET": "s"}), nil)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want %q", in, err, want)
		}
	}
	if _, err := Parse([]byte(`{"tenants": [`+tenant+`]}`), env(nil), nil); err == nil || !strings.Contains(err.Error(), "secret") {
		t.Errorf("missing secret: %v", err)
	}
}

func TestExampleConfigLoads(t *testing.T) {
	b, err := os.ReadFile("../../deploy/config.example.json")
	if err != nil {
		t.Fatal(err)
	}
	c, err := Parse(b, env(map[string]string{"AZCONFIGDRIFT_CONTOSO_SECRET": "s", "AZCONFIGDRIFT_FABRIKAM_SECRET": "s", "AZCONFIGDRIFT_CONTOSO_PASSWORD": "p"}), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Tenants) != 2 || !c.Tenants[0].HasServiceAccount() || c.Tenants[1].HasServiceAccount() {
		t.Errorf("tenants: %d", len(c.Tenants))
	}
}
