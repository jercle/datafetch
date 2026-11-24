package config

import (
	"errors"
	"strings"
	"testing"
	"time"
)

const tenant = `{"tenantName":"Contoso","tenantId":"00000000-0000-0000-0000-000000000001","clientId":"c","clientSecretEnv":"SECRET"}`

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func noFile(string) ([]byte, error) { return nil, errors.New("no file") }

func TestDefaults(t *testing.T) {
	c, err := Parse([]byte(`{"mongo":{"uri":"mongodb://x"},"tenants":[`+tenant+`]}`), env(map[string]string{"SECRET": "s"}), noFile)
	if err != nil {
		t.Fatal(err)
	}
	if c.Mongo.Database != "azstorage" || c.Interval.D() != 24*time.Hour || c.Concurrency.Accounts != 8 ||
		c.ContainerSizes.MaxBlobs != 2_000_000 || !c.MeasureContainers() || !c.CollectDisks() || !c.EnsureIndexes() {
		t.Fatalf("defaults %+v", c)
	}
	tn := c.Tenants[0]
	if tn.ClientSecret != "s" || tn.Cloud != "public" || tn.Endpoints.ARM != "https://management.azure.com" || tn.Endpoints.StorageScope == "" {
		t.Fatalf("tenant %+v", tn)
	}
	if s, v, d := c.BlobIncludes(); !s || !v || !d {
		t.Fatal("includes should default to on")
	}
}

func TestSwitchesAndPatterns(t *testing.T) {
	c, err := Parse([]byte(`{"collect":{"containers":false},"containerSizes":{"versions":false,"maxBlobs":-1,"excludeAccounts":["StDiag*"," logs01 "]},"tenants":[`+tenant+`]}`),
		env(map[string]string{"SECRET": "s"}), noFile)
	if err != nil {
		t.Fatal(err)
	}
	if c.MeasureContainers() {
		t.Fatal("sizes need the container list")
	}
	if _, v, _ := c.BlobIncludes(); v {
		t.Fatal("versions were switched off")
	}
	if !c.SizeExcluded("stdiagprod") || !c.SizeExcluded("LOGS01") || c.SizeExcluded("stapp") {
		t.Fatal("excludeAccounts")
	}
}

func TestEnvironmentTenants(t *testing.T) {
	c, err := Parse([]byte(`{}`), env(map[string]string{
		"AZSTORAGE_MONGO_URI": "mongodb://env", "AZSTORAGE_MONGO_DATABASE": "other",
		"AZSTORAGE_TENANTS": `[{"tenantName":"A","tenantId":"00000000-0000-0000-0000-00000000000A","clientId":"c","clientSecret":"s","cloud":"usgovernment"}]`,
	}), noFile)
	if err != nil {
		t.Fatal(err)
	}
	if c.Mongo.URI != "mongodb://env" || c.Mongo.Database != "other" || c.Tenants[0].ID != "00000000-0000-0000-0000-00000000000a" ||
		c.Tenants[0].Endpoints.Authority != "https://login.microsoftonline.us" {
		t.Fatalf("%+v", c)
	}
}

func TestRejects(t *testing.T) {
	for name, tc := range map[string]struct{ json, want string }{
		"unknown field": {`{"tennants":[]}`, "unknown field"},
		"no tenants":    {`{}`, "no tenants"},
		"bad guid":      {`{"tenants":[{"tenantName":"A","tenantId":"x","clientId":"c","clientSecret":"s"}]}`, "GUID"},
		"no secret":     {`{"tenants":[{"tenantName":"A","tenantId":"00000000-0000-0000-0000-000000000001","clientId":"c","clientSecretEnv":"UNSET"}]}`, "secret"},
		"twice":         {`{"tenants":[` + tenant + `,` + tenant + `]}`, "twice"},
		"interval":      {`{"interval":"1m","tenants":[` + tenant + `]}`, "interval"},
		"pattern":       {`{"containerSizes":{"excludeAccounts":["[a"]},"tenants":[` + tenant + `]}`, "pattern"},
		"subscription":  {`{"tenants":[{"tenantName":"A","tenantId":"00000000-0000-0000-0000-000000000001","clientId":"c","clientSecret":"s","subscriptions":["nope"]}]}`, "subscription ID"},
	} {
		_, err := Parse([]byte(tc.json), env(map[string]string{"SECRET": "s"}), noFile)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want an error containing %q", name, err, tc.want)
		}
	}
}
