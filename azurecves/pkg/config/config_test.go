package config

import (
	"strings"
	"testing"
)

func TestLoadFromEnv(t *testing.T) {
	env := map[string]string{
		"MONGO_URI": "mongodb://x",
		"AZCVES_TENANTS": `[{"tenantName":"Contoso","tenantId":"11111111-1111-1111-1111-11111111111A","clientId":"c","clientSecret":"s"},
		                   {"name":"Fabrikam","TenantId":"22222222-2222-2222-2222-222222222222","ClientID":"c","clientsecret":"s"}]`,
		"AZCVES_INTERVAL": "2d",
	}
	c, err := Load("", func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Tenants) != 2 || c.Tenants[0].ID != "11111111-1111-1111-1111-11111111111a" || c.Tenants[1].Name != "Fabrikam" || c.Tenants[1].ClientSecret != "s" {
		t.Errorf("tenants: %+v", c.Tenants)
	}
	if c.Interval.hours() != 48 || c.Mongo.Database != "azcves" || c.Costs.Database != "azcost" || !c.Enabled("costs") {
		t.Errorf("defaults: %+v", c)
	}
	env["AZCVES_TENANTS"] = `[{"tenantName":"a","tenantId":"nope","clientId":"c"}]`
	if _, err := Load("", func(k string) string { return env[k] }); err == nil || !strings.Contains(err.Error(), "GUID") || !strings.Contains(err.Error(), "clientSecret") {
		t.Errorf("want validation errors, got %v", err)
	}
}

func (d Duration) hours() float64 { return float64(d) / 3.6e12 }
