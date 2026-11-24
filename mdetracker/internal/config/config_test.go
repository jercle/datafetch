package config

import (
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	t.Setenv("SECRET_A", `p"a\ss`)
	c, err := Parse([]byte(`{
	  "mongo": {"uri": "mongodb://localhost"},
	  "interval": "6h",
	  "inactiveAfter": "14d",
	  "tenants": [
	    {"name": "A", "tenantId": "t", "orgId": " ORG-A ", "auth": {"clientId": "c", "clientSecret": "${SECRET_A}"}},
	    {"name": "B", "enabled": false, "auth": {}}
	  ]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if c.Interval.Duration != 6*time.Hour || c.InactiveAfter.Duration != 14*24*time.Hour {
		t.Fatal("durations")
	}
	a := c.Tenants[0]
	if a.Auth.ClientSecret != `p"a\ss` || a.OrgID != "org-a" || a.EffectiveFilter() != "" || len(c.EnabledTenants()) != 1 {
		t.Fatalf("tenant: %+v", a)
	}
}

func TestParseErrors(t *testing.T) {
	if _, err := Parse([]byte(`{"mongo":{"uri":"x"},"tenants":[{"name":"A","tenantId":"t","auth":{"clientId":"c","clientSecret":"${NOPE_UNSET}"}}]}`)); err == nil {
		t.Fatal("expected missing env error")
	}
	if _, err := Parse([]byte(`{"mongo":{"uri":"x"},"tenants":[{"name":"A","tenantId":"t","auth":{"clientId":"c","clientSecret":"s"}}]}`)); err == nil {
		t.Fatal("expected missing orgId error")
	}
}
