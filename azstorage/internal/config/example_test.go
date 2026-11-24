package config

import (
	"os"
	"strings"
	"testing"
)

func TestExampleConfigLoads(t *testing.T) {
	b, err := os.ReadFile("../../deploy/config.example.json")
	if err != nil {
		t.Fatal(err)
	}
	c, err := Parse(b, func(k string) string {
		if strings.HasSuffix(k, "_SECRET") {
			return "secret"
		}
		return ""
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Tenants) != 2 || !c.SizeExcluded("stdiag01") {
		t.Fatalf("%+v", c)
	}
}
