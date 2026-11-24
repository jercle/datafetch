package sxgcheck

import (
	"os"
	"strings"
	"testing"

	"github.com/jercle/datafetch/sxgcheck/internal/config"

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
		"mongo.uri":                   "mongodb://db",
		"instance":                    "zone-a",
		"interval":                    "30s",
		"defaults.timeout":            "3s",
		"defaults.retries":            "2",
		"defaults.tcp.ports":          "4444, 3128",
		"defaults.snmp.community":     "public",
		"defaults.snmp.cpu.warn":      "90",
		"defaults.snmp.cpu.critical":  98,
		"firewalls.fw01.host":         "10.1.0.1",
		"firewalls.fw01.site":         "Sydney",
		"firewalls.fw01.tags":         "ha, edge",
		"firewalls.fw02.host":         "10.1.0.2",
		"firewalls.fw02.tcp.ports":    []any{float64(443)},
		"firewalls.fw02.snmp.enabled": "false",
		"firewalls.fw02.tls.warnDays": "14",
	}, 16)
	c, err := config.Parse(b, none, os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	if c.Instance != "zone-a" || c.Interval.D().Seconds() != 30 || len(c.Firewalls) != 2 {
		t.Fatalf("%+v", c)
	}
	a, b2 := c.Firewalls[0], c.Firewalls[1]
	if a.Name != "fw01" || a.Host != "10.1.0.1" || a.Site != "Sydney" || len(a.Tags) != 2 || a.Timeout.D().Seconds() != 3 || a.Attempts() != 3 ||
		!a.TCPOn() || len(a.TCP.Ports) != 2 || !a.SNMPOn() || a.SNMP.Community != "public" || a.SNMP.CPU.Warn != 90 || a.SNMP.CPU.Critical != 98 {
		t.Errorf("%+v", a)
	}
	if b2.Name != "fw02" || len(b2.TCP.Ports) != 1 || b2.TCP.Ports[0] != 443 || b2.SNMPOn() || !b2.TLSOn() || b2.TLS.WarnDays != 14 {
		t.Errorf("%+v", b2)
	}
}

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
	first := before.Firewalls[0]
	c, err := config.Parse(merged(t, file, map[string]any{
		"firewalls." + first.Name + ".site": "Moved",
		"firewalls.extra.host":              "extra.example",
		"defaults.snmp.community":           "from-app-config",
		"retention.eventsDays":              "90",
	}, 4), env, os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Firewalls) != len(before.Firewalls)+1 || c.Firewalls[0].Site != "Moved" || c.Firewalls[0].Host != first.Host || c.Retention.EventsDays != 90 {
		t.Errorf("%+v", c)
	}
	// The community given in App Configuration replaces the variable the
	// file names, for the firewalls that use the defaults' SNMP settings.
	if got := c.Firewalls[0].SNMP; got == nil || got.Community != "from-app-config" {
		t.Errorf("%+v", got)
	}
}
