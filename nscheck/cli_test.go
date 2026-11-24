package nscheck

import (
	"os"
	"strings"
	"testing"

	"github.com/jercle/datafetch/nscheck/internal/config"

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
		"mongo.uri":                        "mongodb://db",
		"interval":                         "2m",
		"timeout":                          "10s",
		"concurrency":                      "4",
		"thresholds.cpu.warning":           "70",
		"thresholds.cpu.critical":          95,
		"thresholds.vserverHealthPercent":  "50",
		"checks.certificates":              "off",
		"ignore.vservers":                  "test-*; Lab*",
		"defaults.username":                "nscheck",
		"defaults.password":                "pw",
		"appliances.ns-01.address":         "10.0.0.10",
		"appliances.ns-01.tenantName":      "Prod",
		"appliances.ns-01.requireHA":       "true",
		"appliances.ns-02.address":         "https://10.0.0.11",
		"appliances.ns-02.password":        "other",
		"appliances.ns-02.tlsSkipVerify":   true,
		"appliances.ns-02.ignore.services": "svc-old",
	}, 18)
	c, err := config.Parse(b, none, os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	if c.Interval.D().Minutes() != 2 || c.Timeout.D().Seconds() != 10 || c.Concurrency != 4 || c.Thresholds.CPU.Warning != 70 || c.Thresholds.CPU.Critical != 95 ||
		c.VserverHealth() != 50 || c.CheckCertificates() || !c.CheckHA() {
		t.Errorf("%+v", c)
	}
	if len(c.Appliances) != 2 {
		t.Fatalf("%+v", c.Appliances)
	}
	a, b2 := c.Appliances[0], c.Appliances[1]
	if a.Name != "ns-01" || a.Address != "https://10.0.0.10" || a.Username != "nscheck" || a.Password != "pw" || !a.RequireHA || a.SkipVerify || !config.Matches(a.Ignore.Vservers, "lab1") {
		t.Errorf("%+v", a)
	}
	if b2.Name != "ns-02" || b2.Password != "other" || !b2.SkipVerify || !config.Matches(b2.Ignore.Services, "svc-old") {
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
	first := before.Appliances[0]
	c, err := config.Parse(merged(t, file, map[string]any{
		"appliances." + first.Name + ".tenantName": "Renamed",
		"appliances.extra.address":                 "extra.example",
		"thresholds.memory.warning":                "60",
	}, 3), env, os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Appliances) != len(before.Appliances)+1 || c.Appliances[0].TenantName != "Renamed" || c.Appliances[0].Address != first.Address ||
		c.Thresholds.Memory.Warning != 60 || c.Thresholds.Memory.Critical != before.Thresholds.Memory.Critical {
		t.Errorf("%+v", c)
	}
}
