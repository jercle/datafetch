package config

import (
	"os"
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func parse(t *testing.T, js string, e map[string]string) (*Config, error) {
	t.Helper()
	return Parse([]byte(js), env(e), os.ReadFile)
}

func TestExampleConfig(t *testing.T) {
	b, err := os.ReadFile("../../deploy/config.example.json")
	if err != nil {
		t.Fatal(err)
	}
	c, err := Parse(b, env(map[string]string{"SXG_SNMP_COMMUNITY": "public", "MEL_SNMP_AUTH": "a", "MEL_SNMP_PRIV": "p", "MEL_API_PASSWORD": "x"}), os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Firewalls) != 3 || c.Interval.D() != time.Minute {
		t.Fatalf("%+v", c)
	}
	a, b2, m := c.Firewalls[0], c.Firewalls[1], c.Firewalls[2]
	// Defaults are laid under each firewall, field by field.
	if a.SNMP.Community != "public" || a.SNMP.ExpectHA != "primary" || a.SNMP.CPU.Warn != 85 || len(a.SNMP.RequiredServices) != 3 {
		t.Fatalf("fw01 snmp %+v", a.SNMP)
	}
	if !a.ProxyOn() || b2.ProxyOn() || !b2.TCPOn() || b2.SNMP.ExpectHA != "auxiliary" {
		t.Fatal("proxy switch or merge wrong")
	}
	// One firewall's settings must not leak into the next.
	if a.SNMP == b2.SNMP || a.Proxy == b2.Proxy || a.SNMP.Version != "2c" {
		t.Fatal("firewalls share settings")
	}
	if m.SNMP.Version != "3" || m.SNMP.AuthProtocol != "SHA256" || m.SNMP.PrivPassword != "p" || !m.APIOn() || m.API.Password != "x" || m.API.Port != 4444 {
		t.Fatalf("mel %+v %+v", m.SNMP, m.API)
	}
	if a.Attempts() != 2 || a.Timeout.D() != 5*time.Second || a.TLS.WarnDays != 30 || len(a.Proxy.URLs) != 2 {
		t.Fatal("defaults")
	}
}

func TestDefaultsAndErrors(t *testing.T) {
	c, err := parse(t, `{"firewalls":[{"name":"fw1","host":"10.0.0.1","tls":{},"proxy":{},"snmp":{"community":"c","swap":{"warn":-1,"critical":-1}}}]}`, nil)
	if err != nil {
		t.Fatal(err)
	}
	f := c.Firewalls[0]
	if c.Mongo.Database != "sxgcheck" || c.Concurrency != 8 || c.Retention.EventsDays != 180 {
		t.Fatalf("%+v", c)
	}
	if f.TLS.Ports[0] != 4444 || f.Proxy.Port != 3128 || len(f.Proxy.URLs) != 1 || f.SNMP.Port != 161 || f.SNMP.Disk.Critical != 90 || f.SNMP.Swap.Warn != -1 || f.TCPOn() {
		t.Fatalf("%+v %+v %+v", f.TLS, f.Proxy, f.SNMP)
	}

	bad := map[string]string{
		`{"firewalls":[]}`: "no firewalls",
		`{"firewalls":[{"name":"fw1","host":"10.0.0.1"}]}`:                                          "no checks",
		`{"firewalls":[{"name":"fw 1","host":"h","tls":{}}]}`:                                       "name is required",
		`{"firewalls":[{"name":"a","host":"https://h","tls":{}}]}`:                                  "host must be",
		`{"firewalls":[{"name":"a","host":"h","tls":{}},{"name":"A","host":"h","tls":{}}]}`:         "used twice",
		`{"firewalls":[{"name":"a","host":"h","tcp":{}}]}`:                                          "tcp.ports is empty",
		`{"firewalls":[{"name":"a","host":"h","tcp":{"ports":[70000]}}]}`:                           "not a port",
		`{"firewalls":[{"name":"a","host":"h","snmp":{}}]}`:                                         "community",
		`{"firewalls":[{"name":"a","host":"h","snmp":{"version":"3"}}]}`:                            "username",
		`{"firewalls":[{"name":"a","host":"h","snmp":{"community":"c","requiredServices":["x"]}}]}`: "is not one of",
		`{"firewalls":[{"name":"a","host":"h","api":{"username":"u"}}]}`:                            "password",
		`{"firewalls":[{"name":"a","host":"h","proxy":{"urls":["ftp://x"]}}]}`:                      "not an http",
		`{"firewalls":[{"name":"a","host":"h","tls":{},"bogus":1}]}`:                                "unknown field",
		`{"defaults":{"bogus":1},"firewalls":[{"name":"a","host":"h","tls":{}}]}`:                   "defaults",
		`{"interval":"1s","firewalls":[{"name":"a","host":"h","tls":{}}]}`:                          "interval",
	}
	for js, want := range bad {
		if _, err := parse(t, js, nil); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want %q", js, err, want)
		}
	}
}

func TestEnvironment(t *testing.T) {
	c, err := parse(t, `{"firewalls":[{"name":"a","host":"h","tls":{}}]}`, map[string]string{
		"SXGCHECK_MONGO_URI": "mongodb://x", "SXGCHECK_FIREWALLS": `[{"name":"b","host":"h2","tcp":{"ports":[22]}}]`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.Mongo.URI != "mongodb://x" || len(c.Firewalls) != 1 || c.Firewalls[0].Name != "b" {
		t.Fatalf("%+v", c.Firewalls)
	}
}
