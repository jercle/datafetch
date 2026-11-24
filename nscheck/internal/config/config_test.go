package config

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func parse(t *testing.T, body string, env map[string]string) (*Config, error) {
	t.Helper()
	return Parse([]byte(body), func(k string) string { return env[k] }, func(string) ([]byte, error) { return nil, errors.New("no file") })
}

func TestDefaultsAndAppliances(t *testing.T) {
	c, err := parse(t, `{
		"mongo": {"uri": "mongodb://x"},
		"defaults": {"username": "nscheck", "passwordEnv": "NS_PW", "tlsSkipVerify": true},
		"ignore": {"vservers": ["TEST-*"]},
		"appliances": [
			{"name": "ns-a", "address": "10.0.0.10", "tenantName": "Contoso"},
			{"name": "ns-b", "address": "HTTPS://NS-B.example:8443/", "username": "other", "password": "pw", "tlsSkipVerify": false, "ignore": {"vservers": ["lb_old"]}}
		]}`, map[string]string{"NS_PW": "secret", "NSCHECK_MONGO_DATABASE": "other"})
	if err != nil {
		t.Fatal(err)
	}
	if c.Mongo.Database != "other" || c.Interval.D() != time.Minute || c.Timeout.D() != 20*time.Second || c.Concurrency != 8 {
		t.Fatalf("defaults: %+v", c)
	}
	if c.Thresholds.CPU != (Threshold{75, 90}) || c.Thresholds.CertificateDays != (Threshold{30, 7}) || c.VserverHealth() != 100 {
		t.Fatalf("thresholds: %+v", c.Thresholds)
	}
	a, b := c.Appliances[0], c.Appliances[1]
	if a.Address != "https://10.0.0.10" || a.Username != "nscheck" || a.Password != "secret" || !a.SkipVerify {
		t.Fatalf("appliance a: %+v", a)
	}
	if b.Address != "https://ns-b.example:8443" || b.Username != "other" || b.Password != "pw" || b.SkipVerify {
		t.Fatalf("appliance b: %+v", b)
	}
	if !Matches(a.Ignore.Vservers, "Test-web") || Matches(a.Ignore.Vservers, "lb_old") || !Matches(b.Ignore.Vservers, "LB_OLD") || !Matches(b.Ignore.Vservers, "test-1") {
		t.Fatalf("ignore patterns: %v / %v", a.Ignore.Vservers, b.Ignore.Vservers)
	}
	if !c.CheckHA() || !c.CheckCertificates() {
		t.Fatal("checks are on by default")
	}
}

func TestRejects(t *testing.T) {
	ap := `"appliances": [{"name": "a", "address": "ns", "username": "u", "password": "p"}]`
	for name, tc := range map[string]struct{ body, want string }{
		"unknown field":   {`{"nope": 1, ` + ap + `}`, "unknown field"},
		"no appliances":   {`{}`, "no appliances"},
		"no password":     {`{"appliances": [{"name": "a", "address": "ns", "username": "u"}]}`, "password"},
		"twice":           {`{"appliances": [{"name": "a", "address": "ns", "username": "u", "password": "p"}, {"name": "A", "address": "ns2", "username": "u", "password": "p"}]}`, "twice"},
		"path in address": {`{"appliances": [{"name": "a", "address": "https://ns/nitro", "username": "u", "password": "p"}]}`, "just the host"},
		"short interval":  {`{"interval": "5s", ` + ap + `}`, "at least 15s"},
		"bad threshold":   {`{"thresholds": {"cpu": {"warning": 90, "critical": 80}}, ` + ap + `}`, "thresholds.cpu"},
		"bad pattern":     {`{"ignore": {"services": ["[a"]}, ` + ap + `}`, "not a valid pattern"},
	} {
		if _, err := parse(t, tc.body, nil); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want an error containing %q", name, err, tc.want)
		}
	}
}

func TestAppliancesFromEnvironment(t *testing.T) {
	c, err := parse(t, `{"appliances": [{"name": "old", "address": "x", "username": "u", "password": "p"}]}`,
		map[string]string{"NSCHECK_APPLIANCES": `[{"name": "new", "address": "http://ns:80", "username": "u", "password": "p"}]`})
	if err != nil || len(c.Appliances) != 1 || c.Appliances[0].Name != "new" || c.Appliances[0].Address != "http://ns:80" {
		t.Fatalf("%v %+v", err, c)
	}
}

// The example in deploy/ must stay valid.
func TestExampleConfig(t *testing.T) {
	b, err := os.ReadFile("../../deploy/config.example.json")
	if err != nil {
		t.Fatal(err)
	}
	c, err := Parse(b, func(k string) string {
		if strings.HasSuffix(k, "_PASSWORD") {
			return "secret"
		}
		return ""
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Appliances) < 2 {
		t.Fatal("the example should show a pair")
	}
}
