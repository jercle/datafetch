package settings

import (
	"encoding/json"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/jercle/datafetch/azconfigdrift/internal/config"
)

const (
	tA = "00000000-0000-0000-0000-00000000000a"
	tB = "00000000-0000-0000-0000-00000000000b"
)

const file = `{
	"mongo": {"uri": "mongodb://file", "database": "fromfile"},
	"interval": "12h",
	"concurrency": {"tenants": 1},
	"tenants": [
		{"tenantName": "Contoso", "tenantId": "00000000-0000-0000-0000-00000000000A", "clientId": "file-client", "clientSecretEnv": "SECRET", "passwordEnv": "PW", "username": "svc@contoso"}
	],
	"modules": {"azure-network": {"enabled": false}, "m365-intune": {"sources": {"scripts": {"enabled": false}}}},
	"ignore": [{"paths": ["fromFile"]}]
}`

func parse(t *testing.T, r *Result) *config.Config {
	t.Helper()
	c, err := config.Parse(r.Config, func(k string) string { return map[string]string{"SECRET": "file-secret", "PW": "file-pw"}[k] }, nil)
	if err != nil {
		t.Fatalf("%v\n%s", err, r.Config)
	}
	return c
}

func obj(t *testing.T, s string) map[string]any {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestNest(t *testing.T) {
	got := Nest(map[string]any{
		"datafetching.azConfigDrift.interval": "1h", "datafetching.azConfigDrift.concurrency.tenants": "4",
		"datafetching.azConfigDrift.tenants." + tA + ".tenantName": "A", "datafetching.azConfigDrift.modules.m365-intune.sources.scripts.beta": true,
		"general.other": "x",
	})
	b, _ := json.Marshal(Under(got))
	want := `{"concurrency":{"tenants":"4"},"interval":"1h","modules":{"m365-intune":{"sources":{"scripts":{"beta":true}}}},"tenants":{"` + tA + `":{"tenantName":"A"}}}`
	if string(b) != want {
		t.Errorf("%s", b)
	}
	if u := Under(map[string]any{"interval": "1h"}); u["interval"] != "1h" {
		t.Error("an object without the root key is the settings object itself")
	}
}

func TestSettingsWinAndTheFileFillsTheRest(t *testing.T) {
	r, err := Merge([]byte(file), obj(t, `{"azConfigDrift": {
		"interval": "30m",
		"concurrency": {"modules": "5"},
		"retention": {"logsDays": 7},
		"logging": {"level": "DEBUG"},
		"limits": {"sourceTimeout": "10m"},
		"mongo": {"database": "fromgui", "ensureIndexes": "false"},
		"ignore": "[{\"type\": \"microsoft.web/sites\", \"paths\": [\"properties.state\"]}]",
		"skipSources": "m365-identity/domains, azure-governance/locks",
		"tenants": {
			"`+strings.ToUpper(tA)+`": {"tenantName": "Contoso Production", "platforms": "azure, m365", "excludeSubscriptions": ["11111111-1111-1111-1111-111111111111"], "password": "gui-pw"},
			"`+tB+`": {"tenantName": "Fabrikam", "clientId": "gui-client", "clientSecret": "gui-secret", "cloud": "USGovernment", "platforms": ["m365"]}
		},
		"modules": {
			"azure-network": {"enabled": "true"},
			"m365-exchange": {"enabled": true},
			"m365-intune": {"sources": {"settings-catalog": {"beta": false, "delegated": "yes"}}}
		}
	}}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Warnings) != 0 || r.Applied != 22 {
		t.Errorf("applied %d, warnings %v", r.Applied, r.Warnings)
	}
	c := parse(t, r)
	if c.Interval.D().String() != "30m0s" || c.Concurrency.Tenants != 1 || c.Concurrency.Modules != 5 || c.Retention.LogsDays != 7 || c.Retention.RunsDays != 90 ||
		c.Logging.Level != "debug" || c.Limits.SourceTimeout.D().String() != "10m0s" || c.Mongo.URI != "mongodb://file" || c.Mongo.Database != "fromgui" || c.EnsureIndexes() {
		t.Errorf("general: %+v", c)
	}
	if len(c.Ignore) != 1 || c.Ignore[0].Type != "microsoft.web/sites" || !c.Skipped("azure-governance", "locks") {
		t.Errorf("ignore replaces the file's list: %+v %v", c.Ignore, c.SkipSources)
	}
	if len(c.Tenants) != 2 {
		t.Fatalf("tenants: %+v", c.Tenants)
	}
	a, b := c.Tenants[0], c.Tenants[1]
	if a.Name != "Contoso Production" || a.ClientID != "file-client" || a.ClientSecret != "file-secret" || a.Username != "svc@contoso" || a.Password != "gui-pw" ||
		len(a.ExcludeSubscriptions) != 1 || !a.Has("azure") || !a.Has("m365") {
		t.Errorf("a tenant of the file with settings over it: %+v", a)
	}
	if b.ID != tB || b.Name != "Fabrikam" || b.ClientSecret != "gui-secret" || b.Cloud != "usgovernment" || b.Has("azure") {
		t.Errorf("a tenant from the settings alone: %+v", b)
	}
	on := func(p *bool) string {
		if p == nil {
			return "unset"
		}
		if *p {
			return "on"
		}
		return "off"
	}
	in := c.Modules["m365-intune"].Sources
	if on(c.Modules["azure-network"].Enabled) != "on" || on(c.Modules["m365-exchange"].Enabled) != "on" || on(c.Modules["m365-intune"].Enabled) != "unset" ||
		on(in["scripts"].Enabled) != "off" || on(in["settings-catalog"].Beta) != "off" || on(in["settings-catalog"].Delegated) != "on" || on(in["settings-catalog"].Enabled) != "unset" {
		t.Errorf("modules: %+v", c.Modules)
	}
}

func TestABadSettingFallsBackAlone(t *testing.T) {
	in := obj(t, `{
		"interval": "soon", "heartbeatInterval": "5m", "concurrency": {"tenants": 0, "modules": 2.5, "colour": "red"},
		"logging": {"level": "loud"}, "retention": {"logsDays": "many"}, "mongo": {"ensureIndexes": "maybe", "database": ""},
		"ignore": "not json", "nonsense": 1, "limits": {"changePaths": 20},
		"tenants": {
			"not-a-guid": {"tenantName": "x"},
			"`+tA+`": {"cloud": "mars", "shoeSize": 9, "enabled": false},
			"`+tB+`": {"tenantName": "No credentials"}
		},
		"modules": {"Bad Id": {"enabled": true}, "azure-network": {"enabled": "perhaps", "sources": {"resources": {"speed": "fast", "enabled": false}}, "extra": 1}}
	}`)
	before, _ := json.Marshal(in)
	r, err := Merge([]byte(file), in)
	if err != nil {
		t.Fatal(err)
	}
	if after, _ := json.Marshal(in); string(after) != string(before) {
		t.Error("the settings object passed in was changed")
	}
	// Three settings were good: changePaths, the tenant switch, one source.
	if r.Applied != 3 {
		t.Errorf("applied %d: %v", r.Applied, r.Warnings)
	}
	for _, want := range []string{
		"datafetching.azConfigDrift.interval: expected a duration", "datafetching.azConfigDrift.heartbeatInterval: must be between 5s and 1m0s",
		"datafetching.azConfigDrift.concurrency.tenants: must be between 1 and 32", "datafetching.azConfigDrift.concurrency.modules: expected a whole number",
		"datafetching.azConfigDrift.concurrency.colour: not a setting", "datafetching.azConfigDrift.logging.level: must be one of debug, info, warn, error",
		"datafetching.azConfigDrift.retention.logsDays: expected a whole number", "datafetching.azConfigDrift.mongo.ensureIndexes: expected true or false",
		"datafetching.azConfigDrift.ignore: expected a JSON list of objects", "datafetching.azConfigDrift.nonsense: not a setting",
		"datafetching.azConfigDrift.tenants.not-a-guid: the part after tenants. must be a tenant ID", "datafetching.azConfigDrift.tenants." + tA + ".cloud: must be one of",
		"datafetching.azConfigDrift.tenants." + tA + ".shoeSize: not a setting", "datafetching.azConfigDrift.tenants." + tB + ": left out, it needs tenantName, clientId and clientSecret",
		"datafetching.azConfigDrift.modules.Bad Id: expected a module id", "datafetching.azConfigDrift.modules.azure-network.enabled: expected true or false",
		"datafetching.azConfigDrift.modules.azure-network.sources.resources.speed: not a setting", "datafetching.azConfigDrift.modules.azure-network.extra: not a setting",
	} {
		found := false
		for _, w := range r.Warnings {
			found = found || strings.HasPrefix(w, want)
		}
		if !found {
			t.Errorf("no warning starting %q in:\n%s", want, strings.Join(r.Warnings, "\n"))
		}
	}
	if len(r.Warnings) != 18 {
		t.Errorf("%d warnings:\n%s", len(r.Warnings), strings.Join(r.Warnings, "\n"))
	}
	// The one tenant is switched off, so the result does not parse: the
	// caller then runs on the file alone.
	if _, err := config.Parse(r.Config, func(k string) string { return map[string]string{"SECRET": "s", "PW": "p"}[k] }, nil); err == nil || !strings.Contains(err.Error(), "switched off") {
		t.Errorf("parse: %v", err)
	}

	// Without the tenant switch, the file's values stand wherever a setting was bad.
	delete(in["tenants"].(map[string]any)[tA].(map[string]any), "enabled")
	r, _ = Merge([]byte(file), in)
	c := parse(t, r)
	if c.Interval.D().String() != "12h0m0s" || c.Concurrency.Tenants != 1 || c.Concurrency.Modules != 3 || c.Logging.Level != "info" || c.Mongo.Database != "fromfile" ||
		c.Limits.ChangePaths != 20 || len(c.Ignore) != 1 || c.Ignore[0].Paths[0] != "fromFile" || len(c.Tenants) != 1 || c.Tenants[0].Cloud != "public" {
		t.Errorf("fallbacks: %+v", c)
	}
	if m := c.Modules["azure-network"]; m.Enabled == nil || *m.Enabled || m.Sources["resources"].Enabled == nil || *m.Sources["resources"].Enabled {
		t.Errorf("module switches: %+v", m)
	}
}

func TestEverythingFromSettings(t *testing.T) {
	r, err := Merge(nil, obj(t, `{"mongo": {"uri": "mongodb://gui"}, "tenants": {"`+tA+`": {"tenantName": "A", "clientId": "c", "clientSecret": "s"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if c := parse(t, r); c.Mongo.URI != "mongodb://gui" || len(c.Tenants) != 1 || c.Tenants[0].ClientSecret != "s" || c.Interval.D().Hours() != 6 {
		t.Errorf("%+v", c)
	}
	// Nothing set: the file as it is.
	r, _ = Merge([]byte(file), map[string]any{})
	if c := parse(t, r); r.Applied != 0 || c.Mongo.Database != "fromfile" || len(c.Tenants) != 1 {
		t.Errorf("%+v", c)
	}
	if _, err := Merge([]byte("{broken"), nil); err == nil {
		t.Error("a broken file is an error")
	}
}

// The dashboard's field list must name the settings this package reads.
func TestDashboardFieldsMatch(t *testing.T) {
	b, err := os.ReadFile("testdata/settings.fields.ts")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	section := func(name string) []string {
		_, rest, ok := strings.Cut(src, "export const "+name)
		if !ok {
			t.Fatalf("no %s in settings.fields.ts", name)
		}
		rest, _, _ = strings.Cut(rest, "\n];")
		var keys []string
		for _, m := range regexp.MustCompile(`\{ key: '([A-Za-z.]+)'`).FindAllStringSubmatch(rest, -1) {
			keys = append(keys, m[1])
		}
		sort.Strings(keys)
		return keys
	}
	want := func(fields map[string]field, skip ...string) []string {
		var keys []string
	next:
		for k := range fields {
			for _, s := range skip {
				if k == s {
					continue next
				}
			}
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return keys
	}
	// Lists of objects have their own editors, not a field.
	if got, w := section("GENERAL_FIELDS"), want(General, "ignore", "exclude", "extraSources", "skipSources"); strings.Join(got, ",") != strings.Join(w, ",") {
		t.Errorf("general fields\n dashboard: %v\n collector: %v", got, w)
	}
	if got, w := section("TENANT_FIELDS"), want(Tenant, "enabled", "clientSecretEnv", "passwordEnv"); strings.Join(got, ",") != strings.Join(w, ",") {
		t.Errorf("tenant fields\n dashboard: %v\n collector: %v", got, w)
	}
}

// What the dashboard writes to App Configuration (the fixture is produced
// by its own tests) must be read here without a single warning.
func TestWhatTheDashboardWritesIsRead(t *testing.T) {
	b, err := os.ReadFile("testdata/settings.json")
	if err != nil {
		t.Fatal(err)
	}
	var entries []struct {
		Key         string `json:"key"`
		Value       string `json:"value"`
		ContentType string `json:"contentType"`
	}
	if err := json.Unmarshal(b, &entries); err != nil {
		t.Fatal(err)
	}
	// Decoded the way the App Configuration reader does it.
	flat := map[string]any{}
	for _, e := range entries {
		var v any = e.Value
		switch {
		case strings.Contains(e.ContentType, "keyvaultref"):
			var ref struct{ URI string }
			if json.Unmarshal([]byte(e.Value), &ref) != nil || !strings.HasPrefix(ref.URI, "https://kv-prod.vault.azure.net/secrets/") {
				t.Fatalf("%s: not a Key Vault reference: %s", e.Key, e.Value)
			}
			v = "secret-of:" + ref.URI
		case strings.HasPrefix(e.ContentType, "application/json"):
			if err := json.Unmarshal([]byte(e.Value), &v); err != nil {
				t.Fatalf("%s: %v", e.Key, err)
			}
		}
		flat[Root+"."+e.Key] = v
	}
	r, err := Merge([]byte(file), Nest(flat))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Warnings) != 0 || r.Applied != len(entries) {
		t.Fatalf("applied %d of %d settings; warnings:\n%s", r.Applied, len(entries), strings.Join(r.Warnings, "\n"))
	}
	c := parse(t, r)
	if c.Interval.D().Minutes() != 30 || c.Concurrency.Tenants != 4 || c.EnsureIndexes() || c.Mongo.Database != "azconfigdrift" ||
		c.Mongo.URI != "secret-of:https://kv-prod.vault.azure.net/secrets/drift-mongo" {
		t.Errorf("general: %+v", c)
	}
	if len(c.Tenants) != 2 {
		t.Fatalf("tenants: %+v", c.Tenants)
	}
	a, f := c.Tenants[0], c.Tenants[1]
	if a.Name != "Contoso" || a.ClientSecret != "file-secret" || len(a.ExcludeSubscriptions) != 1 {
		t.Errorf("the file's tenant with the dashboard's override: %+v", a)
	}
	if f.ID != tB || f.Name != "Fabrikam" || f.ClientSecret != "s3cret" || f.Cloud != "usgovernment" || f.Has("azure") || f.Username != "svc@fabrikam.com" ||
		f.Password != "secret-of:https://kv-prod.vault.azure.net/secrets/fabrikam-svc" {
		t.Errorf("the dashboard's tenant: %+v", f)
	}
	if len(c.Ignore) != 2 || c.Ignore[0].Type != "microsoft.web/sites" || c.Ignore[1].Module != "m365-applications" || len(c.ExtraSources) != 1 || c.ExtraSources[0].ID != "budgets" {
		t.Errorf("lists: %+v %+v", c.Ignore, c.ExtraSources)
	}
	if len(c.Exclude) != 2 || !c.Excluded("azure-network", "microsoft.network/networkwatchers", "rg", "nw") || c.Excluded("azure-compute", "microsoft.network/networkwatchers", "rg", "nw") ||
		!c.Excluded("azure-compute", "microsoft.compute/disks", "MC_aks_west", "disk") || c.Excluded("azure-network", "microsoft.network/virtualnetworks", "rg", "vnet") {
		t.Errorf("exclusions: %+v", c.Exclude)
	}
	id := c.Modules["m365-identity"].Sources
	if e := c.Modules["m365-exchange"].Enabled; e == nil || *e || id["settings-catalog"].Enabled == nil || !*id["settings-catalog"].Enabled ||
		id["settings-catalog"].Beta == nil || !*id["settings-catalog"].Beta || id["ca-policies"].Delegated == nil || !*id["ca-policies"].Delegated {
		t.Errorf("switches: %+v", c.Modules)
	}
}
