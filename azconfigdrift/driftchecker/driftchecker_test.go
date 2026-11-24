package driftchecker

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	tA = "00000000-0000-0000-0000-00000000000a"
	tB = "00000000-0000-0000-0000-00000000000b"
)

const file = `{
	"mongo": {"uri": "mongodb://file"}, "interval": "12h",
	"tenants": [{"tenantName": "Contoso", "tenantId": "` + tA + `", "clientId": "c", "clientSecret": "from-file"}],
	"modules": {"azure-other": {"enabled": false}}
}`

func write(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func newTestLoader(t *testing.T, o Options) *loader {
	t.Helper()
	o.Getenv = func(string) string { return "" }
	l, err := newLoader(o)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestSettingsOverTheFile(t *testing.T) {
	calls := 0
	current := Settings{"azConfigDrift": map[string]any{
		"interval": "30m",
		"tenants":  map[string]any{tB: map[string]any{"tenantName": "Fabrikam", "clientId": "c2", "clientSecret": "s2"}},
		"modules":  map[string]any{"m365-exchange": map[string]any{"enabled": true}},
	}}
	before, _ := json.Marshal(current)
	l := newTestLoader(t, Options{ConfigFile: write(t, file), Settings: func(context.Context) (Settings, error) {
		calls++
		return current, nil
	}})
	got, err := l.load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	c := got.cfg
	if c.Interval.D().Minutes() != 30 || c.Mongo.URI != "mongodb://file" || len(c.Tenants) != 2 || c.Tenants[0].ClientSecret != "from-file" || c.Tenants[1].Name != "Fabrikam" {
		t.Errorf("merged: %+v", c)
	}
	if on := c.Modules["m365-exchange"].Enabled; on == nil || !*on || *c.Modules["azure-other"].Enabled {
		t.Errorf("modules: %+v", c.Modules)
	}
	if s := got.status; s.Source != "object" || s.Applied != 5 || len(s.Warnings) != 0 || s.Error != "" || s.LoadedAt.IsZero() {
		t.Errorf("status: %+v", s)
	}
	eff := map[string]string{}
	for _, e := range effective(c) {
		eff[e.Key] = e.Value
	}
	if eff["interval"] != "30m" || eff["heartbeatInterval"] != "30s" || eff["limits.sourceTimeout"] != "2h" || eff["concurrency.modules"] != "3" ||
		eff["logging.format"] != "text" || eff["mongo.ensureIndexes"] != "true" || eff["ignore"] != "[]" || eff["extraSources"] != "[]" || eff["skipSources"] != "" {
		t.Errorf("effective: %v", eff)
	}
	if eff["tenants."+tA+".tenantName"] != "Contoso" || eff["tenants."+tB+".clientId"] != "c2" || eff["tenants."+tA+".cloud"] != "public" || eff["tenants."+tA+".platforms"] != "" {
		t.Errorf("effective tenants: %v", eff)
	}
	// No secret is ever reported.
	for k, v := range eff {
		if strings.Contains(strings.ToLower(k), "secret") || strings.Contains(strings.ToLower(k), "password") || strings.Contains(k, "uri") || strings.Contains(v, "from-file") || v == "s2" || strings.Contains(v, "mongodb://") {
			t.Errorf("a secret is reported: %s = %s", k, v)
		}
	}
	if compact(90*time.Minute) != "1h30m" || compact(45*time.Second) != "45s" || compact(26*time.Hour) != "26h" || compact(time.Hour+time.Second) != "1h0m1s" {
		t.Error("compact durations")
	}
	if after, _ := json.Marshal(current); string(after) != string(before) {
		t.Error("the caller's settings object was changed")
	}

	// Changed in the dashboard: the next load sees it.
	current = Settings{"interval": "45m", "concurrency": map[string]any{"tenants": "lots"}}
	got, _ = l.load(context.Background())
	if got.cfg.Interval.D().Minutes() != 45 || len(got.cfg.Tenants) != 1 || calls != 2 {
		t.Errorf("reload: %+v", got.cfg)
	}
	if len(got.status.Warnings) != 1 || !strings.Contains(got.status.Warnings[0], "datafetching.azConfigDrift.concurrency.tenants") {
		t.Errorf("warnings: %v", got.status.Warnings)
	}

	// Settings that make the whole configuration invalid: the file alone.
	current = Settings{"tenants": map[string]any{tA: map[string]any{"enabled": false}}}
	got, err = l.load(context.Background())
	if err != nil || got.status.Source != "file" || !strings.Contains(got.status.Error, "switched off") || len(got.cfg.Tenants) != 1 || got.cfg.Interval.D().Hours() != 12 {
		t.Errorf("fallback: %+v %v", got, err)
	}
}

func TestFallbacks(t *testing.T) {
	// App Configuration is down: the file, with the reason.
	l := newTestLoader(t, Options{ConfigFile: write(t, file), SettingsSource: "appconfig", Settings: func(context.Context) (Settings, error) {
		return nil, errors.New("HTTP 503")
	}})
	got, err := l.load(context.Background())
	if err != nil || got.status.Source != "file" || !strings.Contains(got.status.Error, "could not be read: HTTP 503") || got.cfg.Interval.D().Hours() != 12 {
		t.Errorf("%+v %v", got, err)
	}

	// No file at all: everything from the settings.
	all := Settings{"mongo": map[string]any{"uri": "mongodb://gui"}, "tenants": map[string]any{tA: map[string]any{"tenantName": "A", "clientId": "c", "clientSecret": "s"}}}
	l = newTestLoader(t, Options{ConfigFile: filepath.Join(t.TempDir(), "missing.json"), SettingsSource: "appconfig", Settings: func(context.Context) (Settings, error) { return all, nil }})
	got, err = l.load(context.Background())
	if err != nil || got.status.Source != "appconfig" || got.cfg.Mongo.URI != "mongodb://gui" || len(got.mods) < 19 {
		t.Errorf("settings only: %+v %v", got, err)
	}
	// ...and nothing to fall back to when they are unusable.
	all = Settings{}
	if _, err := l.load(context.Background()); err == nil || !strings.Contains(err.Error(), "no configuration file to fall back to") {
		t.Errorf("nothing usable: %v", err)
	}

	// The file alone.
	l = newTestLoader(t, Options{ConfigFile: write(t, file)})
	if got, err := l.load(context.Background()); err != nil || got.status.Source != "file" || got.status.Error != "" {
		t.Errorf("file only: %+v %v", got, err)
	}
	// A missing file without settings is an error at once.
	if _, err := newLoader(Options{ConfigFile: filepath.Join(t.TempDir(), "missing.json")}); err == nil {
		t.Error("a missing file without settings must fail")
	}
	// -tenant and -modules are checked against the merged configuration.
	l = newTestLoader(t, Options{ConfigFile: write(t, file), Tenant: "Nobody"})
	if _, err := l.load(context.Background()); err == nil || !strings.Contains(err.Error(), `no tenant named "Nobody"`) {
		t.Errorf("unknown tenant: %v", err)
	}
	l = newTestLoader(t, Options{ConfigFile: write(t, file), Modules: []string{"nope"}})
	if _, err := l.load(context.Background()); err == nil || !strings.Contains(err.Error(), `no module "nope"`) {
		t.Errorf("unknown module: %v", err)
	}
}

func TestSettingsOfAndFromKeyValues(t *testing.T) {
	type cldConfig struct {
		AzureDriftChecker map[string]any `json:"azConfigDrift"`
	}
	s, err := SettingsOf(cldConfig{AzureDriftChecker: map[string]any{"interval": "1h"}})
	if err != nil || s["azConfigDrift"].(map[string]any)["interval"] != "1h" {
		t.Errorf("%v %v", s, err)
	}
	if s, err := SettingsOf([]byte(`{"interval": "2h"}`)); err != nil || s["interval"] != "2h" {
		t.Errorf("%v %v", s, err)
	}
	if s, err := SettingsOf(nil); err != nil || len(s) != 0 {
		t.Errorf("%v %v", s, err)
	}
	if _, err := SettingsOf([]byte(`[1]`)); err == nil {
		t.Error("a list is not a settings object")
	}
	kv := FromKeyValues(map[string]any{"datafetching.azConfigDrift.interval": "3h", "datafetching.azConfigDrift.modules.m365-intune.enabled": "false", "other.key": 1})
	b, _ := json.Marshal(kv)
	if string(b) != `{"interval":"3h","modules":{"m365-intune":{"enabled":"false"}}}` {
		t.Errorf("%s", b)
	}
	if fn, ok, err := AppConfig(func(string) string { return "" }); fn != nil || ok || err != nil {
		t.Error("no endpoint: no settings function")
	}
	if _, ok, err := AppConfig(func(k string) string {
		return map[string]string{"AZURE_APPCONFIG_ENDPOINT": "https://x.azconfig.io"}[k]
	}); !ok || err == nil {
		t.Error("an endpoint without credentials is an error")
	}
}

// Settings still under the key used before the move to datafetch are read
// until the new key has any, and said to be in the old place.
func TestTheOldKeyIsReadUntilTheNewOneIsUsed(t *testing.T) {
	store := map[string]any{"azureDriftChecker.interval": "2h", "azureDriftChecker.tenants." + tB + ".tenantName": "Fabrikam"}
	var asked []string
	load := func(_ context.Context, prefix string) (map[string]any, []string, error) {
		asked = append(asked, prefix)
		out := map[string]any{}
		for k, v := range store {
			if strings.HasPrefix(k, prefix) {
				out[k] = v
			}
		}
		return out, nil, nil
	}
	s, err := fromStore(context.Background(), load)
	if err != nil {
		t.Fatal(err)
	}
	w, _ := s[referenceWarnings].([]string)
	if s["interval"] != "2h" || s["tenants"] == nil || len(w) != 1 || !strings.Contains(w[0], "old key azureDriftChecker") {
		t.Errorf("%v", s)
	}
	if strings.Join(asked, " ") != "datafetching.azConfigDrift. azureDriftChecker." {
		t.Errorf("asked for %v", asked)
	}

	store["datafetching.azConfigDrift.interval"] = "30m"
	asked = nil
	s, err = fromStore(context.Background(), load)
	if err != nil {
		t.Fatal(err)
	}
	if s["interval"] != "30m" || s["tenants"] != nil || s[referenceWarnings] != nil || len(asked) != 1 {
		t.Errorf("%v (asked for %v)", s, asked)
	}

	// Neither key: an empty object, not an error.
	store = map[string]any{}
	if s, err = fromStore(context.Background(), load); err != nil || len(s) != 0 {
		t.Errorf("%v %v", s, err)
	}
}
