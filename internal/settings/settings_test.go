package settings

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

type duration time.Duration

func (d *duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return errors.New("durations are strings")
	}
	v, err := time.ParseDuration(s)
	*d = duration(v)
	return err
}

type checks struct {
	Timeout duration `json:"timeout"`
	Ports   []int    `json:"ports"`
}

type entry struct {
	Name        string   `json:"name"`
	Address     string   `json:"address"`
	Password    string   `json:"password"`
	PasswordEnv string   `json:"passwordEnv"`
	Skip        *bool    `json:"skip"`
	Tags        []string `json:"tags"`
	checks
}

type schema struct {
	Mongo struct {
		URI      string `json:"uri"`
		Database string `json:"database"`
		Ensure   *bool  `json:"ensureIndexes"`
	} `json:"mongo"`
	Interval    duration          `json:"interval"`
	Concurrency int               `json:"concurrency"`
	Ratio       *float64          `json:"ratio"`
	Disable     []string          `json:"disable"`
	Entries     []entry           `json:"entries"`
	Plain       []entry           `json:"plain"`
	Labels      map[string]bool   `json:"labels"`
	Defaults    json.RawMessage   `json:"defaults"`
	Hidden      string            `json:"-"`
	Raw         []json.RawMessage `json:"raw"`
}

var spec = Spec{
	Tool:   "test",
	Schema: schema{},
	Lists:  map[string]string{"entries": "name"},
	Types:  map[string]any{"defaults": checks{}, "raw": []entry{}},
}

const file = `{"mongo": {"uri": "mongodb://file", "database": "fromfile"}, "interval": "1h", "concurrency": 2,
 "entries": [{"name": "A", "address": "a.example", "passwordEnv": "A_PASSWORD", "tags": ["x"]}]}`

func merge(t *testing.T, file string, s map[string]any) (*Result, schema) {
	t.Helper()
	r, err := Merge([]byte(file), s, spec)
	if err != nil {
		t.Fatal(err)
	}
	var c schema
	dec := json.NewDecoder(strings.NewReader(string(r.Config)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		t.Fatalf("the merged configuration does not load: %v\n%s", err, r.Config)
	}
	return r, c
}

func TestNestAndUnder(t *testing.T) {
	obj := Nest(map[string]any{"datafetching.test.mongo.uri": "u", "datafetching.test.interval": "5m", "datafetching.other.interval": "1m"})
	s := Under(obj, "test")
	if s["interval"] != "5m" || s["mongo"].(map[string]any)["uri"] != "u" {
		t.Errorf("%v", s)
	}
	if got := Under(map[string]any{"test": map[string]any{"a": 1}}, "test"); got["a"] != 1 {
		t.Errorf("the object under the root: %v", got)
	}
	if got := Under(map[string]any{"a": 1}, "test"); got["a"] != 1 {
		t.Errorf("the object itself: %v", got)
	}
	// Another tool's settings are not this tool's.
	if got := Under(map[string]any{Root: map[string]any{"other": map[string]any{"a": 1}}}, "test"); len(got) != 0 {
		t.Errorf("%v", got)
	}
	if Key("test") != "datafetching.test" {
		t.Error(Key("test"))
	}
}

func TestMergeValues(t *testing.T) {
	r, c := merge(t, file, Nest(map[string]any{
		"mongo.database":      "fromsettings",
		"mongo.ensureIndexes": "false",
		"interval":            " 30m ",
		"concurrency":         "8",
		"ratio":               0.5,
		"disable":             "a, b;c",
		"labels.one":          "yes",
		"labels.two":          false,
		"defaults.timeout":    "5s",
		"defaults.ports":      "[443, 4444]",
	}))
	if len(r.Warnings) != 0 || r.Applied != 10 {
		t.Fatalf("applied %d, warnings %v", r.Applied, r.Warnings)
	}
	if c.Mongo.URI != "mongodb://file" || c.Mongo.Database != "fromsettings" || c.Mongo.Ensure == nil || *c.Mongo.Ensure {
		t.Errorf("mongo: %+v", c.Mongo)
	}
	if time.Duration(c.Interval) != 30*time.Minute || c.Concurrency != 8 || *c.Ratio != 0.5 || strings.Join(c.Disable, "|") != "a|b|c" {
		t.Errorf("%+v", c)
	}
	if !c.Labels["one"] || c.Labels["two"] || len(c.Labels) != 2 {
		t.Errorf("labels: %v", c.Labels)
	}
	var d checks
	if err := json.Unmarshal(c.Defaults, &d); err != nil || time.Duration(d.Timeout) != 5*time.Second || len(d.Ports) != 2 || d.Ports[1] != 4444 {
		t.Errorf("defaults: %s %v", c.Defaults, err)
	}
}

func TestMergeIgnoresWhatIsNotValid(t *testing.T) {
	r, c := merge(t, file, Nest(map[string]any{
		"interval":       "soon",
		"concurrency":    "many",
		"ratio":          "",
		"mongo.colour":   "blue",
		"mongo":          nil,
		"unknown":        "x",
		"Hidden":         "x",
		"disable":        map[string]any{"a": 1},
		"plain.A.name":   "x",
		"labels.one":     "perhaps",
		"mongo.database": "ok",
	}))
	if r.Applied != 1 || c.Mongo.Database != "ok" || time.Duration(c.Interval) != time.Hour || c.Concurrency != 2 {
		t.Errorf("applied %d: %+v", r.Applied, c)
	}
	want := []string{"interval", "concurrency", "mongo.colour: not a setting", "unknown: not a setting", "Hidden: not a setting", "disable", "plain", "labels.one"}
	all := strings.Join(r.Warnings, "\n")
	for _, w := range want {
		if !strings.Contains(all, "datafetching.test."+w) {
			t.Errorf("no warning about %s in:\n%s", w, all)
		}
	}
	if len(r.Warnings) != len(want) {
		t.Errorf("%d warnings:\n%s", len(r.Warnings), all)
	}
}

func TestMergeListsByKey(t *testing.T) {
	r, c := merge(t, file, Nest(map[string]any{
		"entries.a.address":  "new.example",
		"entries.a.password": "direct",
		"entries.a.timeout":  "3s",
		"entries.B.address":  "b.example",
		"entries.B.skip":     "true",
		"entries.B.tags":     "one, two",
		"entries.B.ports":    []any{float64(1), "2"},
		"entries.C.colour":   "red",
		"entries.D":          "text",
	}))
	if len(c.Entries) != 2 || r.Applied != 7 {
		t.Fatalf("applied %d, entries %+v, warnings %v", r.Applied, c.Entries, r.Warnings)
	}
	a, b := c.Entries[0], c.Entries[1]
	// Matched without regard to case; the file's spelling and fields stay.
	if a.Name != "A" || a.Address != "new.example" || a.Password != "direct" || a.PasswordEnv != "" || len(a.Tags) != 1 || time.Duration(a.Timeout) != 3*time.Second {
		t.Errorf("the file's entry with the settings laid over it: %+v", a)
	}
	if b.Name != "B" || b.Address != "b.example" || b.Skip == nil || !*b.Skip || len(b.Tags) != 2 || len(b.Ports) != 2 || b.Ports[1] != 2 {
		t.Errorf("the entry the settings add: %+v", b)
	}
	// An entry nothing valid was said about is not added.
	if all := strings.Join(r.Warnings, "\n"); len(r.Warnings) != 2 || !strings.Contains(all, "entries.C.colour: not a setting") || !strings.Contains(all, "entries.D: expected settings beneath it") {
		t.Errorf("warnings:\n%s", all)
	}
}

func TestMergeListsAsArrays(t *testing.T) {
	// A JSON array, typed or as text, replaces the file's list.
	for _, v := range []any{
		`[{"name": "Z", "address": "z.example", "ports": ["80"], "colour": "red"}]`,
		[]any{map[string]any{"name": "Z", "address": "z.example", "ports": []any{"80"}, "colour": "red"}},
	} {
		r, c := merge(t, file, map[string]any{"entries": v, "plain": v, "raw": v})
		if r.Applied != 3 || len(c.Entries) != 1 || c.Entries[0].Name != "Z" || c.Entries[0].Ports[0] != 80 || len(c.Plain) != 1 || len(c.Raw) != 1 {
			t.Errorf("applied %d: %+v", r.Applied, c)
		}
		if len(r.Warnings) != 3 || !strings.Contains(r.Warnings[0], "entries[0].colour: not a setting") {
			t.Errorf("warnings: %v", r.Warnings)
		}
	}
	r, _ := merge(t, file, map[string]any{"entries": "nonsense", "plain": []any{"x"}})
	if r.Applied != 0 || len(r.Warnings) != 2 {
		t.Errorf("applied %d, warnings %v", r.Applied, r.Warnings)
	}
}

func TestMergeWithoutAFile(t *testing.T) {
	r, c := merge(t, "", map[string]any{Root: map[string]any{"test": map[string]any{"interval": "2h", "entries": map[string]any{"n": map[string]any{"address": "x"}}}}})
	if r.Applied != 2 || time.Duration(c.Interval) != 2*time.Hour || len(c.Entries) != 1 || c.Entries[0].Name != "n" {
		t.Errorf("applied %d: %+v", r.Applied, c)
	}
	if _, err := Merge([]byte("{broken"), nil, spec); err == nil {
		t.Error("a broken file is an error")
	}
}

func TestLoader(t *testing.T) {
	parse := func(b []byte) (*schema, error) {
		var c schema
		dec := json.NewDecoder(strings.NewReader(string(b)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&c); err != nil {
			return nil, err
		}
		if c.Concurrency > 100 {
			return nil, errors.New("concurrency is too high")
		}
		return &c, nil
	}
	ctx := context.Background()
	fetch := func(s map[string]any, err error) Fetch {
		return func(context.Context) (map[string]any, []string, error) { return s, []string{"a reference"}, err }
	}

	// The settings win over the file.
	l := &Loader[*schema]{Spec: spec, File: []byte(file), Parse: parse, Fetch: fetch(map[string]any{"concurrency": 4, "nope": 1}, nil)}
	c, st, err := l.Load(ctx)
	if err != nil || c.Concurrency != 4 || st.Source != "appconfig" || st.Applied != 1 || len(st.Warnings) != 2 || st.Error != "" {
		t.Errorf("%+v %+v %v", c, st, err)
	}
	// Once a configuration is in use, settings that cannot be read or make
	// it invalid are an error: the caller keeps what it has, and the file
	// alone does not take over.
	l.Fetch = fetch(map[string]any{"concurrency": 1000}, nil)
	if _, st, err = l.Load(ctx); err == nil || !strings.Contains(err.Error(), "too high") || !strings.Contains(st.Error, "too high") {
		t.Errorf("%+v %v", st, err)
	}
	l.Fetch = fetch(nil, errors.New("no route"))
	if _, _, err = l.Load(ctx); err == nil || !strings.Contains(err.Error(), "no route") {
		t.Errorf("%v", err)
	}
	l.Fetch = fetch(map[string]any{"concurrency": 5}, nil)
	if c, _, err = l.Load(ctx); err != nil || c.Concurrency != 5 {
		t.Errorf("%+v %v", c, err)
	}

	// At the start it is different: there is nothing to keep.
	// Settings that make the configuration invalid: the file alone, and why.
	l = &Loader[*schema]{Spec: spec, File: []byte(file), Parse: parse, Fetch: fetch(map[string]any{"concurrency": 1000}, nil)}
	c, st, err = l.Load(ctx)
	if err != nil || c.Concurrency != 2 || st.Source != "file" || !strings.Contains(st.Error, "too high") {
		t.Errorf("%+v %+v %v", c, st, err)
	}
	// App Configuration out of reach: the file alone.
	l = &Loader[*schema]{Spec: spec, File: []byte(file), Parse: parse, Fetch: fetch(nil, errors.New("no route"))}
	c, st, err = l.Load(ctx)
	if err != nil || c.Concurrency != 2 || !strings.Contains(st.Error, "no route") {
		t.Errorf("%+v %+v %v", c, st, err)
	}
	// ...and with no file there is nothing to run on.
	l = &Loader[*schema]{Spec: spec, Parse: parse, Fetch: fetch(nil, errors.New("no route"))}
	if _, _, err = l.Load(ctx); err == nil || !strings.Contains(err.Error(), "no route") {
		t.Errorf("%v", err)
	}
	// A file that is not valid either: both reasons.
	l = &Loader[*schema]{Spec: spec, File: []byte(`{"concurrency": 500}`), Parse: parse, Fetch: fetch(nil, errors.New("no route"))}
	if _, _, err = l.Load(ctx); err == nil || !strings.Contains(err.Error(), "no route") || !strings.Contains(err.Error(), "too high") {
		t.Errorf("%v", err)
	}
	// No file, everything from the settings.
	l = &Loader[*schema]{Spec: spec, Parse: parse, Fetch: fetch(map[string]any{"concurrency": 3}, nil)}
	if c, _, err = l.Load(ctx); err != nil || c.Concurrency != 3 {
		t.Errorf("%+v %v", c, err)
	}
	// Neither.
	l = &Loader[*schema]{Spec: spec, Parse: parse}
	if _, _, err = l.Load(ctx); err == nil || !strings.Contains(err.Error(), "datafetching.test") {
		t.Errorf("%v", err)
	}
}

func TestAppConfigNeedsAnEndpoint(t *testing.T) {
	env := map[string]string{}
	get := func(k string) string { return env[k] }
	if _, ok, err := AppConfig(get, "test"); ok || err != nil {
		t.Errorf("%v %v", ok, err)
	}
	env["AZURE_APPCONFIG_ENDPOINT"] = "https://x.azconfig.io"
	if _, ok, err := AppConfig(get, "test"); !ok || err == nil {
		t.Errorf("an endpoint without credentials: %v %v", ok, err)
	}
	env["AZURE_APPCONFIG_MANAGED_IDENTITY"] = "system"
	if f, ok, err := AppConfig(get, "test"); !ok || err != nil || f == nil {
		t.Errorf("%v %v", ok, err)
	}
}
