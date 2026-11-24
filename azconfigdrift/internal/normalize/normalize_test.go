package normalize

import (
	"encoding/json"
	"strings"
	"testing"
)

func decode(t *testing.T, s string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func canon(t *testing.T, v any) string {
	t.Helper()
	b, err := Canonical(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestCleanDropsVolatileAndSortsSets(t *testing.T) {
	rules := NewRules("etag", "provisioningState", "properties.extended", "properties.*.lastSync")
	a := decode(t, `{
		"@odata.context": "x", "assignments@odata.context": "y", "@odata.type": "#microsoft.graph.thing",
		"etag": "W/1", "kind": null,
		"properties": {
			"provisioningState": "Succeeded",
			"extended": {"instanceView": {"powerState": "running"}},
			"sync": {"lastSync": "today", "mode": "full"},
			"allowed": ["b", "a", "c"],
			"rules": [{"name": "z", "Etag": "1", "port": 443}, {"name": "a", "port": 80}],
			"ordered": [{"port": 2}, {"port": 1}],
			"adminPassword": "hunter2", "disablePasswordAuthentication": true,
			"html": "<b>&</b>"
		}}`)
	b := decode(t, `{
		"etag": "W/2",
		"properties": {
			"provisioningState": "Updating",
			"extended": {"instanceView": {"powerState": "stopped"}},
			"sync": {"lastSync": "yesterday", "mode": "full"},
			"allowed": ["c", "b", "a"],
			"rules": [{"name": "a", "port": 80}, {"name": "z", "port": 443, "etag": "2"}],
			"ordered": [{"port": 2}, {"port": 1}],
			"adminPassword": "hunter2", "disablePasswordAuthentication": true,
			"html": "<b>&</b>"
		}, "@odata.type": "#microsoft.graph.thing"}`)
	ca, cb := canon(t, Clean(a, rules)), canon(t, Clean(b, rules))
	if ca != cb {
		t.Fatalf("equal settings gave different JSON:\n%s\n%s", ca, cb)
	}
	for _, gone := range []string{"etag", "Etag", "provisioningState", "powerState", "lastSync", "hunter2", "odata.context", "null", `\` + "u003c"} {
		if strings.Contains(ca, gone) {
			t.Errorf("%q should not be in %s", gone, ca)
		}
	}
	for _, kept := range []string{`"@odata.type"`, `"mode":"full"`, `"allowed":["a","b","c"]`, `"ordered":[{"port":2},{"port":1}]`, `(redacted, fingerprint `, `"disablePasswordAuthentication":true`, `<b>&</b>`} {
		if !strings.Contains(ca, kept) {
			t.Errorf("%q should be in %s", kept, ca)
		}
	}
	if Hash([]byte(ca)) != Hash([]byte(cb)) || len(Hash([]byte(ca))) != 64 {
		t.Error("hash")
	}
	// A changed secret still changes the JSON.
	c := decode(t, `{"properties": {"adminPassword": "other"}}`)
	d := decode(t, `{"properties": {"adminPassword": "hunter2"}}`)
	if canon(t, Clean(c, rules)) == canon(t, Clean(d, rules)) {
		t.Error("a changed secret must change the fingerprint")
	}
}

func TestDiffAndDescribe(t *testing.T) {
	before := decode(t, `{"a": 1, "b": {"c": "x", "gone": true}, "list": [1, 2], "empty": {}, "tags": {"app.kubernetes.io/name": "x"}}`)
	after := decode(t, `{"a": 1, "b": {"c": "y", "new": [ ]}, "list": [1, 2, 3], "empty": {}, "tags": {"app.kubernetes.io/name": "x"}}`)
	paths, total := Diff(before, after, 0)
	got := []string{}
	for _, p := range paths {
		got = append(got, p.Kind+" "+p.Path+" "+p.Before+"→"+p.After)
	}
	want := []string{`changed b.c "x"→"y"`, `removed b.gone true→`, `added b.new →[]`, `added list[2] →3`}
	if total != 4 || strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %d %v", total, got)
	}
	if p, n := Diff(before, after, 2); len(p) != 2 || n != 4 {
		t.Errorf("limit: %d of %d", len(p), n)
	}
	if p, n := Diff(before, before, 0); len(p) != 0 || n != 0 {
		t.Error("no difference expected")
	}
	props, keys := Describe(before, 1000)
	if props != 7 || keys != "a app.kubernetes.io/name c gone list" {
		t.Errorf("describe: %d %q", props, keys)
	}
	if _, k := Describe(before, 8); k != "a" {
		t.Errorf("bounded keys: %q", k)
	}
	long := strings.Repeat("é", 500)
	if s := Shorten(long); len(s) > maxValueLen+3 || !strings.HasSuffix(s, "…") || strings.Contains(s, "�") {
		t.Error("shorten")
	}
}
