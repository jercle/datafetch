// Package normalize turns what an API returns into something that can be
// compared from one pass to the next: properties that change by themselves
// are removed, secrets are replaced by a fingerprint, lists that are really
// sets are sorted, and the result is written as canonical JSON.
package normalize

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/jercle/datafetch/azconfigdrift/internal/model"
)

// Rules says which properties to leave out.
//
// A pattern without a dot ("etag") drops every property of that name, at
// any depth. A pattern with dots ("properties.extended") is a path from the
// top of the object; "*" stands for any one name. List positions are not
// part of a path. Names are compared without regard to case.
type Rules struct {
	names map[string]bool
	paths [][]string
}

func NewRules(patterns ...string) *Rules {
	r := &Rules{names: map[string]bool{}}
	r.Add(patterns...)
	return r
}

func (r *Rules) Add(patterns ...string) {
	for _, p := range patterns {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		if !strings.Contains(p, ".") || strings.HasPrefix(p, "@") {
			r.names[p] = true
			continue
		}
		r.paths = append(r.paths, strings.Split(p, "."))
	}
}

// Merge returns rules that drop what r or any of the others drop.
func (r *Rules) Merge(others ...*Rules) *Rules {
	out := &Rules{names: map[string]bool{}}
	for _, x := range append([]*Rules{r}, others...) {
		if x == nil {
			continue
		}
		for n := range x.names {
			out.names[n] = true
		}
		out.paths = append(out.paths, x.paths...)
	}
	return out
}

func (r *Rules) drop(path []string) bool {
	if r == nil {
		return false
	}
	if r.names[path[len(path)-1]] {
		return true
	}
next:
	for _, p := range r.paths {
		if len(p) != len(path) {
			continue
		}
		for i := range p {
			if p[i] != "*" && p[i] != path[i] {
				continue next
			}
		}
		return true
	}
	return false
}

// secretNames are (lower-case) parts of property names whose string values
// are never stored.
var secretNames = []string{"password", "connectionstring", "sastoken", "accesskey", "sharedkey", "clientsecret", "privatekey", "sharedsecret"}
var secretExact = map[string]bool{"secret": true, "secrettext": true, "primarykey": true, "secondarykey": true, "primarymasterkey": true, "secondarymasterkey": true}

func isSecret(name string) bool {
	if secretExact[name] {
		return true
	}
	for _, s := range secretNames {
		if strings.Contains(name, s) {
			return true
		}
	}
	return false
}

// redact replaces a secret by a short fingerprint, so a changed secret
// still shows as a change.
func redact(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "(redacted, fingerprint " + hex.EncodeToString(sum[:4]) + ")"
}

// Clean returns a copy of a decoded JSON value without the properties the
// rules drop, without OData annotations and nulls, with secrets redacted
// and set-like lists sorted.
func Clean(v any, rules *Rules) any {
	return clean(v, rules, nil)
}

func clean(v any, rules *Rules, path []string) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			if val == nil {
				continue
			}
			lk := strings.ToLower(k)
			// "@odata.context", "assignments@odata.context", ...
			if strings.Contains(lk, "@odata.") && lk != "@odata.type" {
				continue
			}
			p := append(path[:len(path):len(path)], lk)
			if rules.drop(p) {
				continue
			}
			if s, ok := val.(string); ok && s != "" && isSecret(lk) {
				out[k] = redact(s)
				continue
			}
			out[k] = clean(val, rules, p)
		}
		return out
	case []any:
		out := make([]any, 0, len(x))
		for _, e := range x {
			if e != nil {
				out = append(out, clean(e, rules, path))
			}
		}
		sortList(out)
		return out
	default:
		return v
	}
}

// identity properties, in order of preference, by which a list of objects
// is sorted when every element has a distinct value for one of them.
var identityKeys = []string{"id", "name", "Name", "Identity", "Guid", "key", "target", "tenantId", "displayName"}

// sortList orders lists whose order carries no meaning but which an API
// may return in any order: lists of plain values, and lists of objects
// that each have their own id or name. Other lists are left as they are.
func sortList(list []any) {
	if len(list) < 2 {
		return
	}
	scalars, objects := true, true
	for _, e := range list {
		switch e.(type) {
		case map[string]any:
			scalars = false
		case []any:
			scalars, objects = false, false
		default:
			objects = false
		}
	}
	if scalars {
		keys := make([]string, len(list))
		for i, e := range list {
			keys[i] = scalarKey(e)
		}
		sort.Sort(&byKey{keys, list})
		return
	}
	if !objects {
		return
	}
	for _, id := range identityKeys {
		keys := make([]string, len(list))
		seen := make(map[string]bool, len(list))
		ok := true
		for i, e := range list {
			val, has := e.(map[string]any)[id]
			if !has {
				ok = false
				break
			}
			switch val.(type) {
			case string, float64, json.Number:
			default:
				ok = false
			}
			k := scalarKey(val)
			if !ok || seen[k] {
				ok = false
				break
			}
			seen[k], keys[i] = true, k
		}
		if ok {
			sort.Sort(&byKey{keys, list})
			return
		}
	}
}

func scalarKey(v any) string {
	switch x := v.(type) {
	case string:
		return "s" + x
	case bool:
		return "b" + strconv.FormatBool(x)
	case float64:
		return "n" + strconv.FormatFloat(x, 'g', -1, 64)
	case json.Number:
		return "n" + x.String()
	}
	b, _ := json.Marshal(v)
	return "j" + string(b)
}

type byKey struct {
	keys []string
	list []any
}

func (b *byKey) Len() int           { return len(b.keys) }
func (b *byKey) Less(i, j int) bool { return b.keys[i] < b.keys[j] }
func (b *byKey) Swap(i, j int) {
	b.keys[i], b.keys[j] = b.keys[j], b.keys[i]
	b.list[i], b.list[j] = b.list[j], b.list[i]
}

// Canonical writes a value as JSON with sorted keys and no HTML escaping,
// so equal values give equal bytes.
func Canonical(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil { // maps are written with sorted keys
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func Hash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Decode reads canonical JSON back.
func Decode(s string) (any, error) {
	var v any
	err := json.Unmarshal([]byte(s), &v)
	return v, err
}

// Flatten lists every setting of a value as path → JSON value. Paths look
// like "properties.networkAcls.ipRules[0].value". Empty objects and lists
// are settings too.
func Flatten(v any) map[string]string {
	out := map[string]string{}
	flatten(v, "", out)
	return out
}

func flatten(v any, path string, out map[string]string) {
	switch x := v.(type) {
	case map[string]any:
		if len(x) == 0 && path != "" {
			out[path] = "{}"
		}
		for k, val := range x {
			p := k
			if path != "" {
				p = path + "." + k
			}
			flatten(val, p, out)
		}
	case []any:
		if len(x) == 0 {
			out[path] = "[]"
		}
		for i, val := range x {
			flatten(val, path+"["+strconv.Itoa(i)+"]", out)
		}
	default:
		b, _ := Canonical(v)
		out[path] = string(b)
	}
}

// Describe returns the number of settings in a value and their distinct
// names, lower-cased and space-separated (at most maxLen bytes), for search.
func Describe(v any, maxLen int) (props int, keys string) {
	seen := map[string]bool{}
	var names []string
	var walk func(v any, name string)
	walk = func(v any, name string) {
		switch x := v.(type) {
		case map[string]any:
			if len(x) == 0 && name != "" {
				props++
			}
			for k, val := range x {
				walk(val, k)
			}
		case []any:
			if len(x) == 0 {
				props++
			}
			for _, val := range x {
				walk(val, name)
			}
		default:
			props++
			if n := strings.ToLower(name); n != "" && !seen[n] {
				seen[n] = true
				names = append(names, n)
			}
		}
	}
	walk(v, "")
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		if b.Len()+len(n)+1 > maxLen {
			break
		}
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(n)
	}
	return props, b.String()
}

const maxValueLen = 400

// Shorten cuts a JSON value to a length that fits a change record.
func Shorten(s string) string {
	if len(s) <= maxValueLen {
		return s
	}
	cut := maxValueLen
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

// Diff lists the settings that differ between two values, sorted by path.
// At most max are returned; total is how many differ.
func Diff(before, after any, max int) (paths []model.PathChange, total int) {
	a, b := Flatten(before), Flatten(after)
	for p, av := range a {
		bv, ok := b[p]
		switch {
		case !ok:
			paths = append(paths, model.PathChange{Path: p, Kind: model.ChangeRemoved, Before: Shorten(av)})
		case av != bv:
			paths = append(paths, model.PathChange{Path: p, Kind: model.ChangeChanged, Before: Shorten(av), After: Shorten(bv)})
		}
	}
	for p, bv := range b {
		if _, ok := a[p]; !ok {
			paths = append(paths, model.PathChange{Path: p, Kind: model.ChangeAdded, After: Shorten(bv)})
		}
	}
	sort.Slice(paths, func(i, j int) bool { return paths[i].Path < paths[j].Path })
	total = len(paths)
	if max > 0 && len(paths) > max {
		paths = paths[:max]
	}
	return paths, total
}
