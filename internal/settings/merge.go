package settings

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

// Spec describes one tool's settings.
type Spec struct {
	// Tool is the sub-key under Root.
	Tool string
	// Schema is a value of the struct the tool's configuration JSON is
	// decoded into. Its fields, by their json names, are the settings.
	Schema any
	// Lists names the lists of objects that can also be given one group of
	// keys per entry, by path, with the field that identifies an entry:
	// {"tenants": "tenantId"} reads tenants.<tenant id>.clientId and merges
	// it into the file's tenant of that ID, adding the tenant when the file
	// has none. Such a list given as a JSON array replaces the file's.
	Lists map[string]string
	// Types gives the shape of a setting, by path, where Schema's own type
	// does not say (a json.RawMessage).
	Types map[string]any
}

// Result is the merged configuration and what was said about the settings.
type Result struct {
	// Config is the configuration file's JSON with the settings laid over it.
	Config []byte
	// Applied is how many settings were taken.
	Applied int
	// Warnings names the settings that were not, and why.
	Warnings []string
}

// Merge lays the settings over the configuration file's JSON (which may be
// empty: every setting can come from App Configuration). It never fails on
// a bad setting: that setting is left out and named in the warnings.
func Merge(file []byte, s map[string]any, spec Spec) (*Result, error) {
	base := map[string]any{}
	if len(strings.TrimSpace(string(file))) > 0 {
		if err := json.Unmarshal(file, &base); err != nil {
			return nil, fmt.Errorf("config: %w", err)
		}
	}
	m := &merger{spec: spec, types: map[string]reflect.Type{}}
	for path, v := range spec.Types {
		m.types[path] = reflect.TypeOf(v)
	}
	// The object may come from a program rather than from JSON: read it as
	// JSON would have it (float64 numbers, []any lists).
	own := Under(s, spec.Tool)
	if b, err := json.Marshal(own); err == nil {
		own = map[string]any{}
		if err := json.Unmarshal(b, &own); err != nil {
			return nil, fmt.Errorf("settings: %w", err)
		}
	} else {
		return nil, fmt.Errorf("settings: %w", err)
	}
	m.object(base, own, deref(reflect.TypeOf(spec.Schema)), "")
	b, err := json.Marshal(base)
	if err != nil {
		return nil, err
	}
	m.res.Config = b
	sort.Strings(m.res.Warnings)
	return &m.res, nil
}

type merger struct {
	spec  Spec
	types map[string]reflect.Type
	res   Result
}

func (m *merger) warn(path, format string, args ...any) {
	m.res.Warnings = append(m.res.Warnings, Key(m.spec.Tool)+"."+path+": "+fmt.Sprintf(format, args...))
}

const fallback = "; the file's value or the default is used"

func deref(t reflect.Type) reflect.Type {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t
}

var (
	unmarshaler = reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()
	rawMessage  = reflect.TypeOf(json.RawMessage(nil))
)

// fields lists a struct's settings by json name, with the fields of
// embedded structs among them, as encoding/json sees them.
func fields(t reflect.Type) map[string]reflect.Type {
	out := map[string]reflect.Type{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if f.Anonymous && name == "" {
			if et := deref(f.Type); et.Kind() == reflect.Struct {
				for k, v := range fields(et) {
					if _, taken := out[k]; !taken {
						out[k] = v
					}
				}
			}
			continue
		}
		if !f.IsExported() || name == "-" {
			continue
		}
		if name == "" {
			name = f.Name
		}
		out[name] = f.Type
	}
	return out
}

// tagged reports whether a struct has settings of its own, as opposed to
// one that only wraps a value (a duration).
func tagged(t reflect.Type) bool {
	for i := 0; i < t.NumField(); i++ {
		if t.Field(i).Tag.Get("json") != "" {
			return true
		}
	}
	return false
}

// leaf reports whether a type reads its own JSON as a single value.
func leaf(t reflect.Type) bool {
	if !reflect.PointerTo(t).Implements(unmarshaler) {
		return false
	}
	return t.Kind() != reflect.Struct || !tagged(t)
}

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

// object lays the settings in s over target, an object of struct type t.
func (m *merger) object(target, s map[string]any, t reflect.Type, path string) {
	known := fields(t)
	keys := make([]string, 0, len(s))
	for k := range s {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		name, ft := k, known[k]
		if ft == nil {
			// As encoding/json does, a name in another case is the same one.
			for candidate, ct := range known {
				if strings.EqualFold(candidate, k) {
					name, ft = candidate, ct
					break
				}
			}
		}
		p := join(path, name)
		if override, ok := m.types[p]; ok {
			ft = override
		}
		if ft == nil {
			m.warn(join(path, k), "not a setting")
			continue
		}
		if !m.value(target, name, s[k], ft, p) {
			continue
		}
		// A secret given here replaces one the file names a variable for.
		if _, has := known[name+"Env"]; has {
			if _, given := s[name+"Env"]; !given {
				delete(target, name+"Env")
			}
		}
	}
}

// text is the JSON a string holds, when a setting that is a list or an
// object was stored as plain text.
func text(v any, open string) (any, bool) {
	s, ok := v.(string)
	if !ok || !strings.HasPrefix(strings.TrimSpace(s), open) {
		return v, false
	}
	var out any
	if json.Unmarshal([]byte(s), &out) != nil {
		return v, false
	}
	return out, true
}

// value lays one setting into parent[name]. It reports whether anything was
// taken.
func (m *merger) value(parent map[string]any, name string, v any, t reflect.Type, path string) bool {
	t = deref(t)
	if v == nil {
		return false
	}
	if s, isString := v.(string); isString && strings.TrimSpace(s) == "" {
		return false
	}
	switch {
	case t == rawMessage:
		if decoded, ok := text(v, "{"); ok {
			v = decoded
		} else if decoded, ok := text(v, "["); ok {
			v = decoded
		}
		parent[name] = v
		m.res.Applied++
		return true
	case leaf(t):
		if s, isString := v.(string); isString {
			v = strings.TrimSpace(s)
		}
		b, err := json.Marshal(v)
		if err == nil {
			err = json.Unmarshal(b, reflect.New(t).Interface())
		}
		if err != nil {
			m.warn(path, "%v%s", err, fallback)
			return false
		}
		parent[name] = v
		m.res.Applied++
		return true
	}
	switch t.Kind() {
	case reflect.Struct:
		if decoded, ok := text(v, "{"); ok {
			v = decoded
		}
		obj, ok := v.(map[string]any)
		if !ok {
			m.warn(path, "expected a group of keys%s", fallback)
			return false
		}
		child, _ := parent[name].(map[string]any)
		if child == nil {
			child = map[string]any{}
		}
		before := m.res.Applied
		m.object(child, obj, t, path)
		if m.res.Applied == before {
			return false
		}
		parent[name] = child
		return true
	case reflect.Map:
		obj, ok := v.(map[string]any)
		if !ok {
			m.warn(path, "expected a group of keys%s", fallback)
			return false
		}
		child, _ := parent[name].(map[string]any)
		if child == nil {
			child = map[string]any{}
		}
		before := m.res.Applied
		for _, k := range sortedKeys(obj) {
			m.value(child, k, obj[k], t.Elem(), join(path, k))
		}
		if m.res.Applied == before {
			return false
		}
		parent[name] = child
		return true
	case reflect.Slice:
		if et := deref(t.Elem()); et.Kind() == reflect.Struct && !leaf(et) {
			return m.objects(parent, name, v, et, path)
		}
		out, reason := list(v, t.Elem())
		if reason != "" {
			m.warn(path, "%s%s", reason, fallback)
			return false
		}
		parent[name] = out
		m.res.Applied++
		return true
	}
	out, reason := scalar(v, t)
	if reason != "" {
		m.warn(path, "%s%s", reason, fallback)
		return false
	}
	if out == nil {
		return false
	}
	parent[name] = out
	m.res.Applied++
	return true
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// scalar reads a value as text, a number or a boolean. A nil result with
// no reason means "not set".
func scalar(v any, t reflect.Type) (out any, reason string) {
	switch t.Kind() {
	case reflect.String:
		switch x := v.(type) {
		case string:
			if x = strings.TrimSpace(x); x == "" {
				return nil, ""
			}
			return x, ""
		case float64:
			return strconv.FormatFloat(x, 'f', -1, 64), ""
		case bool:
			return strconv.FormatBool(x), ""
		}
		return nil, "expected text"
	case reflect.Bool:
		switch x := v.(type) {
		case bool:
			return x, ""
		case string:
			switch strings.ToLower(strings.TrimSpace(x)) {
			case "true", "1", "yes", "on":
				return true, ""
			case "false", "0", "no", "off":
				return false, ""
			}
		}
		return nil, "expected true or false"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		var n float64
		switch x := v.(type) {
		case float64:
			n = x
		case string:
			p, err := strconv.ParseFloat(strings.TrimSpace(x), 64)
			if err != nil {
				return nil, "expected a number"
			}
			n = p
		default:
			return nil, "expected a number"
		}
		if t.Kind() == reflect.Float32 || t.Kind() == reflect.Float64 {
			return n, ""
		}
		if n != float64(int64(n)) {
			return nil, "expected a whole number"
		}
		return int64(n), ""
	}
	// Anything else is taken as it is; the tool's own validation decides.
	return v, ""
}

// list reads a list of single values: a JSON array, or text holding one,
// or text separated by commas, semicolons or line breaks.
func list(v any, elem reflect.Type) (out []any, reason string) {
	var items []any
	switch x := v.(type) {
	case []any:
		items = x
	case string:
		if decoded, ok := text(x, "["); ok {
			items, _ = decoded.([]any)
			break
		}
		for _, p := range strings.FieldsFunc(x, func(r rune) bool { return r == ',' || r == ';' || r == '\n' }) {
			items = append(items, p)
		}
	default:
		// One value is a list of one.
		items = []any{v}
	}
	out = make([]any, 0, len(items))
	for _, it := range items {
		if elem.Kind() == reflect.Interface || elem == rawMessage {
			out = append(out, it)
			continue
		}
		val, why := scalar(it, deref(elem))
		if why != "" {
			return nil, "expected a list: " + why
		}
		if val != nil {
			out = append(out, val)
		}
	}
	return out, ""
}

// objects lays a list of objects into parent[name]. A JSON array (or text
// holding one) replaces the file's list. A group of keys per entry is
// merged into the file's list by the field that identifies an entry.
func (m *merger) objects(parent map[string]any, name string, v any, et reflect.Type, path string) bool {
	if decoded, ok := text(v, "["); ok {
		v = decoded
	}
	switch x := v.(type) {
	case []any:
		out := make([]any, 0, len(x))
		for i, it := range x {
			obj, ok := it.(map[string]any)
			if !ok {
				m.warn(path, "expected a list of objects%s", fallback)
				return false
			}
			entry := map[string]any{}
			applied := m.res.Applied
			m.object(entry, obj, et, fmt.Sprintf("%s[%d]", path, i))
			// The list is one setting, however many fields it has.
			m.res.Applied = applied
			out = append(out, entry)
		}
		parent[name] = out
		m.res.Applied++
		return true
	case map[string]any:
		key := m.spec.Lists[path]
		if key == "" {
			m.warn(path, "expected a JSON list of objects%s", fallback)
			return false
		}
		existing, _ := parent[name].([]any)
		index := map[string]map[string]any{}
		for _, e := range existing {
			if obj, ok := e.(map[string]any); ok {
				id, _ := obj[key].(string)
				index[strings.ToLower(strings.TrimSpace(id))] = obj
			}
		}
		before := m.res.Applied
		for _, rawID := range sortedKeys(x) {
			id := strings.TrimSpace(rawID)
			where := join(path, rawID)
			group, ok := x[rawID].(map[string]any)
			if !ok || id == "" {
				m.warn(where, "expected settings beneath it, as %s.<%s>.<setting>", path, key)
				continue
			}
			target, existed := index[strings.ToLower(id)]
			if !existed {
				target = map[string]any{key: id}
			}
			// The key of the group is the identity: it is not set again.
			own := make(map[string]any, len(group))
			for k, val := range group {
				if !strings.EqualFold(k, key) {
					own[k] = val
				}
			}
			applied := m.res.Applied
			m.object(target, own, et, where)
			if !existed {
				if m.res.Applied == applied {
					continue
				}
				existing = append(existing, target)
				index[strings.ToLower(id)] = target
			}
		}
		if m.res.Applied == before {
			return false
		}
		parent[name] = existing
		return true
	}
	m.warn(path, "expected a list of objects%s", fallback)
	return false
}
