// Package settings lays the settings kept in Azure App Configuration (the
// ones the dashboard edits) over the configuration file. A setting that is
// present and valid wins; one that is absent or invalid leaves the file's
// value, or the built-in default, in place.
//
// The settings arrive as the object under the key
// datafetching.azConfigDrift: what an App Configuration provider builds
// from "."-separated keys, so datafetching.azConfigDrift.concurrency.tenants
// = 4 is {"concurrency": {"tenants": 4}}.
// Values may be typed (content type application/json) or plain strings:
// "4", "true", "a, b" are read as the number, the boolean and the list.
package settings

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	shared "github.com/jercle/datafetch/internal/settings"
)

// Root is the key every setting lives under in App Configuration:
// az-config-drift's sub-key of the root all datafetch tools share.
const Root = shared.Root + "." + shared.AzConfigDrift

// LegacyRoot is where the settings lived before az-config-drift became
// part of datafetch. It is read when nothing is found under Root.
const LegacyRoot = "azureDriftChecker"

type kind int

const (
	kString kind = iota
	kInt
	kBool
	kDuration
	kList
	kObjects // a list of objects, or its JSON as a string
)

type field struct {
	kind     kind
	min, max int           // kInt
	minDur   time.Duration // kDuration
	maxDur   time.Duration
	enum     []string // kString
}

// General lists the settings that are single values, by their path under
// the root. The dashboard's field list (settings.fields.ts) must name the
// same paths; a test compares them.
var General = map[string]field{
	"interval":              {kind: kDuration, minDur: 5 * time.Minute},
	"heartbeatInterval":     {kind: kDuration, minDur: 5 * time.Second, maxDur: time.Minute},
	"concurrency.tenants":   {kind: kInt, min: 1, max: 32},
	"concurrency.modules":   {kind: kInt, min: 1, max: 32},
	"retention.logsDays":    {kind: kInt, min: -1, max: 36500},
	"retention.runsDays":    {kind: kInt, min: -1, max: 36500},
	"retention.changesDays": {kind: kInt, min: -1, max: 36500},
	"logging.level":         {kind: kString, enum: []string{"debug", "info", "warn", "error"}},
	"logging.mongoLevel":    {kind: kString, enum: []string{"debug", "info", "warn", "error"}},
	"logging.format":        {kind: kString, enum: []string{"text", "json"}},
	"limits.maxItemBytes":   {kind: kInt, min: 1024, max: 12 << 20},
	"limits.changePaths":    {kind: kInt, min: 1, max: 5000},
	"limits.sourceTimeout":  {kind: kDuration, minDur: time.Minute},
	"mongo.uri":             {kind: kString},
	"mongo.database":        {kind: kString},
	"mongo.ensureIndexes":   {kind: kBool},
	"ignore":                {kind: kObjects},
	"exclude":               {kind: kObjects},
	"extraSources":          {kind: kObjects},
	"skipSources":           {kind: kList},
}

// Tenant lists the settings of one tenant, under tenants.<tenant id>.
var Tenant = map[string]field{
	"enabled":              {kind: kBool},
	"tenantName":           {kind: kString},
	"clientId":             {kind: kString},
	"clientSecret":         {kind: kString},
	"clientSecretEnv":      {kind: kString},
	"cloud":                {kind: kString, enum: []string{"public", "usgovernment", "china"}},
	"platforms":            {kind: kList},
	"subscriptions":        {kind: kList},
	"excludeSubscriptions": {kind: kList},
	"initialDomain":        {kind: kString},
	"username":             {kind: kString},
	"password":             {kind: kString},
	"passwordEnv":          {kind: kString},
	"delegatedClientId":    {kind: kString},
}

var (
	guid = regexp.MustCompile(`^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$`)
	slug = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
)

// Nest turns flat "."-separated keys into the nested object. A key that is
// both a value and a parent ("a" and "a.b") keeps the children.
func Nest(flat map[string]any) map[string]any { return shared.Nest(flat) }

// Under returns the settings object from the object itself, from the
// object under the datafetching root, or from a whole configuration object
// that has it under datafetching.azConfigDrift.
func Under(obj map[string]any) map[string]any { return shared.Under(obj, shared.AzConfigDrift) }

// Result is the merged configuration and what was said about the settings.
type Result struct {
	// Config is the configuration file's JSON with the settings laid over it.
	Config []byte
	// Applied is how many settings were taken.
	Applied int
	// Warnings names the settings that were not, and why.
	Warnings []string
}

type merger struct {
	res Result
}

func (m *merger) warn(format string, args ...any) {
	m.res.Warnings = append(m.res.Warnings, fmt.Sprintf(format, args...))
}

// coerce reads a value as the field's type. ok is false, with a reason,
// when it cannot be; skip is true for an empty value, which means "not set".
func coerce(v any, f field) (out any, reason string, skip bool) {
	if v == nil {
		return nil, "", true
	}
	if s, isString := v.(string); isString && strings.TrimSpace(s) == "" && f.kind != kString {
		return nil, "", true
	}
	switch f.kind {
	case kString:
		var s string
		switch x := v.(type) {
		case string:
			s = strings.TrimSpace(x)
		case float64:
			s = strconv.FormatFloat(x, 'f', -1, 64)
		case bool:
			s = strconv.FormatBool(x)
		default:
			return nil, "expected text", false
		}
		if s == "" {
			return nil, "", true
		}
		if len(f.enum) > 0 {
			s = strings.ToLower(s)
			for _, e := range f.enum {
				if e == s {
					return s, "", false
				}
			}
			return nil, "must be one of " + strings.Join(f.enum, ", "), false
		}
		return s, "", false
	case kInt:
		var n float64
		switch x := v.(type) {
		case float64:
			n = x
		case string:
			p, err := strconv.ParseFloat(strings.TrimSpace(x), 64)
			if err != nil {
				return nil, "expected a whole number", false
			}
			n = p
		default:
			return nil, "expected a whole number", false
		}
		if n != float64(int(n)) {
			return nil, "expected a whole number", false
		}
		if int(n) < f.min || int(n) > f.max {
			return nil, fmt.Sprintf("must be between %d and %d", f.min, f.max), false
		}
		return int(n), "", false
	case kBool:
		switch x := v.(type) {
		case bool:
			return x, "", false
		case string:
			switch strings.ToLower(strings.TrimSpace(x)) {
			case "true", "1", "yes", "on":
				return true, "", false
			case "false", "0", "no", "off":
				return false, "", false
			}
		}
		return nil, "expected true or false", false
	case kDuration:
		s, isString := v.(string)
		if !isString {
			return nil, `expected a duration such as "6h" or "30s"`, false
		}
		d, err := time.ParseDuration(strings.TrimSpace(s))
		if err != nil {
			return nil, `expected a duration such as "6h" or "30s"`, false
		}
		if d < f.minDur || (f.maxDur > 0 && d > f.maxDur) {
			if f.maxDur > 0 {
				return nil, fmt.Sprintf("must be between %s and %s", f.minDur, f.maxDur), false
			}
			return nil, fmt.Sprintf("must be at least %s", f.minDur), false
		}
		return strings.TrimSpace(s), "", false
	case kList:
		var items []any
		switch x := v.(type) {
		case []any:
			items = x
		case string:
			x = strings.TrimSpace(x)
			if strings.HasPrefix(x, "[") {
				if err := json.Unmarshal([]byte(x), &items); err != nil {
					return nil, "expected a list", false
				}
			} else {
				for _, p := range strings.FieldsFunc(x, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\n' }) {
					items = append(items, p)
				}
			}
		default:
			return nil, "expected a list", false
		}
		out := make([]any, 0, len(items))
		for _, it := range items {
			s, isString := it.(string)
			if !isString {
				return nil, "expected a list of text values", false
			}
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		return out, "", false
	case kObjects:
		var items []any
		switch x := v.(type) {
		case []any:
			items = x
		case string:
			if err := json.Unmarshal([]byte(x), &items); err != nil {
				return nil, "expected a JSON list of objects", false
			}
		default:
			return nil, "expected a JSON list of objects", false
		}
		for _, it := range items {
			if _, isObject := it.(map[string]any); !isObject {
				return nil, "expected a JSON list of objects", false
			}
		}
		if items == nil {
			items = []any{}
		}
		return items, "", false
	}
	return nil, "unknown kind of setting", false
}

func lookup(obj map[string]any, path string) (any, bool) {
	var cur any = obj
	for _, p := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = m[p]; !ok {
			return nil, false
		}
	}
	return cur, true
}

func set(obj map[string]any, path string, v any) {
	parts := strings.Split(path, ".")
	for _, p := range parts[:len(parts)-1] {
		child, ok := obj[p].(map[string]any)
		if !ok {
			child = map[string]any{}
			obj[p] = child
		}
		obj = child
	}
	obj[parts[len(parts)-1]] = v
}

// Merge lays the settings over the configuration file's JSON (which may be
// empty: every setting can come from App Configuration). It never fails on
// a bad setting: that setting is left out and named in the warnings.
func Merge(file []byte, s map[string]any) (*Result, error) {
	base := map[string]any{}
	if len(strings.TrimSpace(string(file))) > 0 {
		if err := json.Unmarshal(file, &base); err != nil {
			return nil, fmt.Errorf("config: %w", err)
		}
	}
	m := &merger{}
	s = Under(s)

	// Single values.
	known := map[string]bool{"tenants": true, "modules": true}
	for path, f := range General {
		known[strings.Split(path, ".")[0]] = true
		v, ok := lookup(s, path)
		if !ok {
			continue
		}
		out, reason, skip := coerce(v, f)
		switch {
		case skip:
		case reason != "":
			m.warn("%s.%s: %s; the file's value or the default is used", Root, path, reason)
		default:
			set(base, path, out)
			m.res.Applied++
		}
	}
	// Anything else beneath a known group ("logging.colour") is unknown.
	groups := map[string]bool{}
	for path := range General {
		if group, _, nested := strings.Cut(path, "."); nested {
			groups[group] = true
		}
	}
	for group := range groups {
		obj, _ := s[group].(map[string]any)
		for k := range obj {
			if _, ok := General[group+"."+k]; !ok {
				m.warn("%s.%s.%s: not a setting", Root, group, k)
			}
		}
	}
	for k := range s {
		if !known[k] {
			m.warn("%s.%s: not a setting", Root, k)
		}
	}

	m.tenants(base, s["tenants"])
	m.modules(base, s["modules"])

	b, err := json.Marshal(base)
	if err != nil {
		return nil, err
	}
	m.res.Config = b
	sort.Strings(m.res.Warnings)
	return &m.res, nil
}

// tenants merges tenants.<tenant id>.<field> into the file's tenant list,
// matching on the tenant ID. A tenant that only exists in the settings is
// added, provided it ends up with a name and credentials.
func (m *merger) tenants(base map[string]any, v any) {
	if v == nil {
		return
	}
	byID, ok := v.(map[string]any)
	if !ok {
		m.warn("%s.tenants: expected one group of keys per tenant ID", Root)
		return
	}
	list, _ := base["tenants"].([]any)
	index := map[string]map[string]any{}
	for _, t := range list {
		if obj, ok := t.(map[string]any); ok {
			id, _ := obj["tenantId"].(string)
			index[strings.ToLower(strings.TrimSpace(id))] = obj
		}
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, rawID := range ids {
		id := strings.ToLower(strings.TrimSpace(rawID))
		where := Root + ".tenants." + rawID
		fields, ok := byID[rawID].(map[string]any)
		if !guid.MatchString(id) || !ok {
			m.warn("%s: the part after tenants. must be a tenant ID with settings beneath it", where)
			continue
		}
		target, existed := index[id]
		if !existed {
			target = map[string]any{"tenantId": id}
		}
		applied := 0
		names := make([]string, 0, len(fields))
		for name := range fields {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			f, isField := Tenant[name]
			if name == "tenantId" {
				continue
			}
			if !isField {
				m.warn("%s.%s: not a setting", where, name)
				continue
			}
			out, reason, skip := coerce(fields[name], f)
			switch {
			case skip:
			case reason != "":
				m.warn("%s.%s: %s; the file's value or the default is used", where, name, reason)
			default:
				target[name] = out
				applied++
				// A secret given here replaces one named by the file.
				switch name {
				case "clientSecret":
					delete(target, "clientSecretEnv")
				case "password":
					delete(target, "passwordEnv")
				}
			}
		}
		if !existed {
			has := func(k string) bool { s, _ := target[k].(string); return s != "" }
			if !has("tenantName") || !has("clientId") || !(has("clientSecret") || has("clientSecretEnv")) {
				m.warn("%s: left out, it needs tenantName, clientId and clientSecret", where)
				continue
			}
			list = append(list, target)
			index[id] = target
		}
		m.res.Applied += applied
	}
	base["tenants"] = list
}

// modules merges modules.<id>.enabled and
// modules.<id>.sources.<id>.{enabled,beta,delegated} over the file's.
func (m *merger) modules(base map[string]any, v any) {
	if v == nil {
		return
	}
	mods, ok := v.(map[string]any)
	if !ok {
		m.warn("%s.modules: expected one group of keys per module", Root)
		return
	}
	target, _ := base["modules"].(map[string]any)
	if target == nil {
		target = map[string]any{}
	}
	flag := func(where string, v any, into map[string]any, name string) {
		out, reason, skip := coerce(v, field{kind: kBool})
		switch {
		case skip:
		case reason != "":
			m.warn("%s: %s; the file's value or the default is used", where, reason)
		default:
			into[name] = out
			m.res.Applied++
		}
	}
	for id, raw := range mods {
		where := Root + ".modules." + id
		obj, ok := raw.(map[string]any)
		if !slug.MatchString(id) || !ok {
			m.warn("%s: expected a module id with settings beneath it", where)
			continue
		}
		mod, _ := target[id].(map[string]any)
		if mod == nil {
			mod = map[string]any{}
		}
		for k, val := range obj {
			switch k {
			case "enabled":
				flag(where+".enabled", val, mod, "enabled")
			case "sources":
				srcs, ok := val.(map[string]any)
				if !ok {
					m.warn("%s.sources: expected one group of keys per source", where)
					continue
				}
				into, _ := mod["sources"].(map[string]any)
				if into == nil {
					into = map[string]any{}
				}
				for sid, rawSrc := range srcs {
					srcObj, ok := rawSrc.(map[string]any)
					if !slug.MatchString(sid) || !ok {
						m.warn("%s.sources.%s: expected a source id with settings beneath it", where, sid)
						continue
					}
					src, _ := into[sid].(map[string]any)
					if src == nil {
						src = map[string]any{}
					}
					for name, sv := range srcObj {
						if name != "enabled" && name != "beta" && name != "delegated" {
							m.warn("%s.sources.%s.%s: not a setting", where, sid, name)
							continue
						}
						flag(where+".sources."+sid+"."+name, sv, src, name)
					}
					into[sid] = src
				}
				mod["sources"] = into
			default:
				m.warn("%s.%s: not a setting", where, k)
			}
		}
		target[id] = mod
	}
	base["modules"] = target
}
