package collector

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/jercle/datafetch/azconfigdrift/internal/catalog"
	"github.com/jercle/datafetch/azconfigdrift/internal/cloud"
	"github.com/jercle/datafetch/azconfigdrift/internal/model"
	"github.com/jercle/datafetch/azconfigdrift/internal/normalize"
)

// directory names the identifiers found in a tenant's objects: principals
// from Microsoft Graph, role definitions from Resource Graph and Graph.
// Everything is looked up once per pass. A name that cannot be found is
// left out; the object is stored all the same.
type directory struct {
	mu sync.Mutex
	// lookup is held while principals are asked for, so that a second
	// source waits for the names instead of finding them missing.
	lookup sync.Mutex
	// principals: object ID in lower case → name; "" when asked and not found.
	principals map[string]string
	azureOnce  sync.Once
	azureRoles map[string]string
	entraOnce  sync.Once
	entraRoles map[string]string
	warned     map[string]bool
}

// warn logs why names are missing, once per kind and pass.
func (f *fetcher) warnOnce(kind string, err error) {
	f.dir.mu.Lock()
	seen := f.dir.warned[kind]
	if f.dir.warned == nil {
		f.dir.warned = map[string]bool{}
	}
	f.dir.warned[kind] = true
	f.dir.mu.Unlock()
	if !seen {
		f.log.Warn("names not resolved: identifiers are shown as they are", "kind", kind, "error", err)
	}
}

// values calls fn for every string at path in obj; "*" is every element of
// a list (or every value of an object).
func values(v any, path []string, fn func(string)) {
	if len(path) == 0 {
		if s, ok := v.(string); ok && s != "" {
			fn(s)
		}
		return
	}
	switch x := v.(type) {
	case map[string]any:
		if path[0] == "*" {
			for _, c := range x {
				values(c, path[1:], fn)
			}
			return
		}
		values(x[path[0]], path[1:], fn)
	case []any:
		rest := path
		if path[0] == "*" {
			rest = path[1:]
		}
		for _, c := range x {
			values(c, rest, fn)
		}
	}
}

// resolve fills in the names of the identifiers in a batch, and names the
// objects of a source with a Title after them.
func (f *fetcher) resolve(ctx context.Context, src catalog.Source, batch []raw) {
	if len(src.Refs) == 0 {
		return
	}
	kinds := map[string]string{}
	paths := make([][]string, len(src.Refs))
	var principals []string
	asked := map[string]bool{}
	for i, r := range src.Refs {
		paths[i] = strings.Split(r.Path, ".")
		kinds[r.Path] = r.Kind
		if r.Kind != catalog.RefPrincipal {
			continue
		}
		for _, b := range batch {
			values(b.Body, paths[i], func(id string) {
				if k := strings.ToLower(id); !asked[k] {
					asked[k] = true
					principals = append(principals, id)
				}
			})
		}
	}
	f.loadPrincipals(ctx, principals)
	name := func(kind, id string) string {
		switch kind {
		case catalog.RefPrincipal:
			f.dir.mu.Lock()
			defer f.dir.mu.Unlock()
			return f.dir.principals[strings.ToLower(id)]
		case catalog.RefAzureRole:
			return f.azureRole(ctx, id)
		case catalog.RefEntraRole:
			return f.entraRole(ctx, id)
		case catalog.RefAzureScope:
			// A subscription is named; other scopes end in their own name.
			if rest, ok := strings.CutPrefix(strings.ToLower(id), "/subscriptions/"); ok && !strings.Contains(rest, "/") {
				return f.subNames[rest]
			}
		}
		return ""
	}
	for i := range batch {
		b := &batch[i]
		for j, r := range src.Refs {
			values(b.Body, paths[j], func(id string) {
				if n := name(r.Kind, id); n != "" {
					if b.Refs == nil {
						b.Refs = map[string]string{}
					}
					b.Refs[id] = n
				}
			})
		}
		// The title: what each identifier stands for, or the identifier
		// itself where that is not known. Without any name, the object
		// keeps the name it came with.
		var parts []string
		named := false
		for _, p := range src.Title {
			values(b.Body, strings.Split(p, "."), func(id string) {
				n := b.Refs[id]
				named = named || n != ""
				if n == "" {
					n = id[strings.LastIndex(id, "/")+1:]
				}
				if n == "" {
					n = "root"
				}
				parts = append(parts, n)
			})
		}
		if named {
			b.Name = strings.Join(parts, " · ")
		}
	}
}

// refsHash tells whether the names of an item's identifiers changed.
func refsHash(refs map[string]string) string {
	if len(refs) == 0 {
		return ""
	}
	b, _ := json.Marshal(refs) // keys are written in order
	return normalize.Hash(b)[:16]
}

// loadPrincipals asks Microsoft Graph for the names of the object IDs it
// has not been asked for yet.
func (f *fetcher) loadPrincipals(ctx context.Context, ids []string) {
	if len(ids) == 0 {
		return
	}
	f.dir.lookup.Lock()
	defer f.dir.lookup.Unlock()
	f.dir.mu.Lock()
	if f.dir.principals == nil {
		f.dir.principals = map[string]string{}
	}
	var ask []string
	for _, id := range ids {
		k := strings.ToLower(id)
		if _, ok := f.dir.principals[k]; !ok && len(k) == 36 {
			f.dir.principals[k] = ""
			ask = append(ask, k)
		}
	}
	f.dir.mu.Unlock()
	for len(ask) > 0 {
		n := min(1000, len(ask))
		var out struct {
			Value []map[string]any `json:"value"`
		}
		err := f.client.Do(ctx, cloud.Request{
			Method: http.MethodPost, URL: f.graphURL("/directoryObjects/getByIds", false), Scope: f.client.Endpoints.GraphScope,
			Body: map[string]any{"ids": ask[:n], "types": []string{"user", "group", "servicePrincipal", "device"}},
		}, &out)
		ask = ask[n:]
		if err != nil {
			f.warnOnce("principals (needs Directory.Read.All on Microsoft Graph)", err)
			return
		}
		f.dir.mu.Lock()
		for _, o := range out.Value {
			id, _ := o["id"].(string)
			if name := pick(o, "displayName", "userPrincipalName", "appId"); id != "" && name != "" {
				f.dir.principals[strings.ToLower(id)] = name
			}
		}
		f.dir.mu.Unlock()
	}
}

// azureRole names an Azure role definition by its resource ID. The same
// definition has the same GUID at every scope.
func (f *fetcher) azureRole(ctx context.Context, id string) string {
	f.dir.azureOnce.Do(func() {
		roles := map[string]string{}
		q := "authorizationresources | where type =~ 'microsoft.authorization/roledefinitions' | project id, roleName = tostring(properties.roleName) | order by id asc"
		err := f.arg(ctx, catalog.Source{ID: "role-names", Kind: catalog.KindARG, Query: q}, func(rows []raw) error {
			for _, r := range rows {
				if n, _ := r.Body["roleName"].(string); n != "" {
					roles[r.Key[strings.LastIndex(r.Key, "/")+1:]] = n
				}
			}
			return nil
		})
		if err != nil {
			f.warnOnce("Azure role definitions", err)
		}
		f.dir.azureRoles = roles
	})
	return f.dir.azureRoles[strings.ToLower(id[strings.LastIndex(id, "/")+1:])]
}

// entraRole names an Entra ID role definition by its ID or template ID.
func (f *fetcher) entraRole(ctx context.Context, id string) string {
	f.dir.entraOnce.Do(func() {
		roles := map[string]string{}
		u := f.graphURL("/roleManagement/directory/roleDefinitions?$select=id,displayName,templateId", false)
		err := f.graphList(ctx, u, false, func(list []any) error {
			for _, o := range list {
				obj, _ := o.(map[string]any)
				n := pick(obj, "displayName")
				for _, k := range []string{"id", "templateId"} {
					if v := pick(obj, k); v != "" && n != "" {
						roles[strings.ToLower(v)] = n
					}
				}
			}
			return nil
		})
		if err != nil {
			f.warnOnce("Entra ID role definitions (needs RoleManagement.Read.Directory)", err)
		}
		f.dir.entraRoles = roles
	})
	return f.dir.entraRoles[strings.ToLower(id)]
}

// attachment reads the list of an Attach once per pass and groups its
// objects by the object they belong to. nil without an error: the list may
// not be read, and the source is stored without it.
func (f *fetcher) attachment(ctx context.Context, src catalog.Source, a catalog.Attach) (map[string][]any, error) {
	f.attachMu.Lock()
	defer f.attachMu.Unlock()
	if g, ok := f.attached[a.Path]; ok {
		return g, nil
	}
	groups := map[string][]any{}
	err := f.graphList(ctx, f.graphURL(a.Path, src.Beta), src.Delegated, func(list []any) error {
		for _, o := range list {
			obj, _ := o.(map[string]any)
			owner := strings.ToLower(pick(obj, a.By))
			if owner == "" {
				continue
			}
			for _, k := range a.Drop {
				delete(obj, k)
			}
			groups[owner] = append(groups[owner], obj)
		}
		return nil
	})
	switch {
	case err != nil && cloud.Status(err) == model.SourceDenied:
		f.log.Warn("not stored with its objects: the list may not be read", "source", src.ID, "property", a.Field, "needs", a.Permission, "error", err)
		groups = nil
	case err != nil:
		return nil, err
	}
	// A stable order, so that the same grants are the same settings.
	for _, g := range groups {
		sort.SliceStable(g, func(i, j int) bool {
			x, _ := json.Marshal(g[i])
			y, _ := json.Marshal(g[j])
			return string(x) < string(y)
		})
	}
	if f.attached == nil {
		f.attached = map[string]map[string][]any{}
	}
	f.attached[a.Path] = groups
	return groups, nil
}
