package collector

import (
	"context"
	"encoding/json"
	"sort"
	"strings"

	"github.com/jercle/datafetch/azconfigdrift/internal/catalog"
	"github.com/jercle/datafetch/azconfigdrift/internal/model"
)

// roleIndex is every role assignment of a tenant by the principal that
// holds it. A nil map: that kind could not be read (or the tenant is not
// collected for that platform), and nothing is said about it.
type roleIndex struct {
	directory map[string][]any
	azure     map[string][]any
	err       error
}

// into stores a principal's roles inside its object. A kind that could be
// read is always stored, as an empty list for a principal without roles.
func (r *roleIndex) into(obj map[string]any, principal string) {
	put := func(field string, all map[string][]any) {
		if all == nil {
			return
		}
		list := all[principal]
		if list == nil {
			list = []any{}
		}
		obj[field] = list
	}
	put("directoryRoles", r.directory)
	put("azureRoles", r.azure)
}

func sortObjects(groups map[string][]any) {
	for _, g := range groups {
		sort.SliceStable(g, func(i, j int) bool {
			x, _ := json.Marshal(g[i])
			y, _ := json.Marshal(g[j])
			return string(x) < string(y)
		})
	}
}

// roles reads every directory and Azure role assignment, once per pass.
func (f *fetcher) roles(ctx context.Context) *roleIndex {
	f.rolesOnce.Do(func() {
		idx := &roleIndex{}
		if f.tenant.Has(model.PlatformM365) {
			dir := map[string][]any{}
			err := f.graphList(ctx, f.graphURL("/roleManagement/directory/roleAssignments?$top=999", false), false, func(list []any) error {
				for _, o := range list {
					obj, _ := o.(map[string]any)
					p := strings.ToLower(pick(obj, "principalId"))
					if p == "" {
						continue
					}
					dir[p] = append(dir[p], map[string]any{"roleDefinitionId": pick(obj, "roleDefinitionId"), "directoryScopeId": pick(obj, "directoryScopeId")})
				}
				return nil
			})
			if err != nil {
				f.log.Warn("directory roles are not stored with their principals", "needs", "RoleManagement.Read.Directory", "error", err)
				idx.err = err
			} else {
				sortObjects(dir)
				idx.directory = dir
			}
		}
		if f.tenant.Has(model.PlatformAzure) {
			az := map[string][]any{}
			q := "authorizationresources | where type =~ 'microsoft.authorization/roleassignments' | project id, principalId = tostring(properties.principalId), " +
				"roleDefinitionId = tostring(properties.roleDefinitionId), scope = tostring(properties.scope) | order by id asc"
			err := f.arg(ctx, catalog.Source{ID: "roles-by-principal", Kind: catalog.KindARG, Query: q}, func(rows []raw) error {
				for _, r := range rows {
					p, _ := r.Body["principalId"].(string)
					if p == "" {
						continue
					}
					p = strings.ToLower(p)
					az[p] = append(az[p], map[string]any{"roleDefinitionId": r.Body["roleDefinitionId"], "scope": r.Body["scope"]})
				}
				return nil
			})
			if err != nil {
				f.log.Warn("Azure roles are not stored with their principals", "needs", "Reader", "error", err)
				idx.err = err
			} else {
				sortObjects(az)
				idx.azure = az
			}
		}
		f.roleIdx = idx
	})
	return f.roleIdx
}

// servicePrincipalsByApp maps an application (client) ID to the object ID
// of its service principal in this tenant. nil: it could not be read.
func (f *fetcher) servicePrincipalsByApp(ctx context.Context) map[string]string {
	f.spOnce.Do(func() {
		out := map[string]string{}
		err := f.graphList(ctx, f.graphURL("/servicePrincipals?$select=id,appId&$top=999", false), false, func(list []any) error {
			for _, o := range list {
				obj, _ := o.(map[string]any)
				if app, id := strings.ToLower(pick(obj, "appId")), strings.ToLower(pick(obj, "id")); app != "" && id != "" {
					out[app] = id
				}
			}
			return nil
		})
		if err != nil {
			f.log.Warn("roles are not stored with app registrations: their service principals could not be listed", "error", err)
			return
		}
		f.spByApp = out
	})
	return f.spByApp
}

// principals emits one object per principal that holds a role: users,
// groups and applications alike, each with all its directory and Azure
// roles.
func (f *fetcher) principals(ctx context.Context, src catalog.Source, emit func([]raw) error) error {
	idx := f.roles(ctx)
	if idx.directory == nil && idx.azure == nil {
		return idx.err
	}
	seen := map[string]bool{}
	var ids []string
	for _, all := range []map[string][]any{idx.directory, idx.azure} {
		for id := range all {
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	sort.Strings(ids)
	f.loadPrincipals(ctx, ids)
	for len(ids) > 0 {
		n := min(500, len(ids))
		batch := make([]raw, 0, n)
		for _, id := range ids[:n] {
			body := map[string]any{"id": id}
			f.dir.mu.Lock()
			if k := f.dir.kinds[id]; k != "" {
				body["principalType"] = k
			}
			f.dir.mu.Unlock()
			idx.into(body, id)
			batch = append(batch, raw{Key: id, Name: id, Type: src.Type, Body: body})
		}
		ids = ids[n:]
		if err := emit(batch); err != nil {
			return err
		}
	}
	return nil
}

// nesting reads the resources of a source's nested types and returns an
// emit that stores them inside their parents and passes on the rest.
func (f *fetcher) nesting(ctx context.Context, src catalog.Source, emit func([]raw) error) (func([]raw) error, error) {
	// By parent type, then by parent ID.
	children := map[string]map[string][]any{}
	fields := map[string]string{}
	nestedType := map[string]bool{}
	for _, n := range src.Nest {
		parentType := n.Type[:strings.LastIndex(n.Type, "/")]
		marker := "/" + n.Type[strings.LastIndex(n.Type, "/")+1:] + "/"
		fields[parentType] = n.Field
		nestedType[n.Type] = true
		byParent := map[string][]any{}
		q := src.Table + " | where type =~ '" + n.Type + "' | order by id asc"
		err := f.arg(ctx, catalog.Source{ID: src.ID, Kind: catalog.KindARG, Query: q, Delegated: src.Delegated}, func(rows []raw) error {
			for _, r := range rows {
				i := strings.LastIndex(r.Key, marker)
				if i < 0 {
					continue
				}
				child := map[string]any{"name": r.Name}
				for k, v := range r.Body {
					child[k] = v
				}
				byParent[r.Key[:i]] = append(byParent[r.Key[:i]], child)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		sortObjects(byParent)
		children[parentType] = byParent
	}
	return func(batch []raw) error {
		out := batch[:0]
		for _, r := range batch {
			if nestedType[r.Type] {
				continue
			}
			if byParent, ok := children[r.Type]; ok {
				list := byParent[r.Key]
				if list == nil {
					list = []any{}
				}
				r.Body[fields[r.Type]] = list
			}
			out = append(out, r)
		}
		return emit(out)
	}, nil
}
