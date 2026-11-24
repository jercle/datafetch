package collector

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jercle/datafetch/azconfigdrift/internal/catalog"
	"github.com/jercle/datafetch/azconfigdrift/internal/cloud"
	"github.com/jercle/datafetch/azconfigdrift/internal/config"
)

// raw is one object as an API returned it, with what identifies it taken
// out of the body.
type raw struct {
	Key, Name, Type                         string
	SubscriptionID, ResourceGroup, Location string
	Body                                    map[string]any
	// Refs names the identifiers in Body (see model.Item.Refs).
	Refs map[string]string
}

type subscription struct {
	ID    string `json:"subscriptionId"`
	Name  string `json:"displayName"`
	State string `json:"state"`
}

// fetcher reads the sources of one tenant.
type fetcher struct {
	client *cloud.Client
	tenant config.Tenant
	log    *slog.Logger
	// claimed: resource type prefixes other sources take (see the
	// catch-all source).
	claimed []string

	// subs are the subscriptions the Azure sources read; restrict says the
	// configuration narrowed them, so Resource Graph is asked for exactly
	// these instead of the whole tenant.
	subs     []subscription
	subNames map[string]string
	restrict bool

	domainOnce sync.Once
	domain     string
	domainErr  error

	// cmdlets: per embedded PowerShell script, what the catalogue reads with it.
	cmdlets map[string][]string
	// The output of each PowerShell script, run once per pass.
	pwshMu  sync.Mutex
	pwshOut map[string]map[string]pwshResult

	// The workspaces Microsoft Sentinel is enabled on, found once per pass.
	sentinelOnce sync.Once
	sentinel     []string
	sentinelErr  error

	// rolesOnce guards roleIdx: every role assignment, by principal.
	rolesOnce sync.Once
	roleIdx   *roleIndex
	spOnce    sync.Once
	spByApp   map[string]string

	// dir names identifiers; attached holds the lists read to store inside
	// other objects, by path.
	dir      directory
	attachMu sync.Mutex
	attached map[string]map[string][]any
}

const argPageSize = 1000

// subscriptions lists what the service principal can read, less what the
// configuration leaves out.
func (f *fetcher) loadSubscriptions(ctx context.Context) error {
	include, exclude := map[string]bool{}, map[string]bool{}
	for _, s := range f.tenant.Subscriptions {
		include[s] = true
	}
	for _, s := range f.tenant.ExcludeSubscriptions {
		exclude[s] = true
	}
	f.restrict = len(include) > 0 || len(exclude) > 0
	f.subNames = map[string]string{}
	u := strings.TrimRight(f.client.Endpoints.ARM, "/") + "/subscriptions?api-version=2022-12-01"
	for u != "" {
		var out struct {
			Value    []subscription `json:"value"`
			NextLink string         `json:"nextLink"`
		}
		if err := f.client.Do(ctx, cloud.Request{URL: u, Scope: f.client.Endpoints.ARMScope}, &out); err != nil {
			return err
		}
		for _, s := range out.Value {
			s.ID = strings.ToLower(s.ID)
			if exclude[s.ID] || (len(include) > 0 && !include[s.ID]) {
				continue
			}
			f.subs = append(f.subs, s)
			f.subNames[s.ID] = s.Name
		}
		u = out.NextLink
	}
	return nil
}

// fetch reads one source and hands its objects to emit in batches. It
// returns nil only when everything was read.
func (f *fetcher) fetch(ctx context.Context, src catalog.Source, emit func([]raw) error) error {
	switch src.Kind {
	case catalog.KindARG:
		return f.arg(ctx, src, emit)
	case catalog.KindARM:
		return f.arm(ctx, src, emit)
	case catalog.KindGraph:
		return f.graph(ctx, src, emit)
	case catalog.KindEXO:
		return f.exo(ctx, src, emit)
	case catalog.KindMDE:
		return f.mde(ctx, src, emit)
	case catalog.KindSPO:
		return f.spo(ctx, src, emit)
	case catalog.KindPP:
		return f.powerPlatform(ctx, src, emit)
	case catalog.KindPwsh:
		return f.pwsh(ctx, src, emit)
	}
	return fmt.Errorf("unknown kind of source %q", src.Kind)
}

// argQuery builds the Resource Graph query of a source.
func argQuery(src catalog.Source, claimed []string) string {
	if src.Query != "" {
		q := strings.TrimSpace(src.Query)
		if !strings.Contains(strings.ToLower(q), "order by") {
			q += " | order by id asc"
		}
		return q
	}
	starts := func(prefixes []string) string {
		parts := make([]string, len(prefixes))
		for i, p := range prefixes {
			parts[i] = "type startswith '" + strings.ReplaceAll(p, "'", "") + "'"
		}
		return strings.Join(parts, " or ")
	}
	q := src.Table
	switch {
	case src.Other && len(claimed) > 0:
		q += " | where not(" + starts(claimed) + ")"
	case len(src.Types) > 0:
		q += " | where " + starts(src.Types)
	}
	if src.Where != "" {
		q += " | where " + src.Where
	}
	// Paging needs a stable order.
	return q + " | order by id asc"
}

// columns of a Resource Graph row that identify the object rather than
// configure it.
var argMeta = map[string]bool{"id": true, "name": true, "type": true, "tenantId": true, "subscriptionId": true, "resourceGroup": true, "apiVersion": true}

func (f *fetcher) arg(ctx context.Context, src catalog.Source, emit func([]raw) error) error {
	if len(src.Nest) > 0 {
		nested, err := f.nesting(ctx, src, emit)
		if err != nil {
			return err
		}
		emit = nested
	}
	query := argQuery(src, f.claimed)
	u := strings.TrimRight(f.client.Endpoints.ARM, "/") + "/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01"

	// Without a restriction one query covers the tenant, including what
	// sits above subscriptions. With one, the subscriptions are named.
	var scopes [][]string
	if f.restrict {
		ids := make([]string, len(f.subs))
		for i, s := range f.subs {
			ids[i] = s.ID
		}
		for len(ids) > 0 {
			n := min(200, len(ids))
			scopes = append(scopes, ids[:n])
			ids = ids[n:]
		}
	} else {
		scopes = [][]string{nil}
	}

	total, pages, lastLog := 0, 0, time.Now()
	for _, subs := range scopes {
		top, skip := argPageSize, ""
		for {
			opts := map[string]any{"resultFormat": "objectArray", "$top": top}
			if skip != "" {
				opts["$skipToken"] = skip
			}
			body := map[string]any{"query": query, "options": opts}
			if subs != nil {
				body["subscriptions"] = subs
			}
			var out struct {
				Data      []map[string]any `json:"data"`
				SkipToken string           `json:"$skipToken"`
			}
			err := f.client.Do(ctx, cloud.Request{Method: http.MethodPost, URL: u, Scope: f.client.Endpoints.ARMScope, Body: body, Delegated: src.Delegated}, &out)
			if err != nil {
				// A page of large objects can exceed the response limit:
				// ask for fewer rows.
				var api *cloud.APIError
				if errors.As(err, &api) && strings.Contains(strings.ToLower(api.Code+" "+api.Message), "payloadtoolarge") && top > 20 {
					top /= 2
					f.log.Debug("Resource Graph page too large, asking for fewer rows", "source", src.ID, "rows", top)
					continue
				}
				return err
			}
			batch := make([]raw, 0, len(out.Data))
			for _, row := range out.Data {
				id, _ := row["id"].(string)
				if id == "" {
					continue
				}
				r := raw{Key: strings.ToLower(id), Body: map[string]any{}}
				r.Name, _ = row["name"].(string)
				r.Type, _ = row["type"].(string)
				r.Type = strings.ToLower(r.Type)
				if r.Type == "" {
					r.Type = src.Type
				}
				r.SubscriptionID, _ = row["subscriptionId"].(string)
				r.ResourceGroup, _ = row["resourceGroup"].(string)
				r.Location, _ = row["location"].(string)
				for k, v := range row {
					if argMeta[k] || v == nil || v == "" {
						continue
					}
					r.Body[k] = v
				}
				batch = append(batch, r)
			}
			if err := emit(batch); err != nil {
				return err
			}
			total += len(batch)
			pages++
			if time.Since(lastLog) > time.Minute {
				lastLog = time.Now()
				f.log.Info("still reading Resource Graph", "source", src.ID, "items", total, "pages", pages)
			}
			if out.SkipToken == "" || len(out.Data) == 0 {
				break
			}
			skip = out.SkipToken
		}
	}
	return nil
}

// arm reads a Resource Manager list (or single object), once or once per
// subscription.
func (f *fetcher) arm(ctx context.Context, src catalog.Source, emit func([]raw) error) error {
	base := strings.TrimRight(f.client.Endpoints.ARM, "/")
	// Sources read per resource fetch several at once: what they find is
	// handed on one batch at a time, and named after the resource.
	var emitMu sync.Mutex
	parentOf := func(string) string { return "" }
	if len(src.Each) > 0 {
		inner := emit
		emit = func(batch []raw) error {
			emitMu.Lock()
			defer emitMu.Unlock()
			return inner(batch)
		}
		marker := "{resource}"
		_, tail, _ := strings.Cut(src.Path, marker)
		tail, _, _ = strings.Cut(tail, "?")
		parentOf = func(path string) string {
			p, _, _ := strings.Cut(path, "?")
			p = strings.TrimSuffix(p, tail)
			return p[strings.LastIndex(p, "/")+1:]
		}
	}
	one := func(path, sub string) error {
		u := base + path
		for u != "" {
			// Resource Manager answers a list as {"value": [...]}, but some
			// providers (Microsoft.Security/securityContacts, depending on
			// the version) answer with a bare array, and others with the one
			// object there is.
			var body any
			if err := f.client.Do(ctx, cloud.Request{URL: u, Scope: f.client.Endpoints.ARMScope, Delegated: src.Delegated}, &body); err != nil {
				return err
			}
			objects, next := armObjects(body, src.Single)
			batch := make([]raw, 0, len(objects))
			for _, o := range objects {
				obj, ok := o.(map[string]any)
				if !ok {
					continue
				}
				r := raw{SubscriptionID: sub, Body: map[string]any{}}
				id, _ := obj["id"].(string)
				r.Name, _ = obj["name"].(string)
				r.Type, _ = obj["type"].(string)
				r.Type = strings.ToLower(r.Type)
				if r.Type == "" {
					r.Type = src.Type
				}
				r.Location, _ = obj["location"].(string)
				r.Key = strings.ToLower(id)
				if r.Key == "" {
					r.Key = strings.ToLower(path + "/" + r.Name)
				}
				if _, after, ok := strings.Cut(r.Key, "/resourcegroups/"); ok {
					r.ResourceGroup, _, _ = strings.Cut(after, "/")
				}
				for k, v := range obj {
					if k != "id" && k != "name" && k != "type" {
						r.Body[k] = v
					}
				}
				// "default" and "web" say nothing: the resource it belongs to does.
				if parent := parentOf(path); parent != "" {
					if src.Single {
						r.Name = parent
					} else {
						r.Name = parent + " / " + r.Name
					}
				}
				batch = append(batch, r)
			}
			if err := emit(batch); err != nil {
				return err
			}
			u = next
		}
		return nil
	}
	path := strings.ReplaceAll(src.Path, "{tenantId}", f.tenant.ID)
	if strings.Contains(path, "{resource}") {
		return f.armEach(ctx, src, path, one, emit)
	}
	if strings.Contains(path, "{workspace}") {
		workspaces, err := f.sentinelWorkspaces(ctx)
		if err != nil {
			return err
		}
		for _, ws := range workspaces {
			_, rest, _ := strings.Cut(ws, "/subscriptions/")
			subID, _, _ := strings.Cut(rest, "/")
			err := one(strings.ReplaceAll(path, "{workspace}", ws), subID)
			// 404: this workspace has nothing of the kind.
			if err != nil && !cloud.NotFound(err) {
				return fmt.Errorf("workspace %s: %w", ws[strings.LastIndex(ws, "/")+1:], err)
			}
		}
		return nil
	}
	if !strings.Contains(path, "{subscriptionId}") {
		return one(path, "")
	}
	for _, s := range f.subs {
		// A cancelled or deleted subscription refuses most reads.
		if state := strings.ToLower(s.State); state == "disabled" || state == "deleted" {
			continue
		}
		err := one(strings.ReplaceAll(path, "{subscriptionId}", s.ID), s.ID)
		// 404: the resource provider is not registered in this
		// subscription, so there is nothing of this kind in it.
		if err != nil && !cloud.NotFound(err) {
			return fmt.Errorf("subscription %s: %w", s.Name, err)
		}
	}
	return nil
}

// armObjects returns the objects in a Resource Manager answer, whatever its
// shape, and the link to the next page if there is one.
func armObjects(body any, single bool) (objects []any, next string) {
	switch v := body.(type) {
	case []any:
		return v, ""
	case map[string]any:
		if list, ok := v["value"].([]any); ok && !single {
			next, _ = v["nextLink"].(string)
			return list, next
		}
		if len(v) == 0 {
			return nil, ""
		}
		return []any{v}, ""
	}
	return nil, ""
}

// graphURL builds a Graph URL from a catalogue path. Spaces and quotes in
// the query ($filter) are escaped; the rest is written as Graph documents it.
func (f *fetcher) graphURL(path string, beta bool) string {
	version := "v1.0"
	if beta {
		version = "beta"
	}
	path = strings.ReplaceAll(path, "{tenantId}", f.tenant.ID)
	p, q, has := strings.Cut(path, "?")
	u := strings.TrimRight(f.client.Endpoints.Graph, "/") + "/" + version + p
	if has {
		u += "?" + strings.NewReplacer(" ", "%20", "'", "%27").Replace(q)
	}
	return u
}

// nameKeys are tried in order for an object's display name.
var nameKeys = []string{"displayName", "DisplayName", "name", "Name", "Identity", "userPrincipalName", "id"}

func pick(obj map[string]any, keys ...string) string {
	for _, k := range keys {
		switch v := obj[k].(type) {
		case string:
			if v != "" {
				return v
			}
		case float64:
			return fmt.Sprint(v)
		}
	}
	return ""
}

func (f *fetcher) graphList(ctx context.Context, u string, delegated bool, each func([]any) error) error {
	return f.odataList(ctx, u, f.client.Endpoints.GraphScope, delegated, each)
}

// mde reads a list of the Defender for Endpoint API, which pages as Graph does.
func (f *fetcher) mde(ctx context.Context, src catalog.Source, emit func([]raw) error) error {
	base := strings.TrimRight(f.client.Endpoints.Defender, "/")
	if base == "" {
		return &cloud.APIError{Status: http.StatusNotImplemented, Message: "this cloud has no Defender for Endpoint API"}
	}
	return f.odataList(ctx, base+src.Path, f.client.Endpoints.DefenderScope, src.Delegated, func(list []any) error {
		batch := make([]raw, 0, len(list))
		for _, o := range list {
			obj, ok := o.(map[string]any)
			if !ok {
				continue
			}
			id := pick(obj, src.KeyField, "id")
			if id == "" {
				continue
			}
			name := pick(obj, "title", "displayName", "name", "indicatorValue")
			batch = append(batch, raw{Key: strings.ToLower(src.Path + "/" + id), Name: name, Type: src.Type, Body: obj})
		}
		return emit(batch)
	})
}

// odataList pages through a list that answers {"value": [...], "@odata.nextLink": …}.
func (f *fetcher) odataList(ctx context.Context, u, scope string, delegated bool, each func([]any) error) error {
	for u != "" {
		var body any
		if err := f.client.Do(ctx, cloud.Request{URL: u, Scope: scope, Delegated: delegated}, &body); err != nil {
			return err
		}
		var list []any
		next := ""
		switch v := body.(type) {
		case []any:
			list = v
		case map[string]any:
			var ok bool
			if list, ok = v["value"].([]any); !ok {
				// A single object where a list was expected.
				list = []any{v}
			}
			next, _ = v["@odata.nextLink"].(string)
		}
		if err := each(list); err != nil {
			return err
		}
		u = next
	}
	return nil
}

func (f *fetcher) graph(ctx context.Context, src catalog.Source, emit func([]raw) error) error {
	u := f.graphURL(src.Path, src.Beta)
	if src.Single {
		var obj map[string]any
		err := f.client.Do(ctx, cloud.Request{URL: u, Scope: f.client.Endpoints.GraphScope, Delegated: src.Delegated}, &obj)
		if cloud.NotFound(err) {
			// Not configured in this tenant (no branding, no certificate).
			return nil
		}
		if err != nil {
			return err
		}
		delete(obj, "id")
		return emit([]raw{{Key: src.ID, Name: src.Name, Type: src.Type, Body: obj}})
	}
	if src.Principals {
		return f.principals(ctx, src, emit)
	}
	basePath, _, _ := strings.Cut(src.Path, "?")
	var roles *roleIndex
	var spByApp map[string]string
	if src.Roles != "" {
		roles = f.roles(ctx)
		if src.Roles == catalog.RolesApplication {
			spByApp = f.servicePrincipalsByApp(ctx)
		}
	}
	groups := make([]map[string][]any, len(src.Attach))
	for i, a := range src.Attach {
		g, err := f.attachment(ctx, src, a)
		if err != nil {
			return err
		}
		groups[i] = g
	}
	return f.graphList(ctx, u, src.Delegated, func(list []any) error {
		batch := make([]raw, 0, len(list))
		for _, o := range list {
			obj, ok := o.(map[string]any)
			if !ok {
				continue
			}
			id := pick(obj, src.KeyField, "id")
			if id == "" {
				continue
			}
			if k := src.Keep; k != nil && strings.EqualFold(pick(obj, k.Field), k.Value) == k.Not {
				continue
			}
			for i, a := range src.Attach {
				// nil: the list could not be read, and the property is left
				// out rather than stored as "none".
				if groups[i] == nil {
					continue
				}
				part := groups[i][strings.ToLower(id)]
				if part == nil {
					part = []any{}
				}
				obj[a.Field] = part
			}
			if roles != nil {
				principal := strings.ToLower(id)
				if src.Roles == catalog.RolesApplication {
					// "": the application has no service principal here, and so no roles.
					principal = spByApp[strings.ToLower(pick(obj, "appId"))]
				}
				if src.Roles != catalog.RolesApplication || spByApp != nil {
					roles.into(obj, principal)
				}
			}
			for _, c := range src.Children {
				var children []any
				err := f.graphList(ctx, f.graphURL(basePath+"/"+id+"/"+c.Suffix, src.Beta), src.Delegated, func(page []any) error {
					children = append(children, page...)
					return nil
				})
				if err != nil {
					return fmt.Errorf("%s of %s: %w", c.Field, pick(obj, nameKeys...), err)
				}
				if children == nil {
					children = []any{}
				}
				obj[c.Field] = children
			}
			r := raw{Key: id, Name: pick(obj, nameKeys...), Type: src.Type, Body: obj}
			delete(obj, "id")
			batch = append(batch, r)
		}
		return emit(batch)
	})
}

// initialDomain is the tenant's *.onmicrosoft.com domain, which Exchange
// Online needs to route a request made without a mailbox.
func (f *fetcher) initialDomain(ctx context.Context) (string, error) {
	f.domainOnce.Do(func() {
		if f.tenant.InitialDomain != "" {
			f.domain = f.tenant.InitialDomain
			return
		}
		var out struct {
			Value []struct {
				VerifiedDomains []struct {
					Name      string `json:"name"`
					IsInitial bool   `json:"isInitial"`
				} `json:"verifiedDomains"`
			} `json:"value"`
		}
		u := f.graphURL("/organization?$select=verifiedDomains", false)
		if err := f.client.Do(ctx, cloud.Request{URL: u, Scope: f.client.Endpoints.GraphScope}, &out); err != nil {
			f.domainErr = fmt.Errorf("finding the tenant's initial domain (set initialDomain on the tenant to skip this): %w", err)
			return
		}
		for _, org := range out.Value {
			for _, d := range org.VerifiedDomains {
				if d.IsInitial {
					f.domain = d.Name
					return
				}
			}
		}
		f.domainErr = errors.New("the tenant has no initial domain in Microsoft Graph; set initialDomain on the tenant")
	})
	return f.domain, f.domainErr
}

// exo runs one Exchange Online Get- cmdlet without parameters.
func (f *fetcher) exo(ctx context.Context, src catalog.Source, emit func([]raw) error) error {
	domain, err := f.initialDomain(ctx)
	if err != nil {
		return err
	}
	u := strings.TrimRight(f.client.Endpoints.Exchange, "/") + "/adminapi/beta/" + f.tenant.ID + "/InvokeCommand"
	req := cloud.Request{
		Method: http.MethodPost, Scope: f.client.Endpoints.ExchangeScope, Delegated: src.Delegated,
		Body: map[string]any{"CmdletInput": map[string]any{"CmdletName": src.Cmdlet, "Parameters": map[string]any{}}},
		Header: map[string]string{
			"X-AnchorMailbox":  "UPN:SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}@" + domain,
			"X-CmdletName":     src.Cmdlet,
			"X-ResponseFormat": "json",
			"Prefer":           "odata.maxpagesize=1000",
		},
	}
	for u != "" {
		req.URL = u
		var out map[string]any
		if err := f.client.Do(ctx, req, &out); err != nil {
			return err
		}
		list, _ := out["value"].([]any)
		batch := make([]raw, 0, len(list))
		for _, o := range list {
			obj, ok := o.(map[string]any)
			if !ok {
				continue
			}
			key := pick(obj, src.KeyField, "Guid", "Identity", "Name")
			if key == "" {
				continue
			}
			batch = append(batch, raw{Key: key, Name: pick(obj, "Name", "Identity", "DisplayName", "Guid"), Type: src.Type, Body: obj})
		}
		if err := emit(batch); err != nil {
			return err
		}
		u, _ = out["@odata.nextLink"].(string)
	}
	return nil
}
