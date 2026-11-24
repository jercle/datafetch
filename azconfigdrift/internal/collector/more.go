package collector

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"

	"github.com/jercle/datafetch/azconfigdrift/internal/catalog"
	"github.com/jercle/datafetch/azconfigdrift/internal/cloud"
)

// armEach reads a Resource Manager source once for every resource of the
// source's types, a few at a time.
func (f *fetcher) armEach(ctx context.Context, src catalog.Source, path string, one func(path, sub string) error, _ func([]raw) error) error {
	quoted := make([]string, len(src.Each))
	for i, t := range src.Each {
		quoted[i] = "'" + t + "'"
	}
	var ids []string
	q := "resources | where type in~ (" + strings.Join(quoted, ", ") + ") | project id, name, type | order by id asc"
	if err := f.arg(ctx, catalog.Source{ID: src.ID, Kind: catalog.KindARG, Query: q, Delegated: src.Delegated}, func(rows []raw) error {
		for _, r := range rows {
			ids = append(ids, r.Key)
		}
		return nil
	}); err != nil {
		return err
	}
	const workers = 8
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		first error
		next  = make(chan string)
	)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range next {
				_, rest, _ := strings.Cut(id, "/subscriptions/")
				subID, _, _ := strings.Cut(rest, "/")
				err := one(strings.ReplaceAll(path, "{resource}", id), subID)
				// 404 and 400: this resource has nothing of the kind, or its
				// kind does not support it (a storage account without file
				// shares, a resource type without diagnostics).
				if err == nil || cloud.NotFound(err) || cloud.Status(err) == "unsupported" {
					continue
				}
				mu.Lock()
				if first == nil {
					first = fmt.Errorf("%s: %w", id[strings.LastIndex(id, "/")+1:], err)
				}
				mu.Unlock()
			}
		}()
	}
feed:
	for _, id := range ids {
		mu.Lock()
		stop := first != nil
		mu.Unlock()
		if stop {
			break
		}
		select {
		case next <- id:
		case <-ctx.Done():
			break feed
		}
	}
	close(next)
	wg.Wait()
	if first == nil {
		first = ctx.Err()
	}
	return first
}

// spo reads from the tenant's SharePoint admin site.
func (f *fetcher) spo(ctx context.Context, src catalog.Source, emit func([]raw) error) error {
	suffix := f.client.Endpoints.SharePoint
	if suffix == "" {
		return &cloud.APIError{Status: http.StatusNotImplemented, Message: "the SharePoint domain of this cloud is not known"}
	}
	domain, err := f.initialDomain(ctx)
	if err != nil {
		return err
	}
	name, _, _ := strings.Cut(domain, ".")
	host := "https://" + name + "-admin." + suffix
	if strings.Contains(suffix, "://") {
		host = strings.TrimRight(suffix, "/") // a whole address, as tests give
	}
	var body map[string]any
	err = f.client.Do(ctx, cloud.Request{URL: host + src.Path, Scope: host + "/.default", Delegated: src.Delegated,
		Header: map[string]string{"Accept": "application/json;odata=nometadata"}}, &body)
	if err != nil {
		return err
	}
	return emit([]raw{{Key: strings.ToLower(src.Path), Name: src.Name, Type: src.Type, Body: body}})
}

// powerPlatform reads from the Power Platform admin API.
func (f *fetcher) powerPlatform(ctx context.Context, src catalog.Source, emit func([]raw) error) error {
	base := strings.TrimRight(f.client.Endpoints.PowerPlatform, "/")
	if base == "" {
		return &cloud.APIError{Status: http.StatusNotImplemented, Message: "the Power Platform admin API of this cloud is not known"}
	}
	u := base + src.Path
	for u != "" {
		var body map[string]any
		req := cloud.Request{Method: src.Method, URL: u, Scope: f.client.Endpoints.PowerPlatformScope, Delegated: src.Delegated}
		if src.Method == http.MethodPost {
			req.Body = map[string]any{}
		}
		if err := f.client.Do(ctx, req, &body); err != nil {
			return err
		}
		list, isList := body["value"].([]any)
		if src.Single || !isList {
			return emit([]raw{{Key: strings.ToLower(src.ID), Name: src.Name, Type: src.Type, Body: body}})
		}
		batch := make([]raw, 0, len(list))
		for _, o := range list {
			obj, ok := o.(map[string]any)
			if !ok {
				continue
			}
			id := pick(obj, src.KeyField, "name", "id")
			if id == "" {
				continue
			}
			batch = append(batch, raw{Key: strings.ToLower(src.ID + "/" + id), Name: pick(obj, "displayName", "name"), Type: src.Type, Body: obj})
		}
		if err := emit(batch); err != nil {
			return err
		}
		u, _ = body["nextLink"].(string)
	}
	return nil
}

//go:embed scripts/teams.ps1
var teamsScript string

// The embedded scripts, and the scope of the second token each needs
// beside Microsoft Graph's.
var pwshScripts = map[string]struct{ script, scope string }{
	// The application ID of the Teams admin service.
	"teams": {teamsScript, "48ac35b8-9aa8-4d74-927d-1f4a14a0b239/.default"},
}

// pwshCommand is PowerShell 7 on the path; tests put a stand-in here.
var pwshCommand = "pwsh"

var getCmdlet = regexp.MustCompile(`^Get-[A-Za-z]+$`)

type pwshResult struct {
	Items []any  `json:"items"`
	Error string `json:"error"`
}

// pwsh returns what a cmdlet gave. The script of its module is run once
// per pass, for all the module's cmdlets that are in the catalogue.
func (f *fetcher) pwsh(ctx context.Context, src catalog.Source, emit func([]raw) error) error {
	out, err := f.runScript(ctx, src)
	if err != nil {
		return err
	}
	res, ok := out[src.Cmdlet]
	if all, failed := out["*"]; failed {
		res, ok = all, true
	}
	switch {
	case !ok:
		return fmt.Errorf("%s gave no answer", src.Cmdlet)
	case res.Error != "":
		// Not allowed is not the same as broken.
		if regexp.MustCompile(`(?i)denied|forbidden|unauthori[sz]ed|not authori[sz]ed|permission`).MatchString(res.Error) {
			return &cloud.APIError{Status: http.StatusForbidden, Message: res.Error}
		}
		return errors.New(res.Error)
	}
	batch := make([]raw, 0, len(res.Items))
	for _, o := range res.Items {
		obj, ok := o.(map[string]any)
		if !ok {
			continue
		}
		id := pick(obj, src.KeyField, "Identity", "Id", "Name")
		if id == "" {
			continue
		}
		batch = append(batch, raw{Key: strings.ToLower(src.Cmdlet + "/" + id), Name: id, Type: src.Type, Body: obj})
	}
	return emit(batch)
}

func (f *fetcher) runScript(ctx context.Context, src catalog.Source) (map[string]pwshResult, error) {
	f.pwshMu.Lock()
	defer f.pwshMu.Unlock()
	if out, ok := f.pwshOut[src.Script]; ok {
		return out, nil
	}
	s, ok := pwshScripts[src.Script]
	if !ok {
		return nil, fmt.Errorf("no script %q", src.Script)
	}
	path, err := exec.LookPath(pwshCommand)
	if err != nil {
		return nil, &cloud.APIError{Status: http.StatusNotImplemented, Message: "PowerShell 7 (pwsh) is not installed where the collector runs"}
	}
	// Every cmdlet of this script that the catalogue has, in one run:
	// connecting is the slow part.
	var cmdlets []string
	for _, c := range f.cmdlets[src.Script] {
		if getCmdlet.MatchString(c) {
			cmdlets = append(cmdlets, c)
		}
	}
	if len(cmdlets) == 0 {
		cmdlets = []string{src.Cmdlet}
	}
	graph, err := f.client.Token(ctx, f.client.Endpoints.GraphScope, src.Delegated)
	if err != nil {
		return nil, err
	}
	second, err := f.client.Token(ctx, s.scope, src.Delegated)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, path, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", s.script)
	// The tokens go in the environment of the child, never on its command
	// line, where every user of the machine could read them.
	cmd.Env = append(os.Environ(), "ACD_GRAPH_TOKEN="+graph, "ACD_TEAMS_TOKEN="+second, "ACD_TENANT_ID="+f.tenant.ID, "ACD_CMDLETS="+strings.Join(cmdlets, ","))
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("pwsh: %w: %s", err, firstLine(stderr.String()))
	}
	var out map[string]pwshResult
	// Anything a module prints before the document is not part of it.
	doc := stdout.Bytes()
	if i := bytes.IndexByte(doc, '{'); i > 0 {
		doc = doc[i:]
	}
	if err := json.Unmarshal(doc, &out); err != nil {
		return nil, fmt.Errorf("pwsh: the script's output is not JSON: %s", firstLine(stderr.String()+" "+stdout.String()))
	}
	if f.pwshOut == nil {
		f.pwshOut = map[string]map[string]pwshResult{}
	}
	f.pwshOut[src.Script] = out
	return out, nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}
