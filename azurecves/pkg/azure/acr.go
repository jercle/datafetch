package azure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

func (c *Client) acrBase(host string) string {
	if c.ACRBase != nil {
		return c.ACRBase(host)
	}
	return "https://" + host
}

func (c *Client) form(ctx context.Context, u string, form url.Values, bearer string, out any) error {
	method, body := http.MethodGet, io.Reader(nil)
	if form != nil {
		method, body = http.MethodPost, strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return err
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if resp.StatusCode >= 300 {
		shown, _, _ := strings.Cut(u, "?")
		return &APIError{Status: resp.StatusCode, URL: shown, Body: truncate(strings.TrimSpace(string(b)), 300)}
	}
	return json.Unmarshal(b, out)
}

// ErrACRDenied means the registry would not let this principal read
// repository metadata.
var ErrACRDenied = errors.New("registry denied access")

var indexTypes = []string{
	"application/vnd.oci.image.index.v1+json",
	"application/vnd.docker.distribution.manifest.list.v2+json",
}

// ACRTags reads a repository's tags from an Azure Container Registry and
// returns them by manifest digest.
//
// Defender reports the digest of the image it scanned. For a multi-platform
// image that is the digest of one platform's manifest, while the tag points
// at the index (manifest list) above it, so each index's tags are also
// given to the platform manifests it lists. want holds the digests the
// caller cares about; indexes are only opened while some are unmatched.
//
// The service principal needs data-plane read access to the registry:
// AcrPull, or Container Registry Repository Reader where the registry uses
// ABAC repository permissions. Reader alone is not enough.
//
// The registry does not take Entra ID tokens directly: an ARM token is
// exchanged for a registry refresh token, and that for an access token
// scoped to the repository.
func (c *Client) ACRTags(ctx context.Context, host, repo string, want map[string]bool) (map[string][]string, error) {
	base := c.acrBase(host)
	denied := func(err error) error {
		var api *APIError
		if errors.As(err, &api) && (api.Status == http.StatusUnauthorized || api.Status == http.StatusForbidden) {
			return fmt.Errorf("%w: %v", ErrACRDenied, err)
		}
		return err
	}
	c.mu.Lock()
	refresh := c.tokens["acr|"+host].value
	c.mu.Unlock()
	if refresh == "" {
		aad, err := c.token(ctx, c.Endpoints.ARMScope)
		if err != nil {
			return nil, err
		}
		var out struct {
			RefreshToken string `json:"refresh_token"`
		}
		err = c.form(ctx, base+"/oauth2/exchange", url.Values{
			"grant_type": {"access_token"}, "service": {host}, "tenant": {c.Tenant.ID}, "access_token": {aad}}, "", &out)
		if err != nil {
			return nil, denied(fmt.Errorf("registry sign-in: %w", err))
		}
		refresh = out.RefreshToken
		c.mu.Lock()
		c.tokens["acr|"+host] = token{value: refresh}
		c.mu.Unlock()
	}
	// The registry grants whichever of these actions the principal holds.
	var access struct {
		AccessToken string `json:"access_token"`
	}
	err := c.form(ctx, base+"/oauth2/token", url.Values{
		"grant_type": {"refresh_token"}, "service": {host}, "scope": {"repository:" + repo + ":metadata_read,pull"}, "refresh_token": {refresh}}, "", &access)
	if err != nil {
		return nil, denied(fmt.Errorf("registry token for %s: %w", repo, err))
	}

	tags := map[string][]string{}
	add := func(digest string, names []string) {
		digest = strings.ToLower(digest)
		for _, n := range names {
			found := false
			for _, have := range tags[digest] {
				found = found || have == n
			}
			if !found && n != "" {
				tags[digest] = append(tags[digest], n)
			}
		}
	}
	type manifest struct {
		Digest     string   `json:"digest"`
		Tags       []string `json:"tags"`
		MediaType  string   `json:"mediaType"`
		References []struct {
			Digest string `json:"digest"`
		} `json:"references"`
	}
	var indexes []manifest // tagged indexes whose platform manifests the listing did not give

	// Every manifest with the tags pointing at it.
	const page = 500
	last, listed := "", 0
	for {
		q := url.Values{"n": {fmt.Sprint(page)}}
		if last != "" {
			q.Set("last", last)
		}
		var out struct {
			Manifests []manifest `json:"manifests"`
		}
		if err := c.form(ctx, base+"/acr/v1/"+repo+"/_manifests?"+q.Encode(), nil, access.AccessToken, &out); err != nil {
			if listed == 0 {
				break // fall back to the tag listing below
			}
			return nil, denied(err)
		}
		for _, m := range out.Manifests {
			if len(m.Tags) == 0 {
				continue
			}
			add(m.Digest, m.Tags)
			for _, r := range m.References {
				add(r.Digest, m.Tags)
			}
			isIndex := false
			for _, t := range indexTypes {
				isIndex = isIndex || strings.EqualFold(m.MediaType, t)
			}
			if len(m.References) == 0 && (isIndex || m.MediaType == "") {
				indexes = append(indexes, m)
			}
		}
		listed += len(out.Manifests)
		if len(out.Manifests) < page {
			break
		}
		last = out.Manifests[len(out.Manifests)-1].Digest
	}

	// The plain tag listing, when the manifest listing gave nothing.
	if len(tags) == 0 {
		last = ""
		for {
			q := url.Values{"n": {fmt.Sprint(page)}}
			if last != "" {
				q.Set("last", last)
			}
			var out struct {
				Tags []struct {
					Name   string `json:"name"`
					Digest string `json:"digest"`
				} `json:"tags"`
			}
			if err := c.form(ctx, base+"/acr/v1/"+repo+"/_tags?"+q.Encode(), nil, access.AccessToken, &out); err != nil {
				return nil, denied(err)
			}
			for _, t := range out.Tags {
				add(t.Digest, []string{t.Name})
				indexes = append(indexes, manifest{Digest: t.Digest, Tags: []string{t.Name}})
			}
			if len(out.Tags) < page {
				break
			}
			last = out.Tags[len(out.Tags)-1].Name
		}
	}

	// Open tagged indexes until every wanted digest has its tags. Failures
	// are ignored: reading a manifest needs pull, which the principal may
	// not hold, and the tags found so far still stand.
	missing := func() bool {
		for d := range want {
			if len(tags[d]) == 0 {
				return true
			}
		}
		return false
	}
	opened := map[string]bool{}
	for _, m := range indexes {
		if !missing() || len(opened) >= 300 || ctx.Err() != nil {
			break
		}
		d := strings.ToLower(m.Digest)
		if opened[d] || want[d] {
			continue
		}
		opened[d] = true
		var idx struct {
			Manifests []struct {
				Digest string `json:"digest"`
			} `json:"manifests"`
		}
		if err := c.manifest(ctx, base+"/v2/"+repo+"/manifests/"+m.Digest, access.AccessToken, &idx); err != nil {
			continue
		}
		for _, child := range idx.Manifests {
			add(child.Digest, tags[d])
		}
	}
	return tags, nil
}

// manifest fetches a manifest, asking for the index types so a
// multi-platform tag answers with its list of platform manifests.
func (c *Client) manifest(ctx context.Context, u, bearer string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", strings.Join(append(indexTypes,
		"application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"), ", "))
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode >= 300 {
		return &APIError{Status: resp.StatusCode, URL: u, Body: truncate(strings.TrimSpace(string(b)), 200)}
	}
	return json.Unmarshal(b, out)
}
