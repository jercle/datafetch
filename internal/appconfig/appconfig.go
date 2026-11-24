// Package appconfig reads key-values from Azure App Configuration over its
// REST API, with the standard library only: the same data, signed in the
// same way, as the App Configuration provider that cloudini and the
// dashboard use. Key Vault references are resolved.
//
// It is what the standalone collector uses. A program that already holds
// the configuration object (cloudini's GetCldConfig) passes that object to
// the driftchecker package instead and does not need this one.
package appconfig

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const apiVersion = "2023-11-01"

// Options says where the store is and how to sign in to it.
type Options struct {
	// Endpoint is the store, e.g. https://contoso.azconfig.io.
	Endpoint string
	// Label, when set, is read after the key-values without a label and
	// wins over them.
	Label string

	// A service principal...
	TenantID, ClientID, ClientSecret string
	// ...or a managed identity: the client ID of a user-assigned one, or
	// "system" for the system-assigned one.
	ManagedIdentity string

	// Authority is the Entra ID endpoint (default: the public cloud's).
	Authority string
	HTTP      *http.Client
	// Getenv is where the managed identity endpoint is looked up
	// (IDENTITY_ENDPOINT, IDENTITY_HEADER); nil means no such variables.
	Getenv func(string) string
	// IMDS is the instance metadata endpoint (default: the well-known one).
	IMDS string
}

// FromEnv reads the options from the environment variables cloudini uses:
// AZURE_APPCONFIG_ENDPOINT, AZURE_APPCONFIG_TENANT_ID, _CLIENT_ID and
// _CLIENT_SECRET, or AZURE_APPCONFIG_MANAGED_IDENTITY, and
// AZURE_APPCONFIG_LABEL (or the dashboard's AZURE_APPCONFIG_LABEL_FILTER).
// ok is false when no endpoint is set.
func FromEnv(getenv func(string) string) (o Options, ok bool, err error) {
	o = Options{
		Endpoint:        strings.TrimRight(strings.TrimSpace(getenv("AZURE_APPCONFIG_ENDPOINT")), "/"),
		Label:           getenv("AZURE_APPCONFIG_LABEL"),
		TenantID:        getenv("AZURE_APPCONFIG_TENANT_ID"),
		ClientID:        getenv("AZURE_APPCONFIG_CLIENT_ID"),
		ClientSecret:    getenv("AZURE_APPCONFIG_CLIENT_SECRET"),
		ManagedIdentity: getenv("AZURE_APPCONFIG_MANAGED_IDENTITY"),
		Getenv:          getenv,
	}
	if o.Label == "" {
		o.Label = getenv("AZURE_APPCONFIG_LABEL_FILTER")
	}
	if o.Endpoint == "" {
		return o, false, nil
	}
	if o.ManagedIdentity == "" && (o.TenantID == "" || o.ClientID == "" || o.ClientSecret == "") {
		return o, true, errors.New("AZURE_APPCONFIG_ENDPOINT is set: also set AZURE_APPCONFIG_TENANT_ID, AZURE_APPCONFIG_CLIENT_ID and AZURE_APPCONFIG_CLIENT_SECRET, or AZURE_APPCONFIG_MANAGED_IDENTITY")
	}
	return o, true, nil
}

type token struct {
	value   string
	expires time.Time
}

// Client reads one store.
type Client struct {
	o      Options
	mu     sync.Mutex
	tokens map[string]token
	// anyVault lets tests resolve references to a local server.
	anyVault bool
}

// vaultDomains are the Key Vault domains of the Azure clouds.
var vaultDomains = []string{".vault.azure.net", ".vault.usgovcloudapi.net", ".vault.azure.cn"}

func New(o Options) *Client {
	if o.HTTP == nil {
		o.HTTP = &http.Client{Timeout: 30 * time.Second}
	}
	if o.Authority == "" {
		o.Authority = "https://login.microsoftonline.com"
	}
	if o.IMDS == "" {
		o.IMDS = "http://169.254.169.254"
	}
	if o.Getenv == nil {
		o.Getenv = func(string) string { return "" }
	}
	o.Endpoint = strings.TrimRight(o.Endpoint, "/")
	return &Client{o: o, tokens: map[string]token{}}
}

// audience is the resource a token is asked for: the service's domain
// without the store's or vault's own name (https://azconfig.io,
// https://vault.azure.net, and their national-cloud forms).
func audience(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return endpoint
	}
	host := u.Hostname()
	if _, rest, ok := strings.Cut(host, "."); ok && strings.Contains(rest, ".") {
		host = rest
	}
	return "https://" + host
}

func (c *Client) token(ctx context.Context, resource string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if t, ok := c.tokens[resource]; ok && time.Until(t.expires) > 2*time.Minute {
		return t.value, nil
	}
	var req *http.Request
	var err error
	switch {
	case c.o.ManagedIdentity != "":
		q := url.Values{"resource": {resource}}
		if c.o.ManagedIdentity != "system" {
			q.Set("client_id", c.o.ManagedIdentity)
		}
		if ep := c.o.Getenv("IDENTITY_ENDPOINT"); ep != "" {
			// App Service, Container Apps, Functions.
			q.Set("api-version", "2019-08-01")
			req, err = http.NewRequestWithContext(ctx, http.MethodGet, ep+"?"+q.Encode(), nil)
			if err == nil {
				req.Header.Set("X-IDENTITY-HEADER", c.o.Getenv("IDENTITY_HEADER"))
			}
		} else {
			// Virtual machines and AKS: the instance metadata service.
			q.Set("api-version", "2018-02-01")
			req, err = http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.o.IMDS, "/")+"/metadata/identity/oauth2/token?"+q.Encode(), nil)
			if err == nil {
				req.Header.Set("Metadata", "true")
			}
		}
	default:
		form := url.Values{"grant_type": {"client_credentials"}, "client_id": {c.o.ClientID}, "client_secret": {c.o.ClientSecret}, "scope": {resource + "/.default"}}
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.o.Authority, "/")+"/"+c.o.TenantID+"/oauth2/v2.0/token", strings.NewReader(form.Encode()))
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}
	if err != nil {
		return "", err
	}
	resp, err := c.o.HTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("token for %s: %w", resource, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out struct {
		AccessToken string          `json:"access_token"`
		ExpiresIn   json.RawMessage `json:"expires_in"`
		Description string          `json:"error_description"`
	}
	_ = json.Unmarshal(body, &out)
	if resp.StatusCode != http.StatusOK || out.AccessToken == "" {
		msg := out.Description
		if msg == "" {
			msg = string(body)
		}
		msg, _, _ = strings.Cut(strings.TrimSpace(msg), "\n")
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return "", fmt.Errorf("token for %s: HTTP %d %s", resource, resp.StatusCode, msg)
	}
	// expires_in is a number from Entra ID and a string from the managed
	// identity endpoints.
	seconds, _ := strconv.Atoi(strings.Trim(string(out.ExpiresIn), `"`))
	if seconds <= 0 {
		seconds = 600
	}
	c.tokens[resource] = token{out.AccessToken, time.Now().Add(time.Duration(seconds) * time.Second)}
	return out.AccessToken, nil
}

// get fetches JSON, retrying throttling and server errors a few times.
func (c *Client) get(ctx context.Context, u, resource string, out any) error {
	shown, _, _ := strings.Cut(u, "?")
	for attempt := 1; ; attempt++ {
		tok, err := c.token(ctx, resource)
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Accept", "application/json")
		resp, err := c.o.HTTP.Do(req)
		wait := time.Duration(attempt) * time.Second
		if err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
			resp.Body.Close()
			switch {
			case resp.StatusCode < 300:
				return json.Unmarshal(body, out)
			case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
				if s, e := strconv.Atoi(resp.Header.Get("Retry-After")); e == nil && s > 0 && s <= 30 {
					wait = time.Duration(s) * time.Second
				}
				err = fmt.Errorf("HTTP %d", resp.StatusCode)
			default:
				msg := strings.TrimSpace(string(body))
				if len(msg) > 300 {
					msg = msg[:300]
				}
				return fmt.Errorf("%s: HTTP %d %s", shown, resp.StatusCode, msg)
			}
		}
		if attempt >= 3 || ctx.Err() != nil {
			return fmt.Errorf("%s: %w", shown, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

type keyValue struct {
	Key         string `json:"key"`
	ContentType string `json:"content_type"`
	Value       string `json:"value"`
}

func isJSON(contentType string) bool {
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	return mt == "application/json" || (strings.HasPrefix(mt, "application/") && strings.HasSuffix(mt, "+json"))
}

// Load returns every key-value whose key starts with prefix, by its full
// key. A value with a JSON content type is decoded; a Key Vault reference
// is replaced by the secret; anything else is the text. Values with the
// label win over those without. A reference that cannot be resolved is left
// out and reported in warnings.
func (c *Client) Load(ctx context.Context, prefix string) (values map[string]any, warnings []string, err error) {
	if c.o.Endpoint == "" {
		return nil, nil, errors.New("no App Configuration endpoint")
	}
	values = map[string]any{}
	// "\x00" selects key-values that have no label.
	labels := []string{"\x00"}
	if c.o.Label != "" {
		labels = append(labels, c.o.Label)
	}
	aud := audience(c.o.Endpoint)
	for _, label := range labels {
		next := "/kv?" + url.Values{"key": {prefix + "*"}, "label": {label}, "api-version": {apiVersion}}.Encode()
		for next != "" {
			var page struct {
				Items []keyValue `json:"items"`
				Next  string     `json:"@nextLink"`
			}
			if err := c.get(ctx, c.o.Endpoint+next, aud, &page); err != nil {
				return nil, nil, fmt.Errorf("App Configuration: %w", err)
			}
			for _, kv := range page.Items {
				switch {
				case strings.Contains(kv.ContentType, "keyvaultref"):
					secret, err := c.secret(ctx, kv.Value)
					if err != nil {
						warnings = append(warnings, fmt.Sprintf("%s: the Key Vault reference could not be read: %v", kv.Key, err))
						delete(values, kv.Key)
						continue
					}
					values[kv.Key] = secret
				case isJSON(kv.ContentType):
					var v any
					if json.Unmarshal([]byte(kv.Value), &v) == nil {
						values[kv.Key] = v
					} else {
						values[kv.Key] = kv.Value
					}
				default:
					values[kv.Key] = kv.Value
				}
			}
			next = page.Next
		}
	}
	return values, warnings, nil
}

// secret resolves a Key Vault reference: {"uri": "https://vault/secrets/name[/version]"}.
func (c *Client) secret(ctx context.Context, reference string) (string, error) {
	var ref struct {
		URI string `json:"uri"`
	}
	if err := json.Unmarshal([]byte(reference), &ref); err != nil || ref.URI == "" {
		return "", errors.New("not a reference")
	}
	u, err := url.Parse(ref.URI)
	if err != nil || !strings.HasPrefix(u.Path, "/secrets/") {
		return "", errors.New("not a Key Vault secret address")
	}
	// The reference decides where a Key Vault token is sent, and anyone who
	// can write to the store can write a reference: only real vaults get one.
	if !c.anyVault {
		trusted := false
		for _, suffix := range vaultDomains {
			trusted = trusted || strings.HasSuffix(strings.ToLower(u.Hostname()), suffix)
		}
		if u.Scheme != "https" || !trusted {
			return "", errors.New("the address is not an Azure Key Vault")
		}
	}
	var out struct {
		Value string `json:"value"`
	}
	if err := c.get(ctx, strings.TrimRight(ref.URI, "/")+"?api-version=7.4", audience(ref.URI), &out); err != nil {
		return "", err
	}
	return out.Value, nil
}
