// Package azure is a small standard-library client for what the collector
// reads: Entra ID tokens (client credentials), subscriptions, Azure Resource
// Graph, blob container lists, Azure Monitor capacity metrics, and the blob
// lists of the storage data plane.
package azure

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jercle/datafetch/azstorage/internal/config"
)

const (
	maxAttempts = 7
	// dataAttempts is lower: a storage account that does not answer is
	// usually closed to the collector, not busy.
	dataAttempts = 3
)

type token struct {
	value   string
	expires time.Time
}

// Client makes authenticated calls as one tenant's service principal.
type Client struct {
	// HTTP is used for Entra ID and Azure Resource Manager, Data for the
	// storage accounts' blob endpoints.
	HTTP      *http.Client
	Data      *http.Client
	Tenant    config.Tenant
	Endpoints config.Endpoints
	Log       *slog.Logger
	// Backoff is the first retry delay; it doubles on each attempt.
	Backoff time.Duration
	// MaxWait caps a single wait, including a server's Retry-After.
	MaxWait time.Duration
	// Now is the clock, for the metrics time span.
	Now func() time.Time

	mu     sync.Mutex
	tokens map[string]token
}

func NewClient(t config.Tenant, log *slog.Logger) *Client {
	return &Client{
		HTTP: &http.Client{Timeout: 10 * time.Minute},
		Data: &http.Client{
			Timeout: 5 * time.Minute,
			Transport: &http.Transport{
				Proxy:                 http.ProxyFromEnvironment,
				DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: 2 * time.Minute,
				MaxIdleConnsPerHost:   8,
				IdleConnTimeout:       90 * time.Second,
				ForceAttemptHTTP2:     true,
			},
		},
		Tenant:    t,
		Endpoints: t.Endpoints,
		Log:       log,
		Backoff:   2 * time.Second,
		MaxWait:   5 * time.Minute,
		Now:       time.Now,
		tokens:    map[string]token{},
	}
}

// APIError is a non-retryable (or retries-exhausted) HTTP failure.
type APIError struct {
	Status int
	// Code is the service's error code, when it sends one in a header
	// (storage: AuthorizationPermissionMismatch).
	Code string
	URL  string
	Body string
}

func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("%s: HTTP %d %s", e.URL, e.Status, e.Code)
	}
	return fmt.Sprintf("%s: HTTP %d: %s", e.URL, e.Status, e.Body)
}

func (c *Client) token(ctx context.Context, scope string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if t, ok := c.tokens[scope]; ok && time.Until(t.expires) > 2*time.Minute {
		return t.value, nil
	}
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.Tenant.ClientID},
		"client_secret": {c.Tenant.ClientSecret},
		"scope":         {scope},
	}
	u := strings.TrimRight(c.Endpoints.Authority, "/") + "/" + c.Tenant.ID + "/oauth2/v2.0/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	_ = json.Unmarshal(body, &out)
	if resp.StatusCode != http.StatusOK || out.AccessToken == "" {
		msg := out.Description
		if msg == "" {
			msg = truncate(string(body), 300)
		}
		// Only the first line: the rest is trace and correlation IDs.
		msg, _, _ = strings.Cut(msg, "\n")
		return "", fmt.Errorf("token for %s: HTTP %d %s: %s", scope, resp.StatusCode, out.Error, strings.TrimSpace(msg))
	}
	if out.ExpiresIn <= 0 {
		out.ExpiresIn = 600
	}
	c.tokens[scope] = token{out.AccessToken, time.Now().Add(time.Duration(out.ExpiresIn) * time.Second)}
	return out.AccessToken, nil
}

func (c *Client) dropToken(scope string) {
	c.mu.Lock()
	delete(c.tokens, scope)
	c.mu.Unlock()
}

// call is one request, with how to send it and how to read the answer.
type call struct {
	method, url, scope string
	body               []byte // JSON
	header             map[string]string
	client             *http.Client
	attempts           int
	// decode reads a successful response.
	decode func(io.Reader) error
}

// send makes the call. It retries throttling (429, honouring Retry-After),
// 5xx and transport errors.
func (c *Client) send(ctx context.Context, r call) error {
	shown := r.url
	if i := strings.IndexByte(shown, '?'); i >= 0 {
		shown = shown[:i]
	}
	for attempt := 1; ; attempt++ {
		tok, err := c.token(ctx, r.scope)
		if err != nil {
			return err
		}
		var rd io.Reader
		if r.body != nil {
			rd = bytes.NewReader(r.body)
		}
		req, err := http.NewRequestWithContext(ctx, r.method, r.url, rd)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Accept", "application/json")
		if r.body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		for k, v := range r.header {
			req.Header.Set(k, v)
		}
		wait := c.Backoff << (attempt - 1)
		resp, err := r.client.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if attempt >= r.attempts {
				return fmt.Errorf("%s: %w", shown, err)
			}
		} else {
			status := resp.StatusCode
			if status < 300 {
				err = r.decode(resp.Body)
				resp.Body.Close()
				if err != nil {
					return fmt.Errorf("%s: decoding response: %w", shown, err)
				}
				return nil
			}
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
			resp.Body.Close()
			apiErr := &APIError{Status: status, Code: resp.Header.Get("x-ms-error-code"), URL: shown, Body: truncate(strings.TrimSpace(string(b)), 500)}
			switch {
			case status == http.StatusUnauthorized && attempt == 1:
				c.dropToken(r.scope)
				wait = 0
			case status == http.StatusTooManyRequests || status >= 500:
				if attempt >= r.attempts {
					return apiErr
				}
				if s, e := strconv.Atoi(resp.Header.Get("Retry-After")); e == nil && s > 0 {
					wait = time.Duration(s) * time.Second
				}
			default:
				return apiErr
			}
			err = apiErr
		}
		if c.MaxWait > 0 && wait > c.MaxWait {
			wait = c.MaxWait
		}
		if c.Log != nil && wait > 0 {
			c.Log.Debug("retrying request", "url", shown, "attempt", attempt, "wait", wait.String(), "error", err.Error())
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

// do sends one JSON request to Azure Resource Manager and decodes the
// response into out.
func (c *Client) do(ctx context.Context, method, rawURL string, body []byte, out any) error {
	return c.send(ctx, call{
		method: method, url: rawURL, scope: c.Endpoints.ARMScope, body: body,
		client: c.HTTP, attempts: maxAttempts,
		decode: func(r io.Reader) error { return json.NewDecoder(r).Decode(out) },
	})
}

func (c *Client) arm(path string) string {
	return strings.TrimRight(c.Endpoints.ARM, "/") + path
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
