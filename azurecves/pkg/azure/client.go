// Package azure is a small standard-library client for the three APIs the
// collector reads: Entra ID tokens (client credentials), Azure Resource Graph
// and the Defender for Endpoint API.
package azure

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jercle/datafetch/azurecves/pkg/config"
)

const maxAttempts = 7

type token struct {
	value   string
	expires time.Time
}

// Client makes authenticated calls as one tenant's service principal.
type Client struct {
	HTTP      *http.Client
	Tenant    config.Tenant
	Endpoints config.Endpoints
	Log       *slog.Logger
	// Backoff is the first retry delay; it doubles on each attempt.
	Backoff time.Duration
	// MaxWait caps a single wait, including a server's Retry-After.
	MaxWait time.Duration
	// ACRBase maps a registry host to its API base URL; nil means https://host.
	ACRBase func(host string) string

	mu     sync.Mutex
	tokens map[string]token
}

func NewClient(t config.Tenant, e config.Endpoints, log *slog.Logger) *Client {
	return &Client{
		HTTP:      &http.Client{Timeout: 10 * time.Minute},
		Tenant:    t,
		Endpoints: e,
		Log:       log,
		Backoff:   2 * time.Second,
		MaxWait:   5 * time.Minute,
		tokens:    map[string]token{},
	}
}

// APIError is a non-retryable (or retries-exhausted) HTTP failure.
type APIError struct {
	Status int
	URL    string
	Body   string
}

func (e *APIError) Error() string {
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

// do sends one JSON request and decodes the response into out. It retries
// throttling (429, honouring Retry-After), 5xx and transport errors.
func (c *Client) do(ctx context.Context, method, rawURL, scope string, body []byte, out any) error {
	shown := rawURL
	if i := strings.IndexByte(shown, '?'); i >= 0 {
		shown = shown[:i]
	}
	for attempt := 1; ; attempt++ {
		tok, err := c.token(ctx, scope)
		if err != nil {
			return err
		}
		var rd io.Reader
		if body != nil {
			rd = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, rawURL, rd)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Accept", "application/json")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		wait := c.Backoff << (attempt - 1)
		resp, err := c.HTTP.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if attempt >= maxAttempts {
				return fmt.Errorf("%s: %w", shown, err)
			}
		} else {
			status := resp.StatusCode
			if status < 300 {
				err = json.NewDecoder(resp.Body).Decode(out)
				resp.Body.Close()
				if err != nil {
					return fmt.Errorf("%s: decoding response: %w", shown, err)
				}
				return nil
			}
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
			resp.Body.Close()
			apiErr := &APIError{Status: status, URL: shown, Body: truncate(strings.TrimSpace(string(b)), 500)}
			switch {
			case status == http.StatusUnauthorized && attempt == 1:
				c.dropToken(scope)
				wait = 0
			case status == http.StatusTooManyRequests || status >= 500:
				if attempt >= maxAttempts {
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
			// Long waits are nearly always the API throttling; say so where
			// it can be seen, since the stage looks idle meanwhile.
			lvl, msg := slog.LevelDebug, "retrying request"
			if wait >= 5*time.Second {
				lvl, msg = slog.LevelWarn, "API asked to wait before retrying"
			}
			c.Log.Log(ctx, lvl, msg, "url", shown, "attempt", attempt, "of", maxAttempts, "wait", wait.String(), "error", err.Error())
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
