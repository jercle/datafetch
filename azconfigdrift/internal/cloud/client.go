// Package cloud is a small standard-library client for the Microsoft APIs
// the collector reads: Entra ID tokens (client credentials), and JSON
// requests with retries to Azure Resource Manager, Microsoft Graph and
// Exchange Online.
package cloud

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jercle/datafetch/azconfigdrift/internal/config"
	"github.com/jercle/datafetch/azconfigdrift/internal/model"
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

	mu     sync.Mutex
	tokens map[string]token
}

func NewClient(t config.Tenant, log *slog.Logger) *Client {
	return &Client{
		HTTP:      &http.Client{Timeout: 5 * time.Minute},
		Tenant:    t,
		Endpoints: t.Endpoints,
		Log:       log,
		Backoff:   2 * time.Second,
		MaxWait:   5 * time.Minute,
		tokens:    map[string]token{},
	}
}

// APIError is a non-retryable (or retries-exhausted) HTTP failure.
type APIError struct {
	Status int
	// Code and Message are the service's own, when it sends them.
	Code    string
	Message string
	URL     string
}

func (e *APIError) Error() string {
	msg := e.Message
	if e.Code != "" {
		msg = e.Code + ": " + msg
	}
	return fmt.Sprintf("HTTP %d %s (%s)", e.Status, strings.TrimSuffix(strings.TrimSpace(msg), ":"), e.URL)
}

// TokenError is a failure to get a token: wrong secret, unknown tenant, or
// a resource the application has no permission for at all.
type TokenError struct {
	Scope   string
	Status  int
	Code    string
	Message string
}

func (e *TokenError) Error() string {
	return fmt.Sprintf("token for %s: HTTP %d %s: %s", e.Scope, e.Status, e.Code, e.Message)
}

// Status maps an error from this package to a source status.
func Status(err error) string {
	var api *APIError
	var tok *TokenError
	switch {
	case err == nil:
		return model.SourceOK
	case errors.Is(err, context.Canceled):
		return model.SourceCancelled
	case errors.As(err, &tok):
		return model.SourceDenied
	case errors.As(err, &api):
		switch api.Status {
		case http.StatusUnauthorized, http.StatusForbidden:
			return model.SourceDenied
		case http.StatusBadRequest, http.StatusNotFound, http.StatusNotImplemented, http.StatusMethodNotAllowed:
			return model.SourceUnsupported
		}
	}
	return model.SourceFailed
}

// NotFound reports whether the service answered 404.
func NotFound(err error) bool {
	var api *APIError
	return errors.As(err, &api) && api.Status == http.StatusNotFound
}

// ErrNoServiceAccount is the reason in a TokenError for a delegated request
// in a tenant that has no user name and password configured.
const ErrNoServiceAccount = "no_service_account"

// token returns an access token for the scope: the application's own, or
// with delegated set one for the tenant's service account.
func (c *Client) token(ctx context.Context, scope string, delegated bool) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := scope
	if delegated {
		key = "user " + scope
	}
	if t, ok := c.tokens[key]; ok && time.Until(t.expires) > 2*time.Minute {
		return t.value, nil
	}
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.Tenant.ClientID},
		"client_secret": {c.Tenant.ClientSecret},
		"scope":         {scope},
	}
	if delegated {
		if !c.Tenant.HasServiceAccount() {
			return "", &TokenError{Scope: scope, Status: http.StatusUnauthorized, Code: ErrNoServiceAccount,
				Message: "this source is read as a service account, and the tenant has no username and password in the collector's configuration"}
		}
		// The resource owner password flow: the account signs in without
		// a browser, so it cannot be asked for MFA.
		form.Set("grant_type", "password")
		form.Set("username", c.Tenant.Username)
		form.Set("password", c.Tenant.Password)
		if c.Tenant.DelegatedClientID != "" {
			// A public client: Entra ID refuses a secret for it.
			form.Set("client_id", c.Tenant.DelegatedClientID)
			form.Del("client_secret")
		}
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
		if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
			return "", fmt.Errorf("token for %s: HTTP %d %s", scope, resp.StatusCode, strings.TrimSpace(msg))
		}
		if delegated {
			msg = "signing in as " + c.Tenant.Username + ": " + strings.TrimSpace(msg)
		}
		return "", &TokenError{Scope: scope, Status: resp.StatusCode, Code: out.Error, Message: strings.TrimSpace(msg)}
	}
	if out.ExpiresIn <= 0 {
		out.ExpiresIn = 600
	}
	c.tokens[key] = token{out.AccessToken, time.Now().Add(time.Duration(out.ExpiresIn) * time.Second)}
	return out.AccessToken, nil
}

func (c *Client) dropToken(scope string, delegated bool) {
	c.mu.Lock()
	if delegated {
		scope = "user " + scope
	}
	delete(c.tokens, scope)
	c.mu.Unlock()
}

// Request is one JSON call.
type Request struct {
	Method string // GET when empty
	URL    string
	Scope  string
	// Delegated sends the request as the tenant's service account instead
	// of as the application.
	Delegated bool
	// Body is sent as JSON when not nil.
	Body   any
	Header map[string]string
}

// Do sends the request and decodes the JSON answer into out. It retries
// throttling (429, honouring Retry-After), 5xx and transport errors, and a
// first 401 with a fresh token.
func (c *Client) Do(ctx context.Context, r Request, out any) error {
	shown := r.URL
	if i := strings.IndexByte(shown, '?'); i >= 0 {
		shown = shown[:i]
	}
	method := r.Method
	if method == "" {
		method = http.MethodGet
	}
	var body []byte
	if r.Body != nil {
		var err error
		if body, err = json.Marshal(r.Body); err != nil {
			return err
		}
	}
	for attempt := 1; ; attempt++ {
		tok, err := c.token(ctx, r.Scope, r.Delegated)
		if err != nil {
			return err
		}
		var rd io.Reader
		if body != nil {
			rd = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, r.URL, rd)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Accept", "application/json")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		for k, v := range r.Header {
			req.Header.Set(k, v)
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
				dec := json.NewDecoder(resp.Body)
				err = dec.Decode(out)
				resp.Body.Close()
				if err != nil && !(errors.Is(err, io.EOF) && status == http.StatusNoContent) {
					return fmt.Errorf("%s: decoding response: %w", shown, err)
				}
				return nil
			}
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
			resp.Body.Close()
			apiErr := newAPIError(status, shown, b, resp.Header)
			switch {
			case status == http.StatusUnauthorized && attempt == 1:
				c.dropToken(r.Scope, r.Delegated)
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
			level := slog.LevelDebug
			if wait >= 30*time.Second {
				// A long wait explains a pass that seems to stand still.
				level = slog.LevelInfo
			}
			c.Log.Log(ctx, level, "waiting before retrying a request", "url", shown, "attempt", attempt, "wait", wait.String(), "error", err.Error())
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

// newAPIError reads the error shapes of Resource Manager and Graph
// ({"error": {"code", "message"}}) and falls back to the body's start.
func newAPIError(status int, shown string, body []byte, h http.Header) *APIError {
	e := &APIError{Status: status, URL: shown, Code: h.Get("x-ms-error-code")}
	var parsed struct {
		Error json.RawMessage `json:"error"`
	}
	if json.Unmarshal(body, &parsed) == nil && len(parsed.Error) > 0 {
		var obj struct {
			Code    string `json:"code"`
			Message string `json:"message"`
			Details []struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"details"`
		}
		var text string
		if json.Unmarshal(parsed.Error, &obj) == nil && (obj.Code != "" || obj.Message != "") {
			e.Code, e.Message = obj.Code, obj.Message
			// Resource Graph puts the real reason in the details.
			if len(obj.Details) > 0 && obj.Details[0].Code != "" {
				e.Code = obj.Details[0].Code
				e.Message = obj.Details[0].Message
			}
		} else if json.Unmarshal(parsed.Error, &text) == nil {
			e.Message = text
		}
	}
	if e.Message == "" {
		e.Message = strings.TrimSpace(string(body))
	}
	e.Message, _, _ = strings.Cut(e.Message, "\n")
	e.Message = truncate(strings.TrimSpace(e.Message), 400)
	return e
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
