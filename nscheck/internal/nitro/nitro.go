// Package nitro is a small read-only client for the NetScaler NITRO API:
// log in, GET statistics and configuration resources, log out.
package nitro

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// maxBody bounds one response. A large configuration returns a few MB.
const maxBody = 128 << 20

// Options describe one appliance.
type Options struct {
	// Address is scheme://host[:port].
	Address  string
	Username string
	Password string
	// Timeout of one request.
	Timeout    time.Duration
	SkipVerify bool
	CAFile     string
	// Dump, when set, is called with every resource body that was read.
	Dump func(api, resource string, body []byte)
	// Transport replaces the HTTP transport (tests).
	Transport http.RoundTripper
}

// Client talks to one appliance. It is not safe for concurrent use.
type Client struct {
	o     Options
	hc    *http.Client
	base  *url.URL
	token string
}

// Error is a failed NITRO call.
type Error struct {
	Resource string
	// HTTPStatus is zero when no response arrived.
	HTTPStatus int
	// Code and Message are NITRO's own, when the body had them.
	Code    int
	Message string
	Err     error
}

func (e *Error) Error() string {
	switch {
	case e.Err != nil:
		return fmt.Sprintf("%s: %v", e.Resource, e.Err)
	case e.Message != "":
		return fmt.Sprintf("%s: %s (HTTP %d, NITRO error %d)", e.Resource, e.Message, e.HTTPStatus, e.Code)
	}
	return fmt.Sprintf("%s: HTTP %d", e.Resource, e.HTTPStatus)
}

func (e *Error) Unwrap() error { return e.Err }

// Denied reports whether the appliance refused the credentials or the
// session: a wrong password, an expired session, a missing permission.
func (e *Error) Denied() bool {
	return e.HTTPStatus == http.StatusUnauthorized || e.HTTPStatus == http.StatusForbidden
}

// Answered reports whether the appliance replied at all. An error that was
// answered says something about that resource; one that was not says the
// appliance cannot be reached.
func (e *Error) Answered() bool { return e.HTTPStatus != 0 }

func New(o Options) (*Client, error) {
	base, err := url.Parse(o.Address)
	if err != nil {
		return nil, err
	}
	if o.Timeout <= 0 {
		o.Timeout = 20 * time.Second
	}
	tr := o.Transport
	if tr == nil {
		tc := &tls.Config{InsecureSkipVerify: o.SkipVerify, MinVersion: tls.VersionTLS12} //nolint:gosec // opt-in per appliance
		if o.CAFile != "" {
			pem, err := os.ReadFile(o.CAFile)
			if err != nil {
				return nil, fmt.Errorf("caFile: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("caFile: %s holds no certificates", o.CAFile)
			}
			tc.RootCAs = pool
		}
		tr = &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			TLSClientConfig:       tc,
			TLSHandshakeTimeout:   o.Timeout,
			ResponseHeaderTimeout: o.Timeout,
			MaxIdleConnsPerHost:   2,
			IdleConnTimeout:       90 * time.Second,
		}
	}
	jar, _ := cookiejar.New(nil)
	return &Client{
		o:    o,
		base: base,
		hc: &http.Client{
			Transport: tr, Jar: jar, Timeout: o.Timeout,
			// A redirect (http to https, say) would resend the login.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func (c *Client) url(api, resource string) string {
	return c.base.String() + "/nitro/v1/" + api + "/" + resource
}

func (c *Client) do(ctx context.Context, method, api, resource string, payload any) ([]byte, error) {
	var body io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.url(api, resource), body)
	if err != nil {
		return nil, &Error{Resource: resource, Err: err}
	}
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// The jar replays the cookie the login set. Appliances that only return
	// the session id in the body get it as NITRO_AUTH_TOKEN.
	if c.token != "" && len(c.hc.Jar.Cookies(req.URL)) == 0 {
		req.Header.Set("Cookie", "NITRO_AUTH_TOKEN="+url.QueryEscape(c.token))
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, &Error{Resource: resource, Err: err}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, &Error{Resource: resource, HTTPStatus: resp.StatusCode, Err: err}
	}
	if len(raw) > maxBody {
		return nil, &Error{Resource: resource, HTTPStatus: resp.StatusCode, Err: errors.New("response is too large")}
	}
	var status struct {
		Code    int    `json:"errorcode"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(raw, &status)
	if resp.StatusCode < 200 || resp.StatusCode > 299 || status.Code != 0 {
		e := &Error{Resource: resource, HTTPStatus: resp.StatusCode, Code: status.Code, Message: status.Message}
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			e.Message = "redirected to " + resp.Header.Get("Location") + "; use that address"
		}
		return nil, e
	}
	return raw, nil
}

// Login opens a session. The appliance closes it by itself after sessionTimeout
// without requests, should Logout not be reached.
func (c *Client) Login(ctx context.Context) error {
	const sessionTimeout = 300 // seconds
	raw, err := c.do(ctx, http.MethodPost, "config", "login", map[string]any{
		"login": map[string]any{"username": c.o.Username, "password": c.o.Password, "timeout": sessionTimeout},
	})
	if err != nil {
		return err
	}
	var out struct {
		SessionID string `json:"sessionid"`
	}
	_ = json.Unmarshal(raw, &out)
	c.token = out.SessionID
	if c.token == "" && len(c.hc.Jar.Cookies(c.base.JoinPath("nitro", "v1", "config"))) == 0 {
		return &Error{Resource: "login", HTTPStatus: http.StatusOK, Message: "the login reply held no session"}
	}
	return nil
}

// Logout closes the session. Best effort.
func (c *Client) Logout(ctx context.Context) {
	if c.token == "" && len(c.hc.Jar.Cookies(c.base.JoinPath("nitro", "v1", "config"))) == 0 {
		return
	}
	_, _ = c.do(ctx, http.MethodPost, "config", "logout", map[string]any{"logout": map[string]any{}})
	c.token = ""
	c.hc.Jar, _ = cookiejar.New(nil)
	c.hc.CloseIdleConnections()
}

// Get reads every object of a resource. api is "stat" or "config". A
// resource that has no objects returns an empty list.
func (c *Client) Get(ctx context.Context, api, resource string) ([]Obj, error) {
	raw, err := c.do(ctx, http.MethodGet, api, resource, nil)
	if err != nil {
		return nil, err
	}
	if c.o.Dump != nil {
		c.o.Dump(api, resource, raw)
	}
	objs, err := parse(raw, resource)
	if err != nil {
		return nil, &Error{Resource: resource, HTTPStatus: http.StatusOK, Err: err}
	}
	return objs, nil
}

// parse finds the resource in a reply: {"errorcode":0,...,"<resource>":[{...}]},
// where the value is a list or, for single objects, the object itself.
func parse(raw []byte, resource string) ([]Obj, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var top map[string]json.RawMessage
	if err := dec.Decode(&top); err != nil {
		return nil, fmt.Errorf("not JSON: %w", err)
	}
	var val json.RawMessage
	for k, v := range top {
		if strings.EqualFold(k, resource) {
			val = v
			break
		}
	}
	val = bytes.TrimSpace(val)
	if len(val) == 0 || bytes.Equal(val, []byte("null")) {
		return nil, nil
	}
	decode := func(v any) error {
		d := json.NewDecoder(bytes.NewReader(val))
		d.UseNumber()
		return d.Decode(v)
	}
	if val[0] == '[' {
		var list []Obj
		if err := decode(&list); err != nil {
			return nil, err
		}
		return list, nil
	}
	var one Obj
	if err := decode(&one); err != nil {
		return nil, err
	}
	return []Obj{one}, nil
}

// Obj is one NITRO object. NITRO writes numbers as numbers in some places
// and as strings in others, so the accessors accept both.
type Obj map[string]any

// Has reports whether the field is present and not null.
func (o Obj) Has(key string) bool { return o[key] != nil }

// Str returns the field as text; "" when absent.
func (o Obj) Str(key string) string {
	switch v := o[key].(type) {
	case string:
		return strings.TrimSpace(v)
	case json.Number:
		return v.String()
	case bool:
		return strconv.FormatBool(v)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	}
	return ""
}

// Num returns the field as a number; false when absent or not numeric.
func (o Obj) Num(key string) (float64, bool) {
	switch v := o[key].(type) {
	case json.Number:
		f, err := v.Float64()
		return f, err == nil
	case float64:
		return v, true
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		return f, err == nil
	}
	return 0, false
}

// Int returns the field as an integer; 0 when absent.
func (o Obj) Int(key string) int64 {
	f, _ := o.Num(key)
	return int64(f)
}

// Strs returns a field that is a list of strings (or a single string).
func (o Obj) Strs(key string) []string {
	switch v := o[key].(type) {
	case []any:
		var out []string
		for _, x := range v {
			if s, ok := x.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		if v != "" {
			return []string{v}
		}
	}
	return nil
}

// Truthy reads a flag that NITRO writes as true, 1, "1", "YES", "ON",
// "UP" or "ENABLED".
func (o Obj) Truthy(key string) bool {
	switch strings.ToUpper(o.Str(key)) {
	case "TRUE", "1", "YES", "ON", "UP", "ENABLED":
		return true
	}
	return false
}
