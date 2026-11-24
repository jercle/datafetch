// Package graph is a small Microsoft Graph client for reading an Exchange
// Online mailbox with application (client-credentials) permissions.
//
// It deliberately avoids the full Graph SDK: we need a handful of endpoints,
// raw MIME download ($value) and robust throttling handling.
package graph

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
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxMIMEBytes = 64 << 20 // reports with big attachments are rare; cap anyway

type Config struct {
	TenantID           string
	ClientID           string
	ClientSecret       string
	FederatedTokenFile string
	AuthorityHost      string
	Endpoint           string
	Mailbox            string
}

type Client struct {
	cfg  Config
	http *http.Client
	log  *slog.Logger

	mu     sync.Mutex
	token  string
	expiry time.Time
}

func New(cfg Config, log *slog.Logger) *Client {
	return &Client{cfg: cfg, http: &http.Client{Timeout: 90 * time.Second}, log: log}
}

type Message struct {
	ID                string    `json:"id"`
	Subject           string    `json:"subject"`
	ReceivedDateTime  time.Time `json:"receivedDateTime"`
	InternetMessageID string    `json:"internetMessageId"`
	HasAttachments    bool      `json:"hasAttachments"`
	IsRead            bool      `json:"isRead"`
	From              *struct {
		EmailAddress struct {
			Name    string `json:"name"`
			Address string `json:"address"`
		} `json:"emailAddress"`
	} `json:"from"`
}

func (m Message) FromAddress() string {
	if m.From == nil {
		return ""
	}
	return m.From.EmailAddress.Address
}

type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("graph: HTTP %d %s: %s", e.Status, e.Code, e.Message)
}

func IsNotFound(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == http.StatusNotFound
}

// ---------------------------------------------------------------- auth

func (c *Client) accessToken(ctx context.Context, force bool) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !force && c.token != "" && time.Until(c.expiry) > 2*time.Minute {
		return c.token, nil
	}
	form := url.Values{
		"client_id":  {c.cfg.ClientID},
		"scope":      {c.cfg.Endpoint + "/.default"},
		"grant_type": {"client_credentials"},
	}
	if c.cfg.FederatedTokenFile != "" {
		// Workload identity: the projected token rotates, so re-read every time.
		b, err := os.ReadFile(c.cfg.FederatedTokenFile)
		if err != nil {
			return "", fmt.Errorf("read federated token: %w", err)
		}
		form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		form.Set("client_assertion", strings.TrimSpace(string(b)))
	} else {
		form.Set("client_secret", c.cfg.ClientSecret)
	}
	u := fmt.Sprintf("%s/%s/oauth2/v2.0/token", c.cfg.AuthorityHost, url.PathEscape(c.cfg.TenantID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()
	var tr struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", fmt.Errorf("token response: %w", err)
	}
	if tr.AccessToken == "" {
		return "", fmt.Errorf("token: %s: %s", tr.Error, tr.Description)
	}
	c.token = tr.AccessToken
	c.expiry = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	return c.token, nil
}

// ---------------------------------------------------------------- transport

// do performs a Graph request with retry on throttling / transient errors.
// The caller owns resp.Body on success.
func (c *Client) do(ctx context.Context, method, path string, body any) (*http.Response, error) {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return nil, err
		}
	}
	u := path
	if !strings.HasPrefix(path, "http") {
		u = c.cfg.Endpoint + path
	}
	reauthed := false
	for attempt := 0; ; attempt++ {
		tok, err := c.accessToken(ctx, false)
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(payload))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := c.http.Do(req)
		if err != nil {
			if attempt < 4 && ctx.Err() == nil {
				c.sleep(ctx, backoff(attempt))
				continue
			}
			return nil, err
		}
		switch {
		case resp.StatusCode < 300:
			return resp, nil
		case resp.StatusCode == http.StatusUnauthorized && !reauthed:
			resp.Body.Close()
			reauthed = true
			if _, err := c.accessToken(ctx, true); err != nil {
				return nil, err
			}
			continue
		case (resp.StatusCode == 429 || resp.StatusCode == 503 || resp.StatusCode == 504) && attempt < 6:
			wait := backoff(attempt)
			if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 {
				wait = time.Duration(s) * time.Second
			}
			resp.Body.Close()
			c.log.Warn("graph throttled, backing off", "status", resp.StatusCode, "wait", wait)
			c.sleep(ctx, wait)
			continue
		default:
			defer resp.Body.Close()
			return nil, readAPIError(resp)
		}
	}
}

func (c *Client) getJSON(ctx context.Context, path string, out any) error {
	resp, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(out)
}

func readAPIError(resp *http.Response) error {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var e struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.Unmarshal(b, &e)
	if e.Error.Message == "" {
		e.Error.Message = strings.TrimSpace(string(b))
	}
	return &APIError{Status: resp.StatusCode, Code: e.Error.Code, Message: e.Error.Message}
}

func backoff(attempt int) time.Duration {
	d := time.Duration(1<<attempt) * time.Second
	if d > 60*time.Second {
		d = 60 * time.Second
	}
	return d
}

func (c *Client) sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

func (c *Client) user() string { return "/v1.0/users/" + url.PathEscape(c.cfg.Mailbox) }

// odata encodes query parameters with %20 for spaces (Graph is picky about '+').
func odata(v url.Values) string { return strings.ReplaceAll(v.Encode(), "+", "%20") }

func odataQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// ---------------------------------------------------------------- folders

var wellKnown = map[string]string{
	"inbox": "inbox", "archive": "archive", "junkemail": "junkemail", "junk email": "junkemail",
	"deleteditems": "deleteditems", "deleted items": "deleteditems", "sentitems": "sentitems",
	"drafts": "drafts", "msgfolderroot": "msgfolderroot",
}

// ResolveFolder turns a path like "Inbox/DMARC/Processed" into a folder ID,
// optionally creating missing segments.
func (c *Client) ResolveFolder(ctx context.Context, path string, create bool) (string, error) {
	segs := splitPath(path)
	if len(segs) == 0 {
		return "", errors.New("empty folder path")
	}
	var parent string
	for i, seg := range segs {
		if i == 0 {
			if wk, ok := wellKnown[strings.ToLower(seg)]; ok {
				var f struct {
					ID string `json:"id"`
				}
				if err := c.getJSON(ctx, c.user()+"/mailFolders/"+wk+"?$select=id", &f); err != nil {
					return "", fmt.Errorf("folder %q: %w", seg, err)
				}
				parent = f.ID
				continue
			}
		}
		base := c.user() + "/mailFolders"
		if parent != "" {
			base += "/" + url.PathEscape(parent) + "/childFolders"
		}
		q := url.Values{"$filter": {"displayName eq " + odataQuote(seg)}, "$select": {"id,displayName"}}
		var list struct {
			Value []struct {
				ID string `json:"id"`
			} `json:"value"`
		}
		if err := c.getJSON(ctx, base+"?"+odata(q), &list); err != nil {
			return "", fmt.Errorf("folder %q: %w", seg, err)
		}
		if len(list.Value) > 0 {
			parent = list.Value[0].ID
			continue
		}
		if !create {
			return "", fmt.Errorf("folder %q not found in %q", seg, path)
		}
		resp, err := c.do(ctx, http.MethodPost, base, map[string]any{"displayName": seg})
		if err != nil {
			return "", fmt.Errorf("create folder %q: %w", seg, err)
		}
		var f struct {
			ID string `json:"id"`
		}
		err = json.NewDecoder(resp.Body).Decode(&f)
		resp.Body.Close()
		if err != nil {
			return "", err
		}
		c.log.Info("created mail folder", "path", strings.Join(segs[:i+1], "/"))
		parent = f.ID
	}
	return parent, nil
}

func splitPath(p string) []string {
	var out []string
	for _, s := range strings.Split(p, "/") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// ---------------------------------------------------------------- messages

// ListMessages returns the oldest `top` messages in a folder. Callers process
// and then move/mark them, so re-listing from the start each batch is safe and
// avoids skipping items when pages shift under a nextLink.
//
// skip is the number of messages at the start of the folder to pass over:
// those this run has already looked at and left in place.
func (c *Client) ListMessages(ctx context.Context, folderID string, top, skip int, unreadOnly bool) ([]Message, error) {
	q := url.Values{
		"$select":  {"id,subject,receivedDateTime,internetMessageId,hasAttachments,isRead,from"},
		"$top":     {strconv.Itoa(top)},
		"$orderby": {"receivedDateTime asc"},
	}
	if skip > 0 {
		q.Set("$skip", strconv.Itoa(skip))
	}
	if unreadOnly {
		// Graph requires $orderby properties to lead the $filter.
		q.Set("$filter", "receivedDateTime ge 1970-01-01T00:00:00Z and isRead eq false")
	}
	var list struct {
		Value []Message `json:"value"`
	}
	err := c.getJSON(ctx, c.user()+"/mailFolders/"+url.PathEscape(folderID)+"/messages?"+odata(q), &list)
	return list.Value, err
}

// GetMIME downloads the full RFC 5322 message, attachments included.
func (c *Client) GetMIME(ctx context.Context, id string) ([]byte, error) {
	resp, err := c.do(ctx, http.MethodGet, c.user()+"/messages/"+url.PathEscape(id)+"/$value", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxMIMEBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxMIMEBytes {
		return nil, fmt.Errorf("message larger than %d bytes", maxMIMEBytes)
	}
	return b, nil
}

func (c *Client) Move(ctx context.Context, id, destFolderID string) error {
	resp, err := c.do(ctx, http.MethodPost, c.user()+"/messages/"+url.PathEscape(id)+"/move",
		map[string]string{"destinationId": destFolderID})
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func (c *Client) MarkRead(ctx context.Context, id string, categories ...string) error {
	body := map[string]any{"isRead": true}
	if len(categories) > 0 {
		body["categories"] = categories
	}
	resp, err := c.do(ctx, http.MethodPatch, c.user()+"/messages/"+url.PathEscape(id), body)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}
