// Package defender is a small Microsoft Defender for Endpoint API client.
package defender

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// TokenSource returns a bearer token for the Defender API.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

type Client struct {
	base       string
	tokens     TokenSource
	http       *http.Client
	log        *slog.Logger
	maxRetries int
	backoff    func(attempt int) time.Duration
}

func NewClient(base string, ts TokenSource, log *slog.Logger) *Client {
	return &Client{
		base:       strings.TrimRight(base, "/"),
		tokens:     ts,
		http:       &http.Client{Timeout: 5 * time.Minute},
		log:        log,
		maxRetries: 6,
		backoff:    expBackoff,
	}
}

// ListMachines returns every machine matching the OData filter, following
// @odata.nextLink. On any error no partial result is returned.
func (c *Client) ListMachines(ctx context.Context, filter string, pageSize int) ([]Machine, error) {
	q := "$top=" + strconv.Itoa(pageSize)
	if filter != "" {
		q += "&$filter=" + strings.ReplaceAll(url.QueryEscape(filter), "+", "%20")
	}
	next := c.base + "/api/machines?" + q

	var all []Machine
	for page := 1; next != ""; page++ {
		if page > 1000 {
			return nil, errors.New("aborting: more than 1000 pages returned")
		}
		var p machinesPage
		if err := c.getJSON(ctx, next, &p); err != nil {
			return nil, fmt.Errorf("list machines page %d: %w", page, err)
		}
		for _, raw := range p.Value {
			var m Machine
			if err := json.Unmarshal(raw, &m); err != nil {
				return nil, fmt.Errorf("list machines page %d: decode machine: %w", page, err)
			}
			m.Raw = raw
			all = append(all, m)
		}
		c.log.Debug("fetched machines page", "page", page, "count", len(p.Value), "total", len(all))
		next = p.NextLink
	}
	return all, nil
}

type retryableError struct {
	err  error
	wait time.Duration
}

func (e *retryableError) Error() string { return e.err.Error() }
func (e *retryableError) Unwrap() error { return e.err }

func (c *Client) getJSON(ctx context.Context, u string, out any) error {
	for attempt := 1; ; attempt++ {
		err := c.try(ctx, u, out)
		if err == nil {
			return nil
		}
		var re *retryableError
		if !errors.As(err, &re) || attempt > c.maxRetries {
			return err
		}
		wait := re.wait
		if wait <= 0 {
			wait = c.backoff(attempt)
		}
		c.log.Warn("defender API request failed, retrying",
			"attempt", attempt, "wait", wait.String(), "error", err.Error())
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

func (c *Client) try(ctx context.Context, u string, out any) error {
	tok, err := c.tokens.Token(ctx)
	if err != nil {
		return fmt.Errorf("acquire token: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return &retryableError{err: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return &retryableError{err: fmt.Errorf("decode response: %w", err)}
		}
		return nil
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	apiErr := fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(body)))
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
		return &retryableError{err: apiErr, wait: parseRetryAfter(resp.Header.Get("Retry-After"))}
	}
	return apiErr
}

func parseRetryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	if s, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && s >= 0 {
		return time.Duration(s) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

func expBackoff(attempt int) time.Duration {
	d := time.Duration(1<<min(attempt, 6)) * time.Second // 2s .. 64s
	return d + time.Duration(rand.Int64N(int64(time.Second)))
}
