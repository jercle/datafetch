package defender

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

type staticToken string

func (s staticToken) Token(context.Context) (string, error) { return string(s), nil }

func TestListMachinesPagingAndRetry(t *testing.T) {
	var calls atomic.Int32
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("missing bearer token")
		}
		switch {
		case n == 1:
			if got := r.URL.Query().Get("$filter"); got != "onboardingStatus eq 'Onboarded'" {
				t.Errorf("filter = %q", got)
			}
			fmt.Fprintf(w, `{"value":[{"id":"a","lastSeen":"2026-11-12T10:00:00.1234567Z","vmMetadata":{"vmId":"g","resourceId":"/x"}}],"@odata.nextLink":"%s/api/machines?page=2"}`, srv.URL)
		case n == 2:
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
		default:
			fmt.Fprint(w, `{"value":[{"id":"b","lastSeen":null}]}`)
		}
	}))
	defer srv.Close()

	c := NewClient(srv.URL, staticToken("tok"), slog.New(slog.NewTextHandler(io.Discard, nil)))
	c.backoff = func(int) time.Duration { return time.Millisecond }

	ms, err := c.ListMachines(context.Background(), "onboardingStatus eq 'Onboarded'", 10000)
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 2 || ms[0].ID != "a" || !ms[0].IsAzureVM() || ms[1].LastSeen != nil {
		t.Fatalf("unexpected machines: %+v", ms)
	}
	if calls.Load() != 3 {
		t.Fatalf("calls = %d", calls.Load())
	}
}

func TestNonRetryableError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"error":{"code":"Forbidden","message":"Missing Machine.Read.All"}}`)
	}))
	defer srv.Close()
	c := NewClient(srv.URL, staticToken("tok"), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if _, err := c.ListMachines(context.Background(), "", 100); err == nil {
		t.Fatal("expected error")
	}
}
