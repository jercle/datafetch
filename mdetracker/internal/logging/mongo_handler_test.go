package logging

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jercle/datafetch/mdetracker/internal/model"
)

type fakeInserter struct {
	mu   sync.Mutex
	docs []any
}

func (f *fakeInserter) InsertMany(_ context.Context, docs []any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.docs = append(f.docs, docs...)
	return nil
}

func TestMongoHandler(t *testing.T) {
	ins := &fakeInserter{}
	h := NewMongoHandler(ins, Options{Service: "test", FlushEvery: 10 * time.Millisecond})
	log := slog.New(h).With("runId", "r1", "tenant", "Contoso")
	log.WithGroup("http").Warn("retrying", "status", 429, "error", errors.New("boom"), "wait", 2*time.Second)
	log.Debug("dropped by level")
	if err := h.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(ins.docs) != 1 {
		t.Fatalf("want 1 doc, got %d", len(ins.docs))
	}
	e := ins.docs[0].(model.LogEntry)
	if e.RunID != "r1" || e.Tenant != "Contoso" || e.Level != "WARN" || e.Service != "test" {
		t.Fatalf("unexpected entry: %+v", e)
	}
	grp := e.Attrs["http"].(map[string]any)
	if grp["status"] != int64(429) || grp["error"] != "boom" || grp["wait"] != "2s" {
		t.Fatalf("attrs: %+v", e.Attrs)
	}
	log.Info("after close is a no-op")
}

// Regression for issue #2: a nil *time.Time attribute panicked the handler.
func TestMongoHandlerNilPointerAttrs(t *testing.T) {
	ins := &fakeInserter{}
	h := NewMongoHandler(ins, Options{FlushEvery: 10 * time.Millisecond})
	var nilTime *time.Time
	var nilErr *os.PathError
	ts := time.Date(2026, 11, 18, 1, 0, 0, 0, time.FixedZone("AEDT", 11*3600))
	slog.New(h).Info("VM onboarding org changed", "previousLastSeen", nilTime, "err", nilErr, "nothing", nil, "when", &ts)
	if err := h.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	e := ins.docs[0].(model.LogEntry)
	if e.Attrs["previousLastSeen"] != nil || e.Attrs["err"] != nil || e.Attrs["nothing"] != nil {
		t.Fatalf("nil pointers should be stored as null: %+v", e.Attrs)
	}
	if got, ok := e.Attrs["when"].(time.Time); !ok || !got.Equal(ts) {
		t.Fatalf("*time.Time should be stored as a time: %+v", e.Attrs["when"])
	}
}
