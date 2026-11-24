package monitor

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"
)

type fakeWriter struct {
	mu  sync.Mutex
	got []LogEntry
}

func (f *fakeWriter) WriteLogs(_ context.Context, e []LogEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.got = append(f.got, e...)
	return nil
}

func TestHandlerSink(t *testing.T) {
	w := &fakeWriter{}
	sink := NewSink(w, "host-1", nil)
	stdout := slog.NewJSONHandler(io.Discard, nil)
	log := slog.New(NewHandler(stdout, sink, slog.LevelInfo))

	sink.SetRun("abc123")
	log.Debug("below the sink level")
	log.With("graphId", "G1", "subject", "Report domain: x").Info("processed message", "reports", 2, "took", "1s")
	log.WithGroup("graph").Error("poll failed", "err", errors.New("boom"), "status", 503)
	sink.Close()

	if len(w.got) != 2 {
		t.Fatalf("want 2 entries, got %d: %+v", len(w.got), w.got)
	}
	a, b := w.got[0], w.got[1]
	if a.RunID != "abc123" || a.Instance != "host-1" || a.GraphID != "G1" || a.Subject != "Report domain: x" || a.Level != "info" {
		t.Errorf("entry 0: %+v", a)
	}
	if a.Attrs["reports"] != int64(2) || a.Attrs["took"] != "1s" {
		t.Errorf("attrs 0: %+v", a.Attrs)
	}
	if b.Level != "error" || b.LevelNum != 8 || b.Attrs["graph_status"] != int64(503) || b.Attrs["graph_err"] != "boom" {
		t.Errorf("entry 1: %+v", b)
	}
}

func TestDeriveStatus(t *testing.T) {
	cases := []struct {
		t         Totals
		err       error
		cancelled bool
		want      string
	}{
		{Totals{Messages: 3}, nil, false, StatusSuccess},
		{Totals{PostProcessFailed: 1}, nil, false, StatusPartial},
		{Totals{}, errors.New("x"), false, StatusFailed},
		{Totals{}, errors.New("x"), true, StatusCancelled},
	}
	for _, c := range cases {
		if got := DeriveStatus(c.t, c.err, c.cancelled); got != c.want {
			t.Errorf("%+v err=%v cancelled=%v: got %s want %s", c.t, c.err, c.cancelled, got, c.want)
		}
	}
}

func TestNilSafe(t *testing.T) {
	var m *Monitor
	var s *Sink
	r := m.BeginRun("schedule")
	r.Progress(Totals{})
	r.Finish(Totals{}, nil, false)
	if r.ID() != "" {
		t.Error("nil run id")
	}
	m.SetNext(time.Time{})
	m.Close()
	s.SetRun("x")
	s.Close()
}
