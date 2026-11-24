package monitor

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
)

type memSink struct {
	mu   sync.Mutex
	logs []LogEntry
}

func (m *memSink) SaveRun(context.Context, *Run) error           { return nil }
func (m *memSink) SaveInstance(context.Context, *Instance) error { return nil }
func (m *memSink) InsertLogs(_ context.Context, e []LogEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.logs = append(m.logs, e...)
	return nil
}

func TestHandlerShipsAtLevelWithPromotedFields(t *testing.T) {
	sink := &memSink{}
	h, flush := NewHandler(slog.NewTextHandler(io.Discard, nil), sink, slog.LevelInfo, "host1")
	log := slog.New(h).With("runId", "r1", "tenant", "Contoso")
	log.Debug("not shipped")
	log.With("stage", "devices").Error("stage failed", "error", errors.New("HTTP 403"), "durationMs", 12)
	flush()
	if len(sink.logs) != 1 {
		t.Fatalf("shipped %d entries, want 1", len(sink.logs))
	}
	e := sink.logs[0]
	if e.RunID != "r1" || e.Tenant != "Contoso" || e.Stage != "devices" || e.Error != "HTTP 403" || e.Level != "error" || e.Instance != "host1" || e.Attrs["durationMs"] != int64(12) {
		t.Errorf("entry: %+v", e)
	}
}

func TestSummarise(t *testing.T) {
	s := func(st ...string) []StageResult {
		var out []StageResult
		for _, x := range st {
			out = append(out, StageResult{Status: x})
		}
		return out
	}
	for want, in := range map[string][]StageResult{
		StatusSuccess: s(StatusSuccess, StatusEmpty, StatusSkipped),
		StatusPartial: s(StatusSuccess, StatusFailed),
		StatusFailed:  s(StatusFailed, StatusFailed),
	} {
		if got := Summarise(in); got != want {
			t.Errorf("Summarise = %s, want %s", got, want)
		}
	}
}
