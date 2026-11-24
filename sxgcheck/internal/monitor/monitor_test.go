package monitor

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"

	"github.com/jercle/datafetch/sxgcheck/internal/model"
)

type fakeStore struct {
	mu    sync.Mutex
	logs  []model.LogEntry
	runs  []model.Run
	beats []model.Instance
	fail  bool
}

func (f *fakeStore) WriteLogs(_ context.Context, e []model.LogEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return errors.New("down")
	}
	f.logs = append(f.logs, e...)
	return nil
}
func (f *fakeStore) SaveRun(_ context.Context, r *model.Run) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.runs = append(f.runs, *r)
	return nil
}
func (f *fakeStore) Heartbeat(_ context.Context, i *model.Instance) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.beats = append(f.beats, *i)
	return nil
}

func TestSinkLiftsFieldsAndRetries(t *testing.T) {
	st := &fakeStore{fail: true}
	sink := NewSink(st, "host1", slog.LevelInfo)
	log := slog.New(sink.Handler(slog.NewTextHandler(io.Discard, nil)))
	sink.SetRun("run1")
	log.Debug("not stored")
	log.With("firewall", "syd-fw01", "tenantName", "Contoso").Warn("check failed",
		"check", "tcp/4444", "error", errors.New("connection refused"), "attempts", 3)
	sink.Flush() // fails, entry stays queued
	if len(st.logs) != 0 {
		t.Fatal("wrote while failing")
	}
	st.mu.Lock()
	st.fail = false
	st.mu.Unlock()
	log.Info("later")
	sink.Close()
	if len(st.logs) != 2 {
		t.Fatalf("%d entries", len(st.logs))
	}
	e := st.logs[0]
	if e.Tenant != "Contoso" || e.Firewall != "syd-fw01" || e.Check != "tcp/4444" ||
		e.Error != "connection refused" || e.RunID != "run1" || e.Instance != "host1" || e.Severity != 4 || e.Attrs["attempts"] != int64(3) {
		t.Fatalf("entry %+v", e)
	}
	if st.logs[1].Msg != "later" {
		t.Fatal("order not kept")
	}
}

func TestRunLifecycle(t *testing.T) {
	st := &fakeStore{}
	m := New(st, slog.New(slog.NewTextHandler(io.Discard, nil)), model.Instance{ID: "host1", Version: "1.0", Mode: "once"})
	ctx, cancel := context.WithCancel(context.Background())
	r := m.StartRun(ctx, "schedule", 2)
	m.Progress(func() {
		r.Firewalls = append(r.Firewalls, model.FirewallRun{Name: "syd-fw01", Health: model.HealthOK})
		r.FirewallsDone = 1
	})
	m.Beat(ctx)
	cancel() // a cancelled run is still recorded
	m.FinishRun(ctx, r, model.StatusCancelled, "", nil)

	last := st.runs[len(st.runs)-1]
	if last.Status != model.StatusCancelled || last.FinishedAt == nil || last.FirewallsDone != 1 || len(last.Firewalls) != 1 {
		t.Fatalf("final run %+v", last)
	}
	if st.runs[0].Status != model.StatusRunning {
		t.Fatal("no running record at start")
	}
	b := st.beats[len(st.beats)-1]
	if b.State != model.StateIdle || b.LastRunID != r.ID || b.LastRunStatus != model.StatusCancelled || b.CurrentRunID != "" {
		t.Fatalf("final heartbeat %+v", b)
	}
}
