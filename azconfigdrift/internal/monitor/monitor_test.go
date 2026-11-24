package monitor

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"

	"github.com/jercle/datafetch/azconfigdrift/internal/model"
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
	log.With("tenantName", "Contoso").Warn("source not read",
		"module", "m365-intune", "source", "scripts", "error", errors.New("access denied"), "files", 3)
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
	if e.Tenant != "Contoso" || e.Module != "m365-intune" || e.Source != "scripts" ||
		e.Error != "access denied" || e.RunID != "run1" || e.Instance != "host1" || e.Severity != 4 || e.Attrs["files"] != int64(3) {
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
	r := m.StartRun(ctx, "schedule", 2, []string{"azure-network"})
	m.Progress(func() {
		r.Tenants = append(r.Tenants, model.TenantRun{Status: model.StatusSuccess, Modules: []model.ModuleRun{{Module: "azure-network", Sources: []model.SourceRun{{Source: "resources"}}}}})
		r.TenantsDone = 1
	})
	m.Beat(ctx)
	cancel() // a cancelled run is still recorded
	m.FinishRun(ctx, r, model.StatusCancelled, "", nil)

	last := st.runs[len(st.runs)-1]
	if last.Status != model.StatusCancelled || last.FinishedAt == nil || last.TenantsDone != 1 || len(last.Tenants) != 1 {
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
