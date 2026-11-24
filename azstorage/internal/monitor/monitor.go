package monitor

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"sync"
	"time"

	"github.com/jercle/datafetch/azstorage/internal/model"
)

// Writer is the part of the store the monitor needs.
type Writer interface {
	SaveRun(ctx context.Context, r *model.Run) error
	Heartbeat(ctx context.Context, i *model.Instance) error
}

// Monitor keeps the collector's heartbeat document current and records runs.
type Monitor struct {
	w   Writer
	log *slog.Logger

	mu   sync.Mutex
	inst model.Instance
	run  *model.Run
}

// NewID returns a random 96-bit hex identifier.
func NewID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func New(w Writer, log *slog.Logger, inst model.Instance) *Monitor {
	now := time.Now().UTC()
	inst.State, inst.StartedAt, inst.HeartbeatAt = model.StateIdle, now, now
	if inst.HeartbeatSeconds <= 0 {
		inst.HeartbeatSeconds = 30
	}
	return &Monitor{w: w, log: log, inst: inst}
}

// Update changes the heartbeat document; it is written at the next beat.
func (m *Monitor) Update(fn func(i *model.Instance)) {
	m.mu.Lock()
	fn(&m.inst)
	m.mu.Unlock()
}

// Beat writes the heartbeat now, and the running run's progress with it.
func (m *Monitor) Beat(ctx context.Context) {
	m.mu.Lock()
	m.inst.HeartbeatAt = time.Now().UTC()
	inst := m.inst
	var run *model.Run
	if m.run != nil {
		m.run.HeartbeatAt = inst.HeartbeatAt
		m.run.DurationMs = inst.HeartbeatAt.Sub(m.run.StartedAt).Milliseconds()
		run = cloneRun(m.run)
	}
	m.mu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()
	if err := m.w.Heartbeat(ctx, &inst); err != nil {
		m.log.Debug("heartbeat not written", "error", err)
		return
	}
	if run != nil {
		_ = m.w.SaveRun(ctx, run)
	}
}

func cloneRun(r *model.Run) *model.Run {
	c := *r
	c.Tenants = make([]model.TenantRun, len(r.Tenants))
	for i, t := range r.Tenants {
		t.Steps = append([]model.Step(nil), t.Steps...)
		c.Tenants[i] = t
	}
	return &c
}

// Loop beats until ctx ends, then records that the collector exited.
func (m *Monitor) Loop(ctx context.Context) {
	m.Beat(ctx)
	t := time.NewTicker(time.Duration(m.inst.HeartbeatSeconds) * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			m.Update(func(i *model.Instance) { i.State = model.StateExited; i.NextRunAt = nil })
			m.Beat(context.Background())
			return
		case <-t.C:
			m.Beat(ctx)
		}
	}
}

// StartRun begins a run record.
func (m *Monitor) StartRun(ctx context.Context, trigger string, tenants int) *model.Run {
	now := time.Now().UTC()
	m.mu.Lock()
	r := &model.Run{
		ID: NewID(), Status: model.StatusRunning, Trigger: trigger,
		Instance: m.inst.ID, Version: m.inst.Version,
		StartedAt: now, HeartbeatAt: now, TenantsTotal: tenants,
		Tenants: []model.TenantRun{},
	}
	m.run = r
	m.inst.State, m.inst.CurrentRunID = model.StateRunning, r.ID
	m.mu.Unlock()
	m.Beat(ctx)
	return r
}

// Progress changes the running run under the monitor's lock, so a heartbeat
// never copies it half-updated.
func (m *Monitor) Progress(fn func()) {
	m.mu.Lock()
	fn()
	m.mu.Unlock()
}

// FinishRun closes the run record with the given status.
func (m *Monitor) FinishRun(ctx context.Context, r *model.Run, status, errText string, next *time.Time) {
	now := time.Now().UTC()
	m.mu.Lock()
	r.Status, r.Error = status, errText
	r.FinishedAt, r.HeartbeatAt = &now, now
	r.DurationMs = now.Sub(r.StartedAt).Milliseconds()
	final := cloneRun(r)
	m.run = nil
	m.inst.State, m.inst.CurrentRunID = model.StateIdle, ""
	m.inst.LastRunID, m.inst.LastRunStatus, m.inst.LastRunAt = r.ID, status, &now
	m.inst.NextRunAt = next
	m.mu.Unlock()

	// The run may have ended because ctx was cancelled; still record it.
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), writeTimeout)
	defer cancel()
	if err := m.w.SaveRun(wctx, final); err != nil {
		m.log.Warn("run record not written", "error", err)
	}
	m.Beat(wctx)
}
