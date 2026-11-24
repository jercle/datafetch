// Package monitor records what the collector does: one document per
// collection pass (cve_collector_runs), structured log entries
// (cve_collector_logs), a heartbeat per process (cve_collector_instances)
// and the latest outcome of every stage per tenant (cve_collector_state).
package monitor

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

const (
	StatusRunning   = "running"
	StatusSuccess   = "success"
	StatusPartial   = "partial" // some stages or tenants failed
	StatusFailed    = "failed"
	StatusCancelled = "cancelled"
	StatusEmpty     = "empty"   // the API answered with no rows; existing data was kept
	StatusSkipped   = "skipped" // not due yet, or a stage it depends on failed
)

// StageResult is one stage (resources, devices, software, vulnerabilities,
// cveDetails, costs) for one tenant, or for all tenants when global.
type StageResult struct {
	Stage  string `bson:"stage"`
	Status string `bson:"status"`
	Error  string `bson:"error,omitempty"`
	// Step is what the stage is doing right now (or was doing last).
	Step       string           `bson:"step,omitempty"`
	StartedAt  time.Time        `bson:"startedAt"`
	DurationMs int64            `bson:"durationMs"`
	Counts     map[string]int64 `bson:"counts,omitempty"`
}

type TenantResult struct {
	TenantID   string        `bson:"tenantId"`
	Name       string        `bson:"name"`
	Status     string        `bson:"status"`
	DurationMs int64         `bson:"durationMs"`
	Stages     []StageResult `bson:"stages"`
}

// Finish derives the tenant's status from its stages.
func (t *TenantResult) Finish(d time.Duration) {
	t.DurationMs = d.Milliseconds()
	t.Status = Summarise(t.Stages)
}

// Summarise is success when nothing failed, failed when nothing worked.
func Summarise(stages []StageResult) string {
	ok, failed := 0, 0
	for _, s := range stages {
		switch s.Status {
		case StatusFailed:
			failed++
		case StatusCancelled:
			return StatusCancelled
		case StatusRunning:
			return StatusRunning
		case StatusSuccess, StatusEmpty:
			ok++
		}
	}
	switch {
	case failed == 0:
		return StatusSuccess
	case ok == 0:
		return StatusFailed
	}
	return StatusPartial
}

// Run is one collection pass over every tenant.
type Run struct {
	ID            string           `bson:"_id"`
	Status        string           `bson:"status"`
	Trigger       string           `bson:"trigger"`
	Instance      string           `bson:"instance"`
	Version       string           `bson:"version"`
	StartedAt     time.Time        `bson:"startedAt"`
	FinishedAt    *time.Time       `bson:"finishedAt,omitempty"`
	HeartbeatAt   time.Time        `bson:"heartbeatAt"`
	DurationMs    int64            `bson:"durationMs"`
	TenantsTotal  int              `bson:"tenantsTotal"`
	TenantsDone   int              `bson:"tenantsDone"`
	TenantsFailed int              `bson:"tenantsFailed"`
	Totals        map[string]int64 `bson:"totals"`
	Tenants       []TenantResult   `bson:"tenants"`
	Global        []StageResult    `bson:"global"`
}

// StageState is the latest outcome of a stage for a tenant ("global" for
// the stages that are not per tenant). LastSuccessAt survives failures.
type StageState struct {
	ID            string           `bson:"_id"`
	TenantID      string           `bson:"tenantId"`
	TenantName    string           `bson:"tenantName"`
	Stage         string           `bson:"stage"`
	Status        string           `bson:"status"`
	Error         string           `bson:"error"`
	RunID         string           `bson:"runId"`
	At            time.Time        `bson:"at"`
	DurationMs    int64            `bson:"durationMs"`
	Counts        map[string]int64 `bson:"counts,omitempty"`
	LastSuccessAt *time.Time       `bson:"lastSuccessAt,omitempty"`
}

type Instance struct {
	ID            string     `bson:"_id"`
	Host          string     `bson:"host"`
	Version       string     `bson:"version"`
	Mode          string     `bson:"mode"`  // schedule | once
	State         string     `bson:"state"` // idle | running | exited
	PID           int        `bson:"pid"`
	IntervalSec   int64      `bson:"intervalSec"`
	StartedAt     time.Time  `bson:"startedAt"`
	HeartbeatAt   time.Time  `bson:"heartbeatAt"`
	LastRunID     string     `bson:"lastRunId,omitempty"`
	LastRunStatus string     `bson:"lastRunStatus,omitempty"`
	LastRunAt     *time.Time `bson:"lastRunAt,omitempty"`
	NextRunAt     *time.Time `bson:"nextRunAt,omitempty"`
}

type LogEntry struct {
	Time     time.Time      `bson:"time"`
	Level    string         `bson:"level"`
	LevelNum int            `bson:"levelNum"`
	Msg      string         `bson:"msg"`
	Instance string         `bson:"instance"`
	RunID    string         `bson:"runId,omitempty"`
	Tenant   string         `bson:"tenant,omitempty"`
	Stage    string         `bson:"stage,omitempty"`
	Error    string         `bson:"error,omitempty"`
	Attrs    map[string]any `bson:"attrs,omitempty"`
}

// Sink is where monitoring records go (MongoDB in production).
type Sink interface {
	SaveRun(ctx context.Context, r *Run) error
	SaveInstance(ctx context.Context, i *Instance) error
	InsertLogs(ctx context.Context, entries []LogEntry) error
}

// NewRunID returns 24 hex characters that sort by creation time.
func NewRunID(now time.Time) string {
	var b [12]byte
	binary.BigEndian.PutUint32(b[:4], uint32(now.Unix()))
	_, _ = rand.Read(b[4:])
	return hex.EncodeToString(b[:])
}

// ---- log handler ----

// Handler passes every record to an inner handler (stdout) and queues those
// at or above its level for the sink. It never blocks the collector: when
// the queue is full, entries are dropped and counted.
type Handler struct {
	inner slog.Handler
	level slog.Leveler
	s     *shipper
	attrs []slog.Attr
}

type shipper struct {
	instance string
	ch       chan LogEntry
	done     chan struct{}
	dropped  int
	mu       sync.Mutex
}

// NewHandler starts shipping to sink; call the returned function to flush
// before exit. A nil sink gives a handler that only writes to inner.
func NewHandler(inner slog.Handler, sink Sink, level slog.Leveler, instance string) (*Handler, func()) {
	h := &Handler{inner: inner, level: level}
	if sink == nil {
		return h, func() {}
	}
	s := &shipper{instance: instance, ch: make(chan LogEntry, 4096), done: make(chan struct{})}
	h.s = s
	go s.loop(sink)
	return h, func() { close(s.ch); <-s.done }
}

func (s *shipper) loop(sink Sink) {
	defer close(s.done)
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	var batch []LogEntry
	flush := func() {
		if len(batch) == 0 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		if err := sink.InsertLogs(ctx, batch); err != nil {
			// Not through slog: that would feed this queue.
			fmt.Fprintf(os.Stderr, "monitor: writing %d log entries: %v\n", len(batch), err)
		}
		cancel()
		batch = batch[:0]
	}
	for {
		select {
		case e, ok := <-s.ch:
			if !ok {
				flush()
				return
			}
			batch = append(batch, e)
			if len(batch) >= 200 {
				flush()
			}
		case <-tick.C:
			flush()
		}
	}
}

func (h *Handler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.inner.Enabled(ctx, l) || (h.s != nil && l >= h.level.Level())
}

func (h *Handler) WithAttrs(a []slog.Attr) slog.Handler {
	c := *h
	c.inner = h.inner.WithAttrs(a)
	c.attrs = append(append([]slog.Attr(nil), h.attrs...), a...)
	return &c
}

// WithGroup is passed through to the inner handler only; shipped entries
// keep flat attribute names.
func (h *Handler) WithGroup(name string) slog.Handler {
	c := *h
	c.inner = h.inner.WithGroup(name)
	return &c
}

func (h *Handler) Handle(ctx context.Context, r slog.Record) error {
	var err error
	if h.inner.Enabled(ctx, r.Level) {
		err = h.inner.Handle(ctx, r)
	}
	if h.s == nil || r.Level < h.level.Level() {
		return err
	}
	e := Entry(r, h.attrs)
	e.Instance = h.s.instance
	func() {
		defer func() { _ = recover() }() // queue closed during shutdown
		select {
		case h.s.ch <- e:
		default:
			h.s.mu.Lock()
			h.s.dropped++
			h.s.mu.Unlock()
		}
	}()
	return err
}

// Entry converts a record: runId, tenant, stage and error become top-level
// fields so they can be filtered; everything else goes under attrs.
func Entry(r slog.Record, pre []slog.Attr) LogEntry {
	e := LogEntry{Time: r.Time.UTC(), Level: levelName(r.Level), LevelNum: int(r.Level), Msg: r.Message}
	put := func(a slog.Attr) bool {
		v := a.Value.Resolve()
		switch a.Key {
		case "runId":
			e.RunID = v.String()
		case "tenant":
			e.Tenant = v.String()
		case "stage":
			e.Stage = v.String()
		case "error", "err":
			e.Error = v.String()
		default:
			if e.Attrs == nil {
				e.Attrs = map[string]any{}
			}
			switch v.Kind() {
			case slog.KindInt64:
				e.Attrs[a.Key] = v.Int64()
			case slog.KindUint64:
				e.Attrs[a.Key] = int64(v.Uint64())
			case slog.KindFloat64:
				e.Attrs[a.Key] = v.Float64()
			case slog.KindBool:
				e.Attrs[a.Key] = v.Bool()
			case slog.KindTime:
				e.Attrs[a.Key] = v.Time()
			default:
				e.Attrs[a.Key] = v.String()
			}
		}
		return true
	}
	for _, a := range pre {
		put(a)
	}
	r.Attrs(put)
	return e
}

func levelName(l slog.Level) string {
	switch {
	case l >= slog.LevelError:
		return "error"
	case l >= slog.LevelWarn:
		return "warn"
	case l >= slog.LevelInfo:
		return "info"
	}
	return "debug"
}
