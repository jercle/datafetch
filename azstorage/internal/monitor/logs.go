// Package monitor records what the collector does: structured log entries,
// one document per run, and a heartbeat. Everything is best-effort. If the
// store is unreachable the collector keeps working, the local log still has
// every line, and queued entries are sent when the store comes back.
package monitor

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/jercle/datafetch/azstorage/internal/model"
)

// LogWriter is the part of the store the log sink needs.
type LogWriter interface {
	WriteLogs(ctx context.Context, entries []model.LogEntry) error
}

const (
	maxQueued    = 2000
	flushAt      = 100
	flushEvery   = 10 * time.Second
	writeTimeout = 15 * time.Second
)

// Sink queues log entries and writes them in batches.
type Sink struct {
	w        LogWriter
	instance string
	level    slog.Level

	flushMu sync.Mutex // one write at a time, so entries stay in order
	mu      sync.Mutex
	queue   []model.LogEntry
	dropped int
	runID   string
	wake    chan struct{}
	done    chan struct{}
	stopped chan struct{}
	lastErr time.Time
}

// NewSink starts the background writer. Call Close to flush.
func NewSink(w LogWriter, instance string, level slog.Level) *Sink {
	s := &Sink{
		w:        w,
		level:    level,
		instance: instance,
		wake:     make(chan struct{}, 1),
		done:     make(chan struct{}),
		stopped:  make(chan struct{}),
	}
	go s.loop()
	return s
}

// SetRun tags subsequent entries with the run they belong to.
func (s *Sink) SetRun(id string) {
	s.mu.Lock()
	s.runID = id
	s.mu.Unlock()
}

func (s *Sink) add(e model.LogEntry) {
	s.mu.Lock()
	e.Instance = s.instance
	if e.RunID == "" {
		e.RunID = s.runID
	}
	if len(s.queue) >= maxQueued {
		// Keep the newest: drop from the front.
		s.queue = s.queue[1:]
		s.dropped++
	}
	s.queue = append(s.queue, e)
	n := len(s.queue)
	s.mu.Unlock()
	if n >= flushAt {
		select {
		case s.wake <- struct{}{}:
		default:
		}
	}
}

func (s *Sink) loop() {
	defer close(s.stopped)
	t := time.NewTicker(flushEvery)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			s.Flush()
			return
		case <-t.C:
		case <-s.wake:
		}
		s.Flush()
	}
}

// Flush writes whatever is queued. Entries stay queued if the write fails.
func (s *Sink) Flush() {
	s.flushMu.Lock()
	defer s.flushMu.Unlock()
	s.mu.Lock()
	batch := s.queue
	dropped := s.dropped
	s.queue, s.dropped = nil, 0
	s.mu.Unlock()
	if len(batch) == 0 {
		return
	}
	send := batch
	if dropped > 0 {
		send = append([]model.LogEntry{{
			Time: time.Now().UTC(), Level: "WARN", Severity: int(slog.LevelWarn),
			Msg:      fmt.Sprintf("%d log entries were dropped while the store was unreachable", dropped),
			Instance: s.instance,
		}}, batch...)
	}
	ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
	err := s.w.WriteLogs(ctx, send)
	cancel()
	if err == nil {
		return
	}
	s.mu.Lock()
	// Put the batch back in front of anything logged meanwhile.
	s.queue = append(batch, s.queue...)
	s.dropped += dropped
	if over := len(s.queue) - maxQueued; over > 0 {
		s.queue = s.queue[over:]
		s.dropped += over
	}
	report := time.Since(s.lastErr) > 10*time.Minute
	if report {
		s.lastErr = time.Now()
	}
	s.mu.Unlock()
	if report {
		// Straight to stderr: logging this through the sink would loop.
		fmt.Fprintf(os.Stderr, "az-storage: could not write logs to the store (will retry): %v\n", err)
	}
}

// Close flushes and stops the writer.
func (s *Sink) Close() {
	close(s.done)
	<-s.stopped
}

// Handler returns a slog.Handler that writes to next and, at or above the
// sink's level, queues the entry for the store.
func (s *Sink) Handler(next slog.Handler) slog.Handler {
	return &handler{sink: s, next: next}
}

type handler struct {
	sink  *Sink
	next  slog.Handler
	attrs []slog.Attr
	group string
}

func (h *handler) Enabled(ctx context.Context, l slog.Level) bool {
	return l >= h.sink.level || h.next.Enabled(ctx, l)
}

func (h *handler) Handle(ctx context.Context, r slog.Record) error {
	if r.Level >= h.sink.level {
		e := model.LogEntry{Time: r.Time.UTC(), Level: r.Level.String(), Severity: int(r.Level), Msg: r.Message}
		add := func(a slog.Attr) bool {
			h.put(&e, a)
			return true
		}
		for _, a := range h.attrs {
			add(a)
		}
		r.Attrs(add)
		h.sink.add(e)
	}
	if h.next.Enabled(ctx, r.Level) {
		return h.next.Handle(ctx, r)
	}
	return nil
}

func (h *handler) put(e *model.LogEntry, a slog.Attr) {
	v := a.Value.Resolve()
	key := a.Key
	if h.group != "" {
		key = h.group + "." + key
	}
	switch key {
	case "error", "err":
		e.Error = v.String()
		return
	case "run":
		e.RunID = v.String()
		return
	case "tenantName":
		e.Tenant = v.String()
		return
	case "step":
		e.Step = v.String()
		return
	case "account":
		e.Account = v.String()
		return
	}
	if e.Attrs == nil {
		e.Attrs = map[string]any{}
	}
	switch v.Kind() {
	case slog.KindString:
		e.Attrs[key] = v.String()
	case slog.KindInt64:
		e.Attrs[key] = v.Int64()
	case slog.KindUint64:
		e.Attrs[key] = int64(v.Uint64())
	case slog.KindFloat64:
		e.Attrs[key] = v.Float64()
	case slog.KindBool:
		e.Attrs[key] = v.Bool()
	case slog.KindDuration:
		e.Attrs[key] = v.Duration().String()
	case slog.KindTime:
		e.Attrs[key] = v.Time().UTC()
	default:
		e.Attrs[key] = v.String()
	}
}

func (h *handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	c := *h
	c.attrs = append(append([]slog.Attr{}, h.attrs...), attrs...)
	c.next = h.next.WithAttrs(attrs)
	return &c
}

func (h *handler) WithGroup(name string) slog.Handler {
	c := *h
	if c.group != "" {
		c.group += "."
	}
	c.group += name
	c.next = h.next.WithGroup(name)
	return &c
}

// ParseLevel reads debug / info / warn / error.
func ParseLevel(s string) slog.Level {
	var l slog.Level
	if err := l.UnmarshalText([]byte(s)); err != nil {
		return slog.LevelInfo
	}
	return l
}
