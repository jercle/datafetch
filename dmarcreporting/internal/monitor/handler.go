package monitor

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// LogEntry is one document in the logs collection. Fields the dashboard
// filters on are top-level; everything else is under Attrs.
type LogEntry struct {
	Time     time.Time      `bson:"time"`
	Level    string         `bson:"level"`
	LevelNum int            `bson:"levelNum"`
	Msg      string         `bson:"msg"`
	Instance string         `bson:"instance,omitempty"`
	RunID    string         `bson:"runId,omitempty"`
	GraphID  string         `bson:"graphId,omitempty"`
	Subject  string         `bson:"subject,omitempty"`
	From     string         `bson:"from,omitempty"`
	Error    string         `bson:"error,omitempty"`
	Attrs    map[string]any `bson:"attrs,omitempty"`
}

type LogWriter interface {
	WriteLogs(ctx context.Context, entries []LogEntry) error
}

const (
	sinkBuffer = 4096
	sinkBatch  = 200
	sinkFlush  = 2 * time.Second
)

// Sink batches log entries to a LogWriter on a background goroutine. Logging
// never blocks the collector: when the buffer is full, entries are dropped
// (and counted) rather than waited for.
type Sink struct {
	w        LogWriter
	instance string
	fallback *slog.Logger
	ch       chan LogEntry
	stop     chan struct{}
	done     chan struct{}
	once     sync.Once
	runID    atomic.Value // string
	dropped  atomic.Int64
}

func NewSink(w LogWriter, instance string, fallback *slog.Logger) *Sink {
	s := &Sink{
		w: w, instance: instance, fallback: fallback,
		ch: make(chan LogEntry, sinkBuffer), stop: make(chan struct{}), done: make(chan struct{}),
	}
	s.runID.Store("")
	go s.loop()
	return s
}

// SetRun tags subsequent entries with a run id ("" clears it).
func (s *Sink) SetRun(id string) {
	if s != nil {
		s.runID.Store(id)
	}
}

func (s *Sink) add(e LogEntry) {
	e.Instance = s.instance
	if e.RunID == "" {
		e.RunID, _ = s.runID.Load().(string)
	}
	select {
	case s.ch <- e:
	default:
		s.dropped.Add(1)
	}
}

func (s *Sink) loop() {
	defer close(s.done)
	t := time.NewTicker(sinkFlush)
	defer t.Stop()
	batch := make([]LogEntry, 0, sinkBatch)
	flush := func() {
		if n := s.dropped.Swap(0); n > 0 {
			batch = append(batch, LogEntry{
				Time: time.Now().UTC(), Level: "warn", LevelNum: int(slog.LevelWarn), Instance: s.instance,
				Msg: fmt.Sprintf("monitor: dropped %d log entries (buffer full)", n),
			})
		}
		if len(batch) == 0 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
		if err := s.w.WriteLogs(ctx, batch); err != nil && s.fallback != nil {
			s.fallback.Warn("monitor: writing logs failed", "err", err, "entries", len(batch))
		}
		cancel()
		batch = batch[:0]
	}
	for {
		select {
		case e := <-s.ch:
			if batch = append(batch, e); len(batch) >= sinkBatch {
				flush()
			}
		case <-t.C:
			flush()
		case <-s.stop:
			for {
				select {
				case e := <-s.ch:
					batch = append(batch, e)
				default:
					flush()
					return
				}
			}
		}
	}
}

// Close flushes what is buffered and stops the sink.
func (s *Sink) Close() {
	if s == nil {
		return
	}
	s.once.Do(func() { close(s.stop) })
	select {
	case <-s.done:
	case <-time.After(writeTimeout + time.Second):
	}
}

// Handler is a slog.Handler that passes every record to next (stdout) and
// copies records at or above min to the sink.
type Handler struct {
	next   slog.Handler
	sink   *Sink
	min    slog.Level
	attrs  []slog.Attr
	prefix string
}

func NewHandler(next slog.Handler, sink *Sink, min slog.Level) *Handler {
	return &Handler{next: next, sink: sink, min: min}
}

func (h *Handler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.next.Enabled(ctx, l) || (h.sink != nil && l >= h.min)
}

func (h *Handler) Handle(ctx context.Context, r slog.Record) error {
	var err error
	if h.next.Enabled(ctx, r.Level) {
		err = h.next.Handle(ctx, r.Clone())
	}
	if h.sink != nil && r.Level >= h.min {
		h.sink.add(h.entry(r))
	}
	return err
}

func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	c := *h
	c.next = h.next.WithAttrs(attrs)
	c.attrs = append(append([]slog.Attr{}, h.attrs...), prefixed(h.prefix, attrs)...)
	return &c
}

func (h *Handler) WithGroup(name string) slog.Handler {
	c := *h
	c.next = h.next.WithGroup(name)
	if name != "" {
		c.prefix = h.prefix + name + "."
	}
	return &c
}

func prefixed(prefix string, attrs []slog.Attr) []slog.Attr {
	if prefix == "" {
		return attrs
	}
	out := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		out[i] = slog.Attr{Key: prefix + a.Key, Value: a.Value}
	}
	return out
}

func (h *Handler) entry(r slog.Record) LogEntry {
	t := r.Time
	if t.IsZero() {
		t = time.Now()
	}
	e := LogEntry{Time: t.UTC(), Level: strings.ToLower(r.Level.String()), LevelNum: int(r.Level), Msg: r.Message}
	for _, a := range h.attrs {
		e.set(a.Key, a.Value)
	}
	r.Attrs(func(a slog.Attr) bool {
		e.set(h.prefix+a.Key, a.Value)
		return true
	})
	return e
}

func (e *LogEntry) set(key string, v slog.Value) {
	v = v.Resolve()
	if v.Kind() == slog.KindGroup {
		for _, a := range v.Group() {
			e.set(key+"."+a.Key, a.Value)
		}
		return
	}
	switch key {
	case "runId":
		e.RunID = v.String()
	case "graphId":
		e.GraphID = v.String()
	case "subject":
		e.Subject = v.String()
	case "from":
		e.From = v.String()
	case "err", "error":
		e.Error = v.String()
	default:
		if e.Attrs == nil {
			e.Attrs = map[string]any{}
		}
		// Mongo field names may not contain dots.
		e.Attrs[strings.ReplaceAll(key, ".", "_")] = plain(v)
	}
}

func plain(v slog.Value) any {
	switch v.Kind() {
	case slog.KindString:
		return v.String()
	case slog.KindInt64:
		return v.Int64()
	case slog.KindUint64:
		return int64(v.Uint64())
	case slog.KindFloat64:
		return v.Float64()
	case slog.KindBool:
		return v.Bool()
	case slog.KindTime:
		return v.Time().UTC()
	default: // durations, errors, structs
		return v.String()
	}
}

// ParseLevel maps "debug" / "info" / "warn" / "error" to a slog level.
func ParseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
