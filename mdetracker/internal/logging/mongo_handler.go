// Package logging provides a slog handler that ships records to MongoDB
// asynchronously, plus a fan-out handler for writing to several handlers.
package logging

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jercle/datafetch/mdetracker/internal/model"
)

// Inserter is implemented by the Mongo store (wraps Collection.InsertMany).
type Inserter interface {
	InsertMany(ctx context.Context, docs []any) error
}

type Options struct {
	Level      slog.Leveler
	Service    string
	BufferSize int           // queued entries before dropping (default 10000)
	BatchSize  int           // entries per insert (default 200)
	FlushEvery time.Duration // default 1s
}

type sink struct {
	ins     Inserter
	ch      chan model.LogEntry
	done    chan struct{}
	mu      sync.RWMutex
	closed  bool
	dropped atomic.Int64
}

type frame struct {
	group string
	attrs []slog.Attr
}

// MongoHandler never blocks the caller: when the buffer is full entries are dropped
// and counted. Top-level runId, tenant and vm attributes are promoted to indexed fields.
type MongoHandler struct {
	s       *sink
	level   slog.Leveler
	service string
	frames  []frame
}

func NewMongoHandler(ins Inserter, o Options) *MongoHandler {
	if o.Level == nil {
		o.Level = slog.LevelInfo
	}
	if o.BufferSize <= 0 {
		o.BufferSize = 10000
	}
	if o.BatchSize <= 0 {
		o.BatchSize = 200
	}
	if o.FlushEvery <= 0 {
		o.FlushEvery = time.Second
	}
	s := &sink{ins: ins, ch: make(chan model.LogEntry, o.BufferSize), done: make(chan struct{})}
	go s.loop(o.BatchSize, o.FlushEvery)
	return &MongoHandler{s: s, level: o.Level, service: o.Service, frames: []frame{{}}}
}

func (h *MongoHandler) Enabled(_ context.Context, l slog.Level) bool { return l >= h.level.Level() }

func (h *MongoHandler) Handle(_ context.Context, r slog.Record) error {
	root := map[string]any{}
	cur := root
	for i, f := range h.frames {
		if i > 0 {
			sub := map[string]any{}
			cur[f.group] = sub
			cur = sub
		}
		for _, a := range f.attrs {
			addAttr(cur, a)
		}
	}
	r.Attrs(func(a slog.Attr) bool { addAttr(cur, a); return true })

	e := model.LogEntry{Time: r.Time.UTC(), Level: r.Level.String(), Msg: r.Message, Service: h.service}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	e.RunID = promote(root, "runId")
	e.Tenant = promote(root, "tenant")
	e.VM = promote(root, "vm")
	if len(root) > 0 {
		e.Attrs = root
	}

	h.s.mu.RLock()
	defer h.s.mu.RUnlock()
	if h.s.closed {
		return nil
	}
	select {
	case h.s.ch <- e:
	default:
		h.s.dropped.Add(1)
	}
	return nil
}

func (h *MongoHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	nh := h.clone()
	last := &nh.frames[len(nh.frames)-1]
	last.attrs = append(append([]slog.Attr{}, last.attrs...), attrs...)
	return nh
}

func (h *MongoHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	nh := h.clone()
	nh.frames = append(nh.frames, frame{group: name})
	return nh
}

func (h *MongoHandler) clone() *MongoHandler {
	nh := *h
	nh.frames = append([]frame{}, h.frames...)
	return &nh
}

// Close flushes queued entries. Call it once, on shutdown.
func (h *MongoHandler) Close(ctx context.Context) error {
	h.s.mu.Lock()
	if !h.s.closed {
		h.s.closed = true
		close(h.s.ch)
	}
	h.s.mu.Unlock()
	select {
	case <-h.s.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	if n := h.s.dropped.Load(); n > 0 {
		fmt.Fprintf(os.Stderr, "mongo log handler dropped %d entries (buffer full)\n", n)
	}
	return nil
}

func (s *sink) loop(batch int, every time.Duration) {
	defer close(s.done)
	t := time.NewTicker(every)
	defer t.Stop()
	buf := make([]any, 0, batch)
	flush := func() {
		if len(buf) == 0 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := s.ins.InsertMany(ctx, buf); err != nil {
			fmt.Fprintf(os.Stderr, "mongo log handler: insert %d entries: %v\n", len(buf), err)
		}
		cancel()
		buf = make([]any, 0, batch)
	}
	for {
		select {
		case e, ok := <-s.ch:
			if !ok {
				flush()
				return
			}
			buf = append(buf, e)
			if len(buf) >= batch {
				flush()
			}
		case <-t.C:
			flush()
		}
	}
}

func addAttr(m map[string]any, a slog.Attr) {
	a.Value = a.Value.Resolve()
	if a.Equal(slog.Attr{}) {
		return
	}
	if a.Value.Kind() == slog.KindGroup {
		attrs := a.Value.Group()
		if len(attrs) == 0 {
			return
		}
		target := m
		if a.Key != "" {
			sub, _ := m[a.Key].(map[string]any)
			if sub == nil {
				sub = map[string]any{}
				m[a.Key] = sub
			}
			target = sub
		}
		for _, ga := range attrs {
			addAttr(target, ga)
		}
		return
	}
	m[a.Key] = value(a.Value)
}

// value converts a slog value to something BSON can store. It must never
// panic: a log call should not be able to take the collector down.
func value(v slog.Value) (out any) {
	defer func() {
		if r := recover(); r != nil {
			out = fmt.Sprintf("!unloggable %T: %v", v.Any(), r)
		}
	}()
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
	case slog.KindDuration:
		return v.Duration().String()
	}
	// Typed nil pointers (e.g. a nil *time.Time) satisfy fmt.Stringer and error,
	// and calling their methods panics. Store them as null.
	if a := v.Any(); a == nil {
		return nil
	} else if rv := reflect.ValueOf(a); rv.Kind() == reflect.Pointer && rv.IsNil() {
		return nil
	}
	switch x := v.Any().(type) {
	case time.Time:
		return x.UTC()
	case *time.Time:
		return x.UTC()
	case error:
		return x.Error()
	case []string:
		return x
	case fmt.Stringer:
		return x.String()
	default:
		return fmt.Sprint(x)
	}
}

func promote(m map[string]any, key string) string {
	v, ok := m[key].(string)
	if ok {
		delete(m, key)
	}
	return v
}

// Multi fans a record out to several handlers.
type Multi []slog.Handler

func (m Multi) Enabled(ctx context.Context, l slog.Level) bool {
	for _, h := range m {
		if h.Enabled(ctx, l) {
			return true
		}
	}
	return false
}

func (m Multi) Handle(ctx context.Context, r slog.Record) error {
	var first error
	for _, h := range m {
		if h.Enabled(ctx, r.Level) {
			if err := h.Handle(ctx, r.Clone()); err != nil && first == nil {
				first = err
			}
		}
	}
	return first
}

func (m Multi) WithAttrs(attrs []slog.Attr) slog.Handler {
	out := make(Multi, len(m))
	for i, h := range m {
		out[i] = h.WithAttrs(attrs)
	}
	return out
}

func (m Multi) WithGroup(name string) slog.Handler {
	out := make(Multi, len(m))
	for i, h := range m {
		out[i] = h.WithGroup(name)
	}
	return out
}

// ParseLevel maps "debug" / "info" / "warn" / "error" to a slog level.
func ParseLevel(s string) slog.Level {
	var l slog.Level
	if err := l.UnmarshalText([]byte(s)); err != nil {
		return slog.LevelInfo
	}
	return l
}
