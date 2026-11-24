// Package monitor records what the collector does in MongoDB: one document
// per poll of the mailbox (dmarc_collector_runs), structured log entries
// (dmarc_collector_logs) and a heartbeat per running process
// (dmarc_collector_instances).
//
// Everything here is best-effort. If MongoDB is unreachable the collector
// keeps working and stdout still has every log line. A nil *Monitor, *Run or
// *Sink is valid and does nothing, so callers never need to check.
package monitor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

const (
	StatusRunning   = "running"
	StatusSuccess   = "success"
	StatusPartial   = "partial" // finished, but some messages could not be moved / flagged
	StatusFailed    = "failed"
	StatusCancelled = "cancelled"

	StateIdle    = "idle"
	StateRunning = "running"
	StateExited  = "exited"

	heartbeatEvery = 30 * time.Second
	writeTimeout   = 10 * time.Second
)

// Totals is what one poll did.
type Totals struct {
	Messages            int `bson:"messages"`
	FailureReports      int `bson:"failureReports"`
	FailureInserted     int `bson:"failureInserted"`
	FailureDuplicates   int `bson:"failureDuplicates"`
	Aggregates          int `bson:"aggregates"`
	AggregatesInserted  int `bson:"aggregatesInserted"`
	AggregatesDuplicate int `bson:"aggregatesDuplicate"`
	NoReports           int `bson:"noReports"`
	PostProcessFailed   int `bson:"postProcessFailed"`
}

// DeriveStatus maps a finished poll to a run status.
func DeriveStatus(t Totals, err error, cancelled bool) string {
	switch {
	case cancelled:
		return StatusCancelled
	case err != nil:
		return StatusFailed
	case t.PostProcessFailed > 0:
		return StatusPartial
	default:
		return StatusSuccess
	}
}

type Options struct {
	Instance     string // defaults to the hostname
	Version      string
	Mode         string // "schedule" | "once"
	Mailbox      string
	Folder       string
	PollInterval time.Duration

	RunsCollection      string
	LogsCollection      string
	InstancesCollection string
	LogRetentionDays    int
	RunRetentionDays    int
}

type Monitor struct {
	opt       Options
	db        *mongo.Database
	runs      *mongo.Collection
	logs      *mongo.Collection
	instances *mongo.Collection
	log       *slog.Logger // stdout only: never the Mongo sink, to avoid feedback loops

	mu   sync.Mutex
	cur  *Run
	stop chan struct{}
	done chan struct{}
}

// New prepares the collections (TTL indexes) and registers this instance.
func New(ctx context.Context, db *mongo.Database, opt Options, stdout *slog.Logger) (*Monitor, error) {
	m := &Monitor{
		opt: opt, db: db, log: stdout,
		runs:      db.Collection(opt.RunsCollection),
		logs:      db.Collection(opt.LogsCollection),
		instances: db.Collection(opt.InstancesCollection),
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
	}
	if err := m.ensureIndexes(ctx); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	_, err := m.instances.UpdateOne(ctx, bson.M{"_id": opt.Instance}, bson.M{"$set": bson.M{
		"host": opt.Instance, "version": opt.Version, "mode": opt.Mode, "state": StateIdle,
		"mailbox": opt.Mailbox, "folder": opt.Folder, "pollIntervalSec": int(opt.PollInterval.Seconds()),
		"startedAt": now, "heartbeatAt": now,
	}}, options.UpdateOne().SetUpsert(true))
	if err != nil {
		return nil, fmt.Errorf("register instance: %w", err)
	}
	go m.heartbeat()
	return m, nil
}

func (m *Monitor) ensureIndexes(ctx context.Context) error {
	day := int32(24 * 60 * 60)
	if err := m.ttl(ctx, m.logs, "time", "ttl_time", int32(m.opt.LogRetentionDays)*day); err != nil {
		return err
	}
	if err := m.ttl(ctx, m.runs, "startedAt", "ttl_startedAt", int32(m.opt.RunRetentionDays)*day); err != nil {
		return err
	}
	_, err := m.logs.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "runId", Value: 1}, {Key: "time", Value: 1}}},
		{Keys: bson.D{{Key: "levelNum", Value: 1}, {Key: "time", Value: -1}}},
	})
	if err != nil {
		return fmt.Errorf("log indexes: %w", err)
	}
	return nil
}

// ttl creates a TTL index, or updates the expiry of an existing one when the
// retention setting has changed.
func (m *Monitor) ttl(ctx context.Context, c *mongo.Collection, field, name string, seconds int32) error {
	_, err := c.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: field, Value: -1}},
		Options: options.Index().SetName(name).SetExpireAfterSeconds(seconds),
	})
	if err == nil {
		return nil
	}
	mod := bson.D{
		{Key: "collMod", Value: c.Name()},
		{Key: "index", Value: bson.D{{Key: "name", Value: name}, {Key: "expireAfterSeconds", Value: seconds}}},
	}
	if err2 := m.db.RunCommand(ctx, mod).Err(); err2 != nil {
		return fmt.Errorf("ttl index %s.%s: %w", c.Name(), name, errors.Join(err, err2))
	}
	return nil
}

func (m *Monitor) heartbeat() {
	defer close(m.done)
	t := time.NewTicker(heartbeatEvery)
	defer t.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-t.C:
			now := time.Now().UTC()
			m.setInstance(bson.M{"heartbeatAt": now})
			m.mu.Lock()
			cur := m.cur
			m.mu.Unlock()
			if cur != nil {
				m.setRun(cur.id, bson.M{"heartbeatAt": now})
			}
		}
	}
}

func (m *Monitor) setInstance(set bson.M) {
	ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
	defer cancel()
	if _, err := m.instances.UpdateByID(ctx, m.opt.Instance, bson.M{"$set": set}); err != nil {
		m.log.Warn("monitor: instance update failed", "err", err)
	}
}

func (m *Monitor) setRun(id bson.ObjectID, set bson.M) {
	ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
	defer cancel()
	if _, err := m.runs.UpdateByID(ctx, id, bson.M{"$set": set}); err != nil {
		m.log.Warn("monitor: run update failed", "err", err)
	}
}

// SetNext records when the next scheduled poll is due.
func (m *Monitor) SetNext(t time.Time) {
	if m == nil {
		return
	}
	m.setInstance(bson.M{"nextRunAt": t.UTC()})
}

// Close marks the instance as exited and stops the heartbeat.
func (m *Monitor) Close() {
	if m == nil {
		return
	}
	close(m.stop)
	<-m.done
	m.setInstance(bson.M{"state": StateExited, "heartbeatAt": time.Now().UTC(), "nextRunAt": nil})
}

// WriteLogs implements LogWriter.
func (m *Monitor) WriteLogs(ctx context.Context, entries []LogEntry) error {
	docs := make([]any, len(entries))
	for i := range entries {
		docs[i] = entries[i]
	}
	_, err := m.logs.InsertMany(ctx, docs)
	return err
}

// ---------------------------------------------------------------- runs

type Run struct {
	m       *Monitor
	id      bson.ObjectID
	started time.Time
}

// BeginRun records the start of a poll. trigger is "schedule" or "once".
func (m *Monitor) BeginRun(trigger string) *Run {
	if m == nil {
		return nil
	}
	now := time.Now().UTC()
	r := &Run{m: m, id: bson.NewObjectID(), started: now}
	ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
	defer cancel()
	if _, err := m.runs.InsertOne(ctx, bson.M{
		"_id": r.id, "instance": m.opt.Instance, "version": m.opt.Version, "trigger": trigger,
		"mailbox": m.opt.Mailbox, "status": StatusRunning,
		"startedAt": now, "heartbeatAt": now, "totals": Totals{},
	}); err != nil {
		m.log.Warn("monitor: run insert failed", "err", err)
	}
	m.mu.Lock()
	m.cur = r
	m.mu.Unlock()
	m.setInstance(bson.M{"state": StateRunning, "heartbeatAt": now, "lastRunId": r.ID()})
	return r
}

// ID is the run's id as a hex string ("" for a nil run).
func (r *Run) ID() string {
	if r == nil {
		return ""
	}
	return r.id.Hex()
}

// Progress stores totals so far (called between batches of a long poll).
func (r *Run) Progress(t Totals) {
	if r == nil {
		return
	}
	r.m.setRun(r.id, bson.M{"totals": t, "heartbeatAt": time.Now().UTC()})
}

// Finish records the outcome.
func (r *Run) Finish(t Totals, err error, cancelled bool) {
	if r == nil {
		return
	}
	now := time.Now().UTC()
	status := DeriveStatus(t, err, cancelled)
	set := bson.M{
		"status": status, "totals": t, "finishedAt": now, "heartbeatAt": now,
		"durationMs": now.Sub(r.started).Milliseconds(),
	}
	if err != nil {
		set["error"] = err.Error()
	}
	r.m.setRun(r.id, set)
	r.m.mu.Lock()
	r.m.cur = nil
	r.m.mu.Unlock()
	inst := bson.M{"state": StateIdle, "heartbeatAt": now, "lastRunStatus": status, "lastRunAt": now}
	if status == StatusSuccess || status == StatusPartial {
		inst["lastSuccessAt"] = now
	}
	r.m.setInstance(inst)
}
