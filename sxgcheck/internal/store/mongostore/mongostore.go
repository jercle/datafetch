// Package mongostore writes the checker's data to MongoDB. It is the only
// package that imports the driver.
//
// Collections (the README has the fields):
//
//	sxg_firewalls  one document per firewall: its current state
//	sxg_results    one per firewall per pass: the history
//	sxg_events     one per change of health
//	sxg_runs, sxg_logs, sxg_instances   the checker's own monitoring
package mongostore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/jercle/datafetch/sxgcheck/internal/model"
)

type Store struct {
	client *mongo.Client
	db     *mongo.Database
}

// Open creates the client. The driver connects lazily, so this succeeds
// while MongoDB is unreachable and operations start working when it returns.
func Open(uri, database, appName string) (*Store, error) {
	if uri == "" {
		return nil, errors.New("mongo.uri is not set (or set SXGCHECK_MONGO_URI)")
	}
	opts := options.Client().ApplyURI(uri).
		SetAppName(appName).
		SetServerSelectionTimeout(10 * time.Second).
		SetConnectTimeout(10 * time.Second)
	client, err := mongo.Connect(opts)
	if err != nil {
		return nil, err
	}
	return &Store{client: client, db: client.Database(database)}, nil
}

func (s *Store) Ping(ctx context.Context) error { return s.client.Ping(ctx, nil) }

func (s *Store) Close(ctx context.Context) error { return s.client.Disconnect(ctx) }

func (s *Store) coll(name string) *mongo.Collection { return s.db.Collection(name) }

func (s *Store) LoadFirewalls(ctx context.Context, instance string) ([]model.Firewall, error) {
	cur, err := s.coll(model.CollFirewalls).Find(ctx, bson.D{{Key: "instance", Value: instance}})
	if err != nil {
		return nil, err
	}
	var out []model.Firewall
	if err := cur.All(ctx, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) SaveFirewall(ctx context.Context, f *model.Firewall) error {
	_, err := s.coll(model.CollFirewalls).ReplaceOne(ctx, bson.D{{Key: "_id", Value: f.ID}}, f, options.Replace().SetUpsert(true))
	return err
}

func (s *Store) SaveResult(ctx context.Context, r *model.Result) error {
	_, err := s.coll(model.CollResults).InsertOne(ctx, r)
	return err
}

func (s *Store) SaveEvents(ctx context.Context, events []model.Event) error {
	if len(events) == 0 {
		return nil
	}
	_, err := s.coll(model.CollEvents).InsertMany(ctx, events, options.InsertMany().SetOrdered(false))
	return err
}

func (s *Store) PruneFirewalls(ctx context.Context, instance string, keep []string) error {
	_, err := s.coll(model.CollFirewalls).DeleteMany(ctx, bson.D{
		{Key: "instance", Value: instance},
		{Key: "_id", Value: bson.D{{Key: "$nin", Value: keep}}},
	})
	return err
}

func (s *Store) WriteLogs(ctx context.Context, entries []model.LogEntry) error {
	if len(entries) == 0 {
		return nil
	}
	_, err := s.coll(model.CollLogs).InsertMany(ctx, entries, options.InsertMany().SetOrdered(false))
	return err
}

func (s *Store) SaveRun(ctx context.Context, r *model.Run) error {
	_, err := s.coll(model.CollRuns).ReplaceOne(ctx, bson.D{{Key: "_id", Value: r.ID}}, r, options.Replace().SetUpsert(true))
	return err
}

func (s *Store) Heartbeat(ctx context.Context, i *model.Instance) error {
	_, err := s.coll(model.CollInstances).ReplaceOne(ctx, bson.D{{Key: "_id", Value: i.ID}}, i, options.Replace().SetUpsert(true))
	return err
}

// Retention is how long documents are kept, in days. Zero or less keeps
// them for ever.
type Retention struct {
	LogsDays, RunsDays, ResultsDays, EventsDays int
}

type index struct {
	coll string
	name string
	keys bson.D
	ttl  int // days; 0 = not a TTL index
}

func indexes(r Retention) []index {
	keys := func(spec ...any) bson.D { // name, direction, name, direction...
		d := bson.D{}
		for i := 0; i+1 < len(spec); i += 2 {
			d = append(d, bson.E{Key: spec[i].(string), Value: spec[i+1]})
		}
		return d
	}
	return []index{
		{model.CollFirewalls, "severity", keys("severity", -1, "name", 1), 0},
		{model.CollFirewalls, "tenant", keys("tenantName", 1, "severity", -1), 0},
		{model.CollFirewalls, "instance", keys("instance", 1), 0},
		{model.CollResults, "firewall", keys("firewall", 1, "at", -1), 0},
		{model.CollResults, "ttl", keys("at", 1), r.ResultsDays},
		{model.CollEvents, "time", keys("at", -1, "_id", -1), 0},
		{model.CollEvents, "firewall", keys("firewall", 1, "at", -1), 0},
		{model.CollEvents, "ttl", keys("at", 1), r.EventsDays},
		{model.CollRuns, "started", keys("startedAt", -1), 0},
		{model.CollRuns, "status", keys("status", 1, "startedAt", -1), 0},
		{model.CollRuns, "ttl", keys("finishedAt", 1), r.RunsDays},
		{model.CollLogs, "time", keys("time", -1, "_id", -1), 0},
		{model.CollLogs, "run", keys("runId", 1), 0},
		{model.CollLogs, "severity", keys("severity", 1, "time", -1), 0},
		{model.CollLogs, "firewall", keys("firewall", 1, "time", -1), 0},
		{model.CollLogs, "ttl", keys("time", 1), r.LogsDays},
		{model.CollInstances, "heartbeat", keys("heartbeatAt", 1), 0},
	}
}

// EnsureIndexes creates the indexes, and applies changed retention periods to
// TTL indexes that already exist.
func (s *Store) EnsureIndexes(ctx context.Context, r Retention) error {
	var errs []error
	for _, ix := range indexes(r) {
		if ix.name == "ttl" && ix.ttl <= 0 {
			continue
		}
		opts := options.Index().SetName(ix.name)
		seconds := int32(ix.ttl * 86400)
		if ix.name == "ttl" {
			opts.SetExpireAfterSeconds(seconds)
		}
		_, err := s.coll(ix.coll).Indexes().CreateOne(ctx, mongo.IndexModel{Keys: ix.keys, Options: opts})
		if err != nil && ix.name == "ttl" {
			// The index exists with another period: change it in place.
			err = s.db.RunCommand(ctx, bson.D{
				{Key: "collMod", Value: ix.coll},
				{Key: "index", Value: bson.D{
					{Key: "name", Value: ix.name},
					{Key: "expireAfterSeconds", Value: seconds},
				}},
			}).Err()
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s.%s: %w", ix.coll, ix.name, err))
		}
	}
	return errors.Join(errs...)
}
