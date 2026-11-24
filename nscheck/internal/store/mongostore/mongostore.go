// Package mongostore writes the checker's data to MongoDB. It is the only
// package that imports the driver.
//
// Collections (the README has the fields):
//
//	nsc_appliances    one document per NetScaler: health, checks, system, HA
//	nsc_vservers      one per virtual server (lb, cs, vpn, aaa, gslb)
//	nsc_services      one per service and service group
//	nsc_certificates  one per installed certificate
//	nsc_samples       one per appliance and pass: the history
//	nsc_events        one per change of state
//	nsc_runs, nsc_logs, nsc_instances   the checker's own monitoring
package mongostore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/jercle/datafetch/nscheck/internal/model"
	"github.com/jercle/datafetch/nscheck/internal/store"
)

const batchSize = 500

type Store struct {
	client *mongo.Client
	db     *mongo.Database
}

// Open creates the client. The driver connects lazily, so this succeeds
// while MongoDB is unreachable and operations start working when it returns.
func Open(uri, database, appName string) (*Store, error) {
	if uri == "" {
		return nil, errors.New("mongo.uri is not set (or set NSCHECK_MONGO_URI)")
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

var upsert = options.Replace().SetUpsert(true)

func byID(id string) bson.D { return bson.D{{Key: "_id", Value: id}} }

// objectState is the part of an object document LoadState reads.
type objectState struct {
	ID          string    `bson:"_id"`
	Kind        string    `bson:"kind"`
	Status      string    `bson:"status"`
	StatusSince time.Time `bson:"statusSince"`
	FirstSeenAt time.Time `bson:"firstSeenAt"`
	Hash        string    `bson:"hash"`
}

func (s *Store) LoadState(ctx context.Context, applianceID string) (*model.State, error) {
	st := &model.State{Objects: map[string]map[string]model.ObjectState{}}
	var a model.Appliance
	err := s.coll(model.CollAppliances).FindOne(ctx, byID(applianceID)).Decode(&a)
	switch {
	case err == nil:
		st.Appliance = &a
	case !errors.Is(err, mongo.ErrNoDocuments):
		return nil, fmt.Errorf("%s: %w", model.CollAppliances, err)
	}
	fields := options.Find().SetProjection(bson.D{
		{Key: "kind", Value: 1}, {Key: "status", Value: 1}, {Key: "statusSince", Value: 1}, {Key: "firstSeenAt", Value: 1}, {Key: "hash", Value: 1},
	})
	for _, coll := range []string{model.CollVservers, model.CollServices, model.CollCertificates} {
		cur, err := s.coll(coll).Find(ctx, bson.D{{Key: "applianceId", Value: applianceID}}, fields)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", coll, err)
		}
		var docs []objectState
		if err := cur.All(ctx, &docs); err != nil {
			return nil, fmt.Errorf("%s: %w", coll, err)
		}
		m := make(map[string]model.ObjectState, len(docs))
		for _, d := range docs {
			m[d.ID] = model.ObjectState{Kind: d.Kind, Status: d.Status, Since: d.StatusSince, FirstSeen: d.FirstSeenAt, Hash: d.Hash}
		}
		st.Objects[coll] = m
	}
	return st, nil
}

func (s *Store) SaveAppliance(ctx context.Context, a *model.Appliance, full bool) error {
	if full {
		_, err := s.coll(model.CollAppliances).ReplaceOne(ctx, byID(a.ID), a, upsert)
		return err
	}
	// The attempt failed: record that, and keep what the last good pass read.
	set := bson.D{
		{Key: "name", Value: a.Name},
		{Key: "tenantName", Value: a.TenantName},
		{Key: "address", Value: a.Address},
		{Key: "runId", Value: a.RunID},
		{Key: "status", Value: a.Status},
		{Key: "statusSince", Value: a.StatusSince},
		{Key: "summary", Value: a.Summary},
		{Key: "reachable", Value: a.Reachable},
		{Key: "error", Value: a.Error},
		{Key: "latencyMs", Value: a.LatencyMs},
		{Key: "checkedAt", Value: a.CheckedAt},
		{Key: "intervalSeconds", Value: a.IntervalSeconds},
		{Key: "checks", Value: a.Checks},
	}
	update := bson.D{
		{Key: "$set", Value: set},
		{Key: "$setOnInsert", Value: bson.D{{Key: "firstSeenAt", Value: a.FirstSeenAt}, {Key: "counts", Value: a.Counts}}},
	}
	_, err := s.coll(model.CollAppliances).UpdateOne(ctx, byID(a.ID), update, options.UpdateOne().SetUpsert(true))
	return err
}

func (s *Store) SaveObjects(ctx context.Context, collection string, docs []store.Doc) error {
	models := make([]mongo.WriteModel, len(docs))
	for i, d := range docs {
		models[i] = mongo.NewReplaceOneModel().SetFilter(byID(d.ID)).SetReplacement(d.Body).SetUpsert(true)
	}
	unordered := options.BulkWrite().SetOrdered(false)
	for len(models) > 0 {
		n := min(batchSize, len(models))
		if _, err := s.coll(collection).BulkWrite(ctx, models[:n], unordered); err != nil {
			return fmt.Errorf("%s: %w", collection, err)
		}
		models = models[n:]
	}
	return nil
}

func (s *Store) PruneObjects(ctx context.Context, collection, applianceID string, kinds, keep []string) error {
	if keep == nil {
		keep = []string{}
	}
	filter := bson.D{
		{Key: "applianceId", Value: applianceID},
		{Key: "kind", Value: bson.D{{Key: "$in", Value: kinds}}},
		{Key: "_id", Value: bson.D{{Key: "$nin", Value: keep}}},
	}
	if _, err := s.coll(collection).DeleteMany(ctx, filter); err != nil {
		return fmt.Errorf("%s: remove what is gone: %w", collection, err)
	}
	return nil
}

func (s *Store) SaveSample(ctx context.Context, sm *model.Sample) error {
	_, err := s.coll(model.CollSamples).InsertOne(ctx, sm)
	return err
}

func (s *Store) SaveEvents(ctx context.Context, events []model.Event) error {
	if len(events) == 0 {
		return nil
	}
	_, err := s.coll(model.CollEvents).InsertMany(ctx, events, options.InsertMany().SetOrdered(false))
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
	_, err := s.coll(model.CollRuns).ReplaceOne(ctx, byID(r.ID), r, upsert)
	return err
}

func (s *Store) Heartbeat(ctx context.Context, i *model.Instance) error {
	_, err := s.coll(model.CollInstances).ReplaceOne(ctx, byID(i.ID), i, upsert)
	return err
}

// Retention is how long history and monitoring documents are kept, in
// days. Zero or less keeps them for ever.
type Retention struct {
	LogsDays, RunsDays, SamplesDays, EventsDays int
}

type index struct {
	coll string
	name string
	keys bson.D
	ttl  int // days; 0 = not a TTL index
}

// keys builds an index key from name, direction pairs.
func keys(spec ...any) bson.D {
	d := bson.D{}
	for i := 0; i+1 < len(spec); i += 2 {
		d = append(d, bson.E{Key: spec[i].(string), Value: spec[i+1]})
	}
	return d
}

func indexes(r Retention) []index {
	var out []index
	for _, coll := range []string{model.CollVservers, model.CollServices, model.CollCertificates} {
		out = append(out,
			index{coll, "appliance", keys("applianceId", 1, "kind", 1), 0},
			index{coll, "status", keys("status", 1, "name", 1), 0},
			index{coll, "name", keys("name", 1, "_id", 1), 0},
			index{coll, "search", keys("search", 1), 0},
		)
	}
	return append(out,
		index{model.CollAppliances, "tenant", keys("tenantName", 1, "name", 1), 0},
		index{model.CollCertificates, "expiry", keys("notAfter", 1), 0},
		index{model.CollSamples, "appliance", keys("applianceId", 1, "time", -1), 0},
		index{model.CollSamples, "ttl", keys("time", 1), r.SamplesDays},
		index{model.CollEvents, "appliance", keys("applianceId", 1, "time", -1), 0},
		index{model.CollEvents, "time", keys("time", -1, "_id", -1), 0},
		index{model.CollEvents, "ttl", keys("time", 1), r.EventsDays},
		index{model.CollRuns, "started", keys("startedAt", -1), 0},
		index{model.CollRuns, "status", keys("status", 1, "startedAt", -1), 0},
		index{model.CollRuns, "ttl", keys("finishedAt", 1), r.RunsDays},
		index{model.CollLogs, "time", keys("time", -1, "_id", -1), 0},
		index{model.CollLogs, "run", keys("runId", 1), 0},
		index{model.CollLogs, "severity", keys("severity", 1, "time", -1), 0},
		index{model.CollLogs, "appliance", keys("appliance", 1, "time", -1), 0},
		index{model.CollLogs, "ttl", keys("time", 1), r.LogsDays},
		index{model.CollInstances, "heartbeat", keys("heartbeatAt", 1), 0},
	)
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
