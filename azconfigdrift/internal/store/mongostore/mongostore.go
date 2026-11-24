// Package mongostore keeps the collector's data in MongoDB. It is the only
// package that imports the driver.
//
// Collections (the README has the fields):
//
//	acd_modules         one per module: catalogue, and the switches the last pass used
//	acd_tenants         one per tenant: how current each module and source is
//	acd_items           one per configuration object: its current settings
//	acd_changes         one per object added, changed or removed between passes
//	acd_baselines, acd_baseline_items   written by the dashboard, read here
//	acd_control         requests from the dashboard
//	acd_runs, acd_logs, acd_instances   the collector's own monitoring
package mongostore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/jercle/datafetch/azconfigdrift/internal/model"
)

type Store struct {
	client *mongo.Client
	db     *mongo.Database
}

// Open creates the client. The driver connects lazily, so this succeeds
// while MongoDB is unreachable and operations start working when it returns.
func Open(uri, database, appName string) (*Store, error) {
	if uri == "" {
		return nil, errors.New("mongo.uri is not set (or set AZCONFIGDRIFT_MONGO_URI)")
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

// chunk is how many ids go into one $in.
const chunk = 5000

func eachChunk(ids []string, fn func([]string) error) error {
	for len(ids) > 0 {
		n := min(chunk, len(ids))
		if err := fn(ids[:n]); err != nil {
			return err
		}
		ids = ids[n:]
	}
	return nil
}

func (s *Store) SyncModules(ctx context.Context, mods []model.Module, states map[string]model.ModuleState) error {
	for _, m := range mods {
		st := states[m.ID]
		// Never null: the dashboard reads these as a list and two maps.
		off := bson.A{}
		for _, id := range st.DisabledSources {
			off = append(off, id)
		}
		flags := func(in map[string]bool) bson.M {
			out := bson.M{}
			for k, v := range in {
				out[k] = v
			}
			return out
		}
		_, err := s.coll(model.CollModules).UpdateOne(ctx, bson.D{{Key: "_id", Value: m.ID}}, bson.D{
			{Key: "$set", Value: bson.D{
				{Key: "platform", Value: m.Platform}, {Key: "name", Value: m.Name}, {Key: "description", Value: m.Description},
				{Key: "order", Value: m.Order}, {Key: "defaultEnabled", Value: m.DefaultEnabled}, {Key: "sources", Value: m.Sources},
				{Key: "version", Value: m.Version}, {Key: "updatedAt", Value: m.UpdatedAt},
				// The switches as this pass uses them.
				{Key: "enabled", Value: st.Enabled}, {Key: "disabledSources", Value: off},
				{Key: "sourceBeta", Value: flags(st.SourceBeta)}, {Key: "sourceDelegated", Value: flags(st.SourceDelegated)},
			}},
		}, options.UpdateOne().SetUpsert(true))
		if err != nil {
			return fmt.Errorf("module %s: %w", m.ID, err)
		}
	}
	return nil
}

func (s *Store) AcquireTenant(ctx context.Context, tenantID, owner string, ttl time.Duration, doneSince time.Time) (bool, error) {
	now := time.Now().UTC()
	// Free (never held, released or expired) or already ours, and not just
	// finished by someone else. When the document exists and does not
	// match, the upsert collides with it: that is "held".
	filter := bson.D{{Key: "_id", Value: tenantID},
		{Key: "$and", Value: bson.A{
			bson.D{{Key: "$or", Value: bson.A{
				bson.D{{Key: "owner", Value: owner}}, bson.D{{Key: "owner", Value: ""}}, bson.D{{Key: "expiresAt", Value: bson.D{{Key: "$lt", Value: now}}}},
			}}},
			bson.D{{Key: "$or", Value: bson.A{
				bson.D{{Key: "doneBy", Value: owner}}, bson.D{{Key: "doneAt", Value: nil}}, bson.D{{Key: "doneAt", Value: bson.D{{Key: "$lt", Value: doneSince.UTC()}}}},
			}}},
		}},
	}
	_, err := s.coll(model.CollLeases).UpdateOne(ctx, filter, bson.D{{Key: "$set", Value: bson.D{
		{Key: "owner", Value: owner}, {Key: "expiresAt", Value: now.Add(ttl)}, {Key: "acquiredAt", Value: now},
	}}}, options.UpdateOne().SetUpsert(true))
	if mongo.IsDuplicateKeyError(err) {
		return false, nil
	}
	return err == nil, err
}

func (s *Store) RenewTenant(ctx context.Context, tenantID, owner string, ttl time.Duration) error {
	_, err := s.coll(model.CollLeases).UpdateOne(ctx, bson.D{{Key: "_id", Value: tenantID}, {Key: "owner", Value: owner}},
		bson.D{{Key: "$set", Value: bson.D{{Key: "expiresAt", Value: time.Now().UTC().Add(ttl)}}}})
	return err
}

func (s *Store) ReleaseTenant(ctx context.Context, tenantID, owner string, done bool) error {
	set := bson.D{{Key: "owner", Value: ""}, {Key: "expiresAt", Value: time.Unix(0, 0).UTC()}}
	if done {
		set = append(set, bson.E{Key: "doneAt", Value: time.Now().UTC()}, bson.E{Key: "doneBy", Value: owner})
	}
	_, err := s.coll(model.CollLeases).UpdateOne(ctx, bson.D{{Key: "_id", Value: tenantID}, {Key: "owner", Value: owner}}, bson.D{{Key: "$set", Value: set}})
	return err
}

func (s *Store) RecordHistory(ctx context.Context, baselineID string, changes []model.Change) error {
	for _, h := range model.HistoryOf(baselineID, changes) {
		_, err := s.coll(model.CollHistory).UpdateOne(ctx, bson.D{{Key: "_id", Value: h.ID}}, bson.D{
			// Who and what it is, and when it first changed, are kept from
			// the first time; each later change is added to the list.
			{Key: "$setOnInsert", Value: bson.D{
				{Key: "baselineId", Value: h.BaselineID}, {Key: "itemId", Value: h.ItemID}, {Key: "tenantId", Value: h.TenantID}, {Key: "tenantName", Value: h.TenantName},
				{Key: "platform", Value: h.Platform}, {Key: "module", Value: h.Module}, {Key: "source", Value: h.Source}, {Key: "type", Value: h.Type},
				{Key: "path", Value: h.Path}, {Key: "firstAt", Value: h.FirstAt},
			}},
			{Key: "$set", Value: bson.D{{Key: "name", Value: h.Name}, {Key: "lastAt", Value: h.LastAt}}},
			{Key: "$push", Value: bson.D{{Key: "changes", Value: h.Changes[0]}}},
		}, options.UpdateOne().SetUpsert(true))
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) SaveSnapshot(ctx context.Context, snap model.Snapshot) error {
	_, err := s.coll(model.CollSnapshots).ReplaceOne(ctx, bson.D{{Key: "_id", Value: snap.ID}}, snap, options.Replace().SetUpsert(true))
	return err
}

func (s *Store) ModuleSwitches(ctx context.Context) ([]model.ModuleSwitches, error) {
	cur, err := s.coll(model.CollModuleSettings).Find(ctx, bson.D{})
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)
	var out []model.ModuleSwitches
	for cur.Next(ctx) {
		var m model.ModuleSwitches
		if err := cur.Decode(&m); err != nil {
			// One document that is not what it should be must not stop
			// collection: its module falls back to the configuration.
			continue
		}
		out = append(out, m)
	}
	return out, cur.Err()
}

func (s *Store) ActiveBaseline(ctx context.Context) (*model.Baseline, error) {
	var b model.Baseline
	err := s.coll(model.CollBaselines).FindOne(ctx, bson.D{{Key: "status", Value: "ready"}},
		options.FindOne().SetSort(bson.D{{Key: "createdAt", Value: -1}}).SetProjection(bson.D{{Key: "covered", Value: 1}})).Decode(&b)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &b, nil
}

func (s *Store) BaselineHashes(ctx context.Context, baselineID, tenantID, module, source string) (map[string]string, error) {
	cur, err := s.coll(model.CollBaselineItems).Find(ctx, bson.D{
		{Key: "baselineId", Value: baselineID}, {Key: "tenantId", Value: tenantID}, {Key: "module", Value: module}, {Key: "source", Value: source},
	}, options.Find().SetProjection(bson.D{{Key: "_id", Value: 0}, {Key: "itemId", Value: 1}, {Key: "hash", Value: 1}}))
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)
	out := map[string]string{}
	for cur.Next(ctx) {
		var d struct {
			ItemID string `bson:"itemId"`
			Hash   string `bson:"hash"`
		}
		if err := cur.Decode(&d); err != nil {
			return nil, err
		}
		out[d.ItemID] = d.Hash
	}
	return out, cur.Err()
}

func (s *Store) RunRequested(ctx context.Context) (time.Time, error) {
	var d struct {
		At time.Time `bson:"runRequestedAt"`
	}
	err := s.coll(model.CollControl).FindOne(ctx, bson.D{{Key: "_id", Value: "control"}}).Decode(&d)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return time.Time{}, nil
	}
	return d.At, err
}

func (s *Store) ItemIndex(ctx context.Context, tenantID, module, source string) (map[string]model.ItemRef, error) {
	cur, err := s.coll(model.CollItems).Find(ctx, bson.D{{Key: "tenantId", Value: tenantID}, {Key: "module", Value: module}, {Key: "source", Value: source}},
		options.Find().SetProjection(bson.D{{Key: "hash", Value: 1}, {Key: "present", Value: 1}, {Key: "drift", Value: 1}, {Key: "type", Value: 1}, {Key: "key", Value: 1}, {Key: "name", Value: 1}, {Key: "refsHash", Value: 1}, {Key: "resourceGroup", Value: 1}}))
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)
	out := map[string]model.ItemRef{}
	for cur.Next(ctx) {
		var r model.ItemRef
		if err := cur.Decode(&r); err != nil {
			return nil, err
		}
		out[r.ID] = r
	}
	return out, cur.Err()
}

func (s *Store) ItemConfig(ctx context.Context, id string) (string, error) {
	var d struct {
		Config string `bson:"config"`
	}
	err := s.coll(model.CollItems).FindOne(ctx, bson.D{{Key: "_id", Value: id}}, options.FindOne().SetProjection(bson.D{{Key: "config", Value: 1}})).Decode(&d)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return "", nil
	}
	return d.Config, err
}

// saveBatch bounds one bulk write; items can be megabytes each.
const saveBatch = 200

func (s *Store) SaveItems(ctx context.Context, items []model.Item) error {
	for len(items) > 0 {
		n := min(saveBatch, len(items))
		models := make([]mongo.WriteModel, 0, n)
		for i := range items[:n] {
			// Through a document, so firstSeenAt can be kept for an item
			// that exists and removedAt cleared for one that is back.
			raw, err := bson.Marshal(&items[i])
			if err != nil {
				return err
			}
			var set bson.M
			if err := bson.Unmarshal(raw, &set); err != nil {
				return err
			}
			delete(set, "_id")
			delete(set, "firstSeenAt")
			delete(set, "removedAt")
			if items[i].ChangedAt.IsZero() {
				delete(set, "changedAt")
			}
			// Names that no longer apply must go, not linger.
			if len(items[i].Refs) == 0 {
				set["refs"], set["refsHash"] = bson.M{}, ""
			}
			models = append(models, mongo.NewUpdateOneModel().
				SetFilter(bson.D{{Key: "_id", Value: items[i].ID}}).
				SetUpdate(bson.D{
					{Key: "$set", Value: set},
					{Key: "$setOnInsert", Value: bson.D{{Key: "firstSeenAt", Value: items[i].FirstSeenAt}}},
					{Key: "$unset", Value: bson.D{{Key: "removedAt", Value: ""}}},
				}).SetUpsert(true))
		}
		if _, err := s.coll(model.CollItems).BulkWrite(ctx, models, options.BulkWrite().SetOrdered(false)); err != nil {
			return err
		}
		items = items[n:]
	}
	return nil
}

func (s *Store) TouchItems(ctx context.Context, ids []string, at time.Time, runID string, drift model.Drift) error {
	return eachChunk(ids, func(part []string) error {
		_, err := s.coll(model.CollItems).UpdateMany(ctx, bson.D{{Key: "_id", Value: bson.D{{Key: "$in", Value: part}}}},
			bson.D{{Key: "$set", Value: bson.D{{Key: "lastSeenAt", Value: at}, {Key: "runId", Value: runID}, {Key: "drift", Value: drift}}}})
		return err
	})
}

func (s *Store) TombstoneItems(ctx context.Context, ids []string, at time.Time, runID string, drift model.Drift) error {
	return eachChunk(ids, func(part []string) error {
		in := bson.D{{Key: "$in", Value: part}}
		// removedAt only for the ones that were still present.
		_, err := s.coll(model.CollItems).UpdateMany(ctx, bson.D{{Key: "_id", Value: in}, {Key: "present", Value: true}},
			bson.D{{Key: "$set", Value: bson.D{{Key: "present", Value: false}, {Key: "removedAt", Value: at}}}})
		if err != nil {
			return err
		}
		_, err = s.coll(model.CollItems).UpdateMany(ctx, bson.D{{Key: "_id", Value: in}},
			bson.D{{Key: "$set", Value: bson.D{{Key: "runId", Value: runID}, {Key: "drift", Value: drift}}}})
		return err
	})
}

func (s *Store) DropOtherSources(ctx context.Context, tenantID string, keep map[string][]string) (int, error) {
	nor := bson.A{}
	for module, sources := range keep {
		nor = append(nor, bson.D{{Key: "module", Value: module}, {Key: "source", Value: bson.D{{Key: "$in", Value: sources}}}})
	}
	filter := bson.D{{Key: "tenantId", Value: tenantID}}
	if len(nor) > 0 {
		filter = append(filter, bson.E{Key: "$nor", Value: nor})
	}
	res, err := s.coll(model.CollItems).DeleteMany(ctx, filter)
	if err != nil {
		return 0, err
	}
	return int(res.DeletedCount), nil
}

func (s *Store) DeleteItems(ctx context.Context, ids []string) error {
	return eachChunk(ids, func(part []string) error {
		_, err := s.coll(model.CollItems).DeleteMany(ctx, bson.D{{Key: "_id", Value: bson.D{{Key: "$in", Value: part}}}})
		return err
	})
}

func (s *Store) SaveChanges(ctx context.Context, changes []model.Change) error {
	if len(changes) == 0 {
		return nil
	}
	_, err := s.coll(model.CollChanges).InsertMany(ctx, changes, options.InsertMany().SetOrdered(false))
	return err
}

func (s *Store) LoadTenant(ctx context.Context, id string) (*model.Tenant, error) {
	var t model.Tenant
	err := s.coll(model.CollTenants).FindOne(ctx, bson.D{{Key: "_id", Value: id}}).Decode(&t)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *Store) SaveTenant(ctx context.Context, t *model.Tenant) error {
	_, err := s.coll(model.CollTenants).ReplaceOne(ctx, bson.D{{Key: "_id", Value: t.ID}}, t, options.Replace().SetUpsert(true))
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
	LogsDays, RunsDays, ChangesDays int
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
		// The collector's lookups, and the dashboard's lists and counts.
		{model.CollItems, "source", keys("tenantId", 1, "module", 1, "source", 1), 0},
		{model.CollItems, "module", keys("module", 1, "type", 1, "sortName", 1), 0},
		{model.CollItems, "drift", keys("drift.status", 1, "module", 1), 0},
		{model.CollItems, "name", keys("sortName", 1, "_id", 1), 0},
		{model.CollItems, "changed", keys("changedAt", -1, "_id", 1), 0},
		// Covers the dashboard's counts, so they are taken from the index.
		{model.CollItems, "counts", keys("tenantId", 1, "module", 1, "drift.status", 1, "drift.baselineId", 1, "present", 1), 0},
		// Lets a search scan the index instead of the settings.
		{model.CollItems, "text", keys("text", 1), 0},
		{model.CollChanges, "time", keys("at", -1, "_id", -1), 0},
		{model.CollChanges, "item", keys("itemId", 1, "at", -1), 0},
		{model.CollChanges, "module", keys("module", 1, "at", -1), 0},
		{model.CollChanges, "ttl", keys("at", 1), r.ChangesDays},
		{model.CollHistory, "baseline", keys("baselineId", 1, "lastAt", -1), 0},
		{model.CollHistory, "item", keys("itemId", 1, "baselineId", 1), 0},
		{model.CollSnapshots, "time", keys("at", -1), 0},
		{model.CollBaselines, "created", keys("status", 1, "createdAt", -1), 0},
		{model.CollBaselineItems, "source", keys("baselineId", 1, "tenantId", 1, "module", 1, "source", 1), 0},
		{model.CollBaselineItems, "item", keys("baselineId", 1, "itemId", 1), 0},
		{model.CollRuns, "started", keys("startedAt", -1), 0},
		{model.CollRuns, "status", keys("status", 1, "startedAt", -1), 0},
		{model.CollRuns, "ttl", keys("finishedAt", 1), r.RunsDays},
		{model.CollLogs, "time", keys("time", -1, "_id", -1), 0},
		{model.CollLogs, "run", keys("runId", 1), 0},
		{model.CollLogs, "severity", keys("severity", 1, "time", -1), 0},
		{model.CollLogs, "module", keys("module", 1, "time", -1), 0},
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
