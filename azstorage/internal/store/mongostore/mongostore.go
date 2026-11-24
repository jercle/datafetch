// Package mongostore writes the collector's data to MongoDB. It is the only
// package that imports the driver.
//
// Collections (the README has the fields):
//
//	azs_tenants        one document per tenant: status and totals
//	azs_subscriptions  one per subscription, with its totals
//	azs_accounts       one per storage account, with its used capacity
//	azs_containers     one per blob container, with its measured size
//	azs_disks          one per managed disk
//	azs_runs, azs_logs, azs_instances   the collector's own monitoring
package mongostore

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/jercle/datafetch/azstorage/internal/model"
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
		return nil, errors.New("mongo.uri is not set (or set AZSTORAGE_MONGO_URI)")
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

func (s *Store) bulk(ctx context.Context, coll string, models []mongo.WriteModel) error {
	unordered := options.BulkWrite().SetOrdered(false)
	for len(models) > 0 {
		n := min(batchSize, len(models))
		if _, err := s.coll(coll).BulkWrite(ctx, models[:n], unordered); err != nil {
			return fmt.Errorf("%s: %w", coll, err)
		}
		models = models[n:]
	}
	return nil
}

func replace(id string, doc any) mongo.WriteModel {
	return mongo.NewReplaceOneModel().SetFilter(bson.D{{Key: "_id", Value: id}}).SetReplacement(doc).SetUpsert(true)
}

// The fields a pass only writes when it measured them.
var (
	accountUsageFields     = []string{"usageAt", "usedBytes", "blobBytes", "fileBytes", "tableBytes", "queueBytes", "blobCount", "fileShares"}
	accountContainerFields = []string{"containers", "containersMeasured", "containerBytes", "sizeStatus"}
	containerSizeFields    = []string{"usedBytes", "currentBytes", "snapshotBytes", "versionBytes", "deletedBytes", "blobs", "objects", "tiers", "sizedAt"}
)

// upsert sets every field of doc except _id, firstSeenAt (only set when the
// document is created) and those named in keep, which are left as stored.
// Optional fields that are absent from doc are removed from the stored
// document, unless kept.
func upsert(id string, doc any, optional, keep []string) (mongo.WriteModel, error) {
	raw, err := bson.Marshal(doc)
	if err != nil {
		return nil, err
	}
	var all bson.D
	if err := bson.Unmarshal(raw, &all); err != nil {
		return nil, err
	}
	var set, first, unset bson.D
	present := map[string]bool{}
	for _, e := range all {
		present[e.Key] = true
		switch {
		case e.Key == "_id" || slices.Contains(keep, e.Key):
		case e.Key == "firstSeenAt":
			first = append(first, e)
		default:
			set = append(set, e)
		}
	}
	for _, k := range optional {
		if !present[k] && !slices.Contains(keep, k) {
			unset = append(unset, bson.E{Key: k, Value: ""})
		}
	}
	update := bson.D{{Key: "$set", Value: set}}
	if len(first) > 0 {
		update = append(update, bson.E{Key: "$setOnInsert", Value: first})
	}
	if len(unset) > 0 {
		update = append(update, bson.E{Key: "$unset", Value: unset})
	}
	return mongo.NewUpdateOneModel().SetFilter(bson.D{{Key: "_id", Value: id}}).SetUpdate(update).SetUpsert(true), nil
}

func (s *Store) SaveAccounts(ctx context.Context, docs []model.Account) error {
	models := make([]mongo.WriteModel, len(docs))
	for i := range docs {
		d := &docs[i]
		optional := []string{"usageError", "usageAt", "containersError", "sizeStatus", "tags", "accessTier"}
		var keep []string
		if d.UsageStatus != model.UsageKnown {
			keep = append(keep, accountUsageFields...)
		}
		if d.UsageStatus == "" { // not looked at yet in this pass
			keep = append(keep, "usageStatus", "usageError")
		}
		if d.ContainersStatus != model.StatusSuccess {
			keep = append(keep, accountContainerFields...)
		}
		if d.ContainersStatus == "" {
			keep = append(keep, "containersStatus", "containersError")
		}
		m, err := upsert(d.ID, d, optional, keep)
		if err != nil {
			return err
		}
		models[i] = m
	}
	return s.bulk(ctx, model.CollAccounts, models)
}

func (s *Store) SaveContainers(ctx context.Context, docs []model.Container) error {
	models := make([]mongo.WriteModel, len(docs))
	for i := range docs {
		d := &docs[i]
		var keep []string
		if !d.Sized() {
			keep = containerSizeFields
		}
		m, err := upsert(d.ID, d, []string{"sizeError", "tiers"}, keep)
		if err != nil {
			return err
		}
		models[i] = m
	}
	return s.bulk(ctx, model.CollContainers, models)
}

func (s *Store) SaveDisks(ctx context.Context, docs []model.Disk) error {
	models := make([]mongo.WriteModel, len(docs))
	for i := range docs {
		m, err := upsert(docs[i].ID, &docs[i], []string{"managedBy", "attachedTo", "tier", "tags", "zones", "ownershipChangedAt"}, nil)
		if err != nil {
			return err
		}
		models[i] = m
	}
	return s.bulk(ctx, model.CollDisks, models)
}

func staleFilter(sc model.Scope, runID string) bson.D {
	return bson.D{{Key: "tenantId", Value: sc.TenantID}, {Key: "runId", Value: bson.D{{Key: "$ne", Value: runID}}}}
}

func (s *Store) prune(ctx context.Context, coll string, filter bson.D) error {
	if _, err := s.coll(coll).DeleteMany(ctx, filter); err != nil {
		return fmt.Errorf("%s: remove what is gone: %w", coll, err)
	}
	return nil
}

func (s *Store) PruneAccounts(ctx context.Context, sc model.Scope, runID string) error {
	return s.prune(ctx, model.CollAccounts, staleFilter(sc, runID))
}

func (s *Store) PruneDisks(ctx context.Context, sc model.Scope, runID string) error {
	return s.prune(ctx, model.CollDisks, staleFilter(sc, runID))
}

func (s *Store) PruneContainers(ctx context.Context, sc model.Scope, runID string, keepAccounts []string) error {
	filter := staleFilter(sc, runID)
	if len(keepAccounts) > 0 {
		filter = append(filter, bson.E{Key: "accountId", Value: bson.D{{Key: "$nin", Value: keepAccounts}}})
	}
	return s.prune(ctx, model.CollContainers, filter)
}

func (s *Store) SaveSubscriptions(ctx context.Context, sc model.Scope, runID string, docs []model.Subscription, prune bool) error {
	models := make([]mongo.WriteModel, len(docs))
	for i := range docs {
		models[i] = replace(docs[i].ID, &docs[i])
	}
	if err := s.bulk(ctx, model.CollSubscriptions, models); err != nil {
		return err
	}
	if !prune {
		return nil
	}
	return s.prune(ctx, model.CollSubscriptions, staleFilter(sc, runID))
}

// SaveTenant sets the fields that are present: a failed pass has no
// lastSuccessAt, and so leaves the stored one alone.
func (s *Store) SaveTenant(ctx context.Context, t *model.Tenant) error {
	var keep []string
	if t.LastStatus == model.StatusFailed {
		// Keep the totals of the last pass that counted anything.
		keep = []string{"counts", "missing"}
	}
	m, err := upsert(t.ID, t, []string{"lastError"}, keep)
	if err != nil {
		return err
	}
	return s.bulk(ctx, model.CollTenants, []mongo.WriteModel{m})
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

// Retention is how long monitoring documents are kept, in days. Zero or less
// keeps them for ever.
type Retention struct {
	LogsDays, RunsDays int
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
	asc := func(names ...string) bson.D {
		d := bson.D{}
		for _, k := range names {
			d = append(d, bson.E{Key: k, Value: 1})
		}
		return d
	}
	var out []index
	// The lists the dashboard shows are sorted by size or by name, within a
	// tenant or a subscription.
	for coll, size := range map[string]string{model.CollAccounts: "usedBytes", model.CollContainers: "usedBytes", model.CollDisks: "sizeBytes"} {
		out = append(out,
			index{coll, "run", asc("tenantId", "runId"), 0},
			index{coll, "size", keys(size, -1, "_id", 1), 0},
			index{coll, "tenantSize", keys("tenantId", 1, size, -1), 0},
			index{coll, "subscriptionSize", keys("subscriptionId", 1, size, -1), 0},
			index{coll, "search", asc("search"), 0},
		)
	}
	return append(out,
		index{model.CollContainers, "account", keys("accountId", 1, "usedBytes", -1), 0},
		index{model.CollContainers, "sizeStatus", asc("sizeStatus", "tenantId"), 0},
		index{model.CollDisks, "attached", keys("attached", 1, "sizeBytes", -1), 0},
		index{model.CollSubscriptions, "tenant", asc("tenantId", "name"), 0},
		index{model.CollRuns, "started", keys("startedAt", -1), 0},
		index{model.CollRuns, "status", keys("status", 1, "startedAt", -1), 0},
		index{model.CollRuns, "ttl", asc("finishedAt"), r.RunsDays},
		index{model.CollLogs, "time", keys("time", -1, "_id", -1), 0},
		index{model.CollLogs, "run", asc("runId"), 0},
		index{model.CollLogs, "severity", keys("severity", 1, "time", -1), 0},
		index{model.CollLogs, "tenant", keys("tenantName", 1, "time", -1), 0},
		index{model.CollLogs, "ttl", asc("time"), r.LogsDays},
		index{model.CollInstances, "heartbeat", asc("heartbeatAt"), 0},
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
