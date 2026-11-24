// Package mongostore is the MongoDB implementation of collector.Store and
// monitor.Sink. It is the only package that imports the driver.
package mongostore

import (
	"context"
	"errors"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/jercle/datafetch/azurecves/pkg/collector"
	"github.com/jercle/datafetch/azurecves/pkg/config"
	"github.com/jercle/datafetch/azurecves/pkg/graph"
	"github.com/jercle/datafetch/azurecves/pkg/monitor"
)

const (
	CollNodes     = "graph_nodes"
	CollEdges     = "graph_edges"
	CollExposure  = "cve_exposure"
	CollSoftware  = "software_summary"
	CollGroups    = "device_groups"
	CollRuns      = "cve_collector_runs"
	CollLogs      = "cve_collector_logs"
	CollInstances = "cve_collector_instances"
	CollState     = "cve_collector_state"

	batchSize = 1000
)

type Store struct {
	client *mongo.Client
	db     *mongo.Database
	costs  *mongo.Collection
}

func New(ctx context.Context, cfg *config.Config) (*Store, error) {
	client, err := mongo.Connect(options.Client().ApplyURI(cfg.Mongo.URI).SetAppName("azure-cves-collector"))
	if err != nil {
		return nil, err
	}
	if err := client.Ping(ctx, nil); err != nil {
		_ = client.Disconnect(context.Background())
		return nil, err
	}
	return &Store{
		client: client,
		db:     client.Database(cfg.Mongo.Database),
		costs:  client.Database(cfg.Costs.Database).Collection(cfg.Costs.Collection),
	}, nil
}

func (s *Store) Close(ctx context.Context) error { return s.client.Disconnect(ctx) }

func keys(k ...string) bson.D {
	d := bson.D{}
	for _, f := range k {
		d = append(d, bson.E{Key: f, Value: 1})
	}
	return d
}

// EnsureIndexes creates the indexes the collector and dashboard rely on and
// (re)applies log and run retention.
func (s *Store) EnsureIndexes(ctx context.Context, m config.Monitoring) error {
	idx := func(k ...string) mongo.IndexModel { return mongo.IndexModel{Keys: keys(k...)} }
	sets := map[string][]mongo.IndexModel{
		CollNodes: {
			idx("kind", "tenantId", "subscriptionId", "resourceGroup"),
			idx("kind", "type"),
			idx("via", "source", "runId"),
			idx("q"),
			idx("tags.k", "tags.v"),
			{Keys: bson.D{{Key: "kind", Value: 1}, {Key: "vuln.total", Value: -1}}},
			idx("kind", "attrs.tags"),
			idx("kind", "group"),
		},
		CollEdges: {
			idx("from", "rel"),
			idx("to", "rel"),
			idx("via", "source", "runId"),
		},
		CollExposure: {
			idx("tenantId", "source", "runId"),
			idx("cveId"),
			{Keys: bson.D{{Key: "severityRank", Value: -1}, {Key: "devices", Value: -1}}},
		},
		CollSoftware: {idx("tenantId", "runId"), idx("node"), idx("q")},
		CollRuns:     {{Keys: bson.D{{Key: "startedAt", Value: -1}}}, idx("status", "startedAt")},
		CollLogs:     {{Keys: bson.D{{Key: "runId", Value: 1}, {Key: "time", Value: -1}}}, {Keys: bson.D{{Key: "levelNum", Value: 1}, {Key: "time", Value: -1}}}},
	}
	for coll, models := range sets {
		if _, err := s.db.Collection(coll).Indexes().CreateMany(ctx, models); err != nil {
			return err
		}
	}
	if err := s.ttl(ctx, CollLogs, "time", m.LogRetentionDays); err != nil {
		return err
	}
	return s.ttl(ctx, CollRuns, "finishedAt", m.RunRetentionDays)
}

// ttl creates a TTL index, or changes its expiry when it already exists
// with a different one.
func (s *Store) ttl(ctx context.Context, coll, field string, days int) error {
	secs := int32(days * 24 * 3600)
	_, err := s.db.Collection(coll).Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: keys(field), Options: options.Index().SetExpireAfterSeconds(secs).SetName("ttl_" + field)})
	if err == nil {
		return nil
	}
	return s.db.RunCommand(ctx, bson.D{
		{Key: "collMod", Value: coll},
		{Key: "index", Value: bson.D{{Key: "name", Value: "ttl_" + field}, {Key: "expireAfterSeconds", Value: secs}}},
	}).Err()
}

// setDoc marshals v and drops _id, so it can be used as a $set document.
func setDoc(v any) (bson.D, error) {
	raw, err := bson.Marshal(v)
	if err != nil {
		return nil, err
	}
	var d bson.D
	if err := bson.Unmarshal(raw, &d); err != nil {
		return nil, err
	}
	out := d[:0]
	for _, e := range d {
		if e.Key != "_id" {
			out = append(out, e)
		}
	}
	return out, nil
}

// upsert writes documents in unordered batches: each is a $set keyed by
// _id, so fields other stages own on the same document are left alone.
func upsert[T any](ctx context.Context, coll *mongo.Collection, docs []T, id func(*T) string) error {
	for start := 0; start < len(docs); start += batchSize {
		end := min(start+batchSize, len(docs))
		models := make([]mongo.WriteModel, 0, end-start)
		for i := start; i < end; i++ {
			set, err := setDoc(&docs[i])
			if err != nil {
				return err
			}
			models = append(models, mongo.NewUpdateOneModel().
				SetFilter(bson.D{{Key: "_id", Value: id(&docs[i])}}).
				SetUpdate(bson.D{{Key: "$set", Value: set}}).
				SetUpsert(true))
		}
		if _, err := coll.BulkWrite(ctx, models, options.BulkWrite().SetOrdered(false)); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) UpsertNodes(ctx context.Context, nodes []graph.Node) error {
	return upsert(ctx, s.db.Collection(CollNodes), nodes, func(n *graph.Node) string { return n.ID })
}

func (s *Store) UpsertEdges(ctx context.Context, edges []graph.Edge) error {
	return upsert(ctx, s.db.Collection(CollEdges), edges, func(e *graph.Edge) string { return e.ID })
}

func stale(via, source, runID string) bson.D {
	return bson.D{{Key: "via", Value: via}, {Key: "source", Value: source}, {Key: "runId", Value: bson.D{{Key: "$ne", Value: runID}}}}
}

func (s *Store) Sweep(ctx context.Context, via, source, runID string) (int64, error) {
	var total int64
	for _, coll := range []string{CollEdges, CollNodes} {
		res, err := s.db.Collection(coll).DeleteMany(ctx, stale(via, source, runID))
		if err != nil {
			return total, err
		}
		total += res.DeletedCount
	}
	return total, nil
}

func (s *Store) SetNodeField(ctx context.Context, via, field, runID string, values map[string]map[string]any) error {
	coll := s.db.Collection(CollNodes)
	models := make([]mongo.WriteModel, 0, batchSize)
	flush := func() error {
		if len(models) == 0 {
			return nil
		}
		_, err := coll.BulkWrite(ctx, models, options.BulkWrite().SetOrdered(false))
		models = models[:0]
		return err
	}
	for id, v := range values {
		models = append(models, mongo.NewUpdateOneModel().
			SetFilter(bson.D{{Key: "_id", Value: id}}).
			SetUpdate(bson.D{{Key: "$set", Value: bson.D{{Key: field, Value: v}}}}))
		if len(models) == batchSize {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	if err := flush(); err != nil {
		return err
	}
	old := bson.D{{Key: field + ".run", Value: bson.D{{Key: "$exists", Value: true}, {Key: "$ne", Value: runID}}}}
	if via != "" {
		old = append(old, bson.E{Key: "via", Value: via})
	}
	_, err := coll.UpdateMany(ctx, old, bson.D{{Key: "$unset", Value: bson.D{{Key: field, Value: ""}}}})
	return err
}

func (s *Store) replace(ctx context.Context, coll *mongo.Collection, via, source, runID string) error {
	filter := bson.D{{Key: "tenantId", Value: via}, {Key: "runId", Value: bson.D{{Key: "$ne", Value: runID}}}}
	if source != "" {
		filter = append(filter, bson.E{Key: "source", Value: source})
	}
	_, err := coll.DeleteMany(ctx, filter)
	return err
}

func (s *Store) ReplaceExposure(ctx context.Context, via, source, runID string, docs []collector.Exposure) error {
	coll := s.db.Collection(CollExposure)
	if err := upsert(ctx, coll, docs, func(d *collector.Exposure) string { return d.ID }); err != nil {
		return err
	}
	return s.replace(ctx, coll, via, source, runID)
}

func (s *Store) ReplaceSoftware(ctx context.Context, via, runID string, docs []collector.SoftwareSummary) error {
	coll := s.db.Collection(CollSoftware)
	if err := upsert(ctx, coll, docs, func(d *collector.SoftwareSummary) string { return d.ID }); err != nil {
		return err
	}
	return s.replace(ctx, coll, via, "", runID)
}

func (s *Store) SaveDeviceGroups(ctx context.Context, groups []collector.DeviceGroup) error {
	coll := s.db.Collection(CollGroups)
	if err := upsert(ctx, coll, groups, func(g *collector.DeviceGroup) string { return g.ID }); err != nil {
		return err
	}
	ids := bson.A{}
	for _, g := range groups {
		ids = append(ids, g.ID)
	}
	_, err := coll.DeleteMany(ctx, bson.D{{Key: "_id", Value: bson.D{{Key: "$nin", Value: ids}}}})
	return err
}

func (s *Store) CVEIDs(ctx context.Context) ([]string, error) {
	cur, err := s.db.Collection(CollNodes).Find(ctx, bson.D{{Key: "kind", Value: graph.KindCVE}},
		options.Find().SetProjection(bson.D{{Key: "_id", Value: 1}}))
	if err != nil {
		return nil, err
	}
	var docs []struct {
		ID string `bson:"_id"`
	}
	if err := cur.All(ctx, &docs); err != nil {
		return nil, err
	}
	ids := make([]string, len(docs))
	for i, d := range docs {
		ids[i] = d.ID
	}
	return ids, nil
}

func (s *Store) SetCVEDetails(ctx context.Context, details map[string]map[string]any) error {
	if len(details) == 0 {
		return nil
	}
	models := make([]mongo.WriteModel, 0, len(details))
	for id, d := range details {
		models = append(models, mongo.NewUpdateOneModel().
			SetFilter(bson.D{{Key: "_id", Value: id}}).
			SetUpdate(bson.D{{Key: "$set", Value: bson.D{{Key: "details", Value: d}}}}))
	}
	_, err := s.db.Collection(CollNodes).BulkWrite(ctx, models, options.BulkWrite().SetOrdered(false))
	return err
}

func (s *Store) PruneShared(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.Collection(CollNodes).DeleteMany(ctx, bson.D{
		{Key: "kind", Value: bson.D{{Key: "$in", Value: bson.A{graph.KindCVE, graph.KindSoftware}}}},
		{Key: "seenAt", Value: bson.D{{Key: "$lt", Value: before}}},
	})
	if err != nil {
		return 0, err
	}
	return res.DeletedCount, nil
}

// ResourceCosts sums azcost-collector's resource_costs (one document per
// resource per day) over the last 30 days and the month to date.
func (s *Store) ResourceCosts(ctx context.Context, costType string, since, monthStart time.Time) ([]collector.CostRow, error) {
	from := since
	if monthStart.Before(from) {
		from = monthStart
	}
	when := func(start time.Time, field string) bson.D {
		return bson.D{{Key: "$sum", Value: bson.D{{Key: "$cond", Value: bson.A{
			bson.D{{Key: "$gte", Value: bson.A{"$date", start}}}, field, 0}}}}}
	}
	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: bson.D{{Key: "costType", Value: costType}, {Key: "date", Value: bson.D{{Key: "$gte", Value: from}}}}}},
		{{Key: "$group", Value: bson.D{
			{Key: "_id", Value: bson.D{{Key: "t", Value: "$tenantId"}, {Key: "r", Value: "$resourceId"}, {Key: "c", Value: "$currency"}}},
			{Key: "last30", Value: when(since, "$cost")},
			{Key: "last30Usd", Value: when(since, "$costUsd")},
			{Key: "mtd", Value: when(monthStart, "$cost")},
			{Key: "mtdUsd", Value: when(monthStart, "$costUsd")},
		}}},
	}
	cur, err := s.costs.Aggregate(ctx, pipeline, options.Aggregate().SetAllowDiskUse(true))
	if err != nil {
		return nil, err
	}
	var docs []struct {
		ID struct {
			T string `bson:"t"`
			R string `bson:"r"`
			C string `bson:"c"`
		} `bson:"_id"`
		Last30    float64 `bson:"last30"`
		Last30USD float64 `bson:"last30Usd"`
		MTD       float64 `bson:"mtd"`
		MTDUSD    float64 `bson:"mtdUsd"`
	}
	if err := cur.All(ctx, &docs); err != nil {
		return nil, err
	}
	rows := make([]collector.CostRow, len(docs))
	for i, d := range docs {
		rows[i] = collector.CostRow{TenantID: strings.ToLower(d.ID.T), ResourceID: d.ID.R, Currency: d.ID.C,
			Last30: d.Last30, Last30USD: d.Last30USD, MTD: d.MTD, MTDUSD: d.MTDUSD}
	}
	return rows, nil
}

func (s *Store) save(ctx context.Context, coll, id string, doc any) error {
	set, err := setDoc(doc)
	if err != nil {
		return err
	}
	_, err = s.db.Collection(coll).UpdateOne(ctx, bson.D{{Key: "_id", Value: id}}, bson.D{{Key: "$set", Value: set}},
		options.UpdateOne().SetUpsert(true))
	return err
}

func (s *Store) SaveState(ctx context.Context, st *monitor.StageState) error {
	return s.save(ctx, CollState, st.ID, st)
}

func (s *Store) State(ctx context.Context, tenantID, stage string) (*monitor.StageState, error) {
	var st monitor.StageState
	err := s.db.Collection(CollState).FindOne(ctx, bson.D{{Key: "_id", Value: tenantID + "|" + stage}}).Decode(&st)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &st, nil
}

// ---- monitor.Sink ----

func (s *Store) SaveRun(ctx context.Context, r *monitor.Run) error {
	return s.save(ctx, CollRuns, r.ID, r)
}

func (s *Store) SaveInstance(ctx context.Context, i *monitor.Instance) error {
	return s.save(ctx, CollInstances, i.ID, i)
}

func (s *Store) InsertLogs(ctx context.Context, entries []monitor.LogEntry) error {
	docs := make([]any, len(entries))
	for i := range entries {
		docs[i] = entries[i]
	}
	_, err := s.db.Collection(CollLogs).InsertMany(ctx, docs, options.InsertMany().SetOrdered(false))
	return err
}
