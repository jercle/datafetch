// Package store persists VMs, runs and logs in MongoDB.
package store

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/jercle/datafetch/mdetracker/internal/collector"
	"github.com/jercle/datafetch/mdetracker/internal/config"
	"github.com/jercle/datafetch/mdetracker/internal/logging"
	"github.com/jercle/datafetch/mdetracker/internal/model"
)

type Store struct {
	vms, runs, logs *mongo.Collection
}

var _ collector.Store = (*Store)(nil)

func New(db *mongo.Database, c config.Mongo) *Store {
	return &Store{
		vms:  db.Collection(c.VMCollection),
		runs: db.Collection(c.RunCollection),
		logs: db.Collection(c.LogCollection),
	}
}

// EnsureIndexes creates the indexes the collector and dashboard rely on.
// It returns a non-fatal warning if the log TTL index already exists with
// different options.
func (s *Store) EnsureIndexes(ctx context.Context, logRetentionDays int) (warning error, err error) {
	idx := func(keys bson.D) mongo.IndexModel { return mongo.IndexModel{Keys: keys} }
	if _, err := s.vms.Indexes().CreateMany(ctx, []mongo.IndexModel{
		idx(bson.D{{Key: "active", Value: 1}, {Key: "name", Value: 1}}),
		idx(bson.D{{Key: "active", Value: 1}, {Key: "status", Value: 1}}),
		idx(bson.D{{Key: "currentOrgId", Value: 1}}),
		idx(bson.D{{Key: "currentTenantName", Value: 1}}),
		idx(bson.D{{Key: "subscriptionId", Value: 1}}),
		idx(bson.D{{Key: "lastRunId", Value: 1}}),
		idx(bson.D{{Key: "onboardings.orgId", Value: 1}}),
		idx(bson.D{{Key: "tenants.orgId", Value: 1}, {Key: "currentOrgId", Value: 1}}),
		idx(bson.D{{Key: "previousOrgId", Value: 1}}),
		idx(bson.D{{Key: "active", Value: 1}, {Key: "osPlatform", Value: 1}}),
	}); err != nil {
		return nil, fmt.Errorf("vm indexes: %w", err)
	}
	if _, err := s.runs.Indexes().CreateOne(ctx, idx(bson.D{{Key: "startedAt", Value: -1}})); err != nil {
		return nil, fmt.Errorf("run indexes: %w", err)
	}
	if _, err := s.logs.Indexes().CreateMany(ctx, []mongo.IndexModel{
		idx(bson.D{{Key: "runId", Value: 1}, {Key: "ts", Value: -1}}),
		idx(bson.D{{Key: "level", Value: 1}, {Key: "ts", Value: -1}}),
		idx(bson.D{{Key: "tenant", Value: 1}, {Key: "ts", Value: -1}}),
	}); err != nil {
		return nil, fmt.Errorf("log indexes: %w", err)
	}

	ts := mongo.IndexModel{Keys: bson.D{{Key: "ts", Value: 1}}, Options: options.Index().SetName("ts_1")}
	if logRetentionDays > 0 {
		ts.Options = options.Index().SetName("ts_1").SetExpireAfterSeconds(int32(logRetentionDays * 86400))
	}
	if _, err := s.logs.Indexes().CreateOne(ctx, ts); err != nil {
		return fmt.Errorf("log ts/TTL index not changed (drop index ts_1 to apply a new retention): %w", err), nil
	}
	return nil, nil
}

func (s *Store) Ping(ctx context.Context) error {
	return s.vms.Database().Client().Ping(ctx, nil)
}

// LogInserter returns the sink used by the slog Mongo handler.
func (s *Store) LogInserter() logging.Inserter { return logInserter{s.logs} }

type logInserter struct{ c *mongo.Collection }

func (l logInserter) InsertMany(ctx context.Context, docs []any) error {
	_, err := l.c.InsertMany(ctx, docs, options.InsertMany().SetOrdered(false))
	return err
}

func (s *Store) StartRun(ctx context.Context, r *model.Run) error {
	_, err := s.runs.InsertOne(ctx, r)
	return err
}

func (s *Store) FinishRun(ctx context.Context, r *model.Run) error {
	_, err := s.runs.ReplaceOne(ctx, bson.M{"_id": r.ID}, r)
	return err
}

// PreviousState loads every VM's current org and tenant history (including
// VMs no longer active, so a VM that reappears keeps its trail).
func (s *Store) PreviousState(ctx context.Context) (map[string]collector.Previous, error) {
	cur, err := s.vms.Find(ctx, bson.M{},
		options.Find().SetProjection(bson.M{"currentOrgId": 1, "currentTenantName": 1, "active": 1, "tenants": 1}))
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)
	out := map[string]collector.Previous{}
	for cur.Next(ctx) {
		var row struct {
			ID      string                `bson:"_id"`
			OrgID   string                `bson:"currentOrgId"`
			Tenant  string                `bson:"currentTenantName"`
			Active  bool                  `bson:"active"`
			Tenants []model.TenantContact `bson:"tenants"`
		}
		if err := cur.Decode(&row); err != nil {
			return nil, err
		}
		p := collector.Previous{Tenants: row.Tenants}
		if row.Active { // only active VMs count for org-change detection
			p.OrgID, p.Tenant = row.OrgID, row.Tenant
		}
		out[row.ID] = p
	}
	return out, cur.Err()
}

func (s *Store) UpsertVMs(ctx context.Context, vms []model.VM, changes map[string]model.OrgChange) error {
	const chunk = 500
	now := time.Now().UTC()
	for start := 0; start < len(vms); start += chunk {
		end := min(start+chunk, len(vms))
		models := make([]mongo.WriteModel, 0, end-start)
		for _, vm := range vms[start:end] {
			update := bson.M{
				"$set":         vm,
				"$setOnInsert": bson.M{"firstCollectedAt": now},
				"$unset":       bson.M{"deactivatedAt": ""},
			}
			if ch, ok := changes[vm.Key]; ok {
				update["$push"] = bson.M{"orgHistory": bson.M{"$each": []model.OrgChange{ch}, "$slice": -50}}
			}
			models = append(models, mongo.NewUpdateOneModel().
				SetFilter(bson.M{"_id": vm.Key}).SetUpdate(update).SetUpsert(true))
		}
		if _, err := s.vms.BulkWrite(ctx, models, options.BulkWrite().SetOrdered(false)); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) DeactivateMissing(ctx context.Context, runID string) (int64, error) {
	res, err := s.vms.UpdateMany(ctx,
		bson.M{"active": true, "lastRunId": bson.M{"$ne": runID}},
		bson.M{"$set": bson.M{"active": false, "deactivatedAt": time.Now().UTC()}})
	if err != nil {
		return 0, err
	}
	return res.ModifiedCount, nil
}
