// Package store persists failure reports and ingest records in MongoDB.
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jercle/datafetch/dmarcreporting/internal/model"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type Store struct {
	client     *mongo.Client
	reports    *mongo.Collection
	ingest     *mongo.Collection
	aggReports *mongo.Collection
	aggRecords *mongo.Collection
}

// Collections names the collections used (see config for env vars).
type Collections struct {
	Failures, Ingest, AggregateReports, AggregateRecords string
}

func Open(ctx context.Context, uri, db string, cols Collections) (*Store, error) {
	client, err := mongo.Connect(options.Client().ApplyURI(uri).SetAppName("dmarc-collector"))
	if err != nil {
		return nil, err
	}
	pctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := client.Ping(pctx, nil); err != nil {
		return nil, fmt.Errorf("mongo ping: %w", err)
	}
	d := client.Database(db)
	s := &Store{
		client:     client,
		reports:    d.Collection(cols.Failures),
		ingest:     d.Collection(cols.Ingest),
		aggReports: d.Collection(cols.AggregateReports),
		aggRecords: d.Collection(cols.AggregateRecords),
	}
	return s, s.ensureIndexes(ctx)
}

func (s *Store) Close(ctx context.Context) error { return s.client.Disconnect(ctx) }

// DB exposes the database for the monitor package.
func (s *Store) DB() *mongo.Database { return s.reports.Database() }

func (s *Store) ensureIndexes(ctx context.Context) error {
	idx := func(unique bool, keys ...string) mongo.IndexModel {
		d := bson.D{}
		for _, k := range keys {
			dir := 1
			if k[0] == '-' {
				k, dir = k[1:], -1
			}
			d = append(d, bson.E{Key: k, Value: dir})
		}
		m := mongo.IndexModel{Keys: d}
		if unique {
			m.Options = options.Index().SetUnique(true)
		}
		return m
	}
	// Indexes mirror the dashboard's $match/$group patterns.
	if _, err := s.reports.Indexes().CreateMany(ctx, []mongo.IndexModel{
		idx(true, "fingerprint"),
		idx(false, "-eventAt"),
		idx(false, "reportedDomain", "-eventAt"),
		idx(false, "reportedOrgDomain", "-eventAt"),
		idx(false, "source.ip", "-eventAt"),
		idx(false, "source.asn.number", "-eventAt"),
		idx(false, "source.geo.countryCode", "-eventAt"),
		idx(false, "reporter.orgDomain", "-eventAt"),
		idx(false, "original.fromDomain", "-eventAt"),
	}); err != nil {
		return fmt.Errorf("report indexes: %w", err)
	}
	if _, err := s.ingest.Indexes().CreateMany(ctx, []mongo.IndexModel{
		idx(false, "-processedAt"),
		idx(false, "internetMessageId"),
		idx(false, "runId"),
	}); err != nil {
		return fmt.Errorf("ingest indexes: %w", err)
	}
	if _, err := s.aggReports.Indexes().CreateMany(ctx, []mongo.IndexModel{
		idx(true, "reportKey"),
		idx(false, "-eventAt"),
		idx(false, "reportedDomain", "-eventAt"),
		idx(false, "reporter.orgDomain", "-eventAt"),
		idx(false, "contentHash"),
	}); err != nil {
		return fmt.Errorf("aggregate report indexes: %w", err)
	}
	if _, err := s.aggRecords.Indexes().CreateMany(ctx, []mongo.IndexModel{
		idx(true, "reportKey", "idx"),
		idx(false, "-eventAt"),
		idx(false, "reportedDomain", "-eventAt"),
		idx(false, "reportedOrgDomain", "-eventAt"),
		idx(false, "source.ip", "-eventAt"),
		idx(false, "source.asn.number", "-eventAt"),
		idx(false, "source.geo.countryCode", "-eventAt"),
		idx(false, "headerFrom", "-eventAt"),
		idx(false, "reporter.orgDomain", "-eventAt"),
	}); err != nil {
		return fmt.Errorf("aggregate record indexes: %w", err)
	}
	return nil
}

// AggregateExists reports whether a complete copy of this aggregate report is
// already stored - matched by reporter + report_id (ReportKey) or by identical
// XML content.
func (s *Store) AggregateExists(ctx context.Context, reportKey, contentHash string) (bool, error) {
	n, err := s.aggReports.CountDocuments(ctx, bson.M{"$or": bson.A{
		bson.M{"reportKey": reportKey},
		bson.M{"contentHash": contentHash},
	}}, options.Count().SetLimit(1))
	return n > 0, err
}

// InsertAggregate stores an aggregate report and its rows. Rows are upserted
// first and the report document last, so the report document only exists once
// every row is safely written - a crash mid-way is repaired by the next
// attempt instead of being mistaken for a duplicate. Returns true if new.
func (s *Store) InsertAggregate(ctx context.Context, rep *model.AggregateReport, recs []*model.AggregateRecord) (bool, error) {
	const chunk = 1000
	for i := 0; i < len(recs); i += chunk {
		var models []mongo.WriteModel
		for _, r := range recs[i:min(i+chunk, len(recs))] {
			models = append(models, mongo.NewUpdateOneModel().
				SetFilter(bson.M{"reportKey": r.ReportKey, "idx": r.Idx}).
				SetUpdate(bson.M{"$setOnInsert": r}).
				SetUpsert(true))
		}
		if _, err := s.aggRecords.BulkWrite(ctx, models, options.BulkWrite().SetOrdered(false)); err != nil &&
			!mongo.IsDuplicateKeyError(err) {
			return false, fmt.Errorf("aggregate records: %w", err)
		}
	}
	res, err := s.aggReports.UpdateOne(ctx,
		bson.M{"reportKey": rep.ReportKey},
		bson.M{"$setOnInsert": rep},
		options.UpdateOne().SetUpsert(true))
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return false, nil
		}
		return false, fmt.Errorf("aggregate report: %w", err)
	}
	return res.UpsertedCount > 0, nil
}

// UpsertReport inserts a report unless one with the same fingerprint exists.
// Returns true if it was new.
func (s *Store) UpsertReport(ctx context.Context, r *model.FailureReport) (bool, error) {
	res, err := s.reports.UpdateOne(ctx,
		bson.M{"fingerprint": r.Fingerprint},
		bson.M{"$setOnInsert": r},
		options.UpdateOne().SetUpsert(true))
	if err != nil {
		if mongo.IsDuplicateKeyError(err) { // concurrent upsert race
			return false, nil
		}
		return false, err
	}
	return res.UpsertedCount > 0, nil
}

func (s *Store) RecordIngest(ctx context.Context, rec *model.IngestRecord) error {
	_, err := s.ingest.InsertOne(ctx, rec)
	return err
}

// ClearUnparsed removes earlier "no report found" rows for a message that has
// now been parsed, so it stops being listed as needing attention.
func (s *Store) ClearUnparsed(ctx context.Context, internetMessageID string) error {
	if internetMessageID == "" {
		return nil
	}
	_, err := s.ingest.DeleteMany(ctx, bson.M{"internetMessageId": internetMessageID, "status": "no_reports"})
	return err
}

// PriorIngestStatus returns "ok" if a mailbox message was already processed
// successfully, or "" if not. Protects against reprocessing when a move fails
// after the write. Messages in which no report was found are not counted, so
// they are parsed again whenever they are seen (after a parser fix, say).
func (s *Store) PriorIngestStatus(ctx context.Context, internetMessageID string) (string, error) {
	if internetMessageID == "" {
		return "", nil
	}
	var rec model.IngestRecord
	err := s.ingest.FindOne(ctx, bson.M{
		"internetMessageId": internetMessageID,
		"status":            "ok",
	}).Decode(&rec)
	if err == mongo.ErrNoDocuments {
		return "", nil
	}
	return rec.Status, err
}
