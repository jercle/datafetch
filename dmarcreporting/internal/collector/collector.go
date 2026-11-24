// Package collector ties the mailbox, parser, enricher and store together.
package collector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jercle/datafetch/dmarcreporting/internal/config"
	"github.com/jercle/datafetch/dmarcreporting/internal/enrich"
	"github.com/jercle/datafetch/dmarcreporting/internal/graph"
	"github.com/jercle/datafetch/dmarcreporting/internal/model"
	"github.com/jercle/datafetch/dmarcreporting/internal/monitor"
	"github.com/jercle/datafetch/dmarcreporting/internal/parser"
	"github.com/jercle/datafetch/dmarcreporting/internal/store"
)

const (
	categoryOK     = "DMARC-Processed"
	categoryFailed = "DMARC-Failed"
	maxBatches     = 400 // per poll, so a huge backlog can't starve health checks forever
)

type Collector struct {
	cfg    *config.Config
	graph  *graph.Client
	parser *parser.Parser
	enrich *enrich.Enricher
	store  *store.Store
	log    *slog.Logger

	srcID, okID, failID string
	skip                map[string]time.Time // messages we could not move/mark; retry later

	mon  *monitor.Monitor // nil when monitoring is off
	sink *monitor.Sink
	run  *monitor.Run

	LastSuccess atomic.Int64 // unix seconds of last completed poll
	interval    atomic.Int64 // the poll interval in use, for Interval
}

type Stats struct {
	Messages, Reports, Inserted, Duplicates, NoReports, PostFailed int
	Aggregates, AggInserted, AggDuplicates                         int
}

func New(cfg *config.Config, g *graph.Client, p *parser.Parser, e *enrich.Enricher, s *store.Store, log *slog.Logger) *Collector {
	c := &Collector{cfg: cfg, graph: g, parser: p, enrich: e, store: s, log: log, skip: map[string]time.Time{}}
	c.interval.Store(int64(cfg.PollInterval))
	return c
}

// SetMonitor attaches run recording and the log sink (both may be nil).
func (c *Collector) SetMonitor(m *monitor.Monitor, s *monitor.Sink) { c.mon, c.sink = m, s }

func (st Stats) totals() monitor.Totals {
	return monitor.Totals{
		Messages: st.Messages, FailureReports: st.Reports, FailureInserted: st.Inserted,
		FailureDuplicates: st.Duplicates, Aggregates: st.Aggregates, AggregatesInserted: st.AggInserted,
		AggregatesDuplicate: st.AggDuplicates, NoReports: st.NoReports, PostProcessFailed: st.PostFailed,
	}
}

func (c *Collector) Init(ctx context.Context) error {
	var err error
	if c.srcID, err = c.graph.ResolveFolder(ctx, c.cfg.SourceFolder, false); err != nil {
		return fmt.Errorf("source folder: %w", err)
	}
	if c.cfg.PostProcess == "move" {
		if c.okID, err = c.graph.ResolveFolder(ctx, c.cfg.ProcessedFolder, true); err != nil {
			return fmt.Errorf("processed folder: %w", err)
		}
		if c.failID, err = c.graph.ResolveFolder(ctx, c.cfg.FailedFolder, true); err != nil {
			return fmt.Errorf("failed folder: %w", err)
		}
	}
	return nil
}

// Reconfigure takes a changed configuration between polls: the poll
// interval, the batch size, the folders and what is done with a message
// after it is read, and where unparsed messages are saved. p replaces the
// parser when it is not nil. When the folders cannot be resolved the
// configuration in use stays as it was.
func (c *Collector) Reconfigure(ctx context.Context, cfg *config.Config, p *parser.Parser) error {
	old, ids := c.cfg, [3]string{c.srcID, c.okID, c.failID}
	c.cfg = cfg
	if cfg.SourceFolder != old.SourceFolder || cfg.ProcessedFolder != old.ProcessedFolder || cfg.FailedFolder != old.FailedFolder || cfg.PostProcess != old.PostProcess {
		if err := c.Init(ctx); err != nil {
			c.cfg, c.srcID, c.okID, c.failID = old, ids[0], ids[1], ids[2]
			return err
		}
	}
	if p != nil {
		c.parser = p
	}
	return nil
}

// Interval is the time between polls of the configuration in use. It is
// safe to call while the collector runs.
func (c *Collector) Interval() time.Duration { return time.Duration(c.interval.Load()) }

// Run polls until ctx is cancelled. reload, when not nil, is called before
// every poll after the first, to take what changed in the configuration.
func (c *Collector) Run(ctx context.Context, reload func(context.Context)) {
	for first := true; ; first = false {
		if !first && reload != nil {
			reload(ctx)
		}
		c.interval.Store(int64(c.cfg.PollInterval))
		begun := time.Now()
		c.Poll(ctx, "schedule")
		next := begun.Add(c.cfg.PollInterval)
		if now := time.Now(); next.Before(now) {
			next = now
		}
		if ctx.Err() == nil {
			c.mon.SetNext(next)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Until(next)):
		}
	}
}

// Poll drains the mailbox once, recording the pass as a run.
func (c *Collector) Poll(ctx context.Context, trigger string) (Stats, error) {
	start := time.Now()
	c.run = c.mon.BeginRun(trigger)
	c.sink.SetRun(c.run.ID())
	defer c.sink.SetRun("")
	st, err := c.RunOnce(ctx)
	defer func() { c.run.Finish(st.totals(), err, ctx.Err() != nil) }()
	attrs := []any{"messages", st.Messages, "reports", st.Reports, "inserted", st.Inserted,
		"duplicates", st.Duplicates, "noReports", st.NoReports, "postProcessFailed", st.PostFailed,
		"aggregates", st.Aggregates, "aggregatesInserted", st.AggInserted, "aggregatesDuplicate", st.AggDuplicates, "took", time.Since(start).Round(time.Millisecond)}
	if err != nil {
		c.log.Error("poll failed", append(attrs, "err", err)...)
		return st, err
	}
	c.log.Info("poll complete", attrs...)
	return st, nil
}

// RunOnce drains the source folder.
func (c *Collector) RunOnce(ctx context.Context) (Stats, error) {
	var st Stats
	for k, until := range c.skip {
		if time.Now().After(until) {
			delete(c.skip, k)
		}
	}
	// Processed messages leave the listing (moved, or marked read). Messages
	// that stay put are counted in `left` and skipped over on the next page,
	// so one stuck message cannot hide the ones behind it.
	left := 0
	seen := map[string]bool{}
	for batch := 0; batch < maxBatches; batch++ {
		msgs, err := c.graph.ListMessages(ctx, c.srcID, c.cfg.BatchSize, left, c.cfg.PostProcess == "markread")
		if err != nil {
			return st, fmt.Errorf("list messages: %w", err)
		}
		if len(msgs) == 0 {
			break
		}
		for _, m := range msgs {
			if _, skip := c.skip[m.ID]; skip || seen[m.ID] {
				left++
				continue
			}
			seen[m.ID] = true
			remains, err := c.handle(ctx, m, &st)
			if err != nil {
				return st, err // infrastructure error (Mongo/Graph): stop, retry next poll
			}
			if remains {
				left++
			}
		}
		c.run.Progress(st.totals())
	}
	c.LastSuccess.Store(time.Now().Unix())
	return st, nil
}

// handle processes one mailbox message. remains reports whether the message is
// still in the source listing afterwards.
func (c *Collector) handle(ctx context.Context, m graph.Message, st *Stats) (remains bool, err error) {
	st.Messages++
	log := c.log.With("graphId", m.ID, "subject", m.Subject, "from", m.FromAddress())
	rec := &model.IngestRecord{
		InternetMessageID: m.InternetMessageID, GraphID: m.ID, RunID: c.run.ID(), Subject: m.Subject,
		From: m.FromAddress(), ReceivedAt: m.ReceivedDateTime,
	}

	if prior, err := c.store.PriorIngestStatus(ctx, m.InternetMessageID); err != nil {
		return true, err
	} else if prior != "" {
		log.Debug("already ingested; post-processing only", "status", prior)
		return c.postProcess(ctx, m, true, st, log), nil
	}

	raw, err := c.graph.GetMIME(ctx, m.ID)
	if err != nil {
		if graph.IsNotFound(err) {
			return false, nil // moved/deleted by someone else meanwhile
		}
		return true, fmt.Errorf("download %s: %w", m.ID, err)
	}

	res := c.parser.Parse(raw)
	rec.Warnings = res.Warnings
	rec.Reports = len(res.Reports)

	now := time.Now().UTC()
	for _, r := range res.Reports {
		r.ReceivedAt = m.ReceivedDateTime.UTC()
		r.IngestedAt = now
		if r.EventAt.IsZero() {
			r.EventAt = r.ReceivedAt
		}
		r.Mailbox = model.MailboxRef{
			GraphID: m.ID, InternetMessageID: m.InternetMessageID, Subject: m.Subject,
			From: m.FromAddress(), ReceivedAt: r.ReceivedAt,
		}
		c.enrich.Enrich(ctx, r)
		inserted, err := c.store.UpsertReport(ctx, r)
		if err != nil {
			return true, fmt.Errorf("store report: %w", err)
		}
		if inserted {
			rec.Inserted++
		} else {
			rec.Duplicates++
		}
	}
	st.Reports += rec.Reports
	st.Inserted += rec.Inserted
	st.Duplicates += rec.Duplicates

	// Aggregate (RUA) reports: skip any already stored (same reporter +
	// report_id, or byte-identical XML) before spending time on enrichment.
	rec.Aggregates = len(res.Aggregates)
	for _, a := range res.Aggregates {
		dup, err := c.store.AggregateExists(ctx, a.Report.ReportKey, a.Report.ContentHash)
		if err != nil {
			return true, fmt.Errorf("check aggregate: %w", err)
		}
		if dup {
			rec.AggDuplicates++
			log.Debug("duplicate aggregate report", "org", a.Report.OrgName, "reportId", a.Report.ReportID)
			continue
		}
		a.Report.ReceivedAt = m.ReceivedDateTime.UTC()
		a.Report.IngestedAt = now
		if a.Report.EventAt.IsZero() {
			a.Report.EventAt, a.Report.DateBegin = a.Report.ReceivedAt, a.Report.ReceivedAt
			for _, r := range a.Records {
				r.EventAt, r.DateBegin = a.Report.ReceivedAt, a.Report.ReceivedAt
			}
		}
		a.Report.Mailbox = model.MailboxRef{
			GraphID: m.ID, InternetMessageID: m.InternetMessageID, Subject: m.Subject,
			From: m.FromAddress(), ReceivedAt: a.Report.ReceivedAt,
		}
		c.enrich.EnrichAggregate(ctx, a.Report, a.Records)
		inserted, err := c.store.InsertAggregate(ctx, a.Report, a.Records)
		if err != nil {
			return true, fmt.Errorf("store aggregate: %w", err)
		}
		if inserted {
			rec.AggInserted++
		} else {
			rec.AggDuplicates++
		}
	}
	st.Aggregates += rec.Aggregates
	st.AggInserted += rec.AggInserted
	st.AggDuplicates += rec.AggDuplicates

	ok := len(res.Reports) > 0 || len(res.Aggregates) > 0
	switch {
	case ok:
		rec.Status = "ok"
		if err := c.store.ClearUnparsed(ctx, m.InternetMessageID); err != nil {
			return true, fmt.Errorf("clear earlier failure: %w", err)
		}
	default:
		rec.Structure = res.Structure
		c.saveUnparsed(m, raw, log)
		rec.Status, rec.Error = "no_reports", "no failure report found"
		st.NoReports++
	}
	rec.ProcessedAt = time.Now().UTC()
	if err := c.store.RecordIngest(ctx, rec); err != nil {
		return true, fmt.Errorf("record ingest: %w", err)
	}
	log.Info("processed message", "reports", rec.Reports, "inserted", rec.Inserted,
		"aggregates", rec.Aggregates, "aggregatesInserted", rec.AggInserted, "aggregatesDuplicate", rec.AggDuplicates,
		"status", rec.Status)
	if !ok {
		log.Warn("no report found in message", "structure", strings.Join(res.Structure, " || "))
	}
	return c.postProcess(ctx, m, ok, st, log), nil
}

// postProcess moves or flags a handled message. It returns whether the
// message is still in the source listing afterwards.
func (c *Collector) postProcess(ctx context.Context, m graph.Message, ok bool, st *Stats, log *slog.Logger) (remains bool) {
	var err error
	switch c.cfg.PostProcess {
	case "move":
		dest := c.okID
		if !ok {
			dest = c.failID
		}
		if dest == c.srcID {
			return true // reprocessing the Failed folder: an unparsed message stays where it is
		}
		err = c.graph.Move(ctx, m.ID, dest)
	case "markread":
		cat := categoryOK
		if !ok {
			cat = categoryFailed
		}
		err = c.graph.MarkRead(ctx, m.ID, cat)
	}
	if err != nil && !graph.IsNotFound(err) {
		log.Warn("post-process failed; will skip this message for an hour", "err", err)
		c.skip[m.ID] = time.Now().Add(time.Hour)
		st.PostFailed++
		return true
	}
	return false
}

// saveUnparsed writes a message in which no report was found to
// DMARC_SAVE_UNPARSED_DIR, so it can be inspected or run through -parse.
func (c *Collector) saveUnparsed(m graph.Message, raw []byte, log *slog.Logger) {
	if c.cfg.SaveUnparsedDir == "" {
		return
	}
	sum := sha256.Sum256([]byte(m.InternetMessageID + m.ID))
	name := filepath.Join(c.cfg.SaveUnparsedDir, hex.EncodeToString(sum[:8])+".eml")
	if err := os.MkdirAll(c.cfg.SaveUnparsedDir, 0o700); err == nil {
		err = os.WriteFile(name, raw, 0o600)
		if err == nil {
			log.Info("saved unparsed message", "file", name)
			return
		}
		log.Warn("could not save unparsed message", "err", err)
	}
}
