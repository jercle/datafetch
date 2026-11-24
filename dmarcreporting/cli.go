// Package dmarcreporting is the dmarc-reporting command. It polls an
// Exchange Online mailbox (Microsoft Graph) for DMARC failure and aggregate
// reports, parses and enriches them, and stores them in MongoDB.
//
//	datafetch dmarc-reporting                 run continuously (Deployment)
//	datafetch dmarc-reporting -once           drain the mailbox once and exit (CronJob)
//	datafetch dmarc-reporting -parse a.eml    parse local .eml / .xml files and print JSON (no mailbox / Mongo)
//	datafetch dmarc-reporting -reprocess      re-read the Failed folder once, e.g. after a parser update
//
// It is configured by environment variables. The settings kept in Azure App
// Configuration under the key datafetching.dmarcReporting are read before
// every poll and win over them.
package dmarcreporting

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jercle/datafetch/dmarcreporting/internal/collector"
	"github.com/jercle/datafetch/dmarcreporting/internal/config"
	"github.com/jercle/datafetch/dmarcreporting/internal/enrich"
	"github.com/jercle/datafetch/dmarcreporting/internal/graph"
	"github.com/jercle/datafetch/dmarcreporting/internal/monitor"
	"github.com/jercle/datafetch/dmarcreporting/internal/parser"
	"github.com/jercle/datafetch/dmarcreporting/internal/store"
	"github.com/jercle/datafetch/internal/cli"
	"github.com/jercle/datafetch/internal/settings"
	"github.com/jercle/datafetch/internal/version"
)

// Name is the command: datafetch dmarc-reporting.
const Name = "dmarc-reporting"

// Spec describes the settings under datafetching.dmarcReporting: the paths
// of config.File.
var Spec = settings.Spec{Tool: settings.DMARCReporting, Schema: config.File{}}

// Main runs the command with its arguments, until it is done or ctx is
// cancelled.
func Main(ctx context.Context, args []string) error {
	fs := cli.Flags(Name)
	once := fs.Bool("once", false, "drain the mailbox once and exit")
	parseOnly := fs.Bool("parse", false, "parse the .eml files given as arguments and print JSON (configured by the environment alone)")
	reprocess := fs.Bool("reprocess", false, "re-read the Failed folder once and exit (after a parser update)")
	noAppConfig := fs.Bool("no-app-config", false, "ignore AZURE_APPCONFIG_ENDPOINT and run on the environment alone")
	showVersion := fs.Bool("version", false, "print version")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		fmt.Println(version.Version)
		return nil
	}

	env := config.Load()
	if *parseOnly {
		// Local files only: no mailbox, no database, no App Configuration.
		return parseFiles(ctx, env, newLogger(env.LogLevel), fs.Args())
	}

	fetch, err := cli.Fetch(*noAppConfig, settings.DMARCReporting)
	if err != nil {
		return err
	}
	// The environment is this tool's configuration file.
	file, err := env.JSON()
	if err != nil {
		return err
	}
	loader := &settings.Loader[*config.Config]{
		Spec: Spec, File: file, Fetch: fetch,
		Parse: func(b []byte) (*config.Config, error) {
			cfg, err := config.Parse(b)
			if err != nil {
				return nil, err
			}
			if *reprocess {
				// Messages that now parse move on to Processed; the rest stay put.
				if cfg.PostProcess != "move" {
					return nil, errors.New("-reprocess needs postProcess (DMARC_POST_PROCESS) to be move; in markread mode, mark the messages unread instead")
				}
				cfg.SourceFolder = cfg.FailedFolder
			}
			return cfg, cfg.ValidateService()
		},
	}
	cfg, status, err := loader.Load(ctx)
	if err != nil {
		return err
	}
	log := newLogger(cfg.LogLevel)
	if err := run(ctx, cfg, status, loader, log, *once || *reprocess); err != nil {
		log.Error("fatal", "err", err)
		return err
	}
	return nil
}

func parserOptions(cfg *config.Config) parser.Options {
	return parser.Options{
		RedactSubject:        cfg.RedactSubject,
		StoreOriginalHeaders: cfg.StoreOriginalHeaders,
		StoreRawFields:       cfg.StoreRawFields,
	}
}

func enrichOptions(cfg *config.Config) enrich.Options {
	return enrich.Options{
		CityDB: cfg.GeoIPCityDB, ASNDB: cfg.GeoIPASNDB, IPInfoToken: cfg.IPInfoToken,
		ReverseDNS: cfg.ReverseDNS, DNSTimeout: cfg.DNSTimeout,
	}
}

func run(ctx context.Context, cfg *config.Config, status settings.Status, loader *settings.Loader[*config.Config], stdout *slog.Logger, once bool) error {
	st, err := store.Open(ctx, cfg.MongoURI, cfg.MongoDB, store.Collections{
		Failures: cfg.MongoCollection, Ingest: cfg.MongoIngestColl,
		AggregateReports: cfg.MongoAggReports, AggregateRecords: cfg.MongoAggRecords,
	})
	if err != nil {
		return err
	}
	defer func() {
		cctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = st.Close(cctx)
	}()

	// Monitoring: run records, logs and a heartbeat in MongoDB. Best-effort -
	// if it cannot be set up the collector still runs, logging to stdout only.
	// mon and sink stay nil when monitoring is off; nil values are no-ops.
	mode := "schedule"
	if once {
		mode = "once"
	}
	var (
		mon  *monitor.Monitor
		sink *monitor.Sink
		log  = stdout
	)
	if cfg.MonitoringEnabled {
		instance := cfg.InstanceName
		if instance == "" {
			if instance, _ = os.Hostname(); instance == "" {
				instance = "dmarc-collector"
			}
		}
		mon, err = monitor.New(ctx, st.DB(), monitor.Options{
			Instance: instance, Version: version.Version, Mode: mode,
			Mailbox: cfg.Mailbox, Folder: cfg.SourceFolder, PollInterval: cfg.PollInterval,
			RunsCollection: cfg.MongoRuns, LogsCollection: cfg.MongoLogs, InstancesCollection: cfg.MongoInstances,
			LogRetentionDays: cfg.LogRetentionDays, RunRetentionDays: cfg.RunRetentionDays,
		}, stdout)
		if err != nil {
			stdout.Warn("monitoring disabled: setup failed", "err", err)
			mon = nil
		} else {
			sink = monitor.NewSink(mon, instance, stdout)
			log = slog.New(monitor.NewHandler(stdout.Handler(), sink, monitor.ParseLevel(cfg.MonitoringLevel)))
			// Deferred calls run last-in first-out: flush logs, then mark exited.
			defer mon.Close()
			defer sink.Close()
		}
	}
	var report settings.Reporter
	report.Report(log, status)

	en, err := enrich.New(enrichOptions(cfg), log)
	if err != nil {
		log.Error("enrichment setup failed", "err", err)
		return err
	}
	defer en.Close()

	g := graph.New(graph.Config{
		TenantID: cfg.TenantID, ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret,
		FederatedTokenFile: cfg.FederatedTokenFile, AuthorityHost: cfg.AuthorityHost,
		Endpoint: cfg.GraphEndpoint, Mailbox: cfg.Mailbox,
	}, log)
	c := collector.New(cfg, g, parser.New(parserOptions(cfg)), en, st, log)
	c.SetMonitor(mon, sink)
	if err := c.Init(ctx); err != nil {
		log.Error("startup failed", "err", err)
		return err
	}
	log.Info("collector started", "version", version.Version, "mode", mode, "mailbox", cfg.Mailbox,
		"folder", cfg.SourceFolder, "postProcess", cfg.PostProcess, "interval", cfg.PollInterval.String())

	if once {
		_, err := c.Poll(ctx, "once")
		return err
	}

	srv := healthServer(cfg.HealthAddr, c)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("health server", "err", err)
		}
	}()
	// started is what the mailbox, the database, the enrichment, the
	// monitoring and the logs were set up with: these only change at a
	// restart.
	started := fixed(cfg)
	c.Run(ctx, func(ctx context.Context) {
		// What was changed in App Configuration since the last poll.
		next, status, err := loader.Load(ctx)
		if err != nil {
			report.NotReloaded(log, err)
			return
		}
		report.Report(log, status)
		if *next == *cfg {
			return
		}
		var p *parser.Parser
		if parserOptions(next) != parserOptions(cfg) {
			p = parser.New(parserOptions(next))
		}
		if err := c.Reconfigure(ctx, next, p); err != nil {
			log.Error("the changed configuration could not be used; the poll runs on what was loaded before", "err", err)
			return
		}
		log.Info("configuration changed", "folder", next.SourceFolder, "postProcess", next.PostProcess, "interval", next.PollInterval.String(), "batchSize", next.BatchSize)
		if f := fixed(next); f != started {
			log.Warn("the app registration, mailbox, endpoint, database, enrichment, monitoring, health address and log level settings changed; they apply when the collector is restarted")
			// Warn once per change, not before every poll.
			started = f
		}
		cfg = next
	})
	log.Info("collector stopping")
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(sctx)
}

// fixed is the part of the configuration that is only read at the start:
// everything but what Collector.Reconfigure takes.
func fixed(cfg *config.Config) config.Config {
	f := *cfg
	f.SourceFolder, f.ProcessedFolder, f.FailedFolder, f.PostProcess = "", "", "", ""
	f.PollInterval, f.BatchSize, f.SaveUnparsedDir = 0, 0, ""
	f.RedactSubject, f.StoreOriginalHeaders, f.StoreRawFields = false, false, false
	return f
}

// healthServer: /healthz fails if no poll has completed within 3 intervals
// (after a startup grace period); /readyz is always OK once listening.
func healthServer(addr string, c *collector.Collector) *http.Server {
	started := time.Now()
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		limit := 3*c.Interval() + 2*time.Minute
		last := c.LastSuccess.Load()
		ref := started
		if last > 0 {
			ref = time.Unix(last, 0)
		}
		if time.Since(ref) > limit {
			http.Error(w, "stale: last successful poll "+ref.Format(time.RFC3339), http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "ok") })
	return &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
}

func parseFiles(ctx context.Context, cfg *config.Config, log *slog.Logger, files []string) error {
	if len(files) == 0 {
		return errors.New("-parse needs one or more .eml files")
	}
	p := parser.New(parserOptions(cfg))
	en, err := enrich.New(enrichOptions(cfg), log)
	if err != nil {
		return err
	}
	defer en.Close()
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		if !parser.LooksLikeMessage(raw) { // a bare attachment (.xml, .zip, .gz): wrap it as a part
			raw = []byte("Content-Type: application/octet-stream\nContent-Transfer-Encoding: base64\n\n" +
				base64.StdEncoding.EncodeToString(raw))
		}
		res := p.Parse(raw)
		for _, r := range res.Reports {
			if r.EventAt.IsZero() {
				r.EventAt = time.Now().UTC()
			}
			en.Enrich(ctx, r)
		}
		for _, a := range res.Aggregates {
			en.EnrichAggregate(ctx, a.Report, a.Records)
		}
		if err := enc.Encode(map[string]any{
			"file": f, "reports": res.Reports, "aggregates": res.Aggregates, "warnings": res.Warnings,
			"structure": res.Structure,
		}); err != nil {
			return err
		}
	}
	return nil
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	switch strings.ToLower(level) {
	case "debug":
		l = slog.LevelDebug
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}
