// Package mdetracker is the mde-tracker command. It collects onboarded VMs
// from multiple Microsoft Defender for Endpoint tenants and records which
// Defender org each VM is currently onboarded to. Results, runs and logs
// are written to MongoDB.
//
// The settings kept in Azure App Configuration under the key
// datafetching.mdeTracker are read before every run and win over the
// configuration file, which fills in the rest.
package mdetracker

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"reflect"
	"time"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/jercle/datafetch/internal/cli"
	"github.com/jercle/datafetch/internal/settings"
	"github.com/jercle/datafetch/internal/version"
	"github.com/jercle/datafetch/mdetracker/internal/auth"
	"github.com/jercle/datafetch/mdetracker/internal/collector"
	"github.com/jercle/datafetch/mdetracker/internal/config"
	"github.com/jercle/datafetch/mdetracker/internal/defender"
	"github.com/jercle/datafetch/mdetracker/internal/logging"
	"github.com/jercle/datafetch/mdetracker/internal/store"
)

// Name is the command: datafetch mde-tracker.
const Name = "mde-tracker"

// Spec describes the settings under datafetching.mdeTracker: the paths of
// the configuration file, with the tenants also as tenants.<name>.
var Spec = settings.Spec{
	Tool:   settings.MDETracker,
	Schema: config.Config{},
	Lists:  map[string]string{"tenants": "name"},
}

// Main runs the command with its arguments, until it is done or ctx is
// cancelled.
func Main(ctx context.Context, args []string) error {
	fs := cli.Flags(Name)
	cfgPath := fs.String("config", envOr("MDE_CONFIG", cli.DefaultConfig(Name)), "path to JSON config; optional when App Configuration has the tenants and the MongoDB address")
	once := fs.Bool("once", false, "run one collection and exit (overrides interval)")
	dumpDir := fs.String("dump-dir", os.Getenv("MDE_DUMP_DIR"), "write all collected data as JSON under this directory (troubleshooting)")
	noAppConfig := fs.Bool("no-app-config", false, "ignore AZURE_APPCONFIG_ENDPOINT and run on the configuration file alone")
	showVersion := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		fmt.Println(version.Version)
		return nil
	}

	fetch, err := cli.Fetch(*noAppConfig, settings.MDETracker)
	if err != nil {
		return err
	}
	// A file named by -config or MDE_CONFIG must be there; the default
	// place need not have one when App Configuration is read.
	named := cli.Given(fs, "config") || os.Getenv("MDE_CONFIG") != ""
	file, err := settings.ReadFile(*cfgPath, fetch != nil && !named)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	// ${ENV_VAR} references are the file's: a secret from App
	// Configuration is taken as it is.
	if file, err = config.Expand(file); err != nil {
		return err
	}
	loader := &settings.Loader[*config.Config]{
		Spec: Spec, File: file, Fetch: fetch,
		Parse: func(b []byte) (*config.Config, error) {
			cfg, err := config.ParseExpanded(b)
			if err == nil && *dumpDir != "" {
				cfg.DumpDir = *dumpDir
			}
			return cfg, err
		},
	}
	cfg, status, err := loader.Load(ctx)
	if err != nil {
		return err
	}

	client, err := mongo.Connect(options.Client().ApplyURI(cfg.Mongo.URI).SetAppName("mde-collector"))
	if err != nil {
		return fmt.Errorf("mongo connect: %w", err)
	}
	defer func() {
		dctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = client.Disconnect(dctx)
	}()

	st := store.New(client.Database(cfg.Mongo.Database), cfg.Mongo)
	pctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	err = st.Ping(pctx)
	cancel()
	if err != nil {
		return fmt.Errorf("mongo ping: %w", err)
	}
	idxWarn, err := st.EnsureIndexes(ctx, cfg.Mongo.LogRetentionDays)
	if err != nil {
		return err
	}

	stdout := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logging.ParseLevel(cfg.LogLevel)})
	mh := logging.NewMongoHandler(st.LogInserter(), logging.Options{
		Level:   logging.ParseLevel(cfg.MongoLogLevel),
		Service: "mde-collector",
	})
	defer func() {
		cctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = mh.Close(cctx)
	}()
	log := slog.New(logging.Multi{stdout, mh})
	slog.SetDefault(log)
	if idxWarn != nil {
		log.Warn(idxWarn.Error())
	}
	var report settings.Reporter
	report.Report(log, status)

	// build makes the collector of one configuration.
	build := func(cfg *config.Config) (*collector.Collector, int, error) {
		var sources []collector.Source
		for _, t := range cfg.EnabledTenants() {
			ts, err := auth.New(t, t.Scope)
			if err != nil {
				return nil, 0, err
			}
			tl := log.With("tenant", t.Name, "orgId", t.OrgID)
			sources = append(sources, collector.Source{Tenant: t, Lister: defender.NewClient(t.APIBase, ts, tl)})
		}
		return collector.New(cfg, sources, st, log), len(sources), nil
	}
	col, tenants, err := build(cfg)
	if err != nil {
		return err
	}

	if *once || cfg.Interval.Duration == 0 {
		return col.Run(ctx)
	}

	log.Info("collector started", "interval", cfg.Interval.String(), "tenants", tenants)
	// started is what the store and the logs were set up with: these only
	// change at a restart.
	started := cfg
	for first := true; ; first = false {
		if !first {
			// What was changed in App Configuration since the last run.
			next, status, err := loader.Load(ctx)
			switch {
			case err != nil:
				report.NotReloaded(log, err)
			case reflect.DeepEqual(next, cfg):
				report.Report(log, status)
			default:
				report.Report(log, status)
				if next.Interval.Duration == 0 {
					log.Warn("interval is now 0 (run once): it applies when the collector is restarted; the schedule goes on as before")
					next.Interval = cfg.Interval
				}
				nextCol, n, err := build(next)
				if err != nil {
					log.Error("the changed configuration could not be used; the run uses what was loaded before", "error", err.Error())
					break
				}
				if next.Mongo != started.Mongo || next.LogLevel != started.LogLevel || next.MongoLogLevel != started.MongoLogLevel {
					log.Warn("the database and logging settings changed; they apply when the collector is restarted")
					// Warn once per change, not before every run.
					started = next
				}
				log.Info("configuration changed", "interval", next.Interval.String(), "tenants", n)
				cfg, col = next, nextCol
			}
		}
		begun := time.Now()
		// Errors are logged (and recorded on the run) by the collector; keep the schedule going.
		_ = col.Run(ctx)
		select {
		case <-ctx.Done():
			log.Info("collector stopping")
			return nil
		case <-time.After(time.Until(begun.Add(cfg.Interval.Duration))):
		}
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
