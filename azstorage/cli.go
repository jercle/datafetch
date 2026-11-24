// Package azstorage is the az-storage command. It collects, for one or more
// Azure tenants, every storage account with its used capacity, every blob
// container with its measured size, and every managed disk. Everything goes
// to MongoDB, with the collector's own logs and run history.
//
// The settings kept in Azure App Configuration under the key
// datafetching.azStorage are read before every pass and win over the
// configuration file, which fills in the rest.
package azstorage

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/jercle/datafetch/azstorage/internal/azure"
	"github.com/jercle/datafetch/azstorage/internal/collector"
	"github.com/jercle/datafetch/azstorage/internal/config"
	"github.com/jercle/datafetch/azstorage/internal/model"
	"github.com/jercle/datafetch/azstorage/internal/monitor"
	"github.com/jercle/datafetch/azstorage/internal/store"
	"github.com/jercle/datafetch/azstorage/internal/store/mongostore"
	"github.com/jercle/datafetch/internal/cli"
	"github.com/jercle/datafetch/internal/settings"
	"github.com/jercle/datafetch/internal/version"
)

// Name is the command: datafetch az-storage.
const Name = "az-storage"

// Spec describes the settings under datafetching.azStorage: the paths of
// the configuration file, with the tenants also as tenants.<tenant id>.
var Spec = settings.Spec{
	Tool:   settings.AzStorage,
	Schema: config.Config{},
	Lists:  map[string]string{"tenants": "tenantId"},
}

// Main runs the command with its arguments, until it is done or ctx is
// cancelled.
func Main(ctx context.Context, args []string) error {
	fs := cli.Flags(Name)
	var (
		configPath  = fs.String("config", cli.DefaultConfig(Name), "path to the configuration file; optional when App Configuration has the tenants and the MongoDB address")
		loop        = fs.Bool("loop", false, "keep running: collect, wait for the configured interval, collect again")
		dryRun      = fs.Bool("dry-run", false, "collect once and print what would be stored as JSON lines; writes nothing")
		initDB      = fs.Bool("init-db", false, "create the MongoDB indexes (and apply retention changes), then exit")
		noAppConfig = fs.Bool("no-app-config", false, "ignore AZURE_APPCONFIG_ENDPOINT and run on the configuration file alone")
		logFile     = fs.String("log-file", "", "append the local log to this file instead of stderr")
		showVersion = fs.Bool("version", false, "print the version and exit")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		fmt.Println(version.Version)
		return nil
	}

	logOut, done, err := cli.LogOutput(*logFile)
	if err != nil {
		return err
	}
	defer done()

	fetch, err := cli.Fetch(*noAppConfig, settings.AzStorage)
	if err != nil {
		return err
	}
	file, err := cli.ConfigFile(fs, *configPath, fetch)
	if err != nil {
		return err
	}
	loader := &settings.Loader[*config.Config]{
		Spec: Spec, File: file, Fetch: fetch,
		Parse: func(b []byte) (*config.Config, error) { return config.Parse(b, os.Getenv, os.ReadFile) },
	}
	cfg, status, err := loader.Load(ctx)
	if err != nil {
		return err
	}

	ctx, stop := context.WithCancel(ctx)
	defer stop()

	var st store.Store
	retention := mongostore.Retention{LogsDays: cfg.Retention.LogsDays, RunsDays: cfg.Retention.RunsDays}
	if *dryRun {
		st = store.NewDryRun(os.Stdout)
	} else {
		ms, err := mongostore.Open(cfg.Mongo.URI, cfg.Mongo.Database, "az-storage/"+version.Version)
		if err != nil {
			return err
		}
		st = ms
		ictx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		if *initDB {
			defer cancel()
			if err := ms.Ping(ictx); err != nil {
				return fmt.Errorf("cannot reach MongoDB: %w", err)
			}
			if err := ms.EnsureIndexes(ictx, retention); err != nil {
				return err
			}
			fmt.Printf("indexes are in place in database %q\n", cfg.Mongo.Database)
			return nil
		}
		if cfg.EnsureIndexes() {
			if err := ms.EnsureIndexes(ictx, retention); err != nil {
				fmt.Fprintln(os.Stderr, "az-storage: indexes not ensured:", err)
			}
		}
		cancel()
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = st.Close(ctx)
	}()

	host, _ := os.Hostname()
	if host == "" {
		host = "unknown"
	}
	sink := monitor.NewSink(st, host, monitor.ParseLevel(cfg.Logging.MongoLevel))
	defer sink.Close()
	hopts := &slog.HandlerOptions{Level: monitor.ParseLevel(cfg.Logging.Level)}
	var local slog.Handler = slog.NewTextHandler(logOut, hopts)
	if cfg.Logging.Format == "json" {
		local = slog.NewJSONHandler(logOut, hopts)
	}
	log := slog.New(sink.Handler(local))

	inst := model.Instance{
		ID: host, Host: host, Version: version.Version, Mode: "once", PID: os.Getpid(),
		HeartbeatSeconds: int(cfg.HeartbeatInterval.D() / time.Second),
	}
	if *loop {
		inst.Mode = "schedule"
	}
	mon := monitor.New(st, log, inst)

	beatDone := make(chan struct{})
	go func() {
		mon.Loop(ctx)
		close(beatDone)
	}()
	defer func() {
		stop()
		<-beatDone
	}()

	col := &collector.Collector{
		Store: st, Mon: mon, Log: log, SetRun: sink.SetRun,
		NewClient: func(t config.Tenant) collector.AzureAPI { return azure.NewClient(t, log.With("tenantName", t.Name)) },
	}
	// started is what the store and the logs were set up with: these only
	// change at a restart.
	started := cfg
	var report settings.Reporter
	apply := func(c *config.Config, status settings.Status) {
		col.Cfg = c
		mon.Update(func(i *model.Instance) {
			// A new list: a heartbeat may be writing the old one.
			tenants := make([]model.Scope, 0, len(c.Tenants))
			for _, t := range c.Tenants {
				tenants = append(tenants, model.Scope{TenantName: t.Name, TenantID: t.ID})
			}
			i.Tenants = tenants
			if *loop {
				i.IntervalSeconds = int(c.Interval.D() / time.Second)
			}
		})
		report.Report(log, status)
		if !*dryRun && (c.Mongo.URI != started.Mongo.URI || c.Mongo.Database != started.Mongo.Database || c.Logging != started.Logging || c.HeartbeatInterval != started.HeartbeatInterval) {
			log.Warn("the database, logging and heartbeat settings changed; they apply when the collector is restarted")
			// Warn once per change, not on every pass.
			started = c
		}
	}
	apply(cfg, status)
	log.Info("az-storage started", "version", version.Version, "mode", inst.Mode, "tenants", len(cfg.Tenants),
		"usage", cfg.CollectUsage(), "containers", cfg.CollectContainers(), "containerSizes", cfg.MeasureContainers(), "disks", cfg.CollectDisks())
	if !*loop {
		r := col.Run(ctx, "manual", nil)
		sink.Flush()
		if r.Status == model.StatusFailed {
			return fmt.Errorf("run %s failed: %s", r.ID, r.Error)
		}
		return nil
	}
	for first := true; ; first = false {
		if !first {
			// What was changed in App Configuration since the last pass.
			next, status, err := loader.Load(ctx)
			if err != nil {
				report.NotReloaded(log, err)
			} else {
				cfg = next
				apply(cfg, status)
			}
		}
		next := time.Now().UTC().Add(cfg.Interval.D())
		col.Run(ctx, "schedule", &next)
		select {
		case <-ctx.Done():
			log.Info("az-storage stopping")
			return nil
		case <-time.After(time.Until(next)):
		}
	}
}
