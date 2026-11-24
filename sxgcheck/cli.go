// Package sxgcheck is the sxg-check command. It makes health checks on
// Sophos XG / Sophos Firewall appliances: ports, certificates, the web admin
// console, requests through the web proxy, the XML API, and the firewall's
// own numbers over SNMP. The state, its history and every change go to
// MongoDB, with the checker's own logs and run history.
//
// The settings kept in Azure App Configuration under the key
// datafetching.sxgCheck are read before every pass and win over the
// configuration file, which fills in the rest.
package sxgcheck

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/jercle/datafetch/internal/cli"
	"github.com/jercle/datafetch/internal/settings"
	"github.com/jercle/datafetch/internal/version"
	"github.com/jercle/datafetch/sxgcheck/internal/checker"
	"github.com/jercle/datafetch/sxgcheck/internal/config"
	"github.com/jercle/datafetch/sxgcheck/internal/model"
	"github.com/jercle/datafetch/sxgcheck/internal/monitor"
	"github.com/jercle/datafetch/sxgcheck/internal/probe"
	"github.com/jercle/datafetch/sxgcheck/internal/store"
	"github.com/jercle/datafetch/sxgcheck/internal/store/mongostore"
)

// Name is the command: datafetch sxg-check.
const Name = "sxg-check"

// Spec describes the settings under datafetching.sxgCheck: the paths of the
// configuration file, with the firewalls also as firewalls.<name>.
var Spec = settings.Spec{
	Tool:   settings.SXGCheck,
	Schema: config.Config{},
	Lists:  map[string]string{"firewalls": "name"},
	// The file keeps these as raw JSON, to lay a firewall over the defaults.
	Types: map[string]any{"defaults": config.Checks{}, "firewalls": []config.Firewall{}},
}

// Main runs the command with its arguments, until it is done or ctx is
// cancelled.
func Main(ctx context.Context, args []string) error {
	fs := cli.Flags(Name)
	var (
		configPath  = fs.String("config", cli.DefaultConfig(Name), "path to the configuration file; optional when App Configuration has the firewalls and the MongoDB address")
		loop        = fs.Bool("loop", false, "keep running: check, wait for the configured interval, check again")
		dryRun      = fs.Bool("dry-run", false, "check once and print what would be stored as JSON lines; writes nothing")
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

	fetch, err := cli.Fetch(*noAppConfig, settings.SXGCheck)
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
	retention := mongostore.Retention{LogsDays: cfg.Retention.LogsDays, RunsDays: cfg.Retention.RunsDays, ResultsDays: cfg.Retention.ResultsDays, EventsDays: cfg.Retention.EventsDays}
	if *dryRun {
		st = store.NewDryRun(os.Stdout)
	} else {
		ms, err := mongostore.Open(cfg.Mongo.URI, cfg.Mongo.Database, "sxg-check/"+version.Version)
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
				fmt.Fprintln(os.Stderr, "sxg-check: indexes not ensured:", err)
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
	instance := cfg.Instance
	if instance == "" {
		instance = host
	}
	sink := monitor.NewSink(st, instance, monitor.ParseLevel(cfg.Logging.MongoLevel))
	defer sink.Close()
	hopts := &slog.HandlerOptions{Level: monitor.ParseLevel(cfg.Logging.Level)}
	var local slog.Handler = slog.NewTextHandler(logOut, hopts)
	if cfg.Logging.Format == "json" {
		local = slog.NewJSONHandler(logOut, hopts)
	}
	log := slog.New(sink.Handler(local))

	inst := model.Instance{
		ID: instance, Host: host, Version: version.Version, Mode: "once", PID: os.Getpid(),
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

	prober := &probe.Prober{}
	chk := &checker.Checker{Store: st, Mon: mon, Log: log, SetRun: sink.SetRun, Instance: instance, Probe: prober.Probe}
	// started is what the store, the logs and the instance were set up
	// with: these only change at a restart.
	started := cfg
	var report settings.Reporter
	apply := func(c *config.Config, status settings.Status) {
		chk.Cfg = c
		if *loop {
			chk.IntervalSeconds = int(c.Interval.D() / time.Second)
		}
		mon.Update(func(i *model.Instance) {
			i.Firewalls = len(c.Firewalls)
			i.IntervalSeconds = chk.IntervalSeconds
		})
		report.Report(log, status)
		if !*dryRun && (c.Mongo.URI != started.Mongo.URI || c.Mongo.Database != started.Mongo.Database || c.Logging != started.Logging || c.HeartbeatInterval != started.HeartbeatInterval || c.Instance != started.Instance) {
			log.Warn("the database, logging, heartbeat and instance settings changed; they apply when the checker is restarted")
			// Warn once per change, not on every pass.
			started = c
		}
	}
	apply(cfg, status)
	log.Info("sxg-check started", "version", version.Version, "mode", inst.Mode, "firewalls", len(cfg.Firewalls), "interval", cfg.Interval.D().String())
	if !*loop {
		r := chk.Run(ctx, "manual", nil)
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
		chk.Run(ctx, "schedule", &next)
		select {
		case <-ctx.Done():
			log.Info("sxg-check stopping")
			return nil
		case <-time.After(time.Until(next)):
		}
	}
}
