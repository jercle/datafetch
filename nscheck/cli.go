// Package nscheck is the ns-check command. It logs in to one or more Citrix
// NetScaler (ADC) appliances over the NITRO API, checks their health, and
// writes the outcome to MongoDB together with its own logs and run history.
//
// The settings kept in Azure App Configuration under the key
// datafetching.nsCheck are read before every pass and win over the
// configuration file, which fills in the rest.
package nscheck

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/jercle/datafetch/internal/cli"
	"github.com/jercle/datafetch/internal/settings"
	"github.com/jercle/datafetch/internal/version"
	"github.com/jercle/datafetch/nscheck/internal/checker"
	"github.com/jercle/datafetch/nscheck/internal/config"
	"github.com/jercle/datafetch/nscheck/internal/model"
	"github.com/jercle/datafetch/nscheck/internal/monitor"
	"github.com/jercle/datafetch/nscheck/internal/nitro"
	"github.com/jercle/datafetch/nscheck/internal/store"
	"github.com/jercle/datafetch/nscheck/internal/store/mongostore"
)

// Name is the command: datafetch ns-check.
const Name = "ns-check"

// Spec describes the settings under datafetching.nsCheck: the paths of the
// configuration file, with the appliances also as appliances.<name>.
var Spec = settings.Spec{
	Tool:   settings.NSCheck,
	Schema: config.Config{},
	Lists:  map[string]string{"appliances": "name"},
}

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// Main runs the command with its arguments, until it is done or ctx is
// cancelled.
func Main(ctx context.Context, args []string) error {
	fs := cli.Flags(Name)
	var (
		configPath  = fs.String("config", cli.DefaultConfig(Name), "path to the configuration file; optional when App Configuration has the appliances and the MongoDB address")
		loop        = fs.Bool("loop", false, "keep running: check, wait for the configured interval, check again")
		dryRun      = fs.Bool("dry-run", false, "check once and print what would be stored as JSON lines; writes nothing")
		initDB      = fs.Bool("init-db", false, "create the MongoDB indexes (and apply retention changes), then exit")
		only        = fs.String("appliance", "", "check only the appliance with this name")
		dumpDir     = fs.String("dump-dir", "", "write every NITRO response to this folder (overrides dumpDir in the configuration)")
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

	fetch, err := cli.Fetch(*noAppConfig, settings.NSCheck)
	if err != nil {
		return err
	}
	file, err := cli.ConfigFile(fs, *configPath, fetch)
	if err != nil {
		return err
	}
	loader := &settings.Loader[*config.Config]{
		Spec: Spec, File: file, Fetch: fetch,
		Parse: func(b []byte) (*config.Config, error) {
			cfg, err := config.Parse(b, os.Getenv, os.ReadFile)
			if err != nil {
				return nil, err
			}
			// What the command line says holds for every reading.
			if *dumpDir != "" {
				cfg.DumpDir = *dumpDir
			}
			if *only != "" {
				var keep []config.Appliance
				for _, a := range cfg.Appliances {
					if strings.EqualFold(a.Name, *only) {
						keep = append(keep, a)
					}
				}
				if len(keep) == 0 {
					return nil, fmt.Errorf("no appliance named %q in the configuration", *only)
				}
				cfg.Appliances = keep
			}
			return cfg, nil
		},
	}
	cfg, status, err := loader.Load(ctx)
	if err != nil {
		return err
	}

	ctx, stop := context.WithCancel(ctx)
	defer stop()

	var st store.Store
	retention := mongostore.Retention{
		LogsDays: cfg.Retention.LogsDays, RunsDays: cfg.Retention.RunsDays,
		SamplesDays: cfg.Retention.SamplesDays, EventsDays: cfg.Retention.EventsDays,
	}
	if *dryRun {
		st = store.NewDryRun(os.Stdout)
	} else {
		ms, err := mongostore.Open(cfg.Mongo.URI, cfg.Mongo.Database, "ns-check/"+version.Version)
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
				fmt.Fprintln(os.Stderr, "ns-check: indexes not ensured:", err)
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

	chk := &checker.Checker{Store: st, Mon: mon, Log: log, SetRun: sink.SetRun}
	chk.NewClient = func(a config.Appliance) (checker.API, error) {
		// The configuration of the pass that is running.
		cfg := chk.Cfg
		o := nitro.Options{
			Address: a.Address, Username: a.Username, Password: a.Password,
			Timeout: cfg.Timeout.D(), SkipVerify: a.SkipVerify, CAFile: a.CAFile,
		}
		if cfg.DumpDir != "" {
			o.Dump = dumper(cfg.DumpDir, a.Name, log)
		}
		return nitro.New(o)
	}
	// started is what the store and the logs were set up with: these only
	// change at a restart.
	started := cfg
	var report settings.Reporter
	plain := map[string]bool{}
	apply := func(c *config.Config, status settings.Status) {
		chk.Cfg = c
		if *loop {
			chk.Interval = c.Interval.D()
		}
		mon.Update(func(i *model.Instance) {
			i.Appliances = len(c.Appliances)
			if *loop {
				i.IntervalSeconds = int(c.Interval.D() / time.Second)
			}
		})
		report.Report(log, status)
		for _, a := range c.Appliances {
			if strings.HasPrefix(a.Address, "http://") && !plain[a.Name] {
				plain[a.Name] = true
				log.Warn("the appliance is configured over plain http: its password is sent unencrypted", "appliance", a.Name)
			}
		}
		if !*dryRun && (c.Mongo.URI != started.Mongo.URI || c.Mongo.Database != started.Mongo.Database || c.Logging != started.Logging || c.HeartbeatInterval != started.HeartbeatInterval) {
			log.Warn("the database, logging and heartbeat settings changed; they apply when the checker is restarted")
			// Warn once per change, not on every pass.
			started = c
		}
	}
	apply(cfg, status)
	log.Info("ns-check started", "version", version.Version, "mode", inst.Mode, "appliances", len(cfg.Appliances), "interval", cfg.Interval.D().String())
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
			log.Info("ns-check stopping")
			return nil
		case <-time.After(time.Until(next)):
		}
	}
}

// dumper writes each NITRO response to <dir>/<appliance>/<api>_<resource>.json,
// replacing the one from the pass before.
func dumper(dir, appliance string, log *slog.Logger) func(api, resource string, body []byte) {
	folder := filepath.Join(dir, unsafeName.ReplaceAllString(appliance, "_"))
	return func(api, resource string, body []byte) {
		err := os.MkdirAll(folder, 0o750)
		if err == nil {
			err = os.WriteFile(filepath.Join(folder, api+"_"+unsafeName.ReplaceAllString(resource, "_")+".json"), body, 0o640)
		}
		if err != nil {
			log.Debug("response not dumped", "appliance", appliance, "error", err)
		}
	}
}
