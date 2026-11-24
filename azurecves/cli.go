// Package azurecves is the azure-cves command. It continually collects, for
// every configured tenant: Azure resources and how they relate, Defender
// for Endpoint devices, the software installed on them and the CVEs
// affecting them. Everything goes into one MongoDB database as a graph of
// nodes and edges.
//
// The settings kept in Azure App Configuration under the key
// datafetching.azureCves are read before every collection and win over the
// configuration file and the environment, which fill in the rest.
package azurecves

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/jercle/datafetch/azurecves/pkg/azure"
	"github.com/jercle/datafetch/azurecves/pkg/collector"
	"github.com/jercle/datafetch/azurecves/pkg/config"
	"github.com/jercle/datafetch/azurecves/pkg/mongostore"
	"github.com/jercle/datafetch/azurecves/pkg/monitor"
	"github.com/jercle/datafetch/internal/cli"
	"github.com/jercle/datafetch/internal/settings"
	"github.com/jercle/datafetch/internal/version"
)

// Name is the command: datafetch azure-cves.
const Name = "azure-cves"

// Spec describes the settings under datafetching.azureCves: the paths of
// the configuration file, with the tenants also as tenants.<tenant id>.
var Spec = settings.Spec{
	Tool:   settings.AzureCVEs,
	Schema: config.Config{},
	Lists:  map[string]string{"tenants": "tenantId"},
}

// Main runs the command with its arguments, until it is done or ctx is
// cancelled.
func Main(ctx context.Context, args []string) error {
	fs := cli.Flags(Name)
	cfgPath := fs.String("config", os.Getenv("AZCVES_CONFIG"), "path of the JSON config file (optional when App Configuration or the environment has everything)")
	once := fs.Bool("once", false, "collect once and exit (for cron / Kubernetes CronJobs / Container App Jobs)")
	check := fs.Bool("check", false, "validate the configuration and exit")
	sample := fs.Int("sample-containers", 0, "print up to N raw Defender for Cloud container findings per tenant and exit (to check their shape)")
	logLevel := fs.String("log-level", "info", "stdout log level: debug, info, warn, error")
	noAppConfig := fs.Bool("no-app-config", false, "ignore AZURE_APPCONFIG_ENDPOINT and run on the configuration file and the environment alone")
	showVersion := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		fmt.Println(version.Version)
		return nil
	}

	fetch, err := cli.Fetch(*noAppConfig, settings.AzureCVEs)
	if err != nil {
		return err
	}
	file, err := settings.ReadFile(*cfgPath, false)
	if err != nil {
		return err
	}
	if len(file) == 0 {
		// No file: the environment and App Configuration have everything.
		file = []byte("{}")
	}
	loader := &settings.Loader[*config.Config]{
		Spec: Spec, File: file, Fetch: fetch,
		Parse: func(b []byte) (*config.Config, error) { return config.Parse(b, os.Getenv) },
	}
	cfg, status, err := loader.Load(ctx)
	if err != nil {
		return fmt.Errorf("configuration:\n%w", err)
	}
	if *check {
		fmt.Printf("configuration OK: %d tenants, database %q, every %s (from %s, %d settings applied)\n", len(cfg.Tenants), cfg.Mongo.Database, time.Duration(cfg.Interval), status.Source, status.Applied)
		if status.Error != "" {
			fmt.Println("warning:", status.Error)
		}
		for _, w := range status.Warnings {
			fmt.Println("setting ignored:", w)
		}
		return nil
	}

	if *sample > 0 {
		return sampleContainers(ctx, cfg, *sample)
	}

	connectCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	store, err := mongostore.New(connectCtx, cfg)
	cancel()
	if err != nil {
		return fmt.Errorf("connecting to MongoDB: %w", err)
	}
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = store.Close(c)
	}()

	host, _ := os.Hostname()
	var stdoutLevel, shipLevel slog.Level
	if err := stdoutLevel.UnmarshalText([]byte(*logLevel)); err != nil {
		return fmt.Errorf("-log-level: %w", err)
	}
	if err := shipLevel.UnmarshalText([]byte(cfg.Monitoring.LogLevel)); err != nil {
		return fmt.Errorf("monitoring.logLevel: %w", err)
	}
	var sink monitor.Sink
	if cfg.MonitoringEnabled() {
		sink = store
	}
	handler, flush := monitor.NewHandler(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: stdoutLevel}), sink, shipLevel, host)
	defer flush()
	log := slog.New(handler)

	idxCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	err = store.EnsureIndexes(idxCtx, cfg.Monitoring)
	cancel()
	if err != nil {
		return fmt.Errorf("creating indexes: %w", err)
	}

	c := collector.New(cfg, store, sink, log)
	c.Instance, c.Version = host, version.Version

	start := time.Now().UTC()
	inst := &monitor.Instance{ID: host, Host: host, Version: version.Version, Mode: "schedule", State: "idle", PID: os.Getpid(),
		IntervalSec: int64(time.Duration(cfg.Interval).Seconds()), StartedAt: start}
	if *once {
		inst.Mode = "once"
	}
	beat := func() {
		if sink == nil {
			return
		}
		cp := *inst
		cp.HeartbeatAt = time.Now().UTC()
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := sink.SaveInstance(c, &cp); err != nil {
			log.Debug("saving heartbeat failed", "error", err)
		}
	}
	defer func() { inst.State, inst.NextRunAt = "exited", nil; beat() }()

	// started is what the store and the logs were set up with: these only
	// change at a restart.
	started := cfg
	var report settings.Reporter
	report.Report(log, status)
	log.Info("collector started", "version", version.Version, "tenants", len(cfg.Tenants), "interval", time.Duration(cfg.Interval).String(), "once", *once)
	trigger := "startup"
	for first := true; ; first = false {
		if !first {
			// What was changed in App Configuration since the last run.
			// inst is only written between runs, as here.
			next, status, err := loader.Load(ctx)
			if err != nil {
				report.NotReloaded(log, err)
			} else {
				cfg = next
				c.Cfg = cfg
				inst.IntervalSec = int64(time.Duration(cfg.Interval).Seconds())
				report.Report(log, status)
				if fixed(cfg) != fixed(started) {
					log.Warn("the database, cost source and monitoring settings changed; they apply when the collector is restarted")
					// Warn once per change, not before every run.
					started = cfg
				}
			}
		}
		inst.State, inst.NextRunAt = "running", nil
		beat()
		// Heartbeat while the run is in progress; inst is only written
		// between runs, so the copy in beat() is safe.
		hbDone := make(chan struct{})
		hbStop := make(chan struct{})
		go func() {
			defer close(hbDone)
			t := time.NewTicker(30 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-hbStop:
					return
				case <-t.C:
					beat()
				}
			}
		}()
		r := c.Run(ctx, trigger)
		close(hbStop)
		<-hbDone

		inst.LastRunID, inst.LastRunStatus, inst.LastRunAt = r.ID, r.Status, r.FinishedAt
		if *once {
			if r.Status == monitor.StatusFailed || r.Status == monitor.StatusCancelled {
				return fmt.Errorf("collection %s", r.Status)
			}
			return nil
		}
		next := r.StartedAt.Add(time.Duration(cfg.Interval))
		if wait := time.Until(next); wait < time.Minute {
			next = time.Now().UTC().Add(time.Minute)
		}
		inst.State, inst.NextRunAt = "idle", &next
		beat()
		trigger = "schedule"
		idle := time.NewTicker(30 * time.Second)
	wait:
		for {
			select {
			case <-ctx.Done():
				idle.Stop()
				log.Info("shutting down")
				return nil
			case <-idle.C:
				beat()
				if !time.Now().Before(next) {
					break wait
				}
			}
		}
		idle.Stop()
	}
}

// fixed is what the store and the logs are set up with at the start.
func fixed(c *config.Config) string {
	m := c.Monitoring
	return fmt.Sprint(c.Mongo, c.Costs.Database, c.Costs.Collection, c.MonitoringEnabled(), m.LogLevel, m.LogRetentionDays, m.RunRetentionDays)
}

// sampleContainers prints raw container findings, so the fields Defender
// uses to describe an image or a running container can be checked against
// what pkg/graph/containers.go looks for.
func sampleContainers(ctx context.Context, cfg *config.Config, n int) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	for _, t := range cfg.Tenants {
		client := azure.NewClient(t, cfg.Endpoints, nil)
		for _, kind := range []string{".containerimage", "K8s-container"} {
			query := fmt.Sprintf(`securityresources
| where type == 'microsoft.security/assessments'
| where properties.metadata.recommendationCategory == 'SoftwareUpdate'
| where properties.resourceDetails.ResourceType =~ '%s'
| project id, properties
| take %d`, kind, n)
			fmt.Printf("// %s: %s\n", t.Name, kind)
			err := client.ResourceGraphRows(ctx, query, func(rows []azure.Row) error { return enc.Encode(rows) })
			if err != nil {
				return fmt.Errorf("%s: %w", t.Name, err)
			}
		}
	}
	return nil
}
