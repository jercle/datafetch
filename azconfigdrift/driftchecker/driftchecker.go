// Package driftchecker runs the az-config-drift collector. It is the
// collector's public entry point, for the az-config-drift command and for
// any program that wants to run it in-process: cloudini's cld, say, which
// already holds the configuration object it loads from Azure App
// Configuration.
//
// Configuration comes from two places. Settings, the object under the key
// datafetching.azConfigDrift in App Configuration, is what the dashboard edits; it
// is asked for before every pass and wins. The configuration file fills in
// whatever the settings do not say, and built-in defaults the rest. A
// setting that is not valid is ignored, with a warning, and the file's
// value or the default stands.
//
// With cloudini:
//
//	cfg := lib.GetCldConfig(nil) // has Datafetching map[string]any `json:"datafetching"`
//	err := driftchecker.Run(ctx, driftchecker.Options{
//		Loop: true,
//		Settings: func(context.Context) (driftchecker.Settings, error) {
//			return driftchecker.SettingsOf(lib.GetCldConfig(nil).Datafetching["azConfigDrift"])
//		},
//	})
package driftchecker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/jercle/datafetch/azconfigdrift/internal/catalog"
	"github.com/jercle/datafetch/azconfigdrift/internal/collector"
	"github.com/jercle/datafetch/azconfigdrift/internal/config"
	"github.com/jercle/datafetch/azconfigdrift/internal/model"
	"github.com/jercle/datafetch/azconfigdrift/internal/monitor"
	"github.com/jercle/datafetch/azconfigdrift/internal/settings"
	"github.com/jercle/datafetch/azconfigdrift/internal/store"
	"github.com/jercle/datafetch/azconfigdrift/internal/store/mongostore"
	"github.com/jercle/datafetch/internal/appconfig"
)

// Root is the App Configuration key the settings live under:
// datafetching.azConfigDrift.
const Root = settings.Root

// Settings is the object under datafetching.azConfigDrift: nested objects
// as an App Configuration provider builds them from "."-separated keys,
// with values that are typed or plain text. The whole configuration object,
// with the settings under datafetching.azConfigDrift, is accepted too.
//
//	{"interval": "6h", "concurrency": {"tenants": 2},
//	 "tenants": {"<tenant id>": {"tenantName": "...", "clientId": "...", "clientSecret": "..."}},
//	 "modules": {"m365-intune": {"enabled": true, "sources": {"scripts": {"beta": false}}}}}
type Settings = map[string]any

// SettingsFunc returns the current settings. It is called before every
// pass, so that what is changed in the dashboard applies to the next one.
type SettingsFunc func(ctx context.Context) (Settings, error)

// SettingsOf turns a value that holds the settings (a struct with JSON
// tags, a map, or JSON bytes) into Settings.
func SettingsOf(v any) (Settings, error) {
	var b []byte
	switch x := v.(type) {
	case nil:
		return Settings{}, nil
	case map[string]any:
		return x, nil
	case []byte:
		b = x
	case json.RawMessage:
		b = x
	default:
		var err error
		if b, err = json.Marshal(v); err != nil {
			return nil, err
		}
	}
	var out Settings
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("settings: expected a JSON object: %w", err)
	}
	return out, nil
}

// FromKeyValues builds Settings from flat key-values, for a client that
// returns "datafetching.azConfigDrift.interval" → "6h" rather than a nested
// object.
func FromKeyValues(kv map[string]any) Settings {
	return settings.Under(settings.Nest(kv))
}

// AppConfig returns a SettingsFunc that reads the settings from Azure App
// Configuration itself, signed in as the environment says (the variables
// cloudini uses: AZURE_APPCONFIG_ENDPOINT, AZURE_APPCONFIG_TENANT_ID,
// AZURE_APPCONFIG_CLIENT_ID, AZURE_APPCONFIG_CLIENT_SECRET or
// AZURE_APPCONFIG_MANAGED_IDENTITY, and AZURE_APPCONFIG_LABEL). ok is false
// when no endpoint is set. Key Vault references are resolved.
func AppConfig(getenv func(string) string) (fn SettingsFunc, ok bool, err error) {
	o, ok, err := appconfig.FromEnv(getenv)
	if !ok || err != nil {
		return nil, ok, err
	}
	client := appconfig.New(o)
	return func(ctx context.Context) (Settings, error) {
		ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		return fromStore(ctx, client.Load)
	}, true, nil
}

// fromStore reads the settings with load, which returns the key-values
// whose key starts with a prefix.
func fromStore(ctx context.Context, load func(ctx context.Context, prefix string) (map[string]any, []string, error)) (Settings, error) {
	kv, warnings, err := load(ctx, Root+".")
	if err != nil {
		return nil, err
	}
	s := FromKeyValues(kv)
	if len(kv) == 0 {
		// Nothing under the new key yet: the settings may still be where
		// the dashboard wrote them before the move to datafetch.
		old, oldWarnings, err := load(ctx, settings.LegacyRoot+".")
		if err != nil {
			return nil, err
		}
		if legacy, ok := settings.Nest(old)[settings.LegacyRoot].(map[string]any); ok && len(legacy) > 0 {
			s = legacy
			warnings = append(oldWarnings, "the settings were read from the old key "+settings.LegacyRoot+": move them under "+Root+" (they are ignored as soon as that key has any setting)")
		}
	}
	if len(warnings) > 0 {
		// Carried to the status the dashboard shows.
		s[referenceWarnings] = warnings
	}
	return s, nil
}

// referenceWarnings is a private key AppConfig uses to hand its warnings
// to the loader. It is removed before the settings are read.
const referenceWarnings = "\x00warnings"

// Options says how to run the collector.
type Options struct {
	// ConfigFile is the JSON configuration file. Optional when Settings
	// supplies the tenants and the MongoDB address.
	ConfigFile string
	// Settings supplies the datafetching.azConfigDrift object before every pass.
	// Nil runs on the file alone.
	Settings SettingsFunc
	// SettingsSource names where Settings reads from, for the status shown
	// in the dashboard: "appconfig", or "object" (the default) when the
	// embedding program hands the object in.
	SettingsSource string

	// Loop keeps running: a pass, then a wait for the interval or for a
	// request from the dashboard. Otherwise one pass is made.
	Loop bool
	// DryRun prints what would be stored and touches no database.
	DryRun bool
	// InitDB creates the indexes and returns.
	InitDB bool
	// Modules limits the pass to these module ids whatever their switches say.
	Modules []string
	// Tenant limits the pass to the tenant of this name.
	Tenant string

	Version string
	// LogOutput receives the local log (default: standard error); Out
	// receives the dry run's JSON lines (default: standard output).
	LogOutput io.Writer
	Out       io.Writer
	// Getenv reads environment variables (default: os.Getenv).
	Getenv func(string) string
}

// loaded is one reading of the configuration.
type loaded struct {
	cfg    *config.Config
	mods   []catalog.Module
	status model.SettingsStatus
}

type loader struct {
	o    Options
	file []byte
}

func newLoader(o Options) (*loader, error) {
	l := &loader{o: o}
	if o.ConfigFile == "" {
		return l, nil
	}
	b, err := os.ReadFile(o.ConfigFile)
	switch {
	case err == nil:
		l.file = b
	case errors.Is(err, os.ErrNotExist) && o.Settings != nil:
		// Everything may come from the settings.
	default:
		return nil, err
	}
	return l, nil
}

func (l *loader) parse(b []byte) (*config.Config, []catalog.Module, error) {
	cfg, err := config.Parse(b, l.o.Getenv, os.ReadFile)
	if err != nil {
		return nil, nil, err
	}
	if l.o.Tenant != "" {
		var keep []config.Tenant
		for _, t := range cfg.Tenants {
			if t.Name == l.o.Tenant {
				keep = append(keep, t)
			}
		}
		if len(keep) == 0 {
			return nil, nil, fmt.Errorf("no tenant named %q in the configuration", l.o.Tenant)
		}
		cfg.Tenants = keep
	}
	mods, err := catalog.Build(cfg)
	if err != nil {
		return nil, nil, err
	}
	known := map[string]bool{}
	for _, m := range mods {
		known[m.ID] = true
	}
	for _, id := range l.o.Modules {
		if !known[id] {
			return nil, nil, fmt.Errorf("there is no module %q (see -list-modules)", id)
		}
	}
	return cfg, mods, nil
}

// load reads the settings and lays them over the file. When the settings
// cannot be read, or the result is not a valid configuration, it falls back
// to the file alone and says why in the status.
func (l *loader) load(ctx context.Context) (*loaded, error) {
	status := model.SettingsStatus{Source: "file", LoadedAt: time.Now().UTC(), Warnings: []string{}}
	if l.o.Settings != nil {
		source := l.o.SettingsSource
		if source == "" {
			source = "object"
		}
		s, err := l.o.Settings(ctx)
		if err != nil {
			status.Error = "the settings could not be read: " + err.Error()
		} else {
			// Work on a copy: the object belongs to the caller.
			own := make(Settings, len(s))
			for k, v := range settings.Under(s) {
				own[k] = v
			}
			var extra []string
			if w, ok := own[referenceWarnings].([]string); ok {
				extra = w
			}
			delete(own, referenceWarnings)
			res, err := settings.Merge(l.file, own)
			if err == nil {
				cfg, mods, perr := l.parse(res.Config)
				if perr == nil {
					status.Source, status.Applied = source, res.Applied
					status.Warnings = append(append(status.Warnings, extra...), res.Warnings...)
					return &loaded{cfg, mods, status}, nil
				}
				err = perr
			}
			status.Warnings = append(status.Warnings, extra...)
			status.Error = "the settings were not used, the configuration file is: " + err.Error()
		}
	}
	if len(strings.TrimSpace(string(l.file))) == 0 {
		if status.Error != "" {
			return nil, errors.New(status.Error + " (and there is no configuration file to fall back to)")
		}
		return nil, errors.New("no configuration: give a configuration file, or settings under " + Root + " in App Configuration")
	}
	cfg, mods, err := l.parse(l.file)
	if err != nil {
		return nil, err
	}
	return &loaded{cfg, mods, status}, nil
}

// ListModules prints the modules and their sources.
func ListModules(w io.Writer, configFile string) error {
	cfg := &config.Config{}
	if b, err := os.ReadFile(configFile); err == nil {
		// Extra sources and defaults from the file, when it is usable.
		if c, err := config.Parse(b, os.Getenv, os.ReadFile); err == nil {
			cfg = c
		}
	}
	mods, err := catalog.Build(cfg)
	if err != nil {
		return err
	}
	for _, m := range mods {
		state := "on"
		if !m.DefaultEnabled {
			state = "off"
		}
		fmt.Fprintf(w, "%s  (%s, %s by default)  %s\n", m.ID, m.Platform, state, m.Name)
		for _, s := range m.Sources {
			how := ""
			if s.Beta {
				how += ", beta"
			}
			if s.Delegated {
				how += ", as the service account"
			}
			fmt.Fprintf(w, "    %-32s %s  [%s%s]\n", s.ID, s.Reads(), s.Permission, how)
		}
	}
	return nil
}

// Run runs the collector until the pass is done, or with Loop until ctx is
// cancelled. It returns an error when the configuration cannot be loaded at
// all, when the store cannot be opened, or when a single pass failed.
func Run(ctx context.Context, o Options) error {
	if o.Getenv == nil {
		o.Getenv = os.Getenv
	}
	if o.LogOutput == nil {
		o.LogOutput = os.Stderr
	}
	if o.Out == nil {
		o.Out = os.Stdout
	}
	if o.Version == "" {
		o.Version = "dev"
	}
	l, err := newLoader(o)
	if err != nil {
		return err
	}
	cur, err := l.load(ctx)
	if err != nil {
		return err
	}
	cfg := cur.cfg

	var st store.Store
	retention := mongostore.Retention{LogsDays: cfg.Retention.LogsDays, RunsDays: cfg.Retention.RunsDays, ChangesDays: cfg.Retention.ChangesDays}
	if o.DryRun {
		mem := store.NewMemory()
		mem.Out = o.Out
		st = mem
	} else {
		ms, err := mongostore.Open(cfg.Mongo.URI, cfg.Mongo.Database, "az-config-drift/"+o.Version)
		if err != nil {
			return err
		}
		st = ms
		ictx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		if o.InitDB {
			defer cancel()
			if err := ms.Ping(ictx); err != nil {
				return fmt.Errorf("cannot reach MongoDB: %w", err)
			}
			if err := ms.EnsureIndexes(ictx, retention); err != nil {
				return err
			}
			fmt.Fprintf(o.Out, "indexes are in place in database %q\n", cfg.Mongo.Database)
			return nil
		}
		if cfg.EnsureIndexes() {
			if err := ms.EnsureIndexes(ictx, retention); err != nil {
				fmt.Fprintln(o.LogOutput, "az-config-drift: indexes not ensured:", err)
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
	var local slog.Handler = slog.NewTextHandler(o.LogOutput, hopts)
	if cfg.Logging.Format == "json" {
		local = slog.NewJSONHandler(o.LogOutput, hopts)
	}
	log := slog.New(sink.Handler(local))

	inst := model.Instance{
		ID: host, Host: host, Version: o.Version, Mode: "once", PID: os.Getpid(),
		HeartbeatSeconds: int(cfg.HeartbeatInterval.D() / time.Second),
	}
	if o.Loop {
		inst.Mode = "schedule"
	}
	mon := monitor.New(st, log, inst)

	ctx, stop := context.WithCancel(ctx)
	beatDone := make(chan struct{})
	go func() {
		mon.Loop(ctx)
		close(beatDone)
	}()
	defer func() {
		stop()
		<-beatDone
	}()

	// started is what the store and the logs were set up with: these only
	// change at a restart.
	started := cfg
	reported := ""
	apply := func(cur *loaded) *collector.Collector {
		c := cur.cfg
		mon.Update(func(i *model.Instance) {
			// A new list: a heartbeat may be writing the old one.
			tenants := make([]model.Scope, 0, len(c.Tenants))
			for _, t := range c.Tenants {
				tenants = append(tenants, model.Scope{TenantID: t.ID, TenantName: t.Name})
			}
			i.Tenants = tenants
			if o.Loop {
				i.IntervalSeconds = int(c.Interval.D() / time.Second)
			}
			s := cur.status
			s.Effective = effective(c)
			i.Settings = &s
		})
		// Say what the settings did once, and again when it changes.
		summary := cur.status.Source + "|" + cur.status.Error + "|" + strings.Join(cur.status.Warnings, "|")
		if summary != reported {
			reported = summary
			log.Info("configuration loaded", "source", cur.status.Source, "settingsApplied", cur.status.Applied, "tenants", len(c.Tenants), "interval", c.Interval.D().String())
			if cur.status.Error != "" {
				log.Error("settings from App Configuration not used", "error", cur.status.Error)
			}
			for _, w := range cur.status.Warnings {
				log.Warn("setting ignored", "setting", w)
			}
		}
		if !o.DryRun && (c.Mongo.URI != started.Mongo.URI || c.Mongo.Database != started.Mongo.Database || c.Logging != started.Logging || c.HeartbeatInterval != started.HeartbeatInterval) {
			log.Warn("the database, logging and heartbeat settings changed; they apply when the collector is restarted")
			// Warn once per change, not on every pass.
			started = c
		}
		return &collector.Collector{Cfg: c, Modules: cur.mods, Store: st, Mon: mon, Log: log, SetRun: sink.SetRun, Version: o.Version, Only: o.Modules}
	}

	col := apply(cur)
	log.Info("az-config-drift started", "version", o.Version, "mode", inst.Mode, "tenants", len(cfg.Tenants), "modules", len(cur.mods))
	if !o.Loop {
		r := col.Run(ctx, "manual", nil)
		sink.Flush()
		if r.Status == model.StatusFailed {
			return fmt.Errorf("run %s failed: %s", r.ID, r.Error)
		}
		return nil
	}

	trigger := "schedule"
	for first := true; ; first = false {
		if !first {
			// What was changed in the dashboard since the last pass.
			next, err := l.load(ctx)
			if err != nil {
				log.Error("configuration not reloaded; the pass runs on what was loaded before", "error", err)
				s := cur.status
				s.Error, s.LoadedAt = "not reloaded: "+err.Error(), time.Now().UTC()
				mon.Update(func(i *model.Instance) { i.Settings = &s })
			} else {
				cur = next
				col = apply(cur)
			}
		}
		begun := time.Now().UTC()
		next := begun.Add(cur.cfg.Interval.D())
		col.Run(ctx, trigger, &next)
		trigger = waitForNext(ctx, st, log, begun, next, cur.cfg.HeartbeatInterval.D())
		if trigger == "" {
			log.Info("az-config-drift stopping")
			return nil
		}
	}
}

// effective lists the settings as the collector uses them, wherever each
// came from, by the keys they have under the root in App Configuration.
// The dashboard shows them behind a setting it does not set itself, and
// creates the keys that do not exist yet from them. Secrets are left out:
// client secrets, passwords and the MongoDB address.
func effective(c *config.Config) []model.SettingValue {
	var out []model.SettingValue
	add := func(key string, value any) {
		text := ""
		switch x := value.(type) {
		case time.Duration:
			text = compact(x)
		case []string:
			text = strings.Join(x, ", ")
		case string:
			text = x
		default:
			text = fmt.Sprint(value)
		}
		out = append(out, model.SettingValue{Key: key, Value: text})
	}
	list := func(key string, value any, n int) {
		// Lists of objects, as the JSON they are stored as.
		b, err := json.Marshal(value)
		if err != nil || n == 0 {
			b = []byte("[]")
		}
		out = append(out, model.SettingValue{Key: key, Value: string(b)})
	}
	add("interval", c.Interval.D())
	add("heartbeatInterval", c.HeartbeatInterval.D())
	add("concurrency.tenants", c.Concurrency.Tenants)
	add("concurrency.modules", c.Concurrency.Modules)
	add("retention.logsDays", c.Retention.LogsDays)
	add("retention.runsDays", c.Retention.RunsDays)
	add("retention.changesDays", c.Retention.ChangesDays)
	add("logging.level", c.Logging.Level)
	add("logging.mongoLevel", c.Logging.MongoLevel)
	add("logging.format", c.Logging.Format)
	add("limits.maxItemBytes", c.Limits.MaxItemBytes)
	add("limits.changePaths", c.Limits.ChangePaths)
	add("limits.sourceTimeout", c.Limits.SourceTimeout.D())
	add("mongo.database", c.Mongo.Database)
	add("mongo.ensureIndexes", c.EnsureIndexes())
	add("skipSources", c.SkipSources)
	list("ignore", c.Ignore, len(c.Ignore))
	list("exclude", c.Exclude, len(c.Exclude))
	list("extraSources", c.ExtraSources, len(c.ExtraSources))
	for _, t := range c.Tenants {
		k := "tenants." + t.ID + "."
		add(k+"tenantName", t.Name)
		add(k+"clientId", t.ClientID)
		add(k+"cloud", t.Cloud)
		add(k+"platforms", t.Platforms)
		add(k+"subscriptions", t.Subscriptions)
		add(k+"excludeSubscriptions", t.ExcludeSubscriptions)
		add(k+"initialDomain", t.InitialDomain)
		add(k+"username", t.Username)
		add(k+"delegatedClientId", t.DelegatedClientID)
	}
	return out
}

// compact writes a duration the way it is typed: 6h, not 6h0m0s.
func compact(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

// waitForNext returns "schedule" when the next pass is due, "request" when
// the dashboard asked for one since the last pass started, and "" when the
// collector is stopping.
func waitForNext(ctx context.Context, st store.Store, log *slog.Logger, started, next time.Time, poll time.Duration) string {
	tick := time.NewTicker(poll)
	defer tick.Stop()
	due := time.NewTimer(time.Until(next))
	defer due.Stop()
	for {
		select {
		case <-ctx.Done():
			return ""
		case <-due.C:
			return "schedule"
		case <-tick.C:
			rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			at, err := st.RunRequested(rctx)
			cancel()
			if err == nil && at.After(started) {
				log.Info("a pass was requested from the dashboard", "requestedAt", at)
				return "request"
			}
		}
	}
}
