// Package config loads ns-check's JSON configuration.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path"
	"strings"
	"time"
)

// Duration is a time.Duration written as a string ("1m", "30s").
type Duration time.Duration

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return errors.New(`durations are strings such as "1m" or "30s"`)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

func (d Duration) D() time.Duration { return time.Duration(d) }

// Threshold is the pair of levels a value is compared with.
type Threshold struct {
	Warning  float64 `json:"warning"`
	Critical float64 `json:"critical"`
}

// Ignore lists name patterns of objects that are stored but never counted
// against an appliance. * matches any run of characters; case is ignored.
type Ignore struct {
	Vservers     []string `json:"vservers"`
	Services     []string `json:"services"`
	Certificates []string `json:"certificates"`
	Interfaces   []string `json:"interfaces"`
}

type Config struct {
	Mongo struct {
		URI      string `json:"uri"`
		Database string `json:"database"`
		// EnsureIndexes creates the indexes at start-up. Turn it off and run
		// `datafetch ns-check -init-db` once if the checker's account may not.
		EnsureIndexes *bool `json:"ensureIndexes"`
	} `json:"mongo"`
	// Interval between passes when started with -loop.
	Interval          Duration `json:"interval"`
	HeartbeatInterval Duration `json:"heartbeatInterval"`
	// Timeout of one request to an appliance.
	Timeout Duration `json:"timeout"`
	// Concurrency is how many appliances are checked at once.
	Concurrency int `json:"concurrency"`
	Retention   struct {
		LogsDays    int `json:"logsDays"`
		RunsDays    int `json:"runsDays"`
		SamplesDays int `json:"samplesDays"`
		EventsDays  int `json:"eventsDays"`
	} `json:"retention"`
	Logging struct {
		Level      string `json:"level"`      // local log
		MongoLevel string `json:"mongoLevel"` // what is sent to nsc_logs
		Format     string `json:"format"`     // text or json
	} `json:"logging"`

	Thresholds struct {
		// Percentages. CPU is the packet engines; MgmtCPU the management CPU.
		CPU     Threshold `json:"cpu"`
		MgmtCPU Threshold `json:"mgmtCpu"`
		Memory  Threshold `json:"memory"`
		Disk    Threshold `json:"disk"`
		// CertificateDays: days left before a certificate expires.
		CertificateDays Threshold `json:"certificateDays"`
		// VserverHealthPercent: a virtual server that is up with a smaller
		// share of its services up is degraded. 100 flags any service
		// down; 0 switches it off.
		VserverHealthPercent *float64 `json:"vserverHealthPercent"`
	} `json:"thresholds"`

	// Checks switches parts of the pass off. All are on by default.
	Checks struct {
		Hardware     *bool `json:"hardware"`
		Config       *bool `json:"config"`
		HA           *bool `json:"ha"`
		Interfaces   *bool `json:"interfaces"`
		Vservers     *bool `json:"vservers"`
		Services     *bool `json:"services"`
		Certificates *bool `json:"certificates"`
	} `json:"checks"`

	Ignore Ignore `json:"ignore"`

	// DumpDir, when set, receives every NITRO response as a file per
	// appliance and resource, overwritten each pass. For troubleshooting.
	DumpDir string `json:"dumpDir"`

	// Defaults apply to appliances that do not set the field themselves.
	Defaults struct {
		Username      string `json:"username"`
		Password      string `json:"password"`
		PasswordEnv   string `json:"passwordEnv"`
		TLSSkipVerify bool   `json:"tlsSkipVerify"`
		CAFile        string `json:"caFile"`
	} `json:"defaults"`

	Appliances []Appliance `json:"appliances"`
}

// Appliance is one NetScaler to check. In a high-availability pair, list
// both nodes by their own NSIP.
type Appliance struct {
	// Name is the label stored on every document about the appliance.
	Name string `json:"name"`
	// TenantName is an optional label to group appliances by.
	TenantName string `json:"tenantName"`
	// Address is the management address: https://10.0.0.10, or a bare host
	// name or IP (https is assumed).
	Address  string `json:"address"`
	Username string `json:"username"`
	Password string `json:"password"`
	// PasswordEnv names an environment variable holding the password.
	PasswordEnv string `json:"passwordEnv"`
	// TLSSkipVerify accepts any certificate; CAFile is a PEM bundle to
	// verify the management certificate against instead.
	TLSSkipVerify *bool  `json:"tlsSkipVerify"`
	CAFile        string `json:"caFile"`
	// RequireHA makes a node that is not in a pair critical.
	RequireHA bool `json:"requireHA"`
	// Ignore adds to the global ignore patterns.
	Ignore Ignore `json:"ignore"`

	// SkipVerify is TLSSkipVerify with the default applied.
	SkipVerify bool `json:"-"`
}

func on(b *bool) bool { return b == nil || *b }

func (c *Config) EnsureIndexes() bool     { return on(c.Mongo.EnsureIndexes) }
func (c *Config) CheckHardware() bool     { return on(c.Checks.Hardware) }
func (c *Config) CheckConfig() bool       { return on(c.Checks.Config) }
func (c *Config) CheckHA() bool           { return on(c.Checks.HA) }
func (c *Config) CheckInterfaces() bool   { return on(c.Checks.Interfaces) }
func (c *Config) CheckVservers() bool     { return on(c.Checks.Vservers) }
func (c *Config) CheckServices() bool     { return on(c.Checks.Services) }
func (c *Config) CheckCertificates() bool { return on(c.Checks.Certificates) }

// VserverHealth is the health percentage below which a virtual server that
// is up counts as degraded.
func (c *Config) VserverHealth() float64 {
	if c.Thresholds.VserverHealthPercent == nil {
		return 100
	}
	return *c.Thresholds.VserverHealthPercent
}

// Matches reports whether name matches one of the patterns.
func Matches(patterns []string, name string) bool {
	name = strings.ToLower(name)
	for _, p := range patterns {
		if ok, _ := path.Match(p, name); ok {
			return true
		}
	}
	return false
}

// Load reads and validates the file. Environment variables override the
// MongoDB settings (NSCHECK_MONGO_URI, NSCHECK_MONGO_DATABASE) and can
// supply the appliances (NSCHECK_APPLIANCES, a JSON array, or
// NSCHECK_APPLIANCES_FILE).
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b, os.Getenv, os.ReadFile)
}

func Parse(b []byte, getenv func(string) string, readFile func(string) ([]byte, error)) (*Config, error) {
	var c Config
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if v := getenv("NSCHECK_MONGO_URI"); v != "" {
		c.Mongo.URI = v
	}
	if v := getenv("NSCHECK_MONGO_DATABASE"); v != "" {
		c.Mongo.Database = v
	}
	if f := getenv("NSCHECK_APPLIANCES_FILE"); f != "" {
		raw, err := readFile(f)
		if err != nil {
			return nil, fmt.Errorf("config: NSCHECK_APPLIANCES_FILE: %w", err)
		}
		if err := json.Unmarshal(raw, &c.Appliances); err != nil {
			return nil, fmt.Errorf("config: %s: expected a JSON array of appliances: %w", f, err)
		}
	}
	if v := getenv("NSCHECK_APPLIANCES"); v != "" {
		if err := json.Unmarshal([]byte(v), &c.Appliances); err != nil {
			return nil, fmt.Errorf("config: NSCHECK_APPLIANCES: expected a JSON array of appliances: %w", err)
		}
	}
	if c.Mongo.Database == "" {
		c.Mongo.Database = "nscheck"
	}
	if c.Interval == 0 {
		c.Interval = Duration(time.Minute)
	}
	if c.Interval.D() < 15*time.Second {
		return nil, errors.New("config: interval must be at least 15s")
	}
	if c.HeartbeatInterval == 0 {
		c.HeartbeatInterval = Duration(30 * time.Second)
	}
	// The dashboard treats a run as stalled after five minutes of silence.
	if hb := c.HeartbeatInterval.D(); hb < 5*time.Second || hb > time.Minute {
		return nil, errors.New("config: heartbeatInterval must be between 5s and 1m")
	}
	if c.Timeout == 0 {
		c.Timeout = Duration(20 * time.Second)
	}
	if t := c.Timeout.D(); t < time.Second || t > 5*time.Minute {
		return nil, errors.New("config: timeout must be between 1s and 5m")
	}
	if c.Concurrency <= 0 {
		c.Concurrency = 8
	}
	def := func(v *int, d int) {
		if *v == 0 {
			*v = d
		}
	}
	def(&c.Retention.LogsDays, 30)
	def(&c.Retention.RunsDays, 14)
	def(&c.Retention.SamplesDays, 30)
	def(&c.Retention.EventsDays, 180)
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	if c.Logging.MongoLevel == "" {
		c.Logging.MongoLevel = "info"
	}

	th := &c.Thresholds
	for _, t := range []struct {
		name string
		v    *Threshold
		d    Threshold
	}{
		{"cpu", &th.CPU, Threshold{75, 90}},
		{"mgmtCpu", &th.MgmtCPU, Threshold{80, 95}},
		{"memory", &th.Memory, Threshold{80, 90}},
		{"disk", &th.Disk, Threshold{80, 90}},
	} {
		if *t.v == (Threshold{}) {
			*t.v = t.d
		}
		if t.v.Warning <= 0 || t.v.Critical < t.v.Warning || t.v.Critical > 100 {
			return nil, fmt.Errorf("config: thresholds.%s: need 0 < warning <= critical <= 100", t.name)
		}
	}
	if th.CertificateDays == (Threshold{}) {
		th.CertificateDays = Threshold{Warning: 30, Critical: 7}
	}
	if th.CertificateDays.Critical < 0 || th.CertificateDays.Warning < th.CertificateDays.Critical {
		return nil, errors.New("config: thresholds.certificateDays: need warning >= critical >= 0")
	}
	if v := th.VserverHealthPercent; v != nil && (*v < 0 || *v > 100) {
		return nil, errors.New("config: thresholds.vserverHealthPercent must be between 0 and 100")
	}
	if err := c.Ignore.clean("ignore"); err != nil {
		return nil, err
	}

	if len(c.Appliances) == 0 {
		return nil, errors.New("config: no appliances configured (appliances, NSCHECK_APPLIANCES or NSCHECK_APPLIANCES_FILE)")
	}
	if c.Defaults.PasswordEnv != "" {
		if v := getenv(c.Defaults.PasswordEnv); v != "" {
			c.Defaults.Password = v
		}
	}
	names, addrs := map[string]bool{}, map[string]bool{}
	for i := range c.Appliances {
		a := &c.Appliances[i]
		a.Name = strings.TrimSpace(a.Name)
		a.TenantName = strings.TrimSpace(a.TenantName)
		where := fmt.Sprintf("config: appliances[%d]", i)
		if a.Name == "" {
			return nil, fmt.Errorf("%s: name is required", where)
		}
		where += " (" + a.Name + ")"
		addr, err := normaliseAddress(a.Address)
		if err != nil {
			return nil, fmt.Errorf("%s: address: %w", where, err)
		}
		a.Address = addr
		if names[strings.ToLower(a.Name)] || addrs[a.Address] {
			return nil, fmt.Errorf("%s: the name or address is configured twice", where)
		}
		names[strings.ToLower(a.Name)], addrs[a.Address] = true, true

		if a.Username == "" {
			a.Username = c.Defaults.Username
		}
		if a.PasswordEnv != "" {
			if v := getenv(a.PasswordEnv); v != "" {
				a.Password = v
			}
		}
		if a.Password == "" {
			a.Password = c.Defaults.Password
		}
		if a.Username == "" || a.Password == "" {
			return nil, fmt.Errorf("%s: username and a password (password or passwordEnv, here or in defaults) are required", where)
		}
		a.SkipVerify = c.Defaults.TLSSkipVerify
		if a.TLSSkipVerify != nil {
			a.SkipVerify = *a.TLSSkipVerify
		}
		if a.CAFile == "" {
			a.CAFile = c.Defaults.CAFile
		}
		if err := a.Ignore.clean(where + ": ignore"); err != nil {
			return nil, err
		}
		// The global patterns apply to every appliance.
		a.Ignore.Vservers = append(a.Ignore.Vservers, c.Ignore.Vservers...)
		a.Ignore.Services = append(a.Ignore.Services, c.Ignore.Services...)
		a.Ignore.Certificates = append(a.Ignore.Certificates, c.Ignore.Certificates...)
		a.Ignore.Interfaces = append(a.Ignore.Interfaces, c.Ignore.Interfaces...)
	}
	return &c, nil
}

func (ig *Ignore) clean(where string) error {
	for _, list := range [][]string{ig.Vservers, ig.Services, ig.Certificates, ig.Interfaces} {
		for i, p := range list {
			p = strings.ToLower(strings.TrimSpace(p))
			if _, err := path.Match(p, ""); err != nil || p == "" {
				return fmt.Errorf("%s: %q is not a valid pattern", where, list[i])
			}
			list[i] = p
		}
	}
	return nil
}

// normaliseAddress returns scheme://host[:port] for a management address.
func normaliseAddress(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("is required")
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", err
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", errors.New("must be http or https")
	}
	if u.Host == "" || u.User != nil || strings.Trim(u.Path, "/") != "" || u.RawQuery != "" {
		return "", errors.New("give just the host, as https://host or https://host:port")
	}
	return u.Scheme + "://" + strings.ToLower(u.Host), nil
}
