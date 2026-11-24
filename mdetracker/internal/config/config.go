// Package config loads and validates the collector configuration.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Collection modes: which Defender devices are treated as "VMs".
const (
	ModeVMs     = "vms"     // only devices with Azure vmMetadata (resourceId / vmId)
	ModeServers = "servers" // Azure VMs plus any server OS (on-prem, Arc, other clouds)
	ModeAll     = "all"     // every onboarded device
)

// Auth types.
const (
	AuthSecret      = "secret"
	AuthCertificate = "certificate"
	AuthWorkload    = "workload" // AKS / k8s workload identity federation
	AuthDefault     = "default"  // DefaultAzureCredential pinned to the tenant
)

// No filter by default: offboarded records in the old org are evidence of a
// migration. Set "filter": "onboardingStatus eq 'Onboarded'" per tenant to narrow it.
const defaultFilter = ""

// Duration accepts Go durations ("90m", "48h") plus a day suffix ("7d").
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf(`duration must be a string such as "1h" or "7d": %w`, err)
	}
	v, err := ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" {
		return 0, nil
	}
	if strings.HasSuffix(s, "d") {
		n, err := strconv.ParseFloat(strings.TrimSuffix(s, "d"), 64)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		return time.Duration(n * float64(24*time.Hour)), nil
	}
	return time.ParseDuration(s)
}

type Config struct {
	Mongo Mongo `json:"mongo"`

	// Interval between runs. 0 / omitted = run once and exit (CronJob / Container App Job).
	Interval Duration `json:"interval"`

	// Defender for Endpoint API. Override per tenant for GCC / sovereign clouds.
	APIBase string `json:"apiBase"`
	Scope   string `json:"scope"`

	Mode            string `json:"mode"`
	MatchByHostname bool   `json:"matchByHostname"`
	// HostnameFallback (default true): records that share no stable ID are merged
	// when their computerDnsName matches and their Azure VM IDs don't conflict.
	HostnameFallback *bool `json:"hostnameFallback,omitempty"`

	// A record in another org is only a "conflict" if it reported within this window.
	ActiveWindow Duration `json:"activeWindow"`
	// The current record is "inactive" if it hasn't reported within this window.
	InactiveAfter Duration `json:"inactiveAfter"`

	Concurrency int `json:"concurrency"`
	PageSize    int `json:"pageSize"`

	// When false (default), if any tenant fails no VM documents are written, so a
	// missing tenant can't make VMs appear to have moved org.
	WriteOnPartial bool `json:"writeOnPartial"`

	// DumpDir, when set, writes everything collected in each run as JSON files
	// under <dumpDir>/<runId>/ for troubleshooting. DumpKeep = run folders kept (default 5).
	DumpDir  string `json:"dumpDir"`
	DumpKeep int    `json:"dumpKeep"`

	LogLevel      string `json:"logLevel"`
	MongoLogLevel string `json:"mongoLogLevel"`

	Tenants []Tenant `json:"tenants"`
}

type Mongo struct {
	URI              string `json:"uri"`
	Database         string `json:"database"`
	VMCollection     string `json:"vmCollection"`
	RunCollection    string `json:"runCollection"`
	LogCollection    string `json:"logCollection"`
	LogRetentionDays int    `json:"logRetentionDays"` // 0 = default 30, <0 = keep forever
}

type Tenant struct {
	Name     string  `json:"name"`
	TenantID string  `json:"tenantId"`
	OrgID    string  `json:"orgId"`
	Enabled  *bool   `json:"enabled,omitempty"`
	Filter   *string `json:"filter,omitempty"` // OData $filter, default none
	APIBase  string  `json:"apiBase,omitempty"`
	Scope    string  `json:"scope,omitempty"`
	Auth     Auth    `json:"auth"`
}

type Auth struct {
	Type                string `json:"type"`
	ClientID            string `json:"clientId"`
	ClientSecret        string `json:"clientSecret,omitempty"`
	CertificatePath     string `json:"certificatePath,omitempty"`
	CertificatePassword string `json:"certificatePassword,omitempty"`
}

func (t Tenant) IsEnabled() bool { return t.Enabled == nil || *t.Enabled }

func (t Tenant) EffectiveFilter() string {
	if t.Filter == nil {
		return defaultFilter
	}
	return *t.Filter
}

func (c *Config) HostnameFallbackEnabled() bool {
	return c.HostnameFallback == nil || *c.HostnameFallback
}

// EnabledTenants returns the tenants that should be collected.
func (c *Config) EnabledTenants() []Tenant {
	var out []Tenant
	for _, t := range c.Tenants {
		if t.IsEnabled() {
			out = append(out, t)
		}
	}
	return out
}

var envRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// Load reads a JSON config file, expanding ${ENV_VAR} references.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return Parse(raw)
}

func Parse(raw []byte) (*Config, error) {
	expanded, err := Expand(raw)
	if err != nil {
		return nil, err
	}
	return ParseExpanded(expanded)
}

// Expand replaces the ${ENV_VAR} references in a config file.
func Expand(raw []byte) ([]byte, error) {
	missing := map[string]bool{}
	expanded := envRef.ReplaceAllFunc(raw, func(m []byte) []byte {
		name := string(envRef.FindSubmatch(m)[1])
		v, ok := os.LookupEnv(name)
		if !ok {
			missing[name] = true
			return nil
		}
		// Values are substituted inside JSON strings, so escape them.
		b, _ := json.Marshal(v)
		return b[1 : len(b)-1]
	})
	if len(missing) > 0 {
		names := make([]string, 0, len(missing))
		for n := range missing {
			names = append(names, n)
		}
		sort.Strings(names)
		return nil, fmt.Errorf("config references unset environment variables: %s", strings.Join(names, ", "))
	}
	return expanded, nil
}

// ParseExpanded reads config JSON as it is: nothing in it is taken for a
// ${ENV_VAR} reference. It is what the settings from App Configuration,
// laid over the expanded file, are read with.
func ParseExpanded(expanded []byte) (*Config, error) {
	dec := json.NewDecoder(bytes.NewReader(expanded))
	dec.DisallowUnknownFields()
	var c Config
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	c.applyDefaults()
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	if v := os.Getenv("MONGODB_URI"); v != "" && c.Mongo.URI == "" {
		c.Mongo.URI = v
	}
	def := func(s *string, v string) {
		if *s == "" {
			*s = v
		}
	}
	def(&c.Mongo.Database, "mde")
	def(&c.Mongo.VMCollection, "mde_vms")
	def(&c.Mongo.RunCollection, "mde_runs")
	def(&c.Mongo.LogCollection, "mde_logs")
	if c.Mongo.LogRetentionDays == 0 {
		c.Mongo.LogRetentionDays = 30
	}
	def(&c.APIBase, "https://api.security.microsoft.com")
	def(&c.Scope, "https://api.securitycenter.microsoft.com/.default")
	def(&c.Mode, ModeVMs)
	def(&c.LogLevel, "info")
	def(&c.MongoLogLevel, c.LogLevel)
	if c.ActiveWindow.Duration == 0 {
		c.ActiveWindow.Duration = 48 * time.Hour
	}
	if c.InactiveAfter.Duration == 0 {
		c.InactiveAfter.Duration = 7 * 24 * time.Hour
	}
	if c.DumpKeep <= 0 {
		c.DumpKeep = 5
	}
	if c.Concurrency <= 0 {
		c.Concurrency = 4
	}
	if c.PageSize <= 0 || c.PageSize > 10000 {
		c.PageSize = 10000
	}
	for i := range c.Tenants {
		t := &c.Tenants[i]
		def(&t.Auth.Type, AuthSecret)
		def(&t.APIBase, c.APIBase)
		def(&t.Scope, c.Scope)
		t.TenantID = strings.TrimSpace(t.TenantID)
		t.OrgID = strings.ToLower(strings.TrimSpace(t.OrgID))
	}
}

func (c *Config) validate() error {
	var errs []error
	if c.Mongo.URI == "" {
		errs = append(errs, errors.New("mongo.uri (or MONGODB_URI) is required"))
	}
	switch c.Mode {
	case ModeVMs, ModeServers, ModeAll:
	default:
		errs = append(errs, fmt.Errorf("mode must be %q, %q or %q", ModeVMs, ModeServers, ModeAll))
	}
	names := map[string]bool{}
	enabled := 0
	for i, t := range c.Tenants {
		p := fmt.Sprintf("tenants[%d]", i)
		if t.Name == "" {
			errs = append(errs, fmt.Errorf("%s.name is required", p))
		} else if names[t.Name] {
			errs = append(errs, fmt.Errorf("%s.name %q is duplicated", p, t.Name))
		}
		names[t.Name] = true
		if !t.IsEnabled() {
			continue
		}
		enabled++
		if t.TenantID == "" {
			errs = append(errs, fmt.Errorf("%s.tenantId is required", p))
		}
		if t.OrgID == "" {
			errs = append(errs, fmt.Errorf("%s.orgId is required (Defender for Endpoint org ID for this tenant)", p))
		}
		switch t.Auth.Type {
		case AuthSecret:
			if t.Auth.ClientID == "" || t.Auth.ClientSecret == "" {
				errs = append(errs, fmt.Errorf("%s.auth: clientId and clientSecret are required for type secret", p))
			}
		case AuthCertificate:
			if t.Auth.ClientID == "" || t.Auth.CertificatePath == "" {
				errs = append(errs, fmt.Errorf("%s.auth: clientId and certificatePath are required for type certificate", p))
			}
		case AuthWorkload, AuthDefault:
		default:
			errs = append(errs, fmt.Errorf("%s.auth.type %q is not supported", p, t.Auth.Type))
		}
	}
	if enabled == 0 {
		errs = append(errs, errors.New("at least one enabled tenant is required"))
	}
	return errors.Join(errs...)
}
