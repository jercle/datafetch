// Package config loads and validates the collector configuration.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jercle/datafetch/azurecves/pkg/graph"
)

// Tenant is one entry of the tenant array, in the shape stored in Azure App
// Configuration: tenantName, tenantId, clientId, clientSecret.
type Tenant struct {
	Name         string `json:"tenantName"`
	ID           string `json:"tenantId"`
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
}

// UnmarshalJSON also accepts "name" for the tenant name. Key matching is
// case-insensitive, so TenantName / tenantname work too.
func (t *Tenant) UnmarshalJSON(b []byte) error {
	type plain Tenant
	aux := struct {
		*plain
		Alt string `json:"name"`
	}{plain: (*plain)(t)}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	if t.Name == "" {
		t.Name = aux.Alt
	}
	t.Name = strings.TrimSpace(t.Name)
	t.ID = strings.ToLower(strings.TrimSpace(t.ID))
	t.ClientID = strings.TrimSpace(t.ClientID)
	return nil
}

// Duration accepts Go durations ("90m", "6h") plus a day suffix ("7d").
type Duration time.Duration

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return errors.New(`duration must be a string such as "6h"`)
	}
	v, err := ParseDuration(s)
	*d = Duration(v)
	return err
}

func ParseDuration(s string) (time.Duration, error) {
	if n, ok := strings.CutSuffix(s, "d"); ok {
		days, err := strconv.ParseFloat(n, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		return time.Duration(days * 24 * float64(time.Hour)), nil
	}
	return time.ParseDuration(s)
}

type Mongo struct {
	URI      string `json:"uri"`
	Database string `json:"database"`
}

// Costs points at the data written by azcost-collector on the same MongoDB
// server; it is read to put cost figures on graph nodes.
type Costs struct {
	Enabled    *bool  `json:"enabled"`
	Database   string `json:"database"`
	Collection string `json:"collection"`
	CostType   string `json:"costType"`
}

type Monitoring struct {
	Enabled          *bool  `json:"enabled"`
	LogLevel         string `json:"logLevel"`
	LogRetentionDays int    `json:"logRetentionDays"`
	RunRetentionDays int    `json:"runRetentionDays"`
}

// Endpoints only need changing for sovereign clouds (or tests).
type Endpoints struct {
	Authority     string `json:"authority"`
	ARM           string `json:"arm"`
	ARMScope      string `json:"armScope"`
	Defender      string `json:"defender"`
	DefenderScope string `json:"defenderScope"`
}

type Config struct {
	Tenants  []Tenant `json:"tenants"`
	Mongo    Mongo    `json:"mongo"`
	Interval Duration `json:"interval"`
	// TenantConcurrency is how many tenants are collected at once.
	TenantConcurrency int `json:"tenantConcurrency"`
	// Disable lists stages to skip: resources, devices, software,
	// vulnerabilities, containers, cveDetails, costs.
	Disable []string `json:"disable"`
	// DefenderPageSize is the pageSize for the Defender export APIs.
	DefenderPageSize int `json:"defenderPageSize"`
	// CVEDetailsEvery is how often the CVE catalogue (descriptions, exploit
	// flags) is refreshed; it is the same for every tenant and large.
	CVEDetailsEvery Duration `json:"cveDetailsEvery"`
	// HostnameFallback (default true): machine records that share no stable
	// ID are merged into one device when their computerDnsName matches and
	// their Azure VM IDs don't conflict.
	HostnameFallback *bool `json:"hostnameFallback"`
	// MatchByHostname treats the hostname as an identifier with no VM ID check.
	MatchByHostname bool `json:"matchByHostname"`
	// DeviceGroups split devices into named groups by last IP address,
	// computer name or cloud; the first group that matches wins. Groups
	// marked hidden are left out of the dashboard unless asked for.
	DeviceGroups []graph.GroupDef `json:"deviceGroups"`
	// DefaultDeviceGroup names the group for devices that match none
	// (default "Other"); DefaultDeviceGroupHidden hides it by default.
	DefaultDeviceGroup       string `json:"defaultDeviceGroup"`
	DefaultDeviceGroupHidden bool   `json:"defaultDeviceGroupHidden"`
	// ProgressEvery is how often a stage that is still running logs what it
	// is doing. Default 1m.
	ProgressEvery Duration `json:"progressEvery"`
	// ResolveImageTags asks each Azure Container Registry for its tags when
	// Defender's findings identify an image by digest only. Default true.
	ResolveImageTags *bool `json:"resolveImageTags"`
	// StoreProperties keeps each resource's full ARM properties on its node.
	StoreProperties bool       `json:"storeProperties"`
	Costs           Costs      `json:"costs"`
	Monitoring      Monitoring `json:"monitoring"`
	Endpoints       Endpoints  `json:"endpoints"`
}

var Stages = []string{"resources", "devices", "software", "vulnerabilities", "containers", "cveDetails", "costs"}

func (c *Config) Enabled(stage string) bool {
	for _, d := range c.Disable {
		if strings.EqualFold(d, stage) {
			return false
		}
	}
	if stage == "costs" && c.Costs.Enabled != nil {
		return *c.Costs.Enabled
	}
	return true
}

func (c *Config) MonitoringEnabled() bool {
	return c.Monitoring.Enabled == nil || *c.Monitoring.Enabled
}

// Load reads the optional JSON file, then applies environment overrides:
//
//	MONGO_URI            MongoDB connection string
//	AZCVES_DB            database name
//	AZCVES_TENANTS       JSON array of tenant configs
//	AZCVES_TENANTS_FILE  path of a file holding that array
//	AZCVES_INTERVAL      time between collections
func Load(path string, env func(string) string) (*Config, error) {
	var b []byte
	if path != "" {
		var err error
		if b, err = os.ReadFile(path); err != nil {
			return nil, err
		}
	}
	c, err := Parse(b, env)
	if err != nil && path != "" {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, err
}

// Parse reads the configuration JSON (which may be empty), then applies the
// environment overrides, the defaults and the validation.
func Parse(b []byte, env func(string) string) (*Config, error) {
	c := &Config{}
	if len(strings.TrimSpace(string(b))) > 0 {
		if err := json.Unmarshal(b, c); err != nil {
			return nil, err
		}
	}
	if v := env("MONGO_URI"); v != "" {
		c.Mongo.URI = v
	}
	if v := env("AZCVES_DB"); v != "" {
		c.Mongo.Database = v
	}
	if v := env("AZCVES_INTERVAL"); v != "" {
		d, err := ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("AZCVES_INTERVAL: %w", err)
		}
		c.Interval = Duration(d)
	}
	if f := env("AZCVES_TENANTS_FILE"); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		if c.Tenants, err = ParseTenants(b); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
	}
	if v := env("AZCVES_TENANTS"); v != "" {
		t, err := ParseTenants([]byte(v))
		if err != nil {
			return nil, fmt.Errorf("AZCVES_TENANTS: %w", err)
		}
		c.Tenants = t
	}
	c.Defaults()
	return c, c.Validate()
}

// ParseTenants decodes the tenant array.
func ParseTenants(b []byte) ([]Tenant, error) {
	var t []Tenant
	if err := json.Unmarshal(b, &t); err != nil {
		return nil, fmt.Errorf("expected a JSON array of {tenantName, tenantId, clientId, clientSecret}: %w", err)
	}
	return t, nil
}

func (c *Config) Defaults() {
	def := func(s *string, v string) {
		if *s == "" {
			*s = v
		}
	}
	def(&c.Mongo.Database, "azcves")
	def(&c.DefaultDeviceGroup, "Other")
	def(&c.Costs.Database, "azcost")
	def(&c.Costs.Collection, "resource_costs")
	def(&c.Costs.CostType, "actual")
	def(&c.Monitoring.LogLevel, "info")
	def(&c.Endpoints.Authority, "https://login.microsoftonline.com")
	def(&c.Endpoints.ARM, "https://management.azure.com")
	def(&c.Endpoints.Defender, "https://api.securitycenter.microsoft.com")
	def(&c.Endpoints.ARMScope, strings.TrimRight(c.Endpoints.ARM, "/")+"/.default")
	def(&c.Endpoints.DefenderScope, strings.TrimRight(c.Endpoints.Defender, "/")+"/.default")
	if c.Interval <= 0 {
		c.Interval = Duration(6 * time.Hour)
	}
	if c.CVEDetailsEvery <= 0 {
		c.CVEDetailsEvery = Duration(24 * time.Hour)
	}
	if c.ProgressEvery <= 0 {
		c.ProgressEvery = Duration(time.Minute)
	}
	if c.TenantConcurrency <= 0 {
		c.TenantConcurrency = 4
	}
	if c.DefenderPageSize <= 0 {
		c.DefenderPageSize = 50000
	}
	if c.Monitoring.LogRetentionDays <= 0 {
		c.Monitoring.LogRetentionDays = 30
	}
	if c.Monitoring.RunRetentionDays <= 0 {
		c.Monitoring.RunRetentionDays = 180
	}
	for i := range c.Tenants {
		if c.Tenants[i].Name == "" {
			c.Tenants[i].Name = c.Tenants[i].ID
		}
	}
}

var guid = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func (c *Config) Validate() error {
	var errs []error
	if c.Mongo.URI == "" {
		errs = append(errs, errors.New("mongo.uri (or MONGO_URI) is required"))
	}
	if len(c.Tenants) == 0 {
		errs = append(errs, errors.New("no tenants configured (tenants, AZCVES_TENANTS or AZCVES_TENANTS_FILE)"))
	}
	seen := map[string]bool{}
	for i, t := range c.Tenants {
		who := fmt.Sprintf("tenants[%d] (%s)", i, t.Name)
		if !guid.MatchString(t.ID) {
			errs = append(errs, fmt.Errorf("%s: tenantId must be a GUID", who))
		}
		if t.ClientID == "" || t.ClientSecret == "" {
			errs = append(errs, fmt.Errorf("%s: clientId and clientSecret are required", who))
		}
		if seen[t.ID] {
			errs = append(errs, fmt.Errorf("%s: tenantId %s is listed twice", who, t.ID))
		}
		seen[t.ID] = true
	}
	for _, d := range c.Disable {
		ok := false
		for _, s := range Stages {
			ok = ok || strings.EqualFold(d, s)
		}
		if !ok {
			errs = append(errs, fmt.Errorf("disable: unknown stage %q (known: %s)", d, strings.Join(Stages, ", ")))
		}
	}
	if _, err := c.Grouper(); err != nil {
		errs = append(errs, err)
	}
	if c.DefenderPageSize > 200000 {
		errs = append(errs, errors.New("defenderPageSize: the API maximum is 200000"))
	}
	return errors.Join(errs...)
}

// Grouper returns the compiled device groups, or nil when none are configured.
func (c *Config) Grouper() (*graph.Grouper, error) {
	return graph.NewGrouper(c.DeviceGroups, c.DefaultDeviceGroup, c.DefaultDeviceGroupHidden)
}
