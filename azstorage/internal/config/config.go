// Package config loads az-storage's JSON configuration.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"regexp"
	"strings"
	"time"
)

// Duration is a time.Duration written as a string ("24h", "90s").
type Duration time.Duration

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return errors.New(`durations are strings such as "24h" or "30s"`)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

func (d Duration) D() time.Duration { return time.Duration(d) }

type Config struct {
	Mongo struct {
		URI      string `json:"uri"`
		Database string `json:"database"`
		// EnsureIndexes creates the indexes at start-up. Turn it off and run
		// `datafetch az-storage -init-db` once if the collector's account may not.
		EnsureIndexes *bool `json:"ensureIndexes"`
	} `json:"mongo"`
	// Interval between passes when started with -loop. Azure refreshes the
	// capacity metrics about once a day, so more often gains little.
	Interval          Duration `json:"interval"`
	HeartbeatInterval Duration `json:"heartbeatInterval"`
	Concurrency       struct {
		// Tenants collected at once.
		Tenants int `json:"tenants"`
		// Accounts worked on at once within a tenant.
		Accounts int `json:"accounts"`
		// Containers measured at once within a storage account.
		Containers int `json:"containers"`
	} `json:"concurrency"`
	Retention struct {
		LogsDays int `json:"logsDays"`
		RunsDays int `json:"runsDays"`
	} `json:"retention"`
	Logging struct {
		Level      string `json:"level"`      // local log
		MongoLevel string `json:"mongoLevel"` // what is sent to azs_logs
		Format     string `json:"format"`     // text or json
	} `json:"logging"`

	Tenants []Tenant `json:"tenants"`

	// Collect switches parts of the pass off. All are on by default.
	Collect struct {
		// Usage reads each storage account's used capacity from Azure Monitor.
		Usage *bool `json:"usage"`
		// ServiceBreakdown also reads blob, file, table and queue capacity.
		// Without it only the account's total is read (one call per account
		// instead of up to five).
		ServiceBreakdown *bool `json:"serviceBreakdown"`
		// Containers lists each storage account's blob containers.
		Containers *bool `json:"containers"`
		// ContainerSizes lists the blobs of every container to add up its
		// size. This is the only part that reads the storage data plane.
		ContainerSizes *bool `json:"containerSizes"`
		Disks          *bool `json:"disks"`
	} `json:"collect"`

	ContainerSizes struct {
		// Snapshots, Versions and Deleted include blob snapshots, earlier
		// versions and soft-deleted blobs. On by default: they are stored
		// and billed.
		Snapshots *bool `json:"snapshots"`
		Versions  *bool `json:"versions"`
		Deleted   *bool `json:"deleted"`
		// MaxBlobs stops listing a container after this many blobs; its size
		// is then a lower bound, shown as such. Default 2,000,000; -1 for no
		// limit.
		MaxBlobs int64 `json:"maxBlobs"`
		// ExcludeAccounts are storage account names whose containers are not
		// measured. * matches any run of characters: "stdiag*".
		ExcludeAccounts []string `json:"excludeAccounts"`
		// Timeout for measuring one container. Default 30m.
		Timeout Duration `json:"timeout"`
	} `json:"containerSizes"`
}

// Tenant is one Entra tenant and the service principal that reads it.
type Tenant struct {
	// Name is the label stored on every document from this tenant.
	Name         string `json:"tenantName"`
	ID           string `json:"tenantId"`
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
	// ClientSecretEnv names an environment variable holding the secret.
	ClientSecretEnv string `json:"clientSecretEnv"`
	// Cloud is public (default), usgovernment or china.
	Cloud string `json:"cloud"`
	// Subscriptions limits the pass to these subscription IDs;
	// ExcludeSubscriptions leaves some out. Default: every subscription the
	// service principal can read.
	Subscriptions        []string `json:"subscriptions"`
	ExcludeSubscriptions []string `json:"excludeSubscriptions"`

	Endpoints Endpoints `json:"-"`
}

// Endpoints are the URLs of one Azure cloud.
type Endpoints struct {
	Authority string
	ARM       string
	ARMScope  string
	// StorageScope is the token scope of the blob data plane.
	StorageScope string
}

const storageScope = "https://storage.azure.com/.default"

var clouds = map[string]Endpoints{
	"public":       {"https://login.microsoftonline.com", "https://management.azure.com", "https://management.azure.com/.default", storageScope},
	"usgovernment": {"https://login.microsoftonline.us", "https://management.usgovcloudapi.net", "https://management.usgovcloudapi.net/.default", storageScope},
	"china":        {"https://login.chinacloudapi.cn", "https://management.chinacloudapi.cn", "https://management.chinacloudapi.cn/.default", storageScope},
}

func on(b *bool) bool { return b == nil || *b }

func (c *Config) EnsureIndexes() bool     { return on(c.Mongo.EnsureIndexes) }
func (c *Config) CollectUsage() bool      { return on(c.Collect.Usage) }
func (c *Config) ServiceBreakdown() bool  { return on(c.Collect.ServiceBreakdown) }
func (c *Config) CollectContainers() bool { return on(c.Collect.Containers) }
func (c *Config) CollectDisks() bool      { return on(c.Collect.Disks) }

// MeasureContainers reports whether container sizes are collected at all.
func (c *Config) MeasureContainers() bool {
	return c.CollectContainers() && on(c.Collect.ContainerSizes)
}

// BlobIncludes is what a container listing adds to the current blobs.
func (c *Config) BlobIncludes() (snapshots, versions, deleted bool) {
	return on(c.ContainerSizes.Snapshots), on(c.ContainerSizes.Versions), on(c.ContainerSizes.Deleted)
}

// SizeExcluded reports whether a storage account's containers are left
// unmeasured.
func (c *Config) SizeExcluded(account string) bool {
	account = strings.ToLower(account)
	for _, p := range c.ContainerSizes.ExcludeAccounts {
		if ok, _ := path.Match(p, account); ok {
			return true
		}
	}
	return false
}

var guid = regexp.MustCompile(`^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$`)

// Load reads and validates the file. Environment variables override the
// MongoDB settings (AZSTORAGE_MONGO_URI, AZSTORAGE_MONGO_DATABASE) and can
// supply the tenants (AZSTORAGE_TENANTS, a JSON array, or
// AZSTORAGE_TENANTS_FILE).
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
	if v := getenv("AZSTORAGE_MONGO_URI"); v != "" {
		c.Mongo.URI = v
	}
	if v := getenv("AZSTORAGE_MONGO_DATABASE"); v != "" {
		c.Mongo.Database = v
	}
	if f := getenv("AZSTORAGE_TENANTS_FILE"); f != "" {
		raw, err := readFile(f)
		if err != nil {
			return nil, fmt.Errorf("config: AZSTORAGE_TENANTS_FILE: %w", err)
		}
		if err := json.Unmarshal(raw, &c.Tenants); err != nil {
			return nil, fmt.Errorf("config: %s: expected a JSON array of tenants: %w", f, err)
		}
	}
	if v := getenv("AZSTORAGE_TENANTS"); v != "" {
		if err := json.Unmarshal([]byte(v), &c.Tenants); err != nil {
			return nil, fmt.Errorf("config: AZSTORAGE_TENANTS: expected a JSON array of tenants: %w", err)
		}
	}
	if c.Mongo.Database == "" {
		c.Mongo.Database = "azstorage"
	}
	if c.Interval == 0 {
		c.Interval = Duration(24 * time.Hour)
	}
	if c.Interval.D() < 15*time.Minute {
		return nil, errors.New("config: interval must be at least 15m")
	}
	if c.HeartbeatInterval == 0 {
		c.HeartbeatInterval = Duration(30 * time.Second)
	}
	// The dashboard treats a run as stalled after five minutes of silence.
	if hb := c.HeartbeatInterval.D(); hb < 5*time.Second || hb > time.Minute {
		return nil, errors.New("config: heartbeatInterval must be between 5s and 1m")
	}
	if c.Concurrency.Tenants <= 0 {
		c.Concurrency.Tenants = 2
	}
	if c.Concurrency.Accounts <= 0 {
		c.Concurrency.Accounts = 8
	}
	if c.Concurrency.Containers <= 0 {
		c.Concurrency.Containers = 4
	}
	if c.Retention.LogsDays == 0 {
		c.Retention.LogsDays = 30
	}
	if c.Retention.RunsDays == 0 {
		c.Retention.RunsDays = 90
	}
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	if c.Logging.MongoLevel == "" {
		c.Logging.MongoLevel = "info"
	}
	if c.ContainerSizes.MaxBlobs == 0 {
		c.ContainerSizes.MaxBlobs = 2_000_000
	}
	if c.ContainerSizes.Timeout == 0 {
		c.ContainerSizes.Timeout = Duration(30 * time.Minute)
	}
	for i, p := range c.ContainerSizes.ExcludeAccounts {
		p = strings.ToLower(strings.TrimSpace(p))
		if _, err := path.Match(p, ""); err != nil || p == "" {
			return nil, fmt.Errorf("config: containerSizes.excludeAccounts[%d]: %q is not a valid pattern", i, p)
		}
		c.ContainerSizes.ExcludeAccounts[i] = p
	}

	if len(c.Tenants) == 0 {
		return nil, errors.New("config: no tenants configured (tenants, AZSTORAGE_TENANTS or AZSTORAGE_TENANTS_FILE)")
	}
	names, ids := map[string]bool{}, map[string]bool{}
	for i := range c.Tenants {
		t := &c.Tenants[i]
		t.Name = strings.TrimSpace(t.Name)
		t.ID = strings.ToLower(strings.TrimSpace(t.ID))
		where := fmt.Sprintf("config: tenants[%d]", i)
		if t.Name == "" {
			return nil, fmt.Errorf("%s: tenantName is required", where)
		}
		if !guid.MatchString(t.ID) {
			return nil, fmt.Errorf("%s (%s): tenantId must be a GUID", where, t.Name)
		}
		if names[t.Name] || ids[t.ID] {
			return nil, fmt.Errorf("%s (%s): the tenant is configured twice", where, t.Name)
		}
		names[t.Name], ids[t.ID] = true, true
		if t.ClientSecretEnv != "" {
			if v := getenv(t.ClientSecretEnv); v != "" {
				t.ClientSecret = v
			}
		}
		if t.ClientID == "" || t.ClientSecret == "" {
			return nil, fmt.Errorf("%s (%s): clientId and a secret (clientSecret or clientSecretEnv) are required", where, t.Name)
		}
		cloud := strings.ToLower(t.Cloud)
		if cloud == "" {
			cloud = "public"
		}
		e, ok := clouds[cloud]
		if !ok {
			return nil, fmt.Errorf("%s (%s): cloud must be public, usgovernment or china", where, t.Name)
		}
		t.Cloud, t.Endpoints = cloud, e
		for _, list := range [][]string{t.Subscriptions, t.ExcludeSubscriptions} {
			for j, s := range list {
				list[j] = strings.ToLower(strings.TrimSpace(s))
				if !guid.MatchString(list[j]) {
					return nil, fmt.Errorf("%s (%s): %q is not a subscription ID", where, t.Name, s)
				}
			}
		}
	}
	return &c, nil
}
