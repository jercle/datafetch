// Package config loads az-config-drift's JSON configuration.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

// Duration is a time.Duration written as a string ("6h", "90s").
type Duration time.Duration

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return errors.New(`durations are strings such as "6h" or "30s"`)
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
		// `datafetch az-config-drift -init-db` once if the collector's account may not.
		EnsureIndexes *bool `json:"ensureIndexes"`
	} `json:"mongo"`
	// Interval between passes when started with -loop.
	Interval          Duration `json:"interval"`
	HeartbeatInterval Duration `json:"heartbeatInterval"`
	Concurrency       struct {
		// Tenants collected at once.
		Tenants int `json:"tenants"`
		// Modules collected at once within a tenant.
		Modules int `json:"modules"`
	} `json:"concurrency"`
	Retention struct {
		LogsDays    int `json:"logsDays"`
		RunsDays    int `json:"runsDays"`
		ChangesDays int `json:"changesDays"`
	} `json:"retention"`
	Logging struct {
		Level      string `json:"level"`      // local log
		MongoLevel string `json:"mongoLevel"` // what is sent to acd_logs
		Format     string `json:"format"`     // text or json
	} `json:"logging"`

	Tenants []Tenant `json:"tenants"`

	// Modules holds the switches, by module id: whether a module is
	// collected, and per source whether it is read, from which Graph
	// version, and as whom. What is not set here follows the catalogue's
	// defaults. The dashboard writes these under datafetching.azConfigDrift.modules
	// in App Configuration, which takes precedence over the file.
	Modules map[string]ModuleSetting `json:"modules"`
	// ModuleDefaults is the older, shorter way to switch whole modules: it
	// counts where Modules says nothing.
	ModuleDefaults map[string]bool `json:"moduleDefaults"`
	// SkipSources are never read, whatever else says so: "module/source".
	SkipSources []string `json:"skipSources"`
	// Ignore lists properties to leave out of the stored settings, on top
	// of the built-in list.
	Ignore []IgnoreRule `json:"ignore"`
	// Exclude lists objects to leave out altogether: not stored, not
	// compared with the baseline.
	Exclude []ExcludeRule `json:"exclude"`
	// ExtraSources adds things to read without changing the code.
	ExtraSources []ExtraSource `json:"extraSources"`

	Limits struct {
		// MaxItemBytes is the largest settings JSON stored for one object.
		// Larger ones are stored as a note with their size; changes are
		// still detected. Default 4 MiB.
		MaxItemBytes int `json:"maxItemBytes"`
		// ChangePaths is how many differing settings a change record lists.
		// Default 100.
		ChangePaths int `json:"changePaths"`
		// SourceTimeout is the longest one source may take in one tenant.
		// Default 2h.
		SourceTimeout Duration `json:"sourceTimeout"`
	} `json:"limits"`
}

// ModuleSetting is the switches of one module.
type ModuleSetting struct {
	Enabled *bool                    `json:"enabled,omitempty"`
	Sources map[string]SourceSetting `json:"sources,omitempty"`
}

// SourceSetting is the switches of one source. Delegated (read as the
// service account) applies to any source, Beta only to Microsoft Graph's.
type SourceSetting struct {
	Enabled   *bool `json:"enabled,omitempty"`
	Beta      *bool `json:"beta,omitempty"`
	Delegated *bool `json:"delegated,omitempty"`
}

// IgnoreRule drops properties. Module, Source and Type narrow where it
// applies; empty means everywhere. Type is a prefix of the item type.
type IgnoreRule struct {
	Module string `json:"module"`
	Source string `json:"source"`
	Type   string `json:"type"`
	// Paths: a bare name ("etag") matches at any depth, a dotted path
	// ("properties.extended") from the top of the object; "*" is any name.
	Paths []string `json:"paths"`
}

// ExcludeRule leaves whole objects out. Every field that is set must
// match, without regard to case; at least one of Type, ResourceGroup and
// Name is set. "*" stands for any text. Without a "*", Type matches as a
// prefix of the object's type, ResourceGroup and Name exactly.
type ExcludeRule struct {
	// Module narrows the rule to one module; empty means every module.
	Module        string `json:"module,omitempty"`
	Type          string `json:"type,omitempty"`
	ResourceGroup string `json:"resourceGroup,omitempty"`
	Name          string `json:"name,omitempty"`
}

// Excluded reports whether the configuration leaves an object out.
func (c *Config) Excluded(module, typ, resourceGroup, name string) bool {
	for _, r := range c.Exclude {
		if r.Module != "" && r.Module != module {
			continue
		}
		if like(r.Type, typ, true) && like(r.ResourceGroup, resourceGroup, false) && like(r.Name, name, false) {
			return true
		}
	}
	return false
}

// like matches text against a pattern in lower case: "*" is any text, and
// a pattern without one matches exactly, or as a prefix. An empty pattern
// matches everything.
func like(pattern, text string, prefix bool) bool {
	if pattern == "" {
		return true
	}
	text = strings.ToLower(text)
	if !strings.Contains(pattern, "*") {
		if prefix {
			return strings.HasPrefix(text, pattern)
		}
		return text == pattern
	}
	parts := strings.Split(pattern, "*")
	if !strings.HasPrefix(text, parts[0]) {
		return false
	}
	text = text[len(parts[0]):]
	last := parts[len(parts)-1]
	for _, p := range parts[1 : len(parts)-1] {
		i := strings.Index(text, p)
		if i < 0 {
			return false
		}
		text = text[i+len(p):]
	}
	return strings.HasSuffix(text, last)
}

// ExtraSource is a source defined in the configuration.
type ExtraSource struct {
	// Module is an existing module id, or a new one.
	Module string `json:"module"`
	// ModuleName names a new module.
	ModuleName string `json:"moduleName"`
	ID         string `json:"id"`
	Name       string `json:"name"`
	// Kind is arg (Resource Graph query), arm (Resource Manager list or
	// object) or graph (Microsoft Graph list or object).
	Kind string `json:"kind"`
	// Query is a Resource Graph query returning at least an id column.
	Query string `json:"query"`
	// Path for arm and graph, with the api-version for arm. An arm path
	// containing {subscriptionId} is read once per subscription.
	Path string `json:"path"`
	Beta bool   `json:"beta"`
	// Delegated: the source is read as the tenant's service account.
	Delegated bool `json:"delegated"`
	// Single: the path returns one object, not a list.
	Single     bool   `json:"single"`
	Type       string `json:"type"`
	KeyField   string `json:"keyField"`
	Permission string `json:"permission"`
}

// Tenant is one Entra tenant and the service principal that reads it.
type Tenant struct {
	// Enabled false leaves the tenant out of every pass. It lets the
	// dashboard switch off a tenant that the file defines.
	Enabled *bool `json:"enabled,omitempty"`
	// Name is the label stored on every document from this tenant.
	Name         string `json:"tenantName"`
	ID           string `json:"tenantId"`
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
	// ClientSecretEnv names an environment variable holding the secret.
	ClientSecretEnv string `json:"clientSecretEnv"`
	// Cloud is public (default), usgovernment or china.
	Cloud string `json:"cloud"`
	// Platforms limits what is read in this tenant: "azure", "m365" or
	// both (the default).
	Platforms []string `json:"platforms"`
	// Subscriptions limits the Azure modules to these subscription IDs;
	// ExcludeSubscriptions leaves some out. Default: everything the service
	// principal can read, including management-group level objects.
	Subscriptions        []string `json:"subscriptions"`
	ExcludeSubscriptions []string `json:"excludeSubscriptions"`
	// Username and Password (or PasswordEnv, an environment variable holding
	// it) are a service account for the sources switched to it, such as
	// the Graph endpoints that have no application permission. The collector signs in with them directly
	// (the resource owner password flow), so the account cannot have MFA,
	// and the delegated permissions must have admin consent.
	Username    string `json:"username"`
	Password    string `json:"password"`
	PasswordEnv string `json:"passwordEnv"`
	// DelegatedClientID is the application to sign the service account in
	// to, when that is not ClientID. Give a public client application here
	// (one with "Allow public client flows" on): no secret is sent for it.
	DelegatedClientID string `json:"delegatedClientId"`
	// InitialDomain is the tenant's *.onmicrosoft.com domain, needed by the
	// Exchange Online module. Read from Microsoft Graph when empty.
	InitialDomain string `json:"initialDomain"`

	Endpoints Endpoints `json:"-"`
}

// HasServiceAccount reports whether delegated sources can be read.
func (t Tenant) HasServiceAccount() bool { return t.Username != "" && t.Password != "" }

func (t Tenant) Has(platform string) bool {
	if len(t.Platforms) == 0 {
		return true
	}
	for _, p := range t.Platforms {
		if p == platform {
			return true
		}
	}
	return false
}

// Endpoints are the URLs of one Microsoft cloud.
type Endpoints struct {
	Authority     string
	ARM           string
	ARMScope      string
	Graph         string
	GraphScope    string
	Exchange      string
	ExchangeScope string
}

var clouds = map[string]Endpoints{
	"public": {
		"https://login.microsoftonline.com",
		"https://management.azure.com", "https://management.azure.com/.default",
		"https://graph.microsoft.com", "https://graph.microsoft.com/.default",
		"https://outlook.office365.com", "https://outlook.office365.com/.default",
	},
	"usgovernment": {
		"https://login.microsoftonline.us",
		"https://management.usgovcloudapi.net", "https://management.usgovcloudapi.net/.default",
		"https://graph.microsoft.us", "https://graph.microsoft.us/.default",
		"https://outlook.office365.us", "https://outlook.office365.us/.default",
	},
	"china": {
		"https://login.chinacloudapi.cn",
		"https://management.chinacloudapi.cn", "https://management.chinacloudapi.cn/.default",
		"https://microsoftgraph.chinacloudapi.cn", "https://microsoftgraph.chinacloudapi.cn/.default",
		"https://partner.outlook.cn", "https://partner.outlook.cn/.default",
	},
}

func on(b *bool) bool { return b == nil || *b }

func (c *Config) EnsureIndexes() bool { return on(c.Mongo.EnsureIndexes) }

// Skipped reports whether the configuration rules a source out.
func (c *Config) Skipped(module, source string) bool {
	for _, s := range c.SkipSources {
		if s == module+"/"+source {
			return true
		}
	}
	return false
}

var (
	guid = regexp.MustCompile(`^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$`)
	slug = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
)

// Load reads and validates the file. Environment variables override the
// MongoDB settings (AZCONFIGDRIFT_MONGO_URI, AZCONFIGDRIFT_MONGO_DATABASE)
// and can supply the tenants (AZCONFIGDRIFT_TENANTS, a JSON array, or
// AZCONFIGDRIFT_TENANTS_FILE).
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
	if v := getenv("AZCONFIGDRIFT_MONGO_URI"); v != "" {
		c.Mongo.URI = v
	}
	if v := getenv("AZCONFIGDRIFT_MONGO_DATABASE"); v != "" {
		c.Mongo.Database = v
	}
	if f := getenv("AZCONFIGDRIFT_TENANTS_FILE"); f != "" {
		raw, err := readFile(f)
		if err != nil {
			return nil, fmt.Errorf("config: AZCONFIGDRIFT_TENANTS_FILE: %w", err)
		}
		if err := json.Unmarshal(raw, &c.Tenants); err != nil {
			return nil, fmt.Errorf("config: %s: expected a JSON array of tenants: %w", f, err)
		}
	}
	if v := getenv("AZCONFIGDRIFT_TENANTS"); v != "" {
		if err := json.Unmarshal([]byte(v), &c.Tenants); err != nil {
			return nil, fmt.Errorf("config: AZCONFIGDRIFT_TENANTS: expected a JSON array of tenants: %w", err)
		}
	}
	if c.Mongo.Database == "" {
		c.Mongo.Database = "azconfigdrift"
	}
	if c.Interval == 0 {
		c.Interval = Duration(6 * time.Hour)
	}
	if c.Interval.D() < 5*time.Minute {
		return nil, errors.New("config: interval must be at least 5m")
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
	if c.Concurrency.Modules <= 0 {
		c.Concurrency.Modules = 3
	}
	if c.Retention.LogsDays == 0 {
		c.Retention.LogsDays = 30
	}
	if c.Retention.RunsDays == 0 {
		c.Retention.RunsDays = 90
	}
	if c.Retention.ChangesDays == 0 {
		c.Retention.ChangesDays = 365
	}
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	if c.Logging.MongoLevel == "" {
		c.Logging.MongoLevel = "info"
	}
	if c.Logging.Format == "" {
		c.Logging.Format = "text"
	}
	if c.Limits.MaxItemBytes <= 0 {
		c.Limits.MaxItemBytes = 4 << 20
	}
	if c.Limits.MaxItemBytes > 12<<20 {
		return nil, errors.New("config: limits.maxItemBytes cannot exceed 12 MiB (a MongoDB document holds 16)")
	}
	if c.Limits.ChangePaths <= 0 {
		c.Limits.ChangePaths = 100
	}
	if c.Limits.SourceTimeout == 0 {
		c.Limits.SourceTimeout = Duration(2 * time.Hour)
	}
	for i, r := range c.Ignore {
		if len(r.Paths) == 0 {
			return nil, fmt.Errorf("config: ignore[%d]: paths is empty", i)
		}
		c.Ignore[i].Type = strings.ToLower(r.Type)
	}
	for i := range c.Exclude {
		r := &c.Exclude[i]
		r.Module = strings.ToLower(strings.TrimSpace(r.Module))
		r.Type, r.ResourceGroup, r.Name = strings.ToLower(strings.TrimSpace(r.Type)), strings.ToLower(strings.TrimSpace(r.ResourceGroup)), strings.ToLower(strings.TrimSpace(r.Name))
		if r.Type == "" && r.ResourceGroup == "" && r.Name == "" {
			return nil, fmt.Errorf("config: exclude[%d]: give a type, a resource group or a name", i)
		}
		if strings.Trim(r.Type+r.ResourceGroup+r.Name, "*") == "" {
			return nil, fmt.Errorf("config: exclude[%d]: a rule of only * would leave everything out; switch the module off instead", i)
		}
	}
	for i := range c.ExtraSources {
		x := &c.ExtraSources[i]
		where := fmt.Sprintf("config: extraSources[%d]", i)
		if !slug.MatchString(x.Module) || !slug.MatchString(x.ID) {
			return nil, fmt.Errorf("%s: module and id are lower-case letters, digits and dashes", where)
		}
		if x.Name == "" {
			x.Name = x.ID
		}
		switch x.Kind {
		case "arg":
			if strings.TrimSpace(x.Query) == "" {
				return nil, fmt.Errorf("%s (%s): an arg source needs a query", where, x.ID)
			}
		case "arm":
			if !strings.HasPrefix(x.Path, "/") || !strings.Contains(x.Path, "api-version=") {
				return nil, fmt.Errorf("%s (%s): an arm source needs a path starting with / and including api-version", where, x.ID)
			}
		case "graph":
			if !strings.HasPrefix(x.Path, "/") {
				return nil, fmt.Errorf("%s (%s): a graph source needs a path starting with /", where, x.ID)
			}
		default:
			return nil, fmt.Errorf("%s (%s): kind must be arg, arm or graph", where, x.ID)
		}
	}

	enabled := c.Tenants[:0]
	for _, t := range c.Tenants {
		if on(t.Enabled) {
			enabled = append(enabled, t)
		}
	}
	if len(c.Tenants) > 0 && len(enabled) == 0 {
		return nil, errors.New("config: every tenant is switched off")
	}
	c.Tenants = enabled
	if len(c.Tenants) == 0 {
		return nil, errors.New("config: no tenants configured (datafetching.azConfigDrift.tenants in App Configuration, tenants in the file, AZCONFIGDRIFT_TENANTS or AZCONFIGDRIFT_TENANTS_FILE)")
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
		if t.PasswordEnv != "" {
			if v := getenv(t.PasswordEnv); v != "" {
				t.Password = v
			}
		}
		t.Username = strings.TrimSpace(t.Username)
		if (t.Username == "") != (t.Password == "") {
			return nil, fmt.Errorf("%s (%s): username and a password (password or passwordEnv) go together", where, t.Name)
		}
		if t.DelegatedClientID != "" && t.Username == "" {
			return nil, fmt.Errorf("%s (%s): delegatedClientId needs username and a password", where, t.Name)
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
		for j, p := range t.Platforms {
			t.Platforms[j] = strings.ToLower(strings.TrimSpace(p))
			if t.Platforms[j] != "azure" && t.Platforms[j] != "m365" {
				return nil, fmt.Errorf("%s (%s): platforms may hold azure and m365", where, t.Name)
			}
		}
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
