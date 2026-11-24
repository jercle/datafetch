// Package model holds the documents az-config-drift stores in MongoDB.
package model

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

// Collections.
const (
	// CollModules: one document per module (setting category). The dashboard
	// switches modules and single sources on and off here.
	CollModules = "acd_modules"
	// CollModuleSettings: the switches set in the dashboard, one document
	// per module. The collector reads them before every pass; they win
	// over the configuration.
	CollModuleSettings = "acd_module_settings"
	// CollTenants: one per tenant: how current each module and source is.
	CollTenants = "acd_tenants"
	// CollItems: one per configuration object: its current settings.
	CollItems = "acd_items"
	// CollChanges: one per object that was added, changed or removed
	// between two passes.
	CollChanges = "acd_changes"
	// CollBaselines and CollBaselineItems are written by the dashboard: a
	// baseline is a copy of every item at one moment.
	CollBaselines     = "acd_baselines"
	CollBaselineItems = "acd_baseline_items"
	// CollControl: requests from the dashboard ("collect now").
	CollControl   = "acd_control"
	CollRuns      = "acd_runs"
	CollLogs      = "acd_logs"
	CollInstances = "acd_instances"
)

// Run and instance states.
const (
	StatusRunning   = "running"
	StatusSuccess   = "success"
	StatusPartial   = "partial"
	StatusFailed    = "failed"
	StatusCancelled = "cancelled"

	StateIdle    = "idle"
	StateRunning = "running"
	StateExited  = "exited"
)

// Outcome of one source (and, rolled up, of a module).
const (
	SourceOK = "ok"
	// SourceDenied: the service principal lacks the permission (401, 403).
	SourceDenied = "denied"
	// SourceUnsupported: the tenant does not have the endpoint (400, 404,
	// 501: no licence, feature not in this cloud).
	SourceUnsupported = "unsupported"
	SourceFailed      = "failed"
	SourceCancelled   = "cancelled"
	// SourceDisabled: switched off in the dashboard or the configuration.
	SourceDisabled = "disabled"
)

// How an item compares with the active baseline (Item.Drift.Status).
const (
	DriftSame    = "same"
	DriftChanged = "changed"
	// DriftAdded: the baseline covers the item's source, and the item is
	// not in it.
	DriftAdded = "added"
	// DriftRemoved: in the baseline, gone from the tenant.
	DriftRemoved = "removed"
	// DriftUntracked: there is no baseline, or it was saved before this
	// source was first collected.
	DriftUntracked = "untracked"
)

// Kinds of change between two passes.
const (
	ChangeAdded   = "added"
	ChangeChanged = "changed"
	ChangeRemoved = "removed"
)

const (
	PlatformAzure = "azure"
	PlatformM365  = "m365"
)

// Scope names the tenant a document belongs to.
type Scope struct {
	TenantID   string `bson:"tenantId" json:"tenantId"`
	TenantName string `bson:"tenantName" json:"tenantName"`
}

// Module is the catalogue entry of one setting category, rewritten by the
// collector at every pass together with the switches it used (ModuleState,
// in the same document). The switches themselves are set in App
// Configuration or the configuration file, not here.
type Module struct {
	ID          string `bson:"_id" json:"id"`
	Platform    string `bson:"platform" json:"platform"`
	Name        string `bson:"name" json:"name"`
	Description string `bson:"description" json:"description"`
	Order       int    `bson:"order" json:"order"`
	// DefaultEnabled is the state a module starts in.
	DefaultEnabled bool           `bson:"defaultEnabled" json:"defaultEnabled"`
	Sources        []ModuleSource `bson:"sources" json:"sources"`
	Version        string         `bson:"version" json:"version"`
	UpdatedAt      time.Time      `bson:"updatedAt" json:"updatedAt"`
}

// ModuleSource describes one thing a module reads.
type ModuleSource struct {
	ID   string `bson:"id" json:"id"`
	Name string `bson:"name" json:"name"`
	// Kind is arg, arm, graph or exo.
	Kind string `bson:"kind" json:"kind"`
	// Reads says where the settings come from: a path, a table, a cmdlet.
	Reads string `bson:"reads" json:"reads"`
	// Permission the service principal needs.
	Permission string `bson:"permission,omitempty" json:"permission,omitempty"`
	// Beta and Delegated are the source's defaults: read from Microsoft
	// Graph's beta version (Graph sources only), and read as the tenant's
	// service account instead of as the application. The dashboard can
	// override both.
	Beta      bool `bson:"beta,omitempty" json:"beta,omitempty"`
	Delegated bool `bson:"delegated,omitempty" json:"delegated,omitempty"`
}

// ModuleState is the switches of one module as a pass used them.
type ModuleState struct {
	Enabled         bool     `bson:"enabled"`
	DisabledSources []string `bson:"disabledSources"`
	// SourceBeta and SourceDelegated hold the dashboard's choice per source
	// id, for the sources where it differs from (or confirms) the default.
	SourceBeta      map[string]bool `bson:"sourceBeta"`
	SourceDelegated map[string]bool `bson:"sourceDelegated"`
}

// Beta says whether a Graph source is read from the beta version.
func (s ModuleState) Beta(id string, def bool) bool {
	if v, ok := s.SourceBeta[id]; ok {
		return v
	}
	return def
}

// Delegated says whether a source is read as the service account.
func (s ModuleState) Delegated(id string, def bool) bool {
	if v, ok := s.SourceDelegated[id]; ok {
		return v
	}
	return def
}

func (s ModuleState) SourceDisabled(id string) bool {
	for _, d := range s.DisabledSources {
		if d == id {
			return true
		}
	}
	return false
}

// Drift is how an item compares with a baseline.
type Drift struct {
	BaselineID string `bson:"baselineId" json:"baselineId"`
	Status     string `bson:"status" json:"status"`
}

// Item is one configuration object: a resource, a policy, a tenant-wide
// settings object.
type Item struct {
	ID       string `bson:"_id" json:"id"`
	Scope    `bson:",inline"`
	Platform string `bson:"platform" json:"platform"`
	Module   string `bson:"module" json:"module"`
	Source   string `bson:"source" json:"source"`
	// Type is the Azure resource type, or the kind of Microsoft 365 object.
	Type string `bson:"type" json:"type"`
	// Key is the object's own identifier: a resource ID, a Graph id.
	Key  string `bson:"key" json:"key"`
	Name string `bson:"name" json:"name"`

	SubscriptionID   string `bson:"subscriptionId,omitempty" json:"subscriptionId,omitempty"`
	SubscriptionName string `bson:"subscriptionName,omitempty" json:"subscriptionName,omitempty"`
	ResourceGroup    string `bson:"resourceGroup,omitempty" json:"resourceGroup,omitempty"`
	Location         string `bson:"location,omitempty" json:"location,omitempty"`

	// Config is the object's settings as canonical JSON (sorted keys,
	// ignored and volatile properties removed, secrets replaced by a
	// fingerprint). A string, because setting names may contain "." and "$".
	Config string `bson:"config" json:"config"`
	// Hash is the SHA-256 of Config.
	Hash string `bson:"hash" json:"hash"`
	// Props is the number of settings (leaf values) in Config.
	Props int `bson:"props" json:"props"`
	// Text is what the dashboard's search looks through, in lower case: the
	// name, type and location, a tab, then the distinct setting names. It
	// has an index, so a search does not read the settings themselves.
	Text string `bson:"text" json:"text"`
	// SortName is the name in lower case, for sorting.
	SortName string `bson:"sortName" json:"sortName"`

	// Refs names the identifiers that appear in Config: the object ID of a
	// principal, a role definition, an application the object points at.
	// It is not part of Hash: a principal being renamed is not a change to
	// the objects that name it. RefsHash tells when it needs rewriting.
	Refs     map[string]string `bson:"refs,omitempty" json:"refs,omitempty"`
	RefsHash string            `bson:"refsHash,omitempty" json:"refsHash,omitempty"`

	// Present is false for an item that is gone from the tenant and kept
	// only because the baseline still has it.
	Present     bool       `bson:"present" json:"present"`
	FirstSeenAt time.Time  `bson:"firstSeenAt" json:"firstSeenAt"`
	LastSeenAt  time.Time  `bson:"lastSeenAt" json:"lastSeenAt"`
	ChangedAt   time.Time  `bson:"changedAt" json:"changedAt"`
	RemovedAt   *time.Time `bson:"removedAt,omitempty" json:"removedAt,omitempty"`
	RunID       string     `bson:"runId" json:"runId"`
	Drift       Drift      `bson:"drift" json:"drift"`
}

// ModuleSwitches is what the dashboard has set for one module: only the
// switches someone flipped are present.
type ModuleSwitches struct {
	ID      string                    `bson:"_id" json:"id"`
	Enabled *bool                     `bson:"enabled,omitempty" json:"enabled,omitempty"`
	Sources map[string]SourceSwitches `bson:"sources,omitempty" json:"sources,omitempty"`
}

// SourceSwitches is what the dashboard has set for one source.
type SourceSwitches struct {
	Enabled   *bool `bson:"enabled,omitempty" json:"enabled,omitempty"`
	Beta      *bool `bson:"beta,omitempty" json:"beta,omitempty"`
	Delegated *bool `bson:"delegated,omitempty" json:"delegated,omitempty"`
}

// ItemRef is what the collector needs to know of a stored item.
type ItemRef struct {
	ID      string `bson:"_id"`
	Hash    string `bson:"hash"`
	Present bool   `bson:"present"`
	Drift   Drift  `bson:"drift"`
	Type    string `bson:"type"`
	Key     string `bson:"key"`
	Name    string `bson:"name"`
	// RefsHash and ResourceGroup: see Item.
	RefsHash      string `bson:"refsHash"`
	ResourceGroup string `bson:"resourceGroup"`
}

// Change is one object that differs from the pass before.
type Change struct {
	ID       string    `bson:"_id" json:"id"`
	At       time.Time `bson:"at" json:"at"`
	RunID    string    `bson:"runId" json:"runId"`
	Scope    `bson:",inline"`
	Platform string `bson:"platform" json:"platform"`
	Module   string `bson:"module" json:"module"`
	Source   string `bson:"source" json:"source"`
	Type     string `bson:"type" json:"type"`
	ItemID   string `bson:"itemId" json:"itemId"`
	Key      string `bson:"key" json:"key"`
	Name     string `bson:"name" json:"name"`
	Kind     string `bson:"kind" json:"kind"`
	// Paths lists the settings that differ, up to the configured limit;
	// PathCount is how many differ in all.
	Paths      []PathChange `bson:"paths" json:"paths"`
	PathCount  int          `bson:"pathCount" json:"pathCount"`
	HashBefore string       `bson:"hashBefore,omitempty" json:"hashBefore,omitempty"`
	HashAfter  string       `bson:"hashAfter,omitempty" json:"hashAfter,omitempty"`
	// Refs names the identifiers in the object's settings (see Item.Refs).
	Refs map[string]string `bson:"refs,omitempty" json:"refs,omitempty"`
}

// PathChange is one setting that differs. Before and After are JSON values,
// shortened when long.
type PathChange struct {
	Path   string `bson:"path" json:"path"`
	Kind   string `bson:"kind" json:"kind"`
	Before string `bson:"before,omitempty" json:"before,omitempty"`
	After  string `bson:"after,omitempty" json:"after,omitempty"`
}

// Tenant says how current the stored settings of one tenant are.
type Tenant struct {
	ID            string         `bson:"_id" json:"id"`
	TenantName    string         `bson:"tenantName" json:"tenantName"`
	Platforms     []string       `bson:"platforms" json:"platforms"`
	LastStatus    string         `bson:"lastStatus" json:"lastStatus"`
	LastError     string         `bson:"lastError,omitempty" json:"lastError,omitempty"`
	LastRunID     string         `bson:"lastRunId" json:"lastRunId"`
	LastAttemptAt time.Time      `bson:"lastAttemptAt" json:"lastAttemptAt"`
	LastSuccessAt *time.Time     `bson:"lastSuccessAt,omitempty" json:"lastSuccessAt,omitempty"`
	Items         int            `bson:"items" json:"items"`
	Modules       []TenantModule `bson:"modules" json:"modules"`
}

// TenantModule is the latest outcome of one module in one tenant. A module
// that is switched off keeps the entry of its last pass.
type TenantModule struct {
	Module     string         `bson:"module" json:"module"`
	Platform   string         `bson:"platform" json:"platform"`
	Status     string         `bson:"status" json:"status"`
	Items      int            `bson:"items" json:"items"`
	At         time.Time      `bson:"at" json:"at"`
	DurationMs int64          `bson:"durationMs" json:"durationMs"`
	Sources    []TenantSource `bson:"sources" json:"sources"`
}

type TenantSource struct {
	Source string    `bson:"source" json:"source"`
	Status string    `bson:"status" json:"status"`
	Error  string    `bson:"error,omitempty" json:"error,omitempty"`
	Items  int       `bson:"items" json:"items"`
	At     time.Time `bson:"at" json:"at"`
	// LastSuccessAt is the last complete read. A baseline covers a source
	// only when this is set.
	LastSuccessAt *time.Time `bson:"lastSuccessAt,omitempty" json:"lastSuccessAt,omitempty"`
	DurationMs    int64      `bson:"durationMs" json:"durationMs"`
}

// Module returns the tenant's entry for a module, or nil.
func (t *Tenant) Module(id string) *TenantModule {
	for i := range t.Modules {
		if t.Modules[i].Module == id {
			return &t.Modules[i]
		}
	}
	return nil
}

// Source returns the module's entry for a source, or nil.
func (m *TenantModule) Source(id string) *TenantSource {
	if m == nil {
		return nil
	}
	for i := range m.Sources {
		if m.Sources[i].Source == id {
			return &m.Sources[i]
		}
	}
	return nil
}

// Baseline is what the collector reads of a baseline the dashboard saved.
type Baseline struct {
	ID string `bson:"_id"`
	// Covered lists "tenantId|module|source" for every source that had been
	// read when the baseline was saved.
	Covered []string `bson:"covered"`
}

// CoverKey is an entry of Baseline.Covered.
func CoverKey(tenantID, module, source string) string {
	return tenantID + "|" + module + "|" + source
}

// Counts sums what a pass, a tenant or a module did.
type Counts struct {
	Items   int `bson:"items" json:"items"`
	Added   int `bson:"added" json:"added"`
	Changed int `bson:"changed" json:"changed"`
	Removed int `bson:"removed" json:"removed"`
	// Drifted is how many items differ from the baseline after the pass.
	Drifted int `bson:"drifted" json:"drifted"`
	Sources int `bson:"sources" json:"sources"`
	// SourcesFailed counts every source that was not read completely,
	// SourcesDenied those of them that lacked a permission.
	SourcesFailed int `bson:"sourcesFailed" json:"sourcesFailed"`
	SourcesDenied int `bson:"sourcesDenied" json:"sourcesDenied"`
}

func (c *Counts) Add(o Counts) {
	c.Items += o.Items
	c.Added += o.Added
	c.Changed += o.Changed
	c.Removed += o.Removed
	c.Drifted += o.Drifted
	c.Sources += o.Sources
	c.SourcesFailed += o.SourcesFailed
	c.SourcesDenied += o.SourcesDenied
}

// Run is one pass over every tenant.
type Run struct {
	ID          string     `bson:"_id" json:"id"`
	Status      string     `bson:"status" json:"status"`
	Trigger     string     `bson:"trigger" json:"trigger"`
	Instance    string     `bson:"instance" json:"instance"`
	Version     string     `bson:"version" json:"version"`
	StartedAt   time.Time  `bson:"startedAt" json:"startedAt"`
	HeartbeatAt time.Time  `bson:"heartbeatAt" json:"heartbeatAt"`
	FinishedAt  *time.Time `bson:"finishedAt,omitempty" json:"finishedAt,omitempty"`
	DurationMs  int64      `bson:"durationMs" json:"durationMs"`
	Error       string     `bson:"error,omitempty" json:"error,omitempty"`

	TenantsTotal  int    `bson:"tenantsTotal" json:"tenantsTotal"`
	TenantsDone   int    `bson:"tenantsDone" json:"tenantsDone"`
	TenantsFailed int    `bson:"tenantsFailed" json:"tenantsFailed"`
	Counts        Counts `bson:"counts" json:"counts"`
	// Modules that were switched on for this pass.
	Modules []string    `bson:"modules" json:"modules"`
	Tenants []TenantRun `bson:"tenants" json:"tenants"`
}

// Clone copies the run deeply enough to be written while it is updated.
func (r *Run) Clone() *Run {
	c := *r
	c.Modules = append([]string{}, r.Modules...)
	c.Tenants = make([]TenantRun, len(r.Tenants))
	for i, t := range r.Tenants {
		t.Modules = append([]ModuleRun{}, t.Modules...)
		for j, m := range t.Modules {
			t.Modules[j].Sources = append([]SourceRun{}, m.Sources...)
		}
		c.Tenants[i] = t
	}
	return &c
}

// TenantRun is the outcome for one tenant within a run.
type TenantRun struct {
	Scope      `bson:",inline"`
	Status     string      `bson:"status" json:"status"`
	Error      string      `bson:"error,omitempty" json:"error,omitempty"`
	StartedAt  time.Time   `bson:"startedAt" json:"startedAt"`
	DurationMs int64       `bson:"durationMs" json:"durationMs"`
	Counts     Counts      `bson:"counts" json:"counts"`
	Modules    []ModuleRun `bson:"modules" json:"modules"`
}

type ModuleRun struct {
	Module     string      `bson:"module" json:"module"`
	Status     string      `bson:"status" json:"status"`
	DurationMs int64       `bson:"durationMs" json:"durationMs"`
	Counts     Counts      `bson:"counts" json:"counts"`
	Sources    []SourceRun `bson:"sources" json:"sources"`
}

type SourceRun struct {
	Source     string `bson:"source" json:"source"`
	Status     string `bson:"status" json:"status"`
	Error      string `bson:"error,omitempty" json:"error,omitempty"`
	Items      int    `bson:"items" json:"items"`
	Added      int    `bson:"added" json:"added"`
	Changed    int    `bson:"changed" json:"changed"`
	Removed    int    `bson:"removed" json:"removed"`
	DurationMs int64  `bson:"durationMs" json:"durationMs"`
}

// SettingsStatus says where the collector's configuration came from the
// last time it was loaded, for the dashboard.
type SettingsStatus struct {
	// Source is "appconfig" (read from App Configuration by the collector),
	// "object" (handed in by the program that embeds it) or "file".
	Source   string    `bson:"source" json:"source"`
	LoadedAt time.Time `bson:"loadedAt" json:"loadedAt"`
	// Applied is how many settings were taken over the file's.
	Applied int `bson:"applied" json:"applied"`
	// Warnings names settings that were not used, and why.
	Warnings []string `bson:"warnings" json:"warnings"`
	// Error is set when the settings could not be used at all and the
	// collector runs on the file, or on what it loaded before.
	Error string `bson:"error,omitempty" json:"error,omitempty"`
	// Effective is what the collector ended up with for each setting, by
	// its key under the root, so the dashboard can show the value behind a
	// setting it does not set itself and create the keys that are missing
	// in App Configuration. Secrets are not included.
	Effective []SettingValue `bson:"effective" json:"effective"`
}

// SettingValue is one setting by its path under the root ("retention.logsDays").
type SettingValue struct {
	Key   string `bson:"key" json:"key"`
	Value string `bson:"value" json:"value"`
}

// Instance is the heartbeat document of one running collector.
type Instance struct {
	ID               string          `bson:"_id" json:"id"`
	Host             string          `bson:"host" json:"host"`
	Version          string          `bson:"version" json:"version"`
	Mode             string          `bson:"mode" json:"mode"` // schedule or once
	State            string          `bson:"state" json:"state"`
	PID              int             `bson:"pid" json:"pid"`
	StartedAt        time.Time       `bson:"startedAt" json:"startedAt"`
	HeartbeatAt      time.Time       `bson:"heartbeatAt" json:"heartbeatAt"`
	IntervalSeconds  int             `bson:"intervalSeconds,omitempty" json:"intervalSeconds,omitempty"`
	HeartbeatSeconds int             `bson:"heartbeatSeconds" json:"heartbeatSeconds"`
	Tenants          []Scope         `bson:"tenants" json:"tenants"`
	CurrentRunID     string          `bson:"currentRunId,omitempty" json:"currentRunId,omitempty"`
	LastRunID        string          `bson:"lastRunId,omitempty" json:"lastRunId,omitempty"`
	LastRunStatus    string          `bson:"lastRunStatus,omitempty" json:"lastRunStatus,omitempty"`
	LastRunAt        *time.Time      `bson:"lastRunAt,omitempty" json:"lastRunAt,omitempty"`
	NextRunAt        *time.Time      `bson:"nextRunAt,omitempty" json:"nextRunAt,omitempty"`
	Settings         *SettingsStatus `bson:"settings,omitempty" json:"settings,omitempty"`
}

// LogEntry is one structured log line.
type LogEntry struct {
	Time     time.Time      `bson:"time" json:"time"`
	Level    string         `bson:"level" json:"level"`
	Severity int            `bson:"severity" json:"severity"`
	Msg      string         `bson:"msg" json:"msg"`
	Instance string         `bson:"instance,omitempty" json:"instance,omitempty"`
	RunID    string         `bson:"runId,omitempty" json:"runId,omitempty"`
	Tenant   string         `bson:"tenantName,omitempty" json:"tenantName,omitempty"`
	Module   string         `bson:"module,omitempty" json:"module,omitempty"`
	Source   string         `bson:"source,omitempty" json:"source,omitempty"`
	Error    string         `bson:"error,omitempty" json:"error,omitempty"`
	Attrs    map[string]any `bson:"attrs,omitempty" json:"attrs,omitempty"`
}

// ItemID derives an item's _id from where it was read and its own key, so
// the same object always gets the same _id.
func ItemID(tenantID, module, source, key string) string {
	sum := sha256.Sum256([]byte(tenantID + "\x00" + module + "\x00" + source + "\x00" + strings.ToLower(key)))
	return hex.EncodeToString(sum[:16])
}

// NewID returns a random 96-bit hex identifier.
func NewID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
