// Package model holds the documents ns-check writes to MongoDB. The bson
// names are the schema the dashboard reads; see the README before renaming.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
)

// Collections.
const (
	CollAppliances   = "nsc_appliances"
	CollVservers     = "nsc_vservers"
	CollServices     = "nsc_services"
	CollCertificates = "nsc_certificates"
	CollSamples      = "nsc_samples"
	CollEvents       = "nsc_events"
	CollRuns         = "nsc_runs"
	CollLogs         = "nsc_logs"
	CollInstances    = "nsc_instances"
)

// Run, step and instance states: how the checker itself did.
const (
	StatusRunning   = "running"
	StatusSuccess   = "success"
	StatusPartial   = "partial"
	StatusFailed    = "failed"
	StatusCancelled = "cancelled"
	StatusSkipped   = "skipped"

	StateIdle    = "idle"
	StateRunning = "running"
	StateExited  = "exited"
)

// Health of an appliance, a check or an object: what the checker found.
const (
	HealthOK       = "ok"
	HealthWarning  = "warning"
	HealthCritical = "critical"
	// HealthUnknown: the value could not be read.
	HealthUnknown = "unknown"
	// HealthDisabled: switched off on the appliance (OUT OF SERVICE). Only
	// objects have it; it never counts against the appliance.
	HealthDisabled = "disabled"
)

// Rank orders health from best to worst.
func Rank(h string) int {
	switch h {
	case HealthCritical:
		return 3
	case HealthWarning:
		return 2
	case HealthUnknown:
		return 1
	}
	return 0
}

// Worse returns the worse of two health values.
func Worse(a, b string) string {
	if Rank(b) > Rank(a) {
		return b
	}
	if a == "" {
		return HealthOK
	}
	return a
}

// Names of the checks (Check.Name).
const (
	CheckAPI          = "api"
	CheckCPU          = "cpu"
	CheckMgmtCPU      = "mgmt-cpu"
	CheckMemory       = "memory"
	CheckDiskFlash    = "disk-flash"
	CheckDiskVar      = "disk-var"
	CheckHardware     = "hardware"
	CheckConfig       = "config"
	CheckHA           = "ha"
	CheckInterfaces   = "interfaces"
	CheckVservers     = "vservers"
	CheckServices     = "services"
	CheckCertificates = "certificates"
)

// Ref is on every document about an appliance: which one, and its label.
type Ref struct {
	ApplianceID string `bson:"applianceId" json:"applianceId"`
	// Appliance is the configured name.
	Appliance string `bson:"appliance" json:"appliance"`
	// TenantName is the optional label configured for the appliance.
	TenantName string `bson:"tenantName,omitempty" json:"tenantName,omitempty"`
}

// Check is the outcome of one health check on an appliance.
type Check struct {
	Name    string `bson:"name" json:"name"`
	Status  string `bson:"status" json:"status"`
	Message string `bson:"message" json:"message"`
	// Value, with Warning and Critical, for checks against a threshold.
	Value    *float64 `bson:"value,omitempty" json:"value,omitempty"`
	Unit     string   `bson:"unit,omitempty" json:"unit,omitempty"`
	Warning  *float64 `bson:"warning,omitempty" json:"warning,omitempty"`
	Critical *float64 `bson:"critical,omitempty" json:"critical,omitempty"`
	// Since is when the check got its present status.
	Since time.Time `bson:"since" json:"since"`
}

// Appliance is one NetScaler: its present health and what was read from it.
type Appliance struct {
	ID         string `bson:"_id" json:"id"`
	Name       string `bson:"name" json:"name"`
	TenantName string `bson:"tenantName,omitempty" json:"tenantName,omitempty"`
	// Address is the management address the checker calls.
	Address string `bson:"address" json:"address"`
	RunID   string `bson:"runId" json:"runId"`

	Status      string    `bson:"status" json:"status"`
	StatusSince time.Time `bson:"statusSince" json:"statusSince"`
	// Summary is the messages of the checks that are not ok, worst first.
	Summary string `bson:"summary,omitempty" json:"summary,omitempty"`
	// Reachable: the NITRO API answered and accepted the login.
	Reachable bool   `bson:"reachable" json:"reachable"`
	Error     string `bson:"error,omitempty" json:"error,omitempty"`
	// LatencyMs is how long the login took.
	LatencyMs int64 `bson:"latencyMs" json:"latencyMs"`

	CheckedAt     time.Time  `bson:"checkedAt" json:"checkedAt"`
	LastSuccessAt *time.Time `bson:"lastSuccessAt,omitempty" json:"lastSuccessAt,omitempty"`
	FirstSeenAt   time.Time  `bson:"firstSeenAt" json:"firstSeenAt"`
	// IntervalSeconds is the checker's interval, so a reader can tell when
	// the document is overdue. Zero for a single run.
	IntervalSeconds int `bson:"intervalSeconds,omitempty" json:"intervalSeconds,omitempty"`

	Checks []Check `bson:"checks" json:"checks"`

	// The parts below are those of the last pass that could read them.
	System     *System     `bson:"system,omitempty" json:"system,omitempty"`
	HA         *HA         `bson:"ha,omitempty" json:"ha,omitempty"`
	Interfaces []Interface `bson:"interfaces,omitempty" json:"interfaces,omitempty"`
	Counts     Counts      `bson:"counts" json:"counts"`
}

// System is the appliance's identity and resource use.
type System struct {
	Hostname string `bson:"hostname,omitempty" json:"hostname,omitempty"`
	Version  string `bson:"version,omitempty" json:"version,omitempty"`
	Model    string `bson:"model,omitempty" json:"model,omitempty"`
	Serial   string `bson:"serial,omitempty" json:"serial,omitempty"`
	HostID   string `bson:"hostId,omitempty" json:"hostId,omitempty"`

	// Percentages.
	CPU       *float64 `bson:"cpu,omitempty" json:"cpu,omitempty"`
	MgmtCPU   *float64 `bson:"mgmtCpu,omitempty" json:"mgmtCpu,omitempty"`
	Memory    *float64 `bson:"memory,omitempty" json:"memory,omitempty"`
	DiskFlash *float64 `bson:"diskFlash,omitempty" json:"diskFlash,omitempty"`
	DiskVar   *float64 `bson:"diskVar,omitempty" json:"diskVar,omitempty"`
	MemoryMB  *float64 `bson:"memoryMb,omitempty" json:"memoryMb,omitempty"`
	CPUs      int      `bson:"cpus,omitempty" json:"cpus,omitempty"`

	// StartTime is when the appliance last started, as it reports it (in
	// its own time zone).
	StartTime     string        `bson:"startTime,omitempty" json:"startTime,omitempty"`
	PowerSupplies []PowerSupply `bson:"powerSupplies,omitempty" json:"powerSupplies,omitempty"`

	// ConfigChanged and ConfigSaved are the appliance's own timestamps;
	// ConfigUnsaved is set when the running configuration is newer than the
	// saved one.
	ConfigChanged string `bson:"configChanged,omitempty" json:"configChanged,omitempty"`
	ConfigSaved   string `bson:"configSaved,omitempty" json:"configSaved,omitempty"`
	ConfigUnsaved bool   `bson:"configUnsaved,omitempty" json:"configUnsaved,omitempty"`
}

type PowerSupply struct {
	Name   string `bson:"name" json:"name"`
	Status string `bson:"status" json:"status"`
}

// HA is the appliance's view of its high-availability pair.
type HA struct {
	Configured bool `bson:"configured" json:"configured"`
	// State is this node's state: UP, DISABLED, PARTIAL FAIL...
	State string `bson:"state,omitempty" json:"state,omitempty"`
	// MasterState is Primary or Secondary.
	MasterState string `bson:"masterState,omitempty" json:"masterState,omitempty"`
	// SyncState is the worst synchronisation state of the nodes.
	SyncState string `bson:"syncState,omitempty" json:"syncState,omitempty"`
	Peer      string `bson:"peer,omitempty" json:"peer,omitempty"`
	PeerState string `bson:"peerState,omitempty" json:"peerState,omitempty"`
	// LastTransition is when the node last changed master state, as the
	// appliance reports it.
	LastTransition string   `bson:"lastTransition,omitempty" json:"lastTransition,omitempty"`
	SyncFailures   int64    `bson:"syncFailures,omitempty" json:"syncFailures,omitempty"`
	Nodes          []HANode `bson:"nodes,omitempty" json:"nodes,omitempty"`
}

type HANode struct {
	ID          int    `bson:"id" json:"id"`
	Name        string `bson:"name,omitempty" json:"name,omitempty"`
	IP          string `bson:"ip,omitempty" json:"ip,omitempty"`
	State       string `bson:"state,omitempty" json:"state,omitempty"`
	MasterState string `bson:"masterState,omitempty" json:"masterState,omitempty"`
	Sync        string `bson:"sync,omitempty" json:"sync,omitempty"`
}

type Interface struct {
	ID          string `bson:"id" json:"id"`
	Description string `bson:"description,omitempty" json:"description,omitempty"`
	Enabled     bool   `bson:"enabled" json:"enabled"`
	Up          bool   `bson:"up" json:"up"`
	HAMonitor   bool   `bson:"haMonitor" json:"haMonitor"`
	Speed       string `bson:"speed,omitempty" json:"speed,omitempty"`
}

// Counts is what one pass found on an appliance. Ignored objects are left
// out of everything but the totals.
type Counts struct {
	Vservers         int `bson:"vservers" json:"vservers"`
	VserversDown     int `bson:"vserversDown" json:"vserversDown"`
	VserversDegraded int `bson:"vserversDegraded" json:"vserversDegraded"`
	VserversDisabled int `bson:"vserversDisabled" json:"vserversDisabled"`

	Services         int `bson:"services" json:"services"`
	ServicesDown     int `bson:"servicesDown" json:"servicesDown"`
	ServicesDisabled int `bson:"servicesDisabled" json:"servicesDisabled"`

	Certificates  int `bson:"certificates" json:"certificates"`
	CertsExpiring int `bson:"certsExpiring" json:"certsExpiring"`
	CertsExpired  int `bson:"certsExpired" json:"certsExpired"`

	Interfaces     int `bson:"interfaces" json:"interfaces"`
	InterfacesDown int `bson:"interfacesDown" json:"interfacesDown"`
}

// Object is what virtual servers, services and certificates share. Hash
// covers the document's content, so an unchanged object is not rewritten.
type Object struct {
	ID  string `bson:"_id" json:"id"`
	Ref `bson:",inline"`
	// Kind: lb, cs, vpn, aaa, gslb for virtual servers; service or
	// servicegroup for services; certificate.
	Kind string `bson:"kind" json:"kind"`
	Name string `bson:"name" json:"name"`
	// State is what the appliance reports: UP, DOWN, OUT OF SERVICE...
	State       string    `bson:"state" json:"state"`
	Status      string    `bson:"status" json:"status"`
	StatusSince time.Time `bson:"statusSince" json:"statusSince"`
	// Detail says why the status is not ok.
	Detail string `bson:"detail,omitempty" json:"detail,omitempty"`
	// Ignored objects match an ignore pattern: stored, but not counted.
	Ignored bool `bson:"ignored,omitempty" json:"ignored,omitempty"`
	// Search is the lower-cased text the dashboard searches.
	Search      string    `bson:"search" json:"-"`
	Hash        string    `bson:"hash" json:"-"`
	FirstSeenAt time.Time `bson:"firstSeenAt" json:"firstSeenAt"`
	// UpdatedAt is when the document was last written: when it last changed.
	UpdatedAt time.Time `bson:"updatedAt" json:"-"`
}

// Base returns the part every object document shares.
func (o *Object) Base() *Object { return o }

// Vserver is a load balancing, content switching, gateway, authentication
// or GSLB virtual server.
type Vserver struct {
	Object   `bson:",inline"`
	IP       string `bson:"ip,omitempty" json:"ip,omitempty"`
	Port     int    `bson:"port,omitempty" json:"port,omitempty"`
	Protocol string `bson:"protocol,omitempty" json:"protocol,omitempty"`
	// HealthPercent is the share of bound services that are up.
	HealthPercent *float64 `bson:"healthPercent,omitempty" json:"healthPercent,omitempty"`
	ServicesUp    *int     `bson:"servicesUp,omitempty" json:"servicesUp,omitempty"`
	ServicesDown  *int     `bson:"servicesDown,omitempty" json:"servicesDown,omitempty"`
}

// Service is a service or a service group.
type Service struct {
	Object   `bson:",inline"`
	IP       string `bson:"ip,omitempty" json:"ip,omitempty"`
	Port     int    `bson:"port,omitempty" json:"port,omitempty"`
	Protocol string `bson:"protocol,omitempty" json:"protocol,omitempty"`
}

// Certificate is a certificate-key pair installed on the appliance.
type Certificate struct {
	Object    `bson:",inline"`
	Subject   string     `bson:"subject,omitempty" json:"subject,omitempty"`
	Issuer    string     `bson:"issuer,omitempty" json:"issuer,omitempty"`
	Serial    string     `bson:"serial,omitempty" json:"serial,omitempty"`
	Types     []string   `bson:"types,omitempty" json:"types,omitempty"`
	NotBefore *time.Time `bson:"notBefore,omitempty" json:"notBefore,omitempty"`
	NotAfter  *time.Time `bson:"notAfter,omitempty" json:"notAfter,omitempty"`
	// DaysLeft is the appliance's own count of days to expiry.
	DaysLeft *int `bson:"daysLeft,omitempty" json:"daysLeft,omitempty"`
}

// Sample is one point of an appliance's history.
type Sample struct {
	Time         time.Time `bson:"time" json:"time"`
	Ref          `bson:",inline"`
	Status       string   `bson:"status" json:"status"`
	Reachable    bool     `bson:"reachable" json:"reachable"`
	LatencyMs    int64    `bson:"latencyMs" json:"latencyMs"`
	CPU          *float64 `bson:"cpu,omitempty" json:"cpu,omitempty"`
	MgmtCPU      *float64 `bson:"mgmtCpu,omitempty" json:"mgmtCpu,omitempty"`
	Memory       *float64 `bson:"memory,omitempty" json:"memory,omitempty"`
	DiskFlash    *float64 `bson:"diskFlash,omitempty" json:"diskFlash,omitempty"`
	DiskVar      *float64 `bson:"diskVar,omitempty" json:"diskVar,omitempty"`
	VserversDown int      `bson:"vserversDown" json:"vserversDown"`
	ServicesDown int      `bson:"servicesDown" json:"servicesDown"`
}

// Kinds of event (Event.Kind).
const (
	EventAppliance   = "appliance"
	EventCheck       = "check"
	EventHA          = "ha"
	EventRestart     = "restart"
	EventVserver     = "vserver"
	EventService     = "service"
	EventCertificate = "certificate"
)

// Event is a change of state: something went down, recovered, failed over.
type Event struct {
	Time  time.Time `bson:"time" json:"time"`
	Ref   `bson:",inline"`
	RunID string `bson:"runId" json:"runId"`
	Kind  string `bson:"kind" json:"kind"`
	// Name of the check or object; empty for the appliance itself.
	Name string `bson:"name,omitempty" json:"name,omitempty"`
	From string `bson:"from,omitempty" json:"from,omitempty"`
	To   string `bson:"to" json:"to"`
	// Severity is the health after the change.
	Severity string `bson:"severity" json:"severity"`
	Message  string `bson:"message" json:"message"`
}

// RunCounts is how the appliances of one pass came out.
type RunCounts struct {
	OK       int `bson:"ok" json:"ok"`
	Warning  int `bson:"warning" json:"warning"`
	Critical int `bson:"critical" json:"critical"`
	Unknown  int `bson:"unknown" json:"unknown"`
	Events   int `bson:"events" json:"events"`
}

// Run is one pass over every appliance.
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

	AppliancesTotal int `bson:"appliancesTotal" json:"appliancesTotal"`
	AppliancesDone  int `bson:"appliancesDone" json:"appliancesDone"`
	// AppliancesFailed could not be reached or logged in to.
	AppliancesFailed int            `bson:"appliancesFailed" json:"appliancesFailed"`
	Counts           RunCounts      `bson:"counts" json:"counts"`
	Appliances       []ApplianceRun `bson:"appliances" json:"appliances"`
}

// ApplianceRun is how checking one appliance went within a run. Status says
// whether the checker could do its work; Health is what it found.
type ApplianceRun struct {
	Ref        `bson:",inline"`
	Status     string    `bson:"status" json:"status"`
	Health     string    `bson:"health" json:"health"`
	Error      string    `bson:"error,omitempty" json:"error,omitempty"`
	StartedAt  time.Time `bson:"startedAt" json:"startedAt"`
	DurationMs int64     `bson:"durationMs" json:"durationMs"`
	Steps      []Step    `bson:"steps" json:"steps"`
}

type Step struct {
	Name       string `bson:"name" json:"name"`
	Status     string `bson:"status" json:"status"`
	Error      string `bson:"error,omitempty" json:"error,omitempty"`
	DurationMs int64  `bson:"durationMs" json:"durationMs"`
	Count      int    `bson:"count" json:"count"`
}

// Instance is the heartbeat document of one running checker.
type Instance struct {
	ID               string     `bson:"_id" json:"id"`
	Host             string     `bson:"host" json:"host"`
	Version          string     `bson:"version" json:"version"`
	Mode             string     `bson:"mode" json:"mode"` // schedule or once
	State            string     `bson:"state" json:"state"`
	PID              int        `bson:"pid" json:"pid"`
	StartedAt        time.Time  `bson:"startedAt" json:"startedAt"`
	HeartbeatAt      time.Time  `bson:"heartbeatAt" json:"heartbeatAt"`
	IntervalSeconds  int        `bson:"intervalSeconds,omitempty" json:"intervalSeconds,omitempty"`
	HeartbeatSeconds int        `bson:"heartbeatSeconds" json:"heartbeatSeconds"`
	Appliances       int        `bson:"appliances" json:"appliances"`
	CurrentRunID     string     `bson:"currentRunId,omitempty" json:"currentRunId,omitempty"`
	LastRunID        string     `bson:"lastRunId,omitempty" json:"lastRunId,omitempty"`
	LastRunStatus    string     `bson:"lastRunStatus,omitempty" json:"lastRunStatus,omitempty"`
	LastRunAt        *time.Time `bson:"lastRunAt,omitempty" json:"lastRunAt,omitempty"`
	NextRunAt        *time.Time `bson:"nextRunAt,omitempty" json:"nextRunAt,omitempty"`
}

// LogEntry is one structured log line.
type LogEntry struct {
	Time     time.Time `bson:"time" json:"time"`
	Level    string    `bson:"level" json:"level"`
	Severity int       `bson:"severity" json:"severity"`
	Msg      string    `bson:"msg" json:"msg"`
	Instance string    `bson:"instance,omitempty" json:"instance,omitempty"`
	RunID    string    `bson:"runId,omitempty" json:"runId,omitempty"`
	// Appliance is the configured name of the NetScaler the line is about.
	Appliance string         `bson:"appliance,omitempty" json:"appliance,omitempty"`
	Tenant    string         `bson:"tenantName,omitempty" json:"tenantName,omitempty"`
	Step      string         `bson:"step,omitempty" json:"step,omitempty"`
	Error     string         `bson:"error,omitempty" json:"error,omitempty"`
	Attrs     map[string]any `bson:"attrs,omitempty" json:"attrs,omitempty"`
}

// ObjectState is what the checker remembers of an object between passes.
type ObjectState struct {
	Kind      string
	Status    string
	Since     time.Time
	FirstSeen time.Time
	Hash      string
}

// State is what was stored about an appliance by earlier passes: enough to
// tell what changed. Appliance is nil when it has not been seen before.
type State struct {
	Appliance *Appliance
	// Objects by collection, then by document _id.
	Objects map[string]map[string]ObjectState
}

// NewID derives a document _id from its natural key, so the same object
// always gets the same _id.
func NewID(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.Join(parts, "\x00"))))
	return hex.EncodeToString(sum[:16])
}

// HashOf is a digest of v's JSON form.
func HashOf(v any) string {
	b, _ := json.Marshal(v)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}
