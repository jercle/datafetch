// Package model holds the documents sxg-check writes to MongoDB. The bson
// names are the schema the dashboard reads; see the README before renaming.
package model

import "time"

// Collections.
const (
	CollFirewalls = "sxg_firewalls"
	CollResults   = "sxg_results"
	CollEvents    = "sxg_events"
	CollRuns      = "sxg_runs"
	CollLogs      = "sxg_logs"
	CollInstances = "sxg_instances"
)

// Health of a check or a firewall. A firewall is as bad as its worst check.
const (
	HealthOK       = "ok"
	HealthWarning  = "warning"
	HealthCritical = "critical"
)

// Rank orders health states: the higher, the worse.
func Rank(health string) int {
	switch health {
	case HealthCritical:
		return 2
	case HealthWarning:
		return 1
	}
	return 0
}

// Run and instance states. These are about the checker itself, not about the
// firewalls: a run that found every firewall down is still a success.
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

// Kinds of check.
const (
	KindTCP      = "tcp"
	KindTLS      = "tls"
	KindWebAdmin = "webadmin"
	KindProxy    = "proxy"
	KindAPI      = "api"
	KindSNMP     = "snmp"
)

// Check is the outcome of one check on one firewall.
type Check struct {
	// ID is stable across runs: "tcp/4444", "proxy/https://example.com/",
	// "snmp/memory".
	ID   string `bson:"id" json:"id"`
	Kind string `bson:"kind" json:"kind"`
	// Name is what the dashboard shows: "TCP 4444", "Memory".
	Name    string `bson:"name" json:"name"`
	Status  string `bson:"status" json:"status"`
	Message string `bson:"message" json:"message"`
	// LatencyMs is how long the check took, when that means something.
	LatencyMs *int64 `bson:"latencyMs,omitempty" json:"latencyMs,omitempty"`
	// Value is the measured number, with its Unit ("%", "days", "ms").
	Value *float64 `bson:"value,omitempty" json:"value,omitempty"`
	Unit  string   `bson:"unit,omitempty" json:"unit,omitempty"`
	// Since is when the check entered its current Status.
	Since time.Time `bson:"since" json:"since"`
}

// Device is what the firewall says about itself over SNMP.
type Device struct {
	Hostname string `bson:"hostname,omitempty" json:"hostname,omitempty"`
	Model    string `bson:"model,omitempty" json:"model,omitempty"`
	Firmware string `bson:"firmware,omitempty" json:"firmware,omitempty"`
	// AppKey is the appliance key (serial).
	AppKey        string `bson:"appKey,omitempty" json:"appKey,omitempty"`
	WebcatVersion string `bson:"webcatVersion,omitempty" json:"webcatVersion,omitempty"`
	IPSVersion    string `bson:"ipsVersion,omitempty" json:"ipsVersion,omitempty"`
	// APIVersion is from the XML API check.
	APIVersion string `bson:"apiVersion,omitempty" json:"apiVersion,omitempty"`
}

// Metrics are the numbers of one pass. A nil field was not read.
type Metrics struct {
	CPUPercent    *float64 `bson:"cpuPercent,omitempty" json:"cpuPercent,omitempty"`
	MemoryPercent *float64 `bson:"memoryPercent,omitempty" json:"memoryPercent,omitempty"`
	SwapPercent   *float64 `bson:"swapPercent,omitempty" json:"swapPercent,omitempty"`
	DiskPercent   *float64 `bson:"diskPercent,omitempty" json:"diskPercent,omitempty"`
	// Capacities as the firewall reports them (sfosMemoryCapacity and
	// friends), which is megabytes.
	MemoryMB *int64 `bson:"memoryMb,omitempty" json:"memoryMb,omitempty"`
	SwapMB   *int64 `bson:"swapMb,omitempty" json:"swapMb,omitempty"`
	DiskMB   *int64 `bson:"diskMb,omitempty" json:"diskMb,omitempty"`
	// LiveUsers is the number of signed-in users.
	LiveUsers     *int64 `bson:"liveUsers,omitempty" json:"liveUsers,omitempty"`
	UptimeSeconds *int64 `bson:"uptimeSeconds,omitempty" json:"uptimeSeconds,omitempty"`
	// ProxyLatencyMs is the slowest successful request through the proxy.
	ProxyLatencyMs *int64 `bson:"proxyLatencyMs,omitempty" json:"proxyLatencyMs,omitempty"`
}

// Empty reports whether nothing was measured.
func (m Metrics) Empty() bool { return m == Metrics{} }

// HA is the high-availability state.
type HA struct {
	Enabled bool `bson:"enabled" json:"enabled"`
	// State and PeerState: notapplicable, auxiliary, standalone, primary,
	// faulty or ready.
	State     string `bson:"state,omitempty" json:"state,omitempty"`
	PeerState string `bson:"peerState,omitempty" json:"peerState,omitempty"`
	// Mode is the configured mode, as the firewall words it.
	Mode       string `bson:"mode,omitempty" json:"mode,omitempty"`
	PeerAppKey string `bson:"peerAppKey,omitempty" json:"peerAppKey,omitempty"`
}

// Service is one SFOS service: untouched, stopped, initializing, running,
// exiting, dead, frozen or unregistered.
type Service struct {
	Name   string `bson:"name" json:"name"`
	Status string `bson:"status" json:"status"`
}

// License is one subscription: none, evaluating, notsubscribed, subscribed,
// expired or deactivated.
type License struct {
	Name   string `bson:"name" json:"name"`
	Status string `bson:"status" json:"status"`
	// Expires is the expiry date as the firewall gives it; ExpiresAt is set
	// when it could be read as a date.
	Expires   string     `bson:"expires,omitempty" json:"expires,omitempty"`
	ExpiresAt *time.Time `bson:"expiresAt,omitempty" json:"expiresAt,omitempty"`
}

// Counts of checks by health.
type Counts struct {
	OK       int `bson:"ok" json:"ok"`
	Warning  int `bson:"warning" json:"warning"`
	Critical int `bson:"critical" json:"critical"`
}

// Add counts one more of the given health.
func (c *Counts) Add(health string) {
	switch health {
	case HealthCritical:
		c.Critical++
	case HealthWarning:
		c.Warning++
	default:
		c.OK++
	}
}

// Firewall is the current state of one firewall. _id is its configured name.
type Firewall struct {
	ID   string `bson:"_id" json:"id"`
	Name string `bson:"name" json:"name"`
	Host string `bson:"host" json:"host"`
	// Search is name, host and site in lower case.
	Search     string   `bson:"search" json:"search"`
	TenantName string   `bson:"tenantName,omitempty" json:"tenantName,omitempty"`
	Site       string   `bson:"site,omitempty" json:"site,omitempty"`
	Tags       []string `bson:"tags,omitempty" json:"tags,omitempty"`
	// Instance is the checker that owns this document.
	Instance string `bson:"instance" json:"instance"`
	RunID    string `bson:"runId" json:"runId"`

	Status string `bson:"status" json:"status"`
	// Severity is Rank(Status), so the worst sort first.
	Severity    int       `bson:"severity" json:"severity"`
	StatusSince time.Time `bson:"statusSince" json:"statusSince"`
	// Summary is the messages of the checks that are not ok.
	Summary string  `bson:"summary,omitempty" json:"summary,omitempty"`
	Counts  Counts  `bson:"counts" json:"counts"`
	Checks  []Check `bson:"checks" json:"checks"`

	// Device is kept from the last pass that could read it; the rest below
	// is from the latest pass only.
	Device   *Device   `bson:"device,omitempty" json:"device,omitempty"`
	Metrics  *Metrics  `bson:"metrics,omitempty" json:"metrics,omitempty"`
	HA       *HA       `bson:"ha,omitempty" json:"ha,omitempty"`
	Services []Service `bson:"services,omitempty" json:"services,omitempty"`
	Licenses []License `bson:"licenses,omitempty" json:"licenses,omitempty"`

	FirstSeenAt   time.Time  `bson:"firstSeenAt" json:"firstSeenAt"`
	LastCheckedAt time.Time  `bson:"lastCheckedAt" json:"lastCheckedAt"`
	LastOKAt      *time.Time `bson:"lastOkAt,omitempty" json:"lastOkAt,omitempty"`
	// IntervalSeconds is how often the checker comes back (0 for a single
	// run); the dashboard uses it to tell when the state is stale.
	IntervalSeconds int `bson:"intervalSeconds" json:"intervalSeconds"`
}

// Failing is a check that was not ok, as kept in the history.
type Failing struct {
	ID      string `bson:"id" json:"id"`
	Name    string `bson:"name" json:"name"`
	Status  string `bson:"status" json:"status"`
	Message string `bson:"message" json:"message"`
}

// Result is one pass over one firewall, kept as history.
type Result struct {
	At         time.Time `bson:"at" json:"at"`
	RunID      string    `bson:"runId" json:"runId"`
	Firewall   string    `bson:"firewall" json:"firewall"`
	TenantName string    `bson:"tenantName,omitempty" json:"tenantName,omitempty"`
	Status     string    `bson:"status" json:"status"`
	Counts     Counts    `bson:"counts" json:"counts"`
	Metrics    *Metrics  `bson:"metrics,omitempty" json:"metrics,omitempty"`
	Failing    []Failing `bson:"failing,omitempty" json:"failing,omitempty"`
}

// Event is a change of health: of one check, or of the firewall as a whole
// (Check is then empty).
type Event struct {
	At         time.Time `bson:"at" json:"at"`
	RunID      string    `bson:"runId" json:"runId"`
	Firewall   string    `bson:"firewall" json:"firewall"`
	TenantName string    `bson:"tenantName,omitempty" json:"tenantName,omitempty"`
	Check      string    `bson:"check,omitempty" json:"check,omitempty"`
	CheckName  string    `bson:"checkName,omitempty" json:"checkName,omitempty"`
	// From is empty the first time a firewall or check is seen.
	From string `bson:"from,omitempty" json:"from,omitempty"`
	To   string `bson:"to" json:"to"`
	// Severity is Rank(To).
	Severity int    `bson:"severity" json:"severity"`
	Message  string `bson:"message,omitempty" json:"message,omitempty"`
	// DownForMs is how long the previous state lasted.
	DownForMs int64 `bson:"previousMs,omitempty" json:"previousMs,omitempty"`
}

// Run is one pass over every firewall.
type Run struct {
	ID          string     `bson:"_id" json:"id"`
	Status      string     `bson:"status" json:"status"`
	Trigger     string     `bson:"trigger" json:"trigger"` // schedule or manual
	Instance    string     `bson:"instance" json:"instance"`
	Version     string     `bson:"version" json:"version"`
	StartedAt   time.Time  `bson:"startedAt" json:"startedAt"`
	HeartbeatAt time.Time  `bson:"heartbeatAt" json:"heartbeatAt"`
	FinishedAt  *time.Time `bson:"finishedAt,omitempty" json:"finishedAt,omitempty"`
	DurationMs  int64      `bson:"durationMs" json:"durationMs"`
	Error       string     `bson:"error,omitempty" json:"error,omitempty"`

	FirewallsTotal int `bson:"firewallsTotal" json:"firewallsTotal"`
	FirewallsDone  int `bson:"firewallsDone" json:"firewallsDone"`
	// FirewallsFailed could not be stored. A firewall that is down is not a
	// failure of the run.
	FirewallsFailed int `bson:"firewallsFailed" json:"firewallsFailed"`
	// Counts is firewalls by health; Checks is checks by health.
	Counts Counts `bson:"counts" json:"counts"`
	Checks Counts `bson:"checks" json:"checks"`
	// Changes is how many health changes the run recorded.
	Changes   int           `bson:"changes" json:"changes"`
	Firewalls []FirewallRun `bson:"firewalls" json:"firewalls"`
}

// FirewallRun is the outcome for one firewall within a run.
type FirewallRun struct {
	Name       string `bson:"name" json:"name"`
	TenantName string `bson:"tenantName,omitempty" json:"tenantName,omitempty"`
	// Health is the firewall's health; Error is set when it was not stored.
	Health     string `bson:"health" json:"health"`
	Error      string `bson:"error,omitempty" json:"error,omitempty"`
	DurationMs int64  `bson:"durationMs" json:"durationMs"`
	Checks     Counts `bson:"checks" json:"checks"`
	Changes    int    `bson:"changes" json:"changes"`
	Summary    string `bson:"summary,omitempty" json:"summary,omitempty"`
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
	Firewalls        int        `bson:"firewalls" json:"firewalls"`
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
	// Firewall and Check name what the line is about.
	Firewall string         `bson:"firewall,omitempty" json:"firewall,omitempty"`
	Tenant   string         `bson:"tenantName,omitempty" json:"tenantName,omitempty"`
	Check    string         `bson:"check,omitempty" json:"check,omitempty"`
	Error    string         `bson:"error,omitempty" json:"error,omitempty"`
	Attrs    map[string]any `bson:"attrs,omitempty" json:"attrs,omitempty"`
}
