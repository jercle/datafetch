// Package model holds the documents stored in MongoDB.
package model

import "time"

// VM statuses.
const (
	StatusOK       = "ok"       // one current onboarding, nothing elsewhere
	StatusMigrated = "migrated" // older, superseded records exist in another org
	StatusConflict = "conflict" // reporting to more than one org at the same time
	StatusInactive = "inactive" // current record hasn't reported recently
)

// Onboarding record states.
const (
	StateCurrent    = "current"
	StateSuperseded = "superseded"
	StateConflict   = "conflict"
)

// Onboarding is one Defender machine record for a VM, in one tenant/org.
type Onboarding struct {
	OrgID            string     `bson:"orgId" json:"orgId"`
	TenantName       string     `bson:"tenantName" json:"tenantName"`
	TenantID         string     `bson:"tenantId" json:"tenantId"`
	MachineID        string     `bson:"machineId" json:"machineId"`
	ComputerDNSName  string     `bson:"computerDnsName" json:"computerDnsName"`
	FirstSeen        *time.Time `bson:"firstSeen" json:"firstSeen"`
	LastSeen         *time.Time `bson:"lastSeen" json:"lastSeen"`
	HealthStatus     string     `bson:"healthStatus" json:"healthStatus"`
	OnboardingStatus string     `bson:"onboardingStatus" json:"onboardingStatus"`
	RBACGroupName    string     `bson:"rbacGroupName" json:"rbacGroupName"`
	State            string     `bson:"state" json:"state"`
}

// TenantContact is the latest contact a VM has had with one Defender tenant/org,
// aggregated over every machine record the VM has there. Entries persist after
// the tenant stops returning the device (Present=false), so a VM's migration
// history survives Defender ageing out or offboarding the old record.
type TenantContact struct {
	TenantName       string     `bson:"tenantName" json:"tenantName"`
	TenantID         string     `bson:"tenantId" json:"tenantId"`
	OrgID            string     `bson:"orgId" json:"orgId"`
	FirstSeen        *time.Time `bson:"firstSeen" json:"firstSeen"` // earliest firstSeen across records
	LastSeen         *time.Time `bson:"lastSeen" json:"lastSeen"`   // latest contact with this org
	HealthStatus     string     `bson:"healthStatus" json:"healthStatus"`
	OnboardingStatus string     `bson:"onboardingStatus" json:"onboardingStatus"` // of the most recent record
	MachineIDs       []string   `bson:"machineIds" json:"machineIds"`
	Records          int        `bson:"records" json:"records"`
	State            string     `bson:"state" json:"state"`     // current | superseded | conflict
	Present          bool       `bson:"present" json:"present"` // returned by the API in the latest run
	LastCollectedAt  *time.Time `bson:"lastCollectedAt" json:"lastCollectedAt"`
}

type OrgChange struct {
	From       string    `bson:"from" json:"from"`
	To         string    `bson:"to" json:"to"`
	FromTenant string    `bson:"fromTenant" json:"fromTenant"`
	ToTenant   string    `bson:"toTenant" json:"toTenant"`
	At         time.Time `bson:"at" json:"at"`
	RunID      string    `bson:"runId" json:"runId"`
}

// VM is one physical/virtual machine, merged across every tenant it appears in.
// Stored in the VM collection with _id = Key.
type VM struct {
	Key string `bson:"-" json:"key"`

	Name            string `bson:"name" json:"name"`
	AzureResourceID string `bson:"azureResourceId" json:"azureResourceId"`
	AzureVMID       string `bson:"azureVmId" json:"azureVmId"`
	SubscriptionID  string `bson:"subscriptionId" json:"subscriptionId"`
	ResourceGroup   string `bson:"resourceGroup" json:"resourceGroup"`
	CloudProvider   string `bson:"cloudProvider" json:"cloudProvider"`
	AADDeviceID     string `bson:"aadDeviceId" json:"aadDeviceId"`
	OSPlatform      string `bson:"osPlatform" json:"osPlatform"`
	OSVersion       string `bson:"osVersion" json:"osVersion"`
	LastIPAddress   string `bson:"lastIpAddress" json:"lastIpAddress"`

	CurrentOrgID      string     `bson:"currentOrgId" json:"currentOrgId"`
	CurrentTenantName string     `bson:"currentTenantName" json:"currentTenantName"`
	CurrentTenantID   string     `bson:"currentTenantId" json:"currentTenantId"`
	CurrentMachineID  string     `bson:"currentMachineId" json:"currentMachineId"`
	CurrentFirstSeen  *time.Time `bson:"currentFirstSeen" json:"currentFirstSeen"`
	CurrentLastSeen   *time.Time `bson:"currentLastSeen" json:"currentLastSeen"`
	HealthStatus      string     `bson:"healthStatus" json:"healthStatus"`
	OnboardingStatus  string     `bson:"onboardingStatus" json:"onboardingStatus"`
	DefenderAVStatus  string     `bson:"defenderAvStatus" json:"defenderAvStatus"`
	RiskScore         string     `bson:"riskScore" json:"riskScore"`
	ExposureLevel     string     `bson:"exposureLevel" json:"exposureLevel"`
	MachineTags       []string   `bson:"machineTags" json:"machineTags"`

	Status      string          `bson:"status" json:"status"`
	OrgCount    int             `bson:"orgCount" json:"orgCount"` // distinct orgs in Tenants (incl. historical)
	Tenants     []TenantContact `bson:"tenants" json:"tenants"`   // latest contact per tenant, newest first
	Onboardings []Onboarding    `bson:"onboardings" json:"onboardings"`

	// True when records were joined on computerDnsName because they share no stable ID.
	MergedByHostname bool `bson:"mergedByHostname" json:"mergedByHostname"`

	// Migration helpers (derived from Tenants).
	PreviousOrgID      string     `bson:"previousOrgId" json:"previousOrgId"`           // most recent other org
	PreviousTenantName string     `bson:"previousTenantName" json:"previousTenantName"` //
	PreviousLastSeen   *time.Time `bson:"previousLastSeen" json:"previousLastSeen"`     // last contact with that org

	Active      bool      `bson:"active" json:"active"`
	LastRunID   string    `bson:"lastRunId" json:"lastRunId"`
	CollectedAt time.Time `bson:"collectedAt" json:"collectedAt"`
}

type TenantRun struct {
	Name       string `bson:"name" json:"name"`
	TenantID   string `bson:"tenantId" json:"tenantId"`
	OrgID      string `bson:"orgId" json:"orgId"`
	Fetched    int    `bson:"fetched" json:"fetched"` // machines returned by the API
	Matched    int    `bson:"matched" json:"matched"` // machines kept after the mode filter
	DurationMs int64  `bson:"durationMs" json:"durationMs"`
	Error      string `bson:"error,omitempty" json:"error,omitempty"`
}

// Run statuses.
const (
	RunRunning = "running"
	RunSuccess = "success"
	RunPartial = "partial"
	RunFailed  = "failed"
)

type Run struct {
	ID          string      `bson:"_id" json:"_id"`
	StartedAt   time.Time   `bson:"startedAt" json:"startedAt"`
	FinishedAt  *time.Time  `bson:"finishedAt" json:"finishedAt"`
	DurationMs  int64       `bson:"durationMs" json:"durationMs"`
	Status      string      `bson:"status" json:"status"`
	Mode        string      `bson:"mode" json:"mode"`
	Tenants     []TenantRun `bson:"tenants" json:"tenants"`
	VMs         int         `bson:"vms" json:"vms"`
	Conflicts   int         `bson:"conflicts" json:"conflicts"`
	Migrated    int         `bson:"migrated" json:"migrated"`
	Inactive    int         `bson:"inactive" json:"inactive"`
	OrgChanges  int         `bson:"orgChanges" json:"orgChanges"`
	Deactivated int64       `bson:"deactivated" json:"deactivated"`
	// VMs whose history includes an org other than the current one.
	WithPreviousOrg int    `bson:"withPreviousOrg" json:"withPreviousOrg"`
	VMsWritten      bool   `bson:"vmsWritten" json:"vmsWritten"`
	Error           string `bson:"error,omitempty" json:"error,omitempty"`
}

type LogEntry struct {
	Time    time.Time      `bson:"ts" json:"ts"`
	Level   string         `bson:"level" json:"level"`
	Msg     string         `bson:"msg" json:"msg"`
	Service string         `bson:"service" json:"service"`
	RunID   string         `bson:"runId,omitempty" json:"runId,omitempty"`
	Tenant  string         `bson:"tenant,omitempty" json:"tenant,omitempty"`
	VM      string         `bson:"vm,omitempty" json:"vm,omitempty"`
	Attrs   map[string]any `bson:"attrs,omitempty" json:"attrs,omitempty"`
}
