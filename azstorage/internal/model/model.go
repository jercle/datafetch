// Package model holds the documents az-storage writes to MongoDB. The bson
// names are the schema the dashboard reads; see the README before renaming.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

// Collections.
const (
	CollTenants       = "azs_tenants"
	CollSubscriptions = "azs_subscriptions"
	CollAccounts      = "azs_accounts"
	CollContainers    = "azs_containers"
	CollDisks         = "azs_disks"
	CollRuns          = "azs_runs"
	CollLogs          = "azs_logs"
	CollInstances     = "azs_instances"
)

// Run, step and instance states.
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

// How a container's size was arrived at (Container.SizeStatus).
const (
	// SizeMeasured: every blob was listed and added up.
	SizeMeasured = "measured"
	// SizePartial: listing stopped at the configured blob limit; the size is
	// a lower bound.
	SizePartial = "partial"
	// SizeDenied: the service principal may not read blobs here (it needs
	// Storage Blob Data Reader).
	SizeDenied = "denied"
	// SizeBlocked: the account's network rules refused the collector.
	SizeBlocked = "blocked"
	// SizeUnreachable: the blob endpoint could not be connected to.
	SizeUnreachable = "unreachable"
	// SizeFailed: any other error.
	SizeFailed = "failed"
	// SizeSkipped: measuring is switched off, or the account is excluded.
	SizeSkipped = "skipped"
)

// Usage metric status of a storage account (Account.UsageStatus).
const (
	UsageKnown   = "known"
	UsageMissing = "missing" // Azure Monitor returned no value
	UsageFailed  = "failed"
	UsageSkipped = "skipped"
)

// Scope is on every document: which tenant it came from.
type Scope struct {
	// TenantName is the label configured for the tenant.
	TenantName string `bson:"tenantName" json:"tenantName"`
	TenantID   string `bson:"tenantId" json:"tenantId"`
}

// Counts is how much one pass over a tenant, a subscription or the whole run
// found. Sizes are bytes.
type Counts struct {
	Subscriptions int `bson:"subscriptions" json:"subscriptions"`

	Accounts int `bson:"accounts" json:"accounts"`
	// AccountsUnknown have no used size: Azure Monitor returned none, or
	// could not be read.
	AccountsUnknown int `bson:"accountsUnknown" json:"accountsUnknown"`
	// UsedBytes is the storage accounts' used capacity, as Azure Monitor
	// reports it; the four below are its parts.
	UsedBytes  int64 `bson:"usedBytes" json:"usedBytes"`
	BlobBytes  int64 `bson:"blobBytes" json:"blobBytes"`
	FileBytes  int64 `bson:"fileBytes" json:"fileBytes"`
	TableBytes int64 `bson:"tableBytes" json:"tableBytes"`
	QueueBytes int64 `bson:"queueBytes" json:"queueBytes"`

	Containers int `bson:"containers" json:"containers"`
	// ContainersMeasured were sized in this pass (fully or up to the limit).
	ContainersMeasured int `bson:"containersMeasured" json:"containersMeasured"`
	// ContainerBytes is the size of the measured containers.
	ContainerBytes int64 `bson:"containerBytes" json:"containerBytes"`
	// Blobs is the storage accounts' blob count, as Azure Monitor reports it.
	Blobs int64 `bson:"blobs" json:"blobs"`

	Disks int `bson:"disks" json:"disks"`
	// DiskBytes is the provisioned size of the managed disks.
	DiskBytes       int64 `bson:"diskBytes" json:"diskBytes"`
	DisksUnattached int   `bson:"disksUnattached" json:"disksUnattached"`
	UnattachedBytes int64 `bson:"unattachedBytes" json:"unattachedBytes"`

	Warnings int `bson:"warnings" json:"warnings"`
}

// Add accumulates o into c.
func (c *Counts) Add(o Counts) {
	c.Subscriptions += o.Subscriptions
	c.Accounts += o.Accounts
	c.AccountsUnknown += o.AccountsUnknown
	c.UsedBytes += o.UsedBytes
	c.BlobBytes += o.BlobBytes
	c.FileBytes += o.FileBytes
	c.TableBytes += o.TableBytes
	c.QueueBytes += o.QueueBytes
	c.Containers += o.Containers
	c.ContainersMeasured += o.ContainersMeasured
	c.ContainerBytes += o.ContainerBytes
	c.Blobs += o.Blobs
	c.Disks += o.Disks
	c.DiskBytes += o.DiskBytes
	c.DisksUnattached += o.DisksUnattached
	c.UnattachedBytes += o.UnattachedBytes
	c.Warnings += o.Warnings
}

// Tenant is one document per tenant: how fresh the data is. _id is the
// tenant ID.
type Tenant struct {
	ID    string `bson:"_id" json:"id"`
	Scope `bson:",inline"`

	Counts Counts `bson:"counts" json:"counts"`
	// Missing names what the last pass could not collect ("usage",
	// "containers", "disks").
	Missing []string `bson:"missing" json:"missing"`

	LastRunID     string     `bson:"lastRunId" json:"lastRunId"`
	LastStatus    string     `bson:"lastStatus" json:"lastStatus"`
	LastError     string     `bson:"lastError,omitempty" json:"lastError,omitempty"`
	LastAttemptAt time.Time  `bson:"lastAttemptAt" json:"lastAttemptAt"`
	LastSuccessAt *time.Time `bson:"lastSuccessAt,omitempty" json:"lastSuccessAt,omitempty"`
}

// Subscription is one document per subscription, with its totals. _id is
// NewID(scope, "subscription", subscriptionId).
type Subscription struct {
	ID    string `bson:"_id" json:"id"`
	Scope `bson:",inline"`
	RunID string `bson:"runId" json:"runId"`

	SubscriptionID string `bson:"subscriptionId" json:"subscriptionId"`
	Name           string `bson:"name" json:"name"`
	State          string `bson:"state,omitempty" json:"state,omitempty"`
	Counts         Counts `bson:"counts" json:"counts"`

	LastSeenAt time.Time `bson:"lastSeenAt" json:"lastSeenAt"`
}

// Resource is what every Azure resource document carries.
type Resource struct {
	// ResourceID is the ARM id as Azure returns it.
	ResourceID string `bson:"resourceId" json:"resourceId"`
	Name       string `bson:"name" json:"name"`
	Search     string `bson:"search" json:"search"` // lower-case name
	Location   string `bson:"location,omitempty" json:"location,omitempty"`
	// ResourceGroup is lower case, so it can be filtered on exactly.
	ResourceGroup    string            `bson:"resourceGroup,omitempty" json:"resourceGroup,omitempty"`
	SubscriptionID   string            `bson:"subscriptionId" json:"subscriptionId"`
	SubscriptionName string            `bson:"subscriptionName,omitempty" json:"subscriptionName,omitempty"`
	Tags             map[string]string `bson:"tags,omitempty" json:"tags,omitempty"`
}

// Account is one storage account. _id is NewID(scope, "account", resourceId).
type Account struct {
	ID       string `bson:"_id" json:"id"`
	Scope    `bson:",inline"`
	RunID    string `bson:"runId" json:"runId"`
	Resource `bson:",inline"`

	Kind       string `bson:"kind,omitempty" json:"kind,omitempty"`
	Sku        string `bson:"sku,omitempty" json:"sku,omitempty"`
	AccessTier string `bson:"accessTier,omitempty" json:"accessTier,omitempty"`
	// HNS: hierarchical namespace (Data Lake Storage Gen2).
	HNS                 bool       `bson:"hns" json:"hns"`
	CreatedAt           *time.Time `bson:"createdAt,omitempty" json:"createdAt,omitempty"`
	BlobEndpoint        string     `bson:"blobEndpoint,omitempty" json:"blobEndpoint,omitempty"`
	PublicNetworkAccess string     `bson:"publicNetworkAccess,omitempty" json:"publicNetworkAccess,omitempty"`
	// NetworkDefaultAction is the firewall's default: Allow or Deny.
	NetworkDefaultAction string `bson:"networkDefaultAction,omitempty" json:"networkDefaultAction,omitempty"`
	// AllowBlobPublicAccess: containers may be made anonymously readable.
	AllowBlobPublicAccess bool   `bson:"allowBlobPublicAccess" json:"allowBlobPublicAccess"`
	MinimumTLS            string `bson:"minimumTls,omitempty" json:"minimumTls,omitempty"`

	// UsageStatus is known, missing, failed or skipped. The sizes are from
	// Azure Monitor's capacity metrics, which Azure refreshes about daily;
	// UsageAt is the time of the value used. They are only set when known.
	UsageStatus string     `bson:"usageStatus" json:"usageStatus"`
	UsageError  string     `bson:"usageError,omitempty" json:"usageError,omitempty"`
	UsageAt     *time.Time `bson:"usageAt,omitempty" json:"usageAt,omitempty"`
	UsedBytes   int64      `bson:"usedBytes" json:"usedBytes"`
	BlobBytes   int64      `bson:"blobBytes" json:"blobBytes"`
	FileBytes   int64      `bson:"fileBytes" json:"fileBytes"`
	TableBytes  int64      `bson:"tableBytes" json:"tableBytes"`
	QueueBytes  int64      `bson:"queueBytes" json:"queueBytes"`
	BlobCount   int64      `bson:"blobCount" json:"blobCount"`
	FileShares  int64      `bson:"fileShares" json:"fileShares"`

	// Containers is how many blob containers were listed; ContainersStatus
	// is success, failed or skipped.
	Containers       int    `bson:"containers" json:"containers"`
	ContainersStatus string `bson:"containersStatus" json:"containersStatus"`
	ContainersError  string `bson:"containersError,omitempty" json:"containersError,omitempty"`
	// ContainersMeasured of them were sized by listing their blobs, adding
	// up to ContainerBytes.
	ContainersMeasured int   `bson:"containersMeasured" json:"containersMeasured"`
	ContainerBytes     int64 `bson:"containerBytes" json:"containerBytes"`
	// SizeStatus is set when the containers could not be measured for a
	// reason that applies to the whole account (blocked, unreachable,
	// denied, skipped).
	SizeStatus string `bson:"sizeStatus,omitempty" json:"sizeStatus,omitempty"`

	// FirstSeenAt is set when the document is first written and then kept.
	FirstSeenAt time.Time `bson:"firstSeenAt" json:"firstSeenAt"`
	LastSeenAt  time.Time `bson:"lastSeenAt" json:"lastSeenAt"`
}

// TierUsage is the blobs of one access tier in a container.
type TierUsage struct {
	Bytes int64 `bson:"bytes" json:"bytes"`
	Count int64 `bson:"count" json:"count"`
}

// ContainerSize is what listing a container's blobs added up to. Sizes are
// the blobs' content lengths.
type ContainerSize struct {
	// UsedBytes is everything: current blobs, snapshots, earlier versions
	// and soft-deleted blobs.
	UsedBytes     int64 `bson:"usedBytes" json:"usedBytes"`
	CurrentBytes  int64 `bson:"currentBytes" json:"currentBytes"`
	SnapshotBytes int64 `bson:"snapshotBytes" json:"snapshotBytes"`
	VersionBytes  int64 `bson:"versionBytes" json:"versionBytes"`
	DeletedBytes  int64 `bson:"deletedBytes" json:"deletedBytes"`
	// Blobs is the current blobs; Objects adds snapshots, versions and
	// soft-deleted blobs.
	Blobs   int64 `bson:"blobs" json:"blobs"`
	Objects int64 `bson:"objects" json:"objects"`
	// Tiers is UsedBytes by access tier (Hot, Cool, Cold, Archive; "None"
	// for blobs without one, such as page blobs).
	Tiers map[string]TierUsage `bson:"tiers,omitempty" json:"tiers,omitempty"`
	// SizedAt is when the listing finished.
	SizedAt *time.Time `bson:"sizedAt,omitempty" json:"sizedAt,omitempty"`
}

// Container is one blob container. _id is NewID(scope, "container",
// resourceId).
type Container struct {
	ID    string `bson:"_id" json:"id"`
	Scope `bson:",inline"`
	RunID string `bson:"runId" json:"runId"`

	// AccountID is the _id of the storage account document.
	AccountID        string `bson:"accountId" json:"accountId"`
	AccountName      string `bson:"accountName" json:"accountName"`
	ResourceID       string `bson:"resourceId" json:"resourceId"`
	Name             string `bson:"name" json:"name"`
	Search           string `bson:"search" json:"search"` // account/container, lower case
	ResourceGroup    string `bson:"resourceGroup,omitempty" json:"resourceGroup,omitempty"`
	SubscriptionID   string `bson:"subscriptionId" json:"subscriptionId"`
	SubscriptionName string `bson:"subscriptionName,omitempty" json:"subscriptionName,omitempty"`

	// PublicAccess is None, Blob or Container.
	PublicAccess    string     `bson:"publicAccess" json:"publicAccess"`
	LeaseState      string     `bson:"leaseState,omitempty" json:"leaseState,omitempty"`
	LastModifiedAt  *time.Time `bson:"lastModifiedAt,omitempty" json:"lastModifiedAt,omitempty"`
	ImmutablePolicy bool       `bson:"immutablePolicy" json:"immutablePolicy"`
	LegalHold       bool       `bson:"legalHold" json:"legalHold"`

	// SizeStatus says how the size was arrived at. When a pass cannot
	// measure a container, the size of the last pass that could is kept, with
	// its SizedAt; SizeStatus and SizeError are about the latest attempt.
	SizeStatus    string `bson:"sizeStatus" json:"sizeStatus"`
	SizeError     string `bson:"sizeError,omitempty" json:"sizeError,omitempty"`
	ContainerSize `bson:",inline"`

	FirstSeenAt time.Time `bson:"firstSeenAt" json:"firstSeenAt"`
	LastSeenAt  time.Time `bson:"lastSeenAt" json:"lastSeenAt"`
}

// Sized reports whether this pass produced a size.
func (c *Container) Sized() bool {
	return c.SizeStatus == SizeMeasured || c.SizeStatus == SizePartial
}

// Disk is one managed disk. _id is NewID(scope, "disk", resourceId).
type Disk struct {
	ID       string `bson:"_id" json:"id"`
	Scope    `bson:",inline"`
	RunID    string `bson:"runId" json:"runId"`
	Resource `bson:",inline"`

	Sku  string `bson:"sku,omitempty" json:"sku,omitempty"`
	Tier string `bson:"tier,omitempty" json:"tier,omitempty"` // performance tier: P30
	// SizeBytes is the provisioned size. Azure does not report how much of
	// a managed disk is in use.
	SizeGB    int64 `bson:"sizeGb" json:"sizeGb"`
	SizeBytes int64 `bson:"sizeBytes" json:"sizeBytes"`
	// State is Azure's diskState: Attached, Unattached, Reserved, ActiveSAS...
	State    string `bson:"state" json:"state"`
	Attached bool   `bson:"attached" json:"attached"`
	// ManagedBy is the ID of the virtual machine the disk is attached to;
	// AttachedTo is its name.
	ManagedBy  string   `bson:"managedBy,omitempty" json:"managedBy,omitempty"`
	AttachedTo string   `bson:"attachedTo,omitempty" json:"attachedTo,omitempty"`
	OSType     string   `bson:"osType,omitempty" json:"osType,omitempty"`
	IOPS       int64    `bson:"iops,omitempty" json:"iops,omitempty"`
	MBps       int64    `bson:"mbps,omitempty" json:"mbps,omitempty"`
	Zones      []string `bson:"zones,omitempty" json:"zones,omitempty"`
	Encryption string   `bson:"encryption,omitempty" json:"encryption,omitempty"`
	// CreateOption is how the disk was made: Empty, FromImage, Copy, Restore...
	CreateOption        string     `bson:"createOption,omitempty" json:"createOption,omitempty"`
	NetworkAccessPolicy string     `bson:"networkAccessPolicy,omitempty" json:"networkAccessPolicy,omitempty"`
	CreatedAt           *time.Time `bson:"createdAt,omitempty" json:"createdAt,omitempty"`
	// OwnershipChangedAt is when the disk was last attached or detached.
	OwnershipChangedAt *time.Time `bson:"ownershipChangedAt,omitempty" json:"ownershipChangedAt,omitempty"`

	FirstSeenAt time.Time `bson:"firstSeenAt" json:"firstSeenAt"`
	LastSeenAt  time.Time `bson:"lastSeenAt" json:"lastSeenAt"`
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

	TenantsTotal  int         `bson:"tenantsTotal" json:"tenantsTotal"`
	TenantsDone   int         `bson:"tenantsDone" json:"tenantsDone"`
	TenantsFailed int         `bson:"tenantsFailed" json:"tenantsFailed"`
	Counts        Counts      `bson:"counts" json:"counts"`
	Tenants       []TenantRun `bson:"tenants" json:"tenants"`
}

// TenantRun is the outcome for one tenant within a run.
type TenantRun struct {
	Scope      `bson:",inline"`
	Status     string    `bson:"status" json:"status"`
	Error      string    `bson:"error,omitempty" json:"error,omitempty"`
	StartedAt  time.Time `bson:"startedAt" json:"startedAt"`
	DurationMs int64     `bson:"durationMs" json:"durationMs"`
	Counts     Counts    `bson:"counts" json:"counts"`
	Steps      []Step    `bson:"steps" json:"steps"`
}

type Step struct {
	Name       string `bson:"name" json:"name"`
	Status     string `bson:"status" json:"status"`
	Error      string `bson:"error,omitempty" json:"error,omitempty"`
	DurationMs int64  `bson:"durationMs" json:"durationMs"`
	Count      int    `bson:"count" json:"count"`
	// Skipped is how many items the step could not do: accounts without a
	// usage value, containers that were not measured.
	Skipped int `bson:"skipped,omitempty" json:"skipped,omitempty"`
}

// Instance is the heartbeat document of one running collector.
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
	Tenants          []Scope    `bson:"tenants" json:"tenants"`
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
	Tenant   string    `bson:"tenantName,omitempty" json:"tenantName,omitempty"`
	Step     string    `bson:"step,omitempty" json:"step,omitempty"`
	// Account is the storage account the line is about.
	Account string         `bson:"account,omitempty" json:"account,omitempty"`
	Error   string         `bson:"error,omitempty" json:"error,omitempty"`
	Attrs   map[string]any `bson:"attrs,omitempty" json:"attrs,omitempty"`
}

// NewID derives a document _id from the scope, the kind of object and its
// natural key, so the same object always gets the same _id.
func NewID(s Scope, kind, key string) string {
	sum := sha256.Sum256([]byte(s.TenantID + "\x00" + kind + "\x00" + strings.ToLower(key)))
	return hex.EncodeToString(sum[:16])
}
