// Package graph holds the node/edge model stored in MongoDB and the pure
// logic that turns Azure and Defender data into nodes and edges.
package graph

import (
	"crypto/sha1"
	"encoding/hex"
	"sort"
	"strings"
	"time"
)

// Node kinds.
const (
	KindTenant        = "tenant"
	KindSubscription  = "subscription"
	KindResourceGroup = "resourceGroup"
	KindResource      = "resource"
	KindSubnet        = "subnet"
	KindIP            = "ip"
	KindDevice        = "device"
	KindCVE           = "cve"
	KindSoftware      = "software"
)

// Edge relations. Edges are stored once and can be walked both ways.
const (
	RelContains    = "contains"     // tenant > subscription > resource group > resource > child
	RelAttached    = "attached"     // VM -> NIC, VM -> disk, NIC -> public IP resource
	RelHasIP       = "has_ip"       // NIC / VM / public IP resource -> IP address
	RelInSubnet    = "in_subnet"    // NIC / load balancer frontend -> subnet
	RelSecuredBy   = "secured_by"   // NIC -> network security group
	RelFrontend    = "frontend"     // load balancer / app gateway -> public IP resource or IP
	RelBackend     = "backend"      // load balancer / app gateway -> NIC, VM, IP, app service
	RelReferences  = "references"   // any other resource ID found in a resource's properties
	RelRunsOn      = "runs_on"      // Defender device -> Azure resource
	RelAffectedBy  = "affected_by"  // device -> CVE (one edge per software version)
	RelHasSoftware = "has_software" // device -> software (one edge per version)
)

// Sources: which stage owns a node or edge. A stage that completes for a
// tenant deletes whatever it wrote in earlier runs and did not see this time.
const (
	SourceARM      = "arm"
	SourceDevices  = "mde-devices"
	SourceSoftware = "mde-software"
	SourceVulns    = "mde-vulnerabilities"
)

// Tag uses the attribute pattern so one multikey index serves every key.
type Tag struct {
	K string `bson:"k" json:"k"`
	V string `bson:"v" json:"v"`
}

// Node is a document in graph_nodes. Other stages add fields that are not
// part of this struct and survive upserts: vuln, software, cost.
type Node struct {
	ID   string `bson:"_id"`
	Kind string `bson:"kind"`
	// Type is the lower-case ARM type for resources, the OS platform for
	// devices and "public" / "private" for IP addresses.
	Type string `bson:"type"`
	Name string `bson:"name"`
	// Q is lower-case text the dashboard searches.
	Q              string `bson:"q"`
	TenantID       string `bson:"tenantId,omitempty"`
	SubscriptionID string `bson:"subscriptionId,omitempty"`
	ResourceGroup  string `bson:"resourceGroup,omitempty"`
	Location       string `bson:"location,omitempty"`
	// Group is the device group a device was assigned to at collection.
	Group string         `bson:"group,omitempty"`
	Tags  []Tag          `bson:"tags"`
	Attrs map[string]any `bson:"attrs"`
	// Vuln is set here only for images and containers, whose CVE counts are
	// known when the node is built: {critical, high, medium, low, total}.
	Vuln map[string]any `bson:"vuln,omitempty"`
	// Details is written by the CVE catalogue stage only.
	Details map[string]any `bson:"details,omitempty"`
	Source  string         `bson:"source"`
	// Via is the configured tenant whose service principal saw this; empty
	// for CVE and software nodes, which are shared by all tenants.
	Via    string    `bson:"via"`
	RunID  string    `bson:"runId"`
	SeenAt time.Time `bson:"seenAt"`
}

// Edge is a document in graph_edges.
type Edge struct {
	ID       string `bson:"_id"`
	From     string `bson:"from"`
	To       string `bson:"to"`
	Rel      string `bson:"rel"`
	FromKind string `bson:"fromKind,omitempty"`
	ToKind   string `bson:"toKind,omitempty"`
	Key      string `bson:"key,omitempty"`
	// Group is the device group of the device at either end, so lists of
	// devices can leave hidden groups out without loading every device.
	Group  string         `bson:"group,omitempty"`
	Attrs  map[string]any `bson:"attrs,omitempty"`
	Source string         `bson:"source"`
	Via    string         `bson:"via"`
	RunID  string         `bson:"runId"`
	SeenAt time.Time      `bson:"seenAt"`
}

// EdgeID is stable for (from, rel, to, key), so re-collecting upserts in place.
func EdgeID(from, rel, to, key string) string {
	h := sha1.Sum([]byte(from + "\x00" + rel + "\x00" + to + "\x00" + key))
	return hex.EncodeToString(h[:16])
}

// ---- node IDs ----

// ARMID normalises an Azure resource ID: lower case, no trailing slash.
func ARMID(id string) string { return strings.ToLower(strings.TrimRight(strings.TrimSpace(id), "/")) }

func TenantID(tenant string) string { return "/tenants/" + strings.ToLower(tenant) }

func SubscriptionID(sub string) string { return "/subscriptions/" + strings.ToLower(sub) }

func ResourceGroupID(sub, rg string) string {
	return "/subscriptions/" + strings.ToLower(sub) + "/resourcegroups/" + strings.ToLower(rg)
}

func CVEID(cve string) string { return "cve:" + strings.ToUpper(strings.TrimSpace(cve)) }

func SoftwareID(vendor, name string) string {
	return "software:" + strings.ToLower(strings.TrimSpace(vendor)) + "/" + strings.ToLower(strings.TrimSpace(name))
}

// PublicIPID is shared by everything that holds the same public address.
func PublicIPID(addr string) string { return "ip:public/" + strings.ToLower(addr) }

// PrivateIPID scopes a private address to its virtual network (or, when the
// network is unknown, to the tenant), because private ranges overlap.
func PrivateIPID(scope, addr string) string {
	return "ip:" + strings.TrimPrefix(scope, "/") + "/" + strings.ToLower(addr)
}

// ParentID returns the ARM ID one level up from a normalised ID, or "" at
// the top. Subscriptions have no ARM parent; the builder links them to their
// tenant.
func ParentID(id string) string {
	if i := strings.LastIndex(id, "/providers/"); i >= 0 {
		rest := strings.Split(id[i+len("/providers/"):], "/") // namespace, type, name[, type, name...]
		if len(rest) > 3 {
			cut := strings.LastIndex(id, "/")
			if len(rest)%2 == 1 { // ends on a name: drop the type/name pair
				cut = strings.LastIndex(id[:cut], "/")
			}
			return id[:cut]
		}
		return id[:i]
	}
	parts := strings.Split(strings.TrimPrefix(id, "/"), "/")
	if len(parts) == 4 && parts[0] == "subscriptions" && parts[2] == "resourcegroups" {
		return "/subscriptions/" + parts[1]
	}
	return ""
}

// Severity normalises Defender's severity labels.
func Severity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	}
	return "none"
}

func tagList(m map[string]any) []Tag {
	out := make([]Tag, 0, len(m))
	for k, v := range m {
		s, _ := v.(string)
		out = append(out, Tag{K: k, V: s})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].K < out[j].K })
	return out
}

// ---- helpers for walking decoded JSON ----

func get(v any, path ...string) any {
	for _, p := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[p]
	}
	return v
}

func str(v any, path ...string) string {
	s, _ := get(v, path...).(string)
	return s
}

func list(v any, path ...string) []any {
	a, _ := get(v, path...).([]any)
	return a
}
