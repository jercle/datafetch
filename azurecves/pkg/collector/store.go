// Package collector runs the collection stages for every tenant and writes
// the results through a Store.
package collector

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/jercle/datafetch/azurecves/pkg/graph"
	"github.com/jercle/datafetch/azurecves/pkg/monitor"
)

// Exposure is one CVE in one tenant (collection cve_exposure): what the CVE
// list reads, so it never has to group millions of edges.
type Exposure struct {
	ID       string `bson:"_id"` // tenantId|group|CVE for devices, containers:tenantId|CVE for containers
	TenantID string `bson:"tenantId"`
	// Source is "devices" (Defender for Endpoint) or "containers" (Defender
	// for Cloud); each stage replaces only its own documents.
	Source string `bson:"source"`
	// Group is the device group the counted devices are in; one document
	// per group, so the dashboard can leave hidden groups out of the sums.
	Group        string  `bson:"group"`
	CveID        string  `bson:"cveId"`
	Node         string  `bson:"node"`
	Severity     string  `bson:"severity"`
	SeverityRank int     `bson:"severityRank"`
	Cvss         float64 `bson:"cvss"`
	Devices      int     `bson:"devices"`
	Images       int     `bson:"images"`
	Containers   int     `bson:"containers"`
	// Tags is how many image tags the CVE is in (containers source only).
	Tags           int       `bson:"tags"`
	Software       []string  `bson:"software"`
	Exploitability string    `bson:"exploitability,omitempty"`
	FixAvailable   bool      `bson:"fixAvailable"`
	FirstSeen      time.Time `bson:"firstSeen,omitempty"`
	LastSeen       time.Time `bson:"lastSeen,omitempty"`
	RunID          string    `bson:"runId"`
	SeenAt         time.Time `bson:"seenAt"`
}

type VersionCount struct {
	Version string `bson:"version"`
	Devices int    `bson:"devices"`
}

// SoftwareSummary is one product in one tenant (collection software_summary).
type SoftwareSummary struct {
	ID         string         `bson:"_id"` // tenantId|group|vendor/name
	TenantID   string         `bson:"tenantId"`
	Group      string         `bson:"group"`
	Node       string         `bson:"node"`
	Vendor     string         `bson:"vendor"`
	Name       string         `bson:"name"`
	Q          string         `bson:"q"`
	Devices    int            `bson:"devices"`
	Versions   []VersionCount `bson:"versions"`
	Weaknesses int            `bson:"weaknesses"`
	EOSStatus  string         `bson:"eosStatus,omitempty"`
	EOSDate    time.Time      `bson:"eosDate,omitempty"`
	RunID      string         `bson:"runId"`
	SeenAt     time.Time      `bson:"seenAt"`
}

// DeviceGroup is one device group as the dashboard sees it (collection
// device_groups, replaced on every run).
type DeviceGroup struct {
	ID             string `bson:"_id"`
	graph.GroupDef `bson:",inline"`
	Order          int       `bson:"order"`
	Default        bool      `bson:"default"`
	Devices        int       `bson:"devices"`
	RunID          string    `bson:"runId"`
	UpdatedAt      time.Time `bson:"updatedAt"`
}

// CostRow is a resource's cost from the cost collector's resource_costs.
type CostRow struct {
	TenantID   string
	ResourceID string
	Currency   string
	Last30     float64
	Last30USD  float64
	MTD        float64
	MTDUSD     float64
}

// Store is everything the collector needs from the database.
type Store interface {
	UpsertNodes(ctx context.Context, nodes []graph.Node) error
	UpsertEdges(ctx context.Context, edges []graph.Edge) error
	// Sweep deletes the nodes and edges a source wrote for a tenant in
	// earlier runs and did not write again in this one.
	Sweep(ctx context.Context, via, source, runID string) (int64, error)
	// SetNodeField sets one field on the given nodes (each value carries
	// "run": runID), then removes the field from nodes still holding a value
	// from an earlier run - for via's nodes, or for all nodes when via is "".
	SetNodeField(ctx context.Context, via, field, runID string, values map[string]map[string]any) error
	ReplaceExposure(ctx context.Context, via, source, runID string, docs []Exposure) error
	ReplaceSoftware(ctx context.Context, via, runID string, docs []SoftwareSummary) error
	// SaveDeviceGroups replaces the list of device groups.
	SaveDeviceGroups(ctx context.Context, groups []DeviceGroup) error
	// CVEIDs lists the IDs of every CVE node.
	CVEIDs(ctx context.Context) ([]string, error)
	SetCVEDetails(ctx context.Context, details map[string]map[string]any) error
	// PruneShared deletes CVE and software nodes not seen since before.
	PruneShared(ctx context.Context, before time.Time) (int64, error)
	ResourceCosts(ctx context.Context, costType string, since, monthStart time.Time) ([]CostRow, error)
	SaveState(ctx context.Context, s *monitor.StageState) error
	State(ctx context.Context, tenantID, stage string) (*monitor.StageState, error)
}

var severityRank = map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}

// CostFields turns cost rows into the "cost" field for graph nodes. Every
// node gets its own cost plus that of everything beneath it: a resource's
// children, a resource group's resources, a subscription, a tenant. When a
// node has costs in several currencies the largest is shown; the USD figures
// always cover all of them.
func CostFields(rows []CostRow, runID string, now time.Time) map[string]map[string]any {
	type sum struct{ last30, mtd float64 }
	type acc struct {
		byCur             map[string]*sum
		last30USD, mtdUSD float64
	}
	nodes := map[string]*acc{}
	add := func(id string, r CostRow) {
		a := nodes[id]
		if a == nil {
			a = &acc{byCur: map[string]*sum{}}
			nodes[id] = a
		}
		s := a.byCur[r.Currency]
		if s == nil {
			s = &sum{}
			a.byCur[r.Currency] = s
		}
		s.last30 += r.Last30
		s.mtd += r.MTD
		a.last30USD += r.Last30USD
		a.mtdUSD += r.MTDUSD
	}
	for _, r := range rows {
		if id := graph.ARMID(r.ResourceID); strings.HasPrefix(id, "/subscriptions/") {
			for ; id != ""; id = graph.ParentID(id) {
				add(id, r)
			}
		}
		if r.TenantID != "" {
			add(graph.TenantID(r.TenantID), r)
		}
	}
	out := make(map[string]map[string]any, len(nodes))
	for id, a := range nodes {
		curs := make([]string, 0, len(a.byCur))
		for c := range a.byCur {
			curs = append(curs, c)
		}
		sort.Slice(curs, func(i, j int) bool {
			if a.byCur[curs[i]].last30 != a.byCur[curs[j]].last30 {
				return a.byCur[curs[i]].last30 > a.byCur[curs[j]].last30
			}
			return curs[i] < curs[j]
		})
		top := a.byCur[curs[0]]
		out[id] = map[string]any{
			"currency": curs[0], "last30d": round(top.last30), "mtd": round(top.mtd),
			"last30dUsd": round(a.last30USD), "mtdUsd": round(a.mtdUSD),
			"currencies": len(curs), "asOf": now, "run": runID,
		}
	}
	return out
}

func round(f float64) float64 {
	const p = 10000
	if f < 0 {
		return float64(int64(f*p-0.5)) / p
	}
	return float64(int64(f*p+0.5)) / p
}
