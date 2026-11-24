package graph

import (
	"sort"
	"strings"
	"time"
)

// Device is one Defender for Endpoint machine record from one tenant. The
// same machine often has several: re-onboarding leaves the old record
// behind, and a machine moved to another Defender org has one in each.
type Device struct {
	Tenant, TenantName                             string
	ID, Name, OSPlatform, OSVersion                string
	HealthStatus, OnboardingStatus                 string
	RiskScore, ExposureLevel                       string
	LastIP, LastExternalIP, AADDeviceID, RbacGroup string
	ResourceID, VMID, CloudProvider                string
	Tags                                           []string
	FirstSeen, LastSeen                            time.Time
}

// RecordKey identifies a machine record: the tenant it came from and its
// Defender machine ID.
func RecordKey(tenant, machineID string) string {
	return strings.ToLower(tenant) + "/" + strings.ToLower(machineID)
}

// DeviceOptions controls how records are merged; the rules are the ones
// mde-tracker uses.
type DeviceOptions struct {
	RunID string
	Now   time.Time
	// HostnameFallback merges groups left separate by the stable identifiers
	// when they have the same computerDnsName and no conflicting Azure VM IDs.
	HostnameFallback bool
	// MatchByHostname treats the hostname as an identifier outright.
	MatchByHostname bool
	// Groups assigns each device to a device group, from its current record.
	Groups *Grouper
}

// DeviceGraph is the result of BuildDevices.
type DeviceGraph struct {
	Nodes []Node
	Edges []Edge
	// Canonical maps the RecordKey of each device's current record to its
	// node. Software and CVE rows are taken from current records only.
	Canonical map[string]string
	// Superseded holds the RecordKeys of the other records of merged devices.
	Superseded map[string]bool
	// Linked is device node -> the Azure resource node it runs on (nil when
	// only the resource ID is known).
	Linked map[string]*Node
	// Group is device node -> device group ("" when none are configured).
	Group map[string]string
	// Tenant is device node -> tenant of its current record.
	Tenant                            map[string]string
	Records, Merged, MergedByHostname int
	LinkedByResourceID, LinkedByName  int
}

// BuildDevices merges machine records from every tenant into one node per
// machine and links each to the Azure resource it runs on, looked up in
// every tenant's resources (a VM can be onboarded to another tenant's
// Defender org).
//
// Records are merged when they share an Azure resource ID, Azure VM ID or
// Entra device ID. The current record is the onboarded one seen most
// recently; the node takes its details and tenant.
func BuildDevices(o DeviceOptions, indexes []*Index, recs []Device) *DeviceGraph {
	g := &DeviceGraph{Canonical: map[string]string{}, Superseded: map[string]bool{}, Linked: map[string]*Node{}, Tenant: map[string]string{}, Group: map[string]string{}, Records: len(recs)}
	groups, byName := groupDevices(recs, o.MatchByHostname, o.HostnameFallback)
	type built struct {
		node  Node
		edge  Edge
		group []Device
	}
	out := make([]built, 0, len(groups))
	for gi, grp := range groups {
		// Current record first: onboarded, then most recently seen, then newest onboarding.
		sort.SliceStable(grp, func(i, j int) bool {
			a, b := grp[i], grp[j]
			if oa, ob := onboarded(a), onboarded(b); oa != ob {
				return oa
			}
			if !a.LastSeen.Equal(b.LastSeen) {
				return a.LastSeen.After(b.LastSeen)
			}
			return a.FirstSeen.After(b.FirstSeen)
		})
		cur := grp[0]
		via := strings.ToLower(cur.Tenant)

		// Azure identity: each field from the newest record that has it.
		var resID, vmID, aadID string
		for _, r := range grp {
			if resID == "" {
				resID = ARMID(r.ResourceID)
			}
			if vmID == "" {
				vmID = normGUID(r.VMID)
			}
			if aadID == "" {
				aadID = normGUID(r.AADDeviceID)
			}
		}
		var key string
		switch {
		case resID != "":
			key = "res:" + resID
		case vmID != "":
			key = "vm:" + vmID
		case aadID != "":
			key = "aad:" + aadID
		default:
			key = "mde:" + via + ":" + strings.ToLower(cur.ID)
		}
		id := "device:" + key

		n := Node{ID: id, Kind: KindDevice, Type: strings.ToLower(cur.OSPlatform), Name: cur.Name, TenantID: via, Tags: []Tag{},
			Attrs: map[string]any{
				"machineId": cur.ID, "osPlatform": cur.OSPlatform, "osVersion": cur.OSVersion, "healthStatus": cur.HealthStatus,
				"onboardingStatus": cur.OnboardingStatus, "riskScore": cur.RiskScore, "exposureLevel": cur.ExposureLevel,
				"lastIp": cur.LastIP, "lastExternalIp": cur.LastExternalIP, "aadDeviceId": aadID, "rbacGroup": cur.RbacGroup,
				"vmId": vmID,
			},
			Source: SourceDevices, Via: via, RunID: o.RunID, SeenAt: o.Now}
		if n.Name == "" {
			n.Name = cur.ID
		}
		// The cloud comes from whichever record knows it; the rest from the current one.
		for _, r := range grp {
			if cur.CloudProvider == "" {
				cur.CloudProvider = r.CloudProvider
			}
		}
		if cur.CloudProvider != "" {
			n.Attrs["cloudProvider"] = cur.CloudProvider
		}
		n.Group = o.Groups.Group(cur)
		g.Group[id] = n.Group
		if !cur.LastSeen.IsZero() {
			n.Attrs["lastSeen"] = cur.LastSeen
		}
		for _, t := range cur.Tags {
			n.Tags = append(n.Tags, Tag{K: t})
		}
		q := []string{n.Name, cur.LastIP, cur.LastExternalIP}
		for i, r := range grp {
			q = append(q, r.ID)
			if r.Name != cur.Name {
				q = append(q, r.Name)
			}
			if i == 0 {
				g.Canonical[RecordKey(r.Tenant, r.ID)] = id
			} else {
				g.Superseded[RecordKey(r.Tenant, r.ID)] = true
			}
		}
		n.Q = strings.ToLower(strings.Join(q, " "))
		if len(grp) > 1 {
			g.Merged++
			records := make([]map[string]any, 0, len(grp))
			for i, r := range grp {
				rec := map[string]any{"tenantId": strings.ToLower(r.Tenant), "tenantName": r.TenantName, "machineId": r.ID, "name": r.Name,
					"onboardingStatus": r.OnboardingStatus, "healthStatus": r.HealthStatus, "state": "superseded"}
				if i == 0 {
					rec["state"] = "current"
				}
				if !r.LastSeen.IsZero() {
					rec["lastSeen"] = r.LastSeen
				}
				if !r.FirstSeen.IsZero() {
					rec["firstSeen"] = r.FirstSeen
				}
				records = append(records, rec)
			}
			n.Attrs["records"] = records
			if byName[gi] {
				g.MergedByHostname++
				n.Attrs["mergedByHostname"] = true
			}
		}

		// The Azure resource it runs on: by resource ID, else by a VM or Arc
		// machine with the same computer name when exactly one exists.
		var target *Node
		targetID, match := "", ""
		if resID != "" {
			n.Attrs["resourceId"] = resID
			if len(indexes) == 0 {
				targetID, match = resID, "resourceId" // no resources were collected this run
			}
			for _, ix := range indexes {
				if r := ix.Resolve(resID); r != nil && r.Kind == KindResource {
					target, targetID, match = r, r.ID, "resourceId"
					break
				}
			}
		}
		if targetID == "" {
			seen := map[string]*Node{}
			for _, ix := range indexes {
				for _, c := range ix.Machines(hostLabel(n.Name)) {
					seen[c] = ix.Node(c)
				}
			}
			if len(seen) == 1 {
				for c, r := range seen {
					target, targetID, match = r, c, "name"
				}
			}
		}
		e := Edge{From: TenantID(via), To: id, Rel: RelContains, FromKind: KindTenant, ToKind: KindDevice, Group: n.Group,
			Source: SourceDevices, Via: via, RunID: o.RunID, SeenAt: o.Now}
		if targetID != "" {
			g.Linked[id] = target
			if match == "name" {
				g.LinkedByName++
			} else {
				g.LinkedByResourceID++
			}
			if target != nil {
				n.SubscriptionID, n.ResourceGroup, n.Location = target.SubscriptionID, target.ResourceGroup, target.Location
			}
			e.From, e.To, e.Rel, e.FromKind, e.ToKind = id, targetID, RelRunsOn, KindDevice, KindResource
			e.Attrs = map[string]any{"match": match}
		}
		e.ID = EdgeID(e.From, e.Rel, e.To, "")
		g.Tenant[id] = via
		out = append(out, built{n, e, grp})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].node.ID < out[j].node.ID })
	for _, b := range out {
		g.Nodes = append(g.Nodes, b.node)
		g.Edges = append(g.Edges, b.edge)
	}
	return g
}

func onboarded(d Device) bool {
	return d.OnboardingStatus == "" || strings.EqualFold(d.OnboardingStatus, "Onboarded")
}

// normGUID lower-cases a GUID and treats empty or all-zero ones as absent.
func normGUID(s string) string {
	s = strings.ToLower(strings.Trim(strings.TrimSpace(s), "{}"))
	if s == "" || strings.Trim(s, "0-") == "" {
		return ""
	}
	return s
}

func deviceIdentifiers(d Device, byHost bool) []string {
	ids := []string{"mde:" + RecordKey(d.Tenant, d.ID)}
	if s := ARMID(d.ResourceID); s != "" {
		ids = append(ids, "res:"+s)
	}
	if s := normGUID(d.VMID); s != "" {
		ids = append(ids, "vm:"+s)
	}
	if s := normGUID(d.AADDeviceID); s != "" {
		ids = append(ids, "aad:"+s)
	}
	if byHost {
		if h := strings.ToLower(strings.TrimSpace(d.Name)); h != "" {
			ids = append(ids, "host:"+h)
		}
	}
	return ids
}

// groupDevices unions records that share any stable identifier (Azure
// resource ID, Azure VM ID, Entra device ID), within and across tenants.
//
// With hostFallback, groups that are still separate afterwards are merged
// when they have the same computerDnsName (case-insensitive, full name),
// unless both sides carry Azure VM IDs and none match: the VM ID is unique
// per VM and survives moves, so two different ones mean two machines that
// share a name. The second return value marks groups that needed the
// hostname to be merged.
func groupDevices(recs []Device, byHost, hostFallback bool) ([][]Device, []bool) {
	parent := make([]int, len(recs))
	for i := range parent {
		parent[i] = i
	}
	find := func(i int) int {
		for parent[i] != i {
			parent[i] = parent[parent[i]]
			i = parent[i]
		}
		return i
	}
	owner := map[string]int{}
	for i, r := range recs {
		for _, id := range deviceIdentifiers(r, byHost) {
			if j, ok := owner[id]; ok {
				if ri, rj := find(i), find(j); ri != rj {
					parent[ri] = rj
				}
			} else {
				owner[id] = i
			}
		}
	}
	viaName := map[int]bool{}
	if hostFallback {
		vmIDs := map[int]map[string]bool{} // root -> Azure VM IDs in the group
		for i, r := range recs {
			if id := normGUID(r.VMID); id != "" {
				root := find(i)
				if vmIDs[root] == nil {
					vmIDs[root] = map[string]bool{}
				}
				vmIDs[root][id] = true
			}
		}
		conflict := func(a, b int) bool {
			if len(vmIDs[a]) == 0 || len(vmIDs[b]) == 0 {
				return false
			}
			for id := range vmIDs[a] {
				if vmIDs[b][id] {
					return false
				}
			}
			return true
		}
		hostRoots := map[string][]int{} // hostname -> group roots already seen with it
		for i, r := range recs {
			h := strings.ToLower(strings.TrimSpace(r.Name))
			if h == "" {
				continue
			}
			ri := find(i)
			merged := false
			for _, cand := range hostRoots[h] {
				rc := find(cand)
				if rc == ri {
					merged = true
					break
				}
				if conflict(ri, rc) {
					continue
				}
				parent[ri] = rc
				for id := range vmIDs[ri] {
					if vmIDs[rc] == nil {
						vmIDs[rc] = map[string]bool{}
					}
					vmIDs[rc][id] = true
				}
				viaName[rc] = true
				merged = true
				break
			}
			if !merged {
				hostRoots[h] = append(hostRoots[h], ri)
			}
		}
	}

	byRoot := map[int][]Device{}
	var order []int
	for i, r := range recs {
		root := find(i)
		if _, ok := byRoot[root]; !ok {
			order = append(order, root)
		}
		byRoot[root] = append(byRoot[root], r)
	}
	out := make([][]Device, 0, len(order))
	flags := make([]bool, 0, len(order))
	for _, root := range order {
		out = append(out, byRoot[root])
		flags = append(flags, viaName[find(root)])
	}
	return out, flags
}
