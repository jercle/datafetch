package collector

import (
	"sort"
	"strings"
	"time"

	"github.com/jercle/datafetch/mdetracker/internal/defender"
	"github.com/jercle/datafetch/mdetracker/internal/model"
)

// TenantRef identifies the Defender tenant/org a machine record came from.
type TenantRef struct {
	Name     string
	TenantID string
	OrgID    string
}

// Record is one Defender machine record from one tenant.
type Record struct {
	Tenant  TenantRef
	Machine defender.Machine
}

type BuildOptions struct {
	Now             time.Time
	ActiveWindow    time.Duration
	InactiveAfter   time.Duration
	MatchByHostname bool
	// HostnameFallback merges groups left separate by the stable identifiers when
	// they have the same computerDnsName and no conflicting Azure VM IDs.
	HostnameFallback bool
	RunID            string
}

// BuildVMs merges machine records from every tenant into one document per VM
// and works out which Defender org each VM is currently onboarded to.
func BuildVMs(recs []Record, o BuildOptions) []model.VM {
	groups, byName := groupRecords(recs, o.MatchByHostname, o.HostnameFallback)
	vms := make([]model.VM, 0, len(groups))
	for i, g := range groups {
		vm := buildVM(g, o)
		vm.MergedByHostname = byName[i]
		vms = append(vms, vm)
	}
	sort.Slice(vms, func(i, j int) bool { return vms[i].Key < vms[j].Key })
	return vms
}

// groupRecords unions records that share any stable identifier
// (Azure resource ID, Azure VM ID, Entra device ID), across tenants.
//
// With hostFallback, groups that are still separate afterwards are merged when
// they have the same computerDnsName (case-insensitive, full name), unless both
// sides carry Azure VM IDs and none match: the VM ID is unique per VM and
// survives moves, so two different ones mean two machines that share a name.
// The second return value marks groups that needed the hostname to be merged.
func groupRecords(recs []Record, byHost, hostFallback bool) ([][]Record, []bool) {
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
		for _, id := range identifiers(r, byHost) {
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
			if md := r.Machine.VMMetadata; md != nil {
				if id := normGUID(md.VMID); id != "" {
					root := find(i)
					if vmIDs[root] == nil {
						vmIDs[root] = map[string]bool{}
					}
					vmIDs[root][id] = true
				}
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
			h := strings.ToLower(strings.TrimSpace(r.Machine.ComputerDNSName))
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

	byRoot := map[int][]Record{}
	var order []int
	for i, r := range recs {
		root := find(i)
		if _, ok := byRoot[root]; !ok {
			order = append(order, root)
		}
		byRoot[root] = append(byRoot[root], r)
	}
	out := make([][]Record, 0, len(order))
	flags := make([]bool, 0, len(order))
	for _, root := range order {
		out = append(out, byRoot[root])
		flags = append(flags, viaName[root])
	}
	return out, flags
}

func identifiers(r Record, byHost bool) []string {
	m := r.Machine
	ids := []string{"mde:" + strings.ToLower(r.Tenant.TenantID) + ":" + strings.ToLower(m.ID)}
	if vm := m.VMMetadata; vm != nil {
		if s := normResourceID(vm.ResourceID); s != "" {
			ids = append(ids, "res:"+s)
		}
		if s := normGUID(vm.VMID); s != "" {
			ids = append(ids, "vm:"+s)
		}
	}
	if s := normGUID(m.AADDeviceID); s != "" {
		ids = append(ids, "aad:"+s)
	}
	if byHost {
		if h := strings.ToLower(strings.TrimSpace(m.ComputerDNSName)); h != "" {
			ids = append(ids, "host:"+h)
		}
	}
	return ids
}

func buildVM(g []Record, o BuildOptions) model.VM {
	// Current record: onboarded first, then most recently seen, then newest onboarding.
	sort.SliceStable(g, func(i, j int) bool {
		a, b := g[i].Machine, g[j].Machine
		if oa, ob := isOnboarded(a), isOnboarded(b); oa != ob {
			return oa
		}
		if !timeEq(a.LastSeen, b.LastSeen) {
			return after(a.LastSeen, b.LastSeen)
		}
		return after(a.FirstSeen, b.FirstSeen)
	})
	cur := g[0]
	cm := cur.Machine

	vm := model.VM{
		Name:              cm.ComputerDNSName,
		AADDeviceID:       normGUID(cm.AADDeviceID),
		OSPlatform:        cm.OSPlatform,
		OSVersion:         cm.OSVersion,
		LastIPAddress:     cm.LastIPAddress,
		CurrentOrgID:      cur.Tenant.OrgID,
		CurrentTenantName: cur.Tenant.Name,
		CurrentTenantID:   cur.Tenant.TenantID,
		CurrentMachineID:  cm.ID,
		CurrentFirstSeen:  cm.FirstSeen,
		CurrentLastSeen:   cm.LastSeen,
		HealthStatus:      cm.HealthStatus,
		OnboardingStatus:  cm.OnboardingStatus,
		DefenderAVStatus:  cm.DefenderAVStatus,
		RiskScore:         cm.RiskScore,
		ExposureLevel:     cm.ExposureLevel,
		MachineTags:       nonNil(cm.MachineTags),
		Active:            true,
		LastRunID:         o.RunID,
		CollectedAt:       o.Now,
	}

	// Azure metadata: each field from the newest record that has it (g is sorted, current first).
	fill := func(dst *string, v string) {
		if *dst == "" {
			*dst = v
		}
	}
	for _, r := range g {
		md := r.Machine.VMMetadata
		if md == nil {
			continue
		}
		fill(&vm.AzureResourceID, md.ResourceID)
		fill(&vm.AzureVMID, normGUID(md.VMID))
		fill(&vm.CloudProvider, md.CloudProvider)
		fill(&vm.SubscriptionID, strings.ToLower(md.SubscriptionID))
	}
	if vm.AzureResourceID != "" {
		sub, rg, name := parseResourceID(vm.AzureResourceID)
		fill(&vm.SubscriptionID, sub)
		vm.ResourceGroup = rg
		fill(&vm.Name, name)
	}
	if vm.Name == "" {
		vm.Name = cm.ID
	}

	for i, r := range g {
		m := r.Machine
		state := model.StateCurrent
		if i > 0 {
			state = model.StateSuperseded
			if r.Tenant.OrgID != cur.Tenant.OrgID {
				// A record in another org only conflicts if it is still reporting
				// and kept reporting after the current onboarding started.
				active := m.LastSeen != nil && o.Now.Sub(*m.LastSeen) <= o.ActiveWindow
				overlap := cm.FirstSeen == nil || (m.LastSeen != nil && m.LastSeen.After(*cm.FirstSeen))
				if isOnboarded(m) && active && overlap {
					state = model.StateConflict
				}
			}
		}
		vm.Onboardings = append(vm.Onboardings, model.Onboarding{
			OrgID:            r.Tenant.OrgID,
			TenantName:       r.Tenant.Name,
			TenantID:         r.Tenant.TenantID,
			MachineID:        m.ID,
			ComputerDNSName:  m.ComputerDNSName,
			FirstSeen:        m.FirstSeen,
			LastSeen:         m.LastSeen,
			HealthStatus:     m.HealthStatus,
			OnboardingStatus: m.OnboardingStatus,
			RBACGroupName:    m.RBACGroupName,
			State:            state,
		})
	}
	vm.Tenants = tenantContacts(vm.Onboardings, cur.Tenant.TenantID, o.Now)
	Finalize(&vm, o.Now, o.InactiveAfter)

	switch {
	case vm.AzureResourceID != "":
		vm.Key = "res:" + normResourceID(vm.AzureResourceID)
	case vm.AzureVMID != "":
		vm.Key = "vm:" + vm.AzureVMID
	case vm.AADDeviceID != "":
		vm.Key = "aad:" + vm.AADDeviceID
	default:
		vm.Key = "mde:" + cur.Tenant.OrgID + ":" + strings.ToLower(cm.ID)
	}
	return vm
}

func isOnboarded(m defender.Machine) bool {
	return m.OnboardingStatus == "" || strings.EqualFold(m.OnboardingStatus, "Onboarded")
}

func after(a, b *time.Time) bool {
	switch {
	case a == nil:
		return false
	case b == nil:
		return true
	default:
		return a.After(*b)
	}
}

func timeEq(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Equal(*b)
}

func normResourceID(s string) string {
	return strings.TrimRight(strings.ToLower(strings.TrimSpace(s)), "/")
}

func normGUID(s string) string {
	s = strings.ToLower(strings.Trim(strings.TrimSpace(s), "{}"))
	if s == "" || strings.Trim(s, "0-") == "" {
		return ""
	}
	return s
}

func parseResourceID(id string) (sub, rg, name string) {
	parts := strings.Split(strings.Trim(id, "/"), "/")
	for i := 0; i+1 < len(parts); i += 2 {
		switch strings.ToLower(parts[i]) {
		case "subscriptions":
			sub = strings.ToLower(parts[i+1])
		case "resourcegroups":
			rg = parts[i+1]
		}
	}
	if len(parts) > 0 && len(parts)%2 == 0 {
		name = parts[len(parts)-1]
	}
	return
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
