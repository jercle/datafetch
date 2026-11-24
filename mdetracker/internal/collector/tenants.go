package collector

import (
	"sort"
	"strings"
	"time"

	"github.com/jercle/datafetch/mdetracker/internal/model"
)

// tenantContacts aggregates a VM's machine records into one entry per tenant:
// the latest contact (max lastSeen), earliest firstSeen, and all machine IDs.
func tenantContacts(obs []model.Onboarding, currentTenantID string, now time.Time) []model.TenantContact {
	byTenant := map[string]*model.TenantContact{}
	var order []string
	for _, ob := range obs {
		tc, ok := byTenant[ob.TenantID]
		if !ok {
			tc = &model.TenantContact{
				TenantName: ob.TenantName, TenantID: ob.TenantID, OrgID: ob.OrgID,
				State: model.StateSuperseded, Present: true, LastCollectedAt: &now,
			}
			byTenant[ob.TenantID] = tc
			order = append(order, ob.TenantID)
		}
		tc.Records++
		tc.MachineIDs = append(tc.MachineIDs, ob.MachineID)
		if tc.FirstSeen == nil || (ob.FirstSeen != nil && ob.FirstSeen.Before(*tc.FirstSeen)) {
			tc.FirstSeen = ob.FirstSeen
		}
		// obs is sorted best-first, so the first record seen per tenant sets health/status
		// unless a later record has a more recent contact.
		if tc.Records == 1 || after(ob.LastSeen, tc.LastSeen) {
			tc.LastSeen = ob.LastSeen
			tc.HealthStatus = ob.HealthStatus
			tc.OnboardingStatus = ob.OnboardingStatus
		}
		if ob.State == model.StateConflict {
			tc.State = model.StateConflict
		}
	}
	out := make([]model.TenantContact, 0, len(order))
	for _, id := range order {
		tc := *byTenant[id]
		if id == currentTenantID {
			tc.State = model.StateCurrent
		}
		out = append(out, tc)
	}
	sortTenants(out)
	return out
}

// MergeTenants combines this run's tenant contacts with the ones stored by
// previous runs. Tenants that no longer return the VM keep their last known
// contact and are marked Present=false — unless the tenant failed this run,
// in which case its entry is carried over unchanged.
func MergeTenants(cur, prev []model.TenantContact, failedTenantIDs map[string]bool) []model.TenantContact {
	// Keyed by tenant AND org: when a tenant moves to a new Defender org (its
	// orgId changes in config), the entry for the old org is kept as history
	// instead of being overwritten by the new one.
	key := func(tc model.TenantContact) string { return tc.TenantID + "|" + tc.OrgID }
	seen := map[string]bool{}
	curOrg := map[string]string{} // tenant -> org it is configured with now
	for _, tc := range cur {
		seen[key(tc)] = true
		curOrg[tc.TenantID] = tc.OrgID
	}
	out := append([]model.TenantContact{}, cur...)
	for _, p := range prev {
		if seen[key(p)] || p.TenantID == "" {
			continue
		}
		seen[key(p)] = true
		// A failed tenant's entry is carried over untouched, unless the tenant
		// now reports under a different org, which makes this entry history.
		if org, ok := curOrg[p.TenantID]; !failedTenantIDs[p.TenantID] || (ok && org != p.OrgID) {
			p.Present = false
		}
		if p.State != model.StateSuperseded {
			p.State = model.StateSuperseded // it can't be current if this run didn't return it
		}
		if p.MachineIDs == nil {
			p.MachineIDs = []string{}
		}
		out = append(out, p)
	}
	sortTenants(out)
	return out
}

// Finalize derives status, org count and previous-org fields from vm.Tenants.
func Finalize(vm *model.VM, now time.Time, inactiveAfter time.Duration) {
	orgs := map[string]bool{}
	conflict, otherOrg := false, false
	vm.PreviousOrgID, vm.PreviousTenantName, vm.PreviousLastSeen = "", "", nil
	for _, tc := range vm.Tenants { // newest first
		orgs[tc.OrgID] = true
		if tc.State == model.StateConflict {
			conflict = true
		}
		if tc.OrgID != vm.CurrentOrgID {
			otherOrg = true
			if vm.PreviousOrgID == "" {
				vm.PreviousOrgID, vm.PreviousTenantName, vm.PreviousLastSeen = tc.OrgID, tc.TenantName, tc.LastSeen
			}
		}
	}
	vm.OrgCount = len(orgs)

	inactive := vm.CurrentLastSeen == nil || now.Sub(*vm.CurrentLastSeen) > inactiveAfter ||
		strings.EqualFold(vm.HealthStatus, "Inactive") ||
		(vm.OnboardingStatus != "" && !strings.EqualFold(vm.OnboardingStatus, "Onboarded"))
	switch {
	case conflict:
		vm.Status = model.StatusConflict
	case inactive:
		vm.Status = model.StatusInactive
	case otherOrg:
		vm.Status = model.StatusMigrated
	default:
		vm.Status = model.StatusOK
	}
}

// sortTenants orders by current first, then latest contact.
func sortTenants(t []model.TenantContact) {
	sort.SliceStable(t, func(i, j int) bool {
		if ci, cj := t[i].State == model.StateCurrent, t[j].State == model.StateCurrent; ci != cj {
			return ci
		}
		return after(t[i].LastSeen, t[j].LastSeen)
	})
}
