package collector

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jercle/datafetch/mdetracker/internal/config"
	"github.com/jercle/datafetch/mdetracker/internal/defender"
	"github.com/jercle/datafetch/mdetracker/internal/model"
)

// dumper writes everything a run collected as JSON under <dumpDir>/<runId>/,
// for troubleshooting. A nil dumper (dumpDir unset) does nothing, and a failed
// write only logs a warning: dumping never fails a collection run.
//
//	run.json                        run summary (same as the mde_runs document)
//	tenants/<tenant>.machines.json  every machine exactly as the Defender API returned it
//	tenants/<tenant>.records.json   one line per machine: kept or excluded (and why),
//	                                the identifiers used for matching, and the VM it joined
//	vms.json                        merged VM documents as written to MongoDB
//	org-changes.json                org changes detected this run
//	unlinked-hostnames.json         hostnames seen in 2+ tenants whose records did NOT
//	                                end up as one VM (the usual "migrated but missing" cause)
type dumper struct {
	dir  string
	root string
	keep int
	mode string
	log  *slog.Logger
}

var runDirPattern = regexp.MustCompile(`^\d{8}T\d{6}Z-[0-9a-f]{6}$`)

func newDumper(cfg *config.Config, runID string, log *slog.Logger) *dumper {
	if cfg.DumpDir == "" {
		return nil
	}
	d := &dumper{root: cfg.DumpDir, dir: filepath.Join(cfg.DumpDir, runID), keep: cfg.DumpKeep, mode: cfg.Mode, log: log}
	if err := os.MkdirAll(filepath.Join(d.dir, "tenants"), 0o750); err != nil {
		log.Warn("debug dump disabled: cannot create directory", "dir", d.dir, "error", err.Error())
		return nil
	}
	return d
}

func (d *dumper) write(name string, v any) {
	path := filepath.Join(d.dir, name)
	b, err := json.MarshalIndent(v, "", "  ")
	if err == nil {
		err = os.WriteFile(path, append(b, '\n'), 0o640)
	}
	if err != nil {
		d.log.Warn("debug dump: write failed", "file", path, "error", err.Error())
	}
}

type tenantDump struct {
	Tenant   string            `json:"tenant"`
	TenantID string            `json:"tenantId"`
	OrgID    string            `json:"orgId"`
	APIBase  string            `json:"apiBase"`
	Filter   string            `json:"filter"`
	Mode     string            `json:"mode"`
	Error    string            `json:"error,omitempty"`
	Fetched  int               `json:"fetched"`
	Matched  int               `json:"matched"`
	Machines []json.RawMessage `json:"machines"`
}

// raw writes each tenant's unmodified API result.
func (d *dumper) raw(results []fetchResult) {
	if d == nil {
		return
	}
	for _, r := range results {
		t := r.src.Tenant
		td := tenantDump{
			Tenant: t.Name, TenantID: t.TenantID, OrgID: t.OrgID, APIBase: t.APIBase,
			Filter: t.EffectiveFilter(), Mode: d.mode, Fetched: r.fetched, Matched: len(r.records),
			Machines: make([]json.RawMessage, 0, len(r.all)),
		}
		if r.err != nil {
			td.Error = r.err.Error()
		}
		for _, m := range r.all {
			raw := m.Raw
			if len(raw) == 0 { // e.g. a test lister that doesn't set Raw
				raw, _ = json.Marshal(m)
			}
			td.Machines = append(td.Machines, raw)
		}
		d.write(filepath.Join("tenants", slug(t.Name)+".machines.json"), td)
	}
}

type recordDump struct {
	Tenant           string     `json:"tenant"`
	OrgID            string     `json:"orgId"`
	MachineID        string     `json:"machineId"`
	ComputerDNSName  string     `json:"computerDnsName"`
	OSPlatform       string     `json:"osPlatform"`
	OnboardingStatus string     `json:"onboardingStatus"`
	HealthStatus     string     `json:"healthStatus"`
	FirstSeen        *time.Time `json:"firstSeen"`
	LastSeen         *time.Time `json:"lastSeen"`
	HasVMMetadata    bool       `json:"hasVmMetadata"`
	Included         bool       `json:"included"`
	// Dropped by the mode filter but kept because its hostname matches a collected VM.
	IncludedByHostname bool   `json:"includedByHostname,omitempty"`
	ExcludedReason     string `json:"excludedReason,omitempty"`
	// Identifiers are what records are matched on across tenants; two records
	// become one VM only if they share at least one (other than the mde: one).
	Identifiers []string `json:"identifiers"`
	VMKey       string   `json:"vmKey,omitempty"`
}

type unlinkedHost struct {
	Hostname string       `json:"hostname"`
	Reason   string       `json:"reason"`
	Records  []recordDump `json:"records"`
}

// analysis writes the per-machine keep/exclude decisions and the list of
// hostnames that appear in several tenants without having been merged.
func (d *dumper) analysis(results []fetchResult, vms []model.VM, byHost bool) {
	if d == nil {
		return
	}
	vmKey := map[string]string{} // tenantId|machineId -> VM key
	for _, vm := range vms {
		for _, ob := range vm.Onboardings {
			vmKey[ob.TenantID+"|"+ob.MachineID] = vm.Key
		}
	}

	byHostname := map[string][]recordDump{}
	for _, r := range results {
		t := r.src.Tenant
		ref := TenantRef{Name: t.Name, TenantID: t.TenantID, OrgID: t.OrgID}
		recs := make([]recordDump, 0, len(r.all))
		for _, m := range r.all {
			rd := recordDump{
				Tenant: t.Name, OrgID: t.OrgID, MachineID: m.ID, ComputerDNSName: m.ComputerDNSName,
				OSPlatform: m.OSPlatform, OnboardingStatus: m.OnboardingStatus, HealthStatus: m.HealthStatus,
				FirstSeen: m.FirstSeen, LastSeen: m.LastSeen, HasVMMetadata: m.IsAzureVM(),
				Included:    matchesMode(m, d.mode),
				Identifiers: identifiers(Record{Tenant: ref, Machine: m}, byHost),
				VMKey:       vmKey[t.TenantID+"|"+m.ID],
			}
			if !rd.Included && rd.VMKey != "" {
				rd.Included, rd.IncludedByHostname = true, true
			}
			if !rd.Included {
				rd.ExcludedReason = excludedReason(m, d.mode)
			}
			recs = append(recs, rd)
			if h := shortHost(m.ComputerDNSName); h != "" {
				byHostname[h] = append(byHostname[h], rd)
			}
		}
		d.write(filepath.Join("tenants", slug(t.Name)+".records.json"), recs)
	}

	unlinked := []unlinkedHost{}
	for h, recs := range byHostname {
		orgs, keys, excluded := map[string]bool{}, map[string]bool{}, 0
		for _, rd := range recs {
			orgs[rd.OrgID] = true
			if rd.Included {
				keys[rd.VMKey] = true
			} else {
				excluded++
			}
		}
		if len(orgs) < 2 || (len(keys) <= 1 && excluded == 0) {
			continue
		}
		var reasons []string
		if excluded > 0 {
			reasons = append(reasons, fmt.Sprintf("%d record(s) excluded by mode=%s", excluded, d.mode))
		}
		if len(keys) > 1 {
			reasons = append(reasons, "records share no identifier and the hostname fallback did not apply (different full computerDnsName, different Azure VM IDs, or fallback disabled), so they were kept as separate VMs")
		}
		unlinked = append(unlinked, unlinkedHost{Hostname: h, Reason: strings.Join(reasons, "; "), Records: recs})
	}
	sort.Slice(unlinked, func(i, j int) bool { return unlinked[i].Hostname < unlinked[j].Hostname })
	d.write("unlinked-hostnames.json", unlinked)
	if len(unlinked) > 0 {
		d.log.Warn("hostnames found in several tenants that were not merged into one VM; see debug dump",
			"count", len(unlinked), "file", filepath.Join(d.dir, "unlinked-hostnames.json"))
	}
}

// vms writes the merged VM documents (after tenant history is merged in).
func (d *dumper) vms(vms []model.VM, changes map[string]model.OrgChange) {
	if d == nil {
		return
	}
	d.write("vms.json", vms)
	d.write("org-changes.json", changes)
}

// finish writes the run summary and prunes old run folders.
func (d *dumper) finish(run *model.Run) {
	if d == nil {
		return
	}
	d.write("run.json", run)
	d.log.Info("debug dump written", "dir", d.dir)

	entries, err := os.ReadDir(d.root)
	if err != nil {
		return
	}
	var runs []string
	for _, e := range entries {
		if e.IsDir() && runDirPattern.MatchString(e.Name()) {
			runs = append(runs, e.Name())
		}
	}
	sort.Strings(runs) // run IDs start with a UTC timestamp
	for i := 0; i < len(runs)-d.keep; i++ {
		if err := os.RemoveAll(filepath.Join(d.root, runs[i])); err != nil {
			d.log.Warn("debug dump: could not remove old run folder", "dir", runs[i], "error", err.Error())
		}
	}
}

func excludedReason(m defender.Machine, mode string) string {
	if mode == config.ModeServers {
		return "mode=servers: client OS (" + m.OSPlatform + ") and Defender has no Azure vmMetadata for it"
	}
	return "mode=vms: Defender has no Azure vmMetadata (resourceId / vmId) for this machine"
}

func shortHost(name string) string {
	h, _, _ := strings.Cut(strings.ToLower(strings.TrimSpace(name)), ".")
	return h
}

var slugRe = regexp.MustCompile(`[^a-z0-9]+`)

func slug(s string) string {
	if out := strings.Trim(slugRe.ReplaceAllString(strings.ToLower(s), "-"), "-"); out != "" {
		return out
	}
	return "tenant"
}
