package collector

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/jercle/datafetch/azurecves/pkg/azure"
	"github.com/jercle/datafetch/azurecves/pkg/config"
	"github.com/jercle/datafetch/azurecves/pkg/graph"
	"github.com/jercle/datafetch/azurecves/pkg/monitor"
)

type tenantRun struct {
	p    *pass
	t    config.Tenant
	cli  *azure.Client
	log  *slog.Logger
	opts graph.BuildOptions
	res  *monitor.TenantResult // this tenant's entry in the run record; guarded by p.mu

	ix         *graph.Index   // nil when the resources stage did not succeed
	machines   []graph.Device // Defender machine records, merged across tenants later
	machinesOK bool
	defenderOK bool
}

// resources reads every subscription, resource group and resource through
// Azure Resource Graph and rebuilds the tenant's part of the graph.
func (t *tenantRun) resources(ctx context.Context, pg *progress) error {
	var containers, resources []graph.Resource
	pg.Step("listing subscriptions and resource groups")
	if err := t.cli.ResourceGraph(ctx, azure.QueryContainers, func(rows []graph.Resource) error {
		containers = append(containers, rows...)
		return nil
	}); err != nil {
		return fmt.Errorf("listing subscriptions: %w", err)
	}
	for _, c := range containers {
		if strings.EqualFold(c.Type, "microsoft.resources/subscriptions") {
			pg.Add("subscriptions", 1)
		}
	}
	pg.Step("listing resources from Azure Resource Graph")
	pages := 0
	if err := t.cli.ResourceGraph(ctx, azure.QueryResources, func(rows []graph.Resource) error {
		resources = append(resources, rows...)
		pg.Add("resources", int64(len(rows)))
		if pages++; pages%10 == 0 {
			pg.Info("resources received so far", "resources", len(resources), "pages", pages)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("listing resources: %w", err)
	}
	if len(containers) == 0 && len(resources) == 0 {
		return fmt.Errorf("%w: the service principal cannot see any subscription (it needs Reader)", errEmpty)
	}
	pg.Step("working out how resources are linked", "resources", len(resources))
	nodes, edges, ix := graph.Build(t.opts, containers, resources)
	pg.Set("nodes", int64(len(nodes)))
	pg.Set("edges", int64(len(edges)))
	if err := pg.write(ctx, nodes, edges); err != nil {
		return err
	}
	pg.Step("removing resources that no longer exist")
	removed, err := t.p.c.Store.Sweep(ctx, t.t.ID, graph.SourceARM, t.opts.RunID)
	if err != nil {
		return err
	}
	t.ix = ix
	pg.Set("removed", removed)
	return nil
}

// devices reads the tenant's Defender for Endpoint machine list. Nothing is
// written here: the deviceMerge stage de-duplicates the records of every
// tenant together.
func (t *tenantRun) devices(ctx context.Context, pg *progress) error {
	var devs []graph.Device
	pg.Step("listing Defender for Endpoint machines")
	err := t.cli.Machines(ctx, func(rows []azure.Machine) error {
		for _, m := range rows {
			d := graph.Device{Tenant: t.t.ID, TenantName: t.t.Name, ID: m.ID, Name: m.ComputerDNSName, OSPlatform: m.OSPlatform, OSVersion: m.Version,
				HealthStatus: m.HealthStatus, OnboardingStatus: m.OnboardingStatus, RiskScore: m.RiskScore, ExposureLevel: m.ExposureLevel,
				LastIP: m.LastIPAddress, LastExternalIP: m.LastExternalIPAddress, AADDeviceID: m.AADDeviceID, RbacGroup: m.RbacGroupName,
				Tags: m.MachineTags, FirstSeen: m.FirstSeen.Time, LastSeen: m.LastSeen.Time}
			if m.VMMetadata != nil {
				d.ResourceID, d.VMID, d.CloudProvider = m.VMMetadata.ResourceID, m.VMMetadata.VMID, m.VMMetadata.CloudProvider
			}
			if d.ID != "" {
				devs = append(devs, d)
			}
		}
		pg.Add("records", int64(len(rows)))
		pg.Info("machine records received so far", "records", len(devs))
		return nil
	})
	if err != nil {
		return err
	}
	t.defenderOK = true
	if len(devs) == 0 {
		return errEmpty
	}
	t.machines, t.machinesOK = devs, true
	return nil
}

// device returns the node for a row of a Defender export. Rows for a
// machine's superseded records (an old onboarding of a machine that has a
// newer one) are skipped, so nothing is counted twice.
func (t *tenantRun) device(machineID string, pg *progress) (string, bool) {
	key := graph.RecordKey(t.t.ID, machineID)
	if id, ok := t.p.canonical[key]; ok {
		return id, true
	}
	if t.p.superseded[key] {
		pg.Add("duplicateRecordRows", 1)
	} else {
		pg.Add("unknownDeviceRows", 1)
	}
	return "", false
}

// software streams the software inventory export: one has_software edge per
// device and version, a shared node per product, and a per-tenant summary.
func (t *tenantRun) software(ctx context.Context, pg *progress) error {
	if !t.p.merged {
		return skip("devices were not de-duplicated this run")
	}
	st, via, run, now := t.p.c.Store, t.t.ID, t.opts.RunID, t.opts.Now
	pg.Step("requesting the software inventory export from Defender")
	type agg struct {
		s        SoftwareSummary
		devices  map[string]struct{}
		versions map[string]int
	}
	type swKey struct{ sw, group string }
	products := map[swKey]*agg{}
	known := map[string]bool{}
	perDevice := map[string]int64{}
	var rows int64

	err := t.cli.SoftwareInventory(ctx, t.p.c.Cfg.DefenderPageSize, func(page []azure.SoftwareInv) error {
		edges := make([]graph.Edge, 0, len(page))
		var nodes []graph.Node
		for _, r := range page {
			if r.DeviceID == "" || r.SoftwareName == "" {
				continue
			}
			dev, ok := t.device(r.DeviceID, pg)
			if !ok {
				continue
			}
			rows++
			sw, group := graph.SoftwareID(r.SoftwareVendor, r.SoftwareName), t.p.devGroup[dev]
			a := products[swKey{sw, group}]
			if a == nil {
				a = &agg{devices: map[string]struct{}{}, versions: map[string]int{}, s: SoftwareSummary{
					ID: via + "|" + group + "|" + strings.TrimPrefix(sw, "software:"), TenantID: via, Group: group, Node: sw, Vendor: r.SoftwareVendor, Name: r.SoftwareName,
					Q: strings.ToLower(r.SoftwareVendor + " " + r.SoftwareName), RunID: run, SeenAt: now}}
				products[swKey{sw, group}] = a
			}
			if !known[sw] {
				known[sw] = true
				nodes = append(nodes, graph.Node{ID: sw, Kind: graph.KindSoftware, Type: "software", Name: r.SoftwareName, Q: a.s.Q,
					Tags: []graph.Tag{}, Attrs: map[string]any{"vendor": r.SoftwareVendor}, Source: graph.SourceSoftware, RunID: run, SeenAt: now})
			}
			if _, seen := a.devices[dev]; !seen {
				a.devices[dev] = struct{}{}
				perDevice[dev]++
			}
			a.versions[r.SoftwareVersion]++
			a.s.Weaknesses = max(a.s.Weaknesses, r.NumberOfWeaknesses)
			if r.EndOfSupportStatus != "" {
				a.s.EOSStatus, a.s.EOSDate = r.EndOfSupportStatus, r.EndOfSupportDate.Time
			}
			attrs := map[string]any{"vendor": r.SoftwareVendor, "name": r.SoftwareName, "version": r.SoftwareVersion, "weaknesses": r.NumberOfWeaknesses}
			if r.EndOfSupportStatus != "" {
				attrs["eosStatus"] = r.EndOfSupportStatus
			}
			if !r.SoftwareFirstSeenTimestamp.IsZero() {
				attrs["firstSeen"] = r.SoftwareFirstSeenTimestamp.Time
			}
			if len(r.DiskPaths) > 0 {
				attrs["paths"] = r.DiskPaths[:min(len(r.DiskPaths), 5)]
			}
			edges = append(edges, graph.Edge{ID: graph.EdgeID(dev, graph.RelHasSoftware, sw, r.SoftwareVersion), From: dev, To: sw,
				Rel: graph.RelHasSoftware, FromKind: graph.KindDevice, ToKind: graph.KindSoftware, Key: r.SoftwareVersion, Group: group, Attrs: attrs,
				Source: graph.SourceSoftware, Via: via, RunID: run, SeenAt: now})
		}
		pg.Set("installs", rows)
		pg.Set("products", int64(len(known)))
		pg.Step("software inventory: page received, writing it", "page", pg.Add("pages", 1), "pageRows", len(page), "installs", rows)
		if err := pg.write(ctx, nodes, edges); err != nil {
			return err
		}
		pg.Step("software inventory: waiting for the next page from Defender", "installs", rows)
		return nil
	})
	if err != nil {
		return err
	}
	t.defenderOK = true
	if rows == 0 {
		return errEmpty
	}
	pg.Step("summarising software per product", "products", len(known))
	docs := make([]SoftwareSummary, 0, len(products))
	for _, a := range products {
		a.s.Devices = len(a.devices)
		for v, n := range a.versions {
			a.s.Versions = append(a.s.Versions, VersionCount{Version: v, Devices: n})
		}
		sort.Slice(a.s.Versions, func(i, j int) bool {
			if a.s.Versions[i].Devices != a.s.Versions[j].Devices {
				return a.s.Versions[i].Devices > a.s.Versions[j].Devices
			}
			return a.s.Versions[i].Version > a.s.Versions[j].Version
		})
		docs = append(docs, a.s)
	}
	if err := st.ReplaceSoftware(ctx, via, run, docs); err != nil {
		return err
	}
	pg.Step("removing software no longer installed")
	removed, err := st.Sweep(ctx, via, graph.SourceSoftware, run)
	if err != nil {
		return err
	}
	values := make(map[string]map[string]any, len(perDevice))
	for dev, n := range perDevice {
		values[dev] = map[string]any{"products": n, "run": run}
	}
	if err := st.SetNodeField(ctx, via, "software", run, values); err != nil {
		return err
	}
	pg.Set("devicesWithSoftware", int64(len(perDevice)))
	pg.Set("removed", removed)
	return nil
}

type sevCount struct{ critical, high, medium, low, devices int64 }

func (s *sevCount) add(sev string, n int64) {
	switch sev {
	case "critical":
		s.critical += n
	case "high":
		s.high += n
	case "medium":
		s.medium += n
	case "low":
		s.low += n
	}
}

func (s *sevCount) merge(o *sevCount) {
	s.critical, s.high, s.medium, s.low, s.devices = s.critical+o.critical, s.high+o.high, s.medium+o.medium, s.low+o.low, s.devices+1
}

func (s *sevCount) value(run string) map[string]any {
	return map[string]any{"critical": s.critical, "high": s.high, "medium": s.medium, "low": s.low,
		"total": s.critical + s.high + s.medium + s.low, "devices": s.devices, "run": run}
}

// vulnerabilities streams the software vulnerabilities export: one
// affected_by edge per device, CVE and software version, a shared node per
// CVE, a per-tenant exposure summary, and CVE counts on each device. The
// vulnRollup stage carries those counts up to resources, resource groups,
// subscriptions and tenants.
func (t *tenantRun) vulnerabilities(ctx context.Context, pg *progress) error {
	if !t.p.merged {
		return skip("devices were not de-duplicated this run")
	}
	st, via, run, now := t.p.c.Store, t.t.ID, t.opts.RunID, t.opts.Now
	pg.Step("requesting the software vulnerabilities export from Defender")
	type agg struct {
		e        Exposure
		devices  map[string]struct{}
		software map[string]struct{}
	}
	type cveKey struct{ cve, group string }
	cves := map[cveKey]*agg{}
	known := map[string]bool{}
	perDevice := map[string]*sevCount{}
	var rows int64

	err := t.cli.SoftwareVulnerabilities(ctx, t.p.c.Cfg.DefenderPageSize, func(page []azure.SoftwareVuln) error {
		edges := make([]graph.Edge, 0, len(page))
		var nodes []graph.Node
		for _, r := range page {
			if r.DeviceID == "" || r.CveID == "" {
				continue // software with no known CVE is listed with an empty cveId
			}
			dev, ok := t.device(r.DeviceID, pg)
			if !ok {
				continue
			}
			rows++
			node := graph.CVEID(r.CveID)
			cve, sev, group := strings.TrimPrefix(node, "cve:"), graph.Severity(r.VulnerabilitySeverityLevel), t.p.devGroup[dev]
			a := cves[cveKey{node, group}]
			if a == nil {
				a = &agg{devices: map[string]struct{}{}, software: map[string]struct{}{}, e: Exposure{
					ID: via + "|" + group + "|" + cve, TenantID: via, Source: "devices", Group: group, CveID: cve, Node: node, Severity: sev, SeverityRank: severityRank[sev],
					Cvss: r.CvssScore, Exploitability: r.ExploitabilityLevel, RunID: run, SeenAt: now}}
				cves[cveKey{node, group}] = a
			}
			if !known[node] {
				known[node] = true
				nodes = append(nodes, graph.Node{ID: node, Kind: graph.KindCVE, Type: sev, Name: cve, Q: strings.ToLower(cve),
					Tags: []graph.Tag{}, Attrs: map[string]any{"severity": sev, "severityRank": severityRank[sev], "cvss": r.CvssScore},
					Source: graph.SourceVulns, RunID: run, SeenAt: now})
			}
			if _, seen := a.devices[dev]; !seen {
				a.devices[dev] = struct{}{}
				c := perDevice[dev]
				if c == nil {
					c = &sevCount{}
					perDevice[dev] = c
				}
				c.add(sev, 1)
			}
			a.software[r.SoftwareVendor+"/"+r.SoftwareName] = struct{}{}
			a.e.FixAvailable = a.e.FixAvailable || r.SecurityUpdateAvailable
			if f := r.FirstSeenTimestamp.Time; !f.IsZero() && (a.e.FirstSeen.IsZero() || f.Before(a.e.FirstSeen)) {
				a.e.FirstSeen = f
			}
			if l := r.LastSeenTimestamp.Time; l.After(a.e.LastSeen) {
				a.e.LastSeen = l
			}
			attrs := map[string]any{"cveId": cve, "severity": sev, "severityRank": severityRank[sev], "cvss": r.CvssScore,
				"vendor": r.SoftwareVendor, "software": r.SoftwareName, "version": r.SoftwareVersion,
				"fixAvailable": r.SecurityUpdateAvailable, "device": r.DeviceName}
			if r.RecommendedSecurityUpdate != "" {
				attrs["update"] = r.RecommendedSecurityUpdate
				attrs["updateId"] = r.RecommendedSecurityUpdateID
			}
			if r.ExploitabilityLevel != "" {
				attrs["exploitability"] = r.ExploitabilityLevel
			}
			if !r.FirstSeenTimestamp.IsZero() {
				attrs["firstSeen"] = r.FirstSeenTimestamp.Time
			}
			key := r.SoftwareVendor + "/" + r.SoftwareName + "/" + r.SoftwareVersion
			edges = append(edges, graph.Edge{ID: graph.EdgeID(dev, graph.RelAffectedBy, node, key), From: dev, To: node,
				Rel: graph.RelAffectedBy, FromKind: graph.KindDevice, ToKind: graph.KindCVE, Key: key, Group: group, Attrs: attrs,
				Source: graph.SourceVulns, Via: via, RunID: run, SeenAt: now})
		}
		pg.Set("findings", rows)
		pg.Set("cves", int64(len(known)))
		pg.Step("vulnerabilities: page received, writing it", "page", pg.Add("pages", 1), "pageRows", len(page), "findings", rows)
		if err := pg.write(ctx, nodes, edges); err != nil {
			return err
		}
		pg.Step("vulnerabilities: waiting for the next page from Defender", "findings", rows)
		return nil
	})
	if err != nil {
		return err
	}
	t.defenderOK = true
	if rows == 0 {
		return errEmpty
	}
	pg.Step("summarising exposure per CVE", "cves", len(known))
	docs := make([]Exposure, 0, len(cves))
	for _, a := range cves {
		a.e.Devices = len(a.devices)
		for s := range a.software {
			a.e.Software = append(a.e.Software, s)
		}
		sort.Strings(a.e.Software)
		a.e.Software = a.e.Software[:min(len(a.e.Software), 20)]
		docs = append(docs, a.e)
	}
	if err := st.ReplaceExposure(ctx, via, "devices", run, docs); err != nil {
		return err
	}
	pg.Step("removing findings that are resolved")
	removed, err := st.Sweep(ctx, via, graph.SourceVulns, run)
	if err != nil {
		return err
	}
	values := make(map[string]map[string]any, len(perDevice))
	for dev, c := range perDevice {
		c.devices = 1
		values[dev] = c.value(run)
	}
	if err := st.SetNodeField(ctx, via, "vuln", run, values); err != nil {
		return err
	}
	t.p.mu.Lock()
	for dev, c := range perDevice {
		t.p.devCounts[dev] = c
	}
	t.p.mu.Unlock()
	pg.Set("devicesWithCves", int64(len(perDevice)))
	pg.Set("removed", removed)
	return nil
}

// containers reads Defender for Cloud's vulnerability findings for images
// in container registries and for running containers, and records which
// image (registry, repository, digest and tags) and which container each
// CVE affects.
func (t *tenantRun) containers(ctx context.Context, pg *progress) error {
	if t.ix == nil {
		return skip("needs the resources stage, which did not succeed this run")
	}
	st, via, run, now := t.p.c.Store, t.t.ID, t.opts.RunID, t.opts.Now
	var findings []graph.ContainerFinding
	pg.Step("listing container findings from Defender for Cloud")
	pages := 0
	err := t.cli.ResourceGraphRows(ctx, azure.QueryContainerFindings, func(rows []azure.Row) error {
		for _, r := range rows {
			if f, ok := graph.ParseContainerFinding(r.ID, r.Properties); ok {
				findings = append(findings, f)
			}
		}
		pg.Set("findings", int64(len(findings)))
		if pages++; pages%10 == 0 {
			pg.Info("container findings received so far", "findings", len(findings), "pages", pages)
		}
		return nil
	})
	if err != nil {
		return err
	}

	// Findings identify an image by digest; where they carry no tags, ask
	// the registry which tags point at each digest. Failures here are not
	// fatal: the image is still recorded, just without tags, and with the
	// reason on it.
	graph.NormaliseFindings(t.ix, findings)
	tags := map[graph.ImageRepo]map[string][]string{}
	outcome := map[graph.ImageRepo]string{}
	repos := graph.ReposWithoutTags(findings)
	if r := t.p.c.Cfg.ResolveImageTags; r != nil && !*r {
		for _, repo := range repos {
			outcome[repo] = graph.UntaggedOff
		}
	} else {
		want := map[graph.ImageRepo]map[string]bool{}
		for _, f := range findings {
			if f.Kind == graph.KindImage && f.Digest != "" {
				r := graph.ImageRepo{Host: f.Host, Repo: f.Repo}
				if want[r] == nil {
					want[r] = map[string]bool{}
				}
				want[r][f.Digest] = true
			}
		}
		hostState := map[string]string{} // registry -> why it is no longer asked
		pg.Step("reading image tags from container registries", "repositories", len(repos))
		for i, repo := range repos {
			if i > 0 && i%25 == 0 {
				pg.Info("image tags read so far", "repositories", i, "of", len(repos))
			}
			if why := hostState[repo.Host]; why != "" {
				outcome[repo] = why
				pg.Add("tagLookupsFailed", 1)
				continue
			}
			if t.ix.Host(repo.Host) == "" && !isACRHost(repo.Host) {
				outcome[repo] = graph.UntaggedNotAsked
				pg.Add("tagLookupsSkipped", 1)
				continue
			}
			m, err := t.cli.ACRTags(ctx, repo.Host, repo.Repo, want[repo])
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err != nil {
				pg.Add("tagLookupsFailed", 1)
				outcome[repo] = graph.UntaggedFailed
				if errors.Is(err, azure.ErrACRDenied) {
					// The answer is the same for every repository in the registry.
					outcome[repo], hostState[repo.Host] = graph.UntaggedDenied, graph.UntaggedDenied
					t.log.Warn("registry refused to list image tags, so its images will show as untagged; give the service principal AcrPull on the registry, "+
						"or Container Registry Repository Reader if it uses ABAC repository permissions (Reader alone does not allow it)",
						"stage", "containers", "registry", repo.Host, "error", err)
				} else {
					t.log.Warn("could not read image tags from registry", "stage", "containers", "registry", repo.Host, "repository", repo.Repo, "error", err)
				}
				continue
			}
			tags[repo] = m
			pg.Add("tagLookups", 1)
		}
	}

	pg.Step("linking images, containers and CVEs", "findings", len(findings))
	g := graph.BuildContainers(t.opts, t.ix, findings, tags, outcome)
	if err := pg.write(ctx, g.Nodes, g.Edges); err != nil {
		return err
	}
	docs := make([]Exposure, 0, len(g.Exposure))
	for id, e := range g.Exposure {
		docs = append(docs, Exposure{
			ID: "containers:" + via + "|" + id, TenantID: via, Source: "containers", CveID: id, Node: graph.CVEID(id),
			Severity: e.CVE.Severity, SeverityRank: severityRank[e.CVE.Severity], Cvss: e.CVE.Cvss,
			Images: e.Images, Containers: e.Containers, Tags: e.Tags, Software: e.Software[:min(len(e.Software), 20)],
			FixAvailable: e.FixAvailable, RunID: run, SeenAt: now,
		})
	}
	if err := st.ReplaceExposure(ctx, via, "containers", run, docs); err != nil {
		return err
	}
	removed, err := st.Sweep(ctx, via, graph.SourceContainers, run)
	if err != nil {
		return err
	}
	if err := st.SetNodeField(ctx, via, "containerVuln", run, g.Rollup); err != nil {
		return err
	}
	for k, v := range map[string]int{"images": g.Images, "taggedImages": g.Tagged, "containers": g.Containers, "cves": len(g.Exposure)} {
		pg.Set(k, int64(v))
	}
	pg.Set("removed", removed)
	// Say why images have no tags; "untagged" in the dashboard is otherwise
	// indistinguishable from a lookup that never happened.
	untagged := 0
	for why, n := range g.Untagged {
		untagged += n
		lvl := slog.LevelWarn
		if why == graph.UntaggedNoTag {
			lvl = slog.LevelInfo // an image nothing points at any more is ordinary
		}
		t.log.Log(ctx, lvl, "images without tags", "stage", "containers", "images", n, "reason", why)
	}
	pg.Set("untaggedImages", int64(untagged))
	if g.NoName > 0 {
		pg.Set("unidentified", int64(g.NoName))
		t.log.Warn("some container findings did not say which image they are about", "stage", "containers", "findings", g.NoName)
	}
	return nil
}

// cveDetails adds descriptions, publication dates and exploit flags from
// Defender's CVE catalogue to the CVE nodes. The catalogue is the same in
// every tenant and has hundreds of thousands of entries, so it is read
// through one tenant and only every cveDetailsEvery.
func (p *pass) cveDetails(ctx context.Context, pg *progress) error {
	if prev, err := p.c.Store.State(ctx, GlobalTenant, "cveDetails"); err == nil && prev != nil && prev.LastSuccessAt != nil {
		if age := p.c.Now().Sub(*prev.LastSuccessAt); age < time.Duration(p.c.Cfg.CVEDetailsEvery) {
			return skip("refreshed %s ago", age.Round(time.Minute))
		}
	}
	if len(p.clients) == 0 {
		return skip("no tenant reached Defender this run")
	}
	ids, err := p.c.Store.CVEIDs(ctx)
	if err != nil {
		return err
	}
	want := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		want[id] = struct{}{}
	}
	var errs []error
	for _, cli := range p.clients {
		var scanned, matched int64
		err := cli.Vulnerabilities(ctx, func(page []azure.Vulnerability) error {
			details := map[string]map[string]any{}
			for _, v := range page {
				id := graph.CVEID(v.ID)
				if _, ok := want[id]; !ok {
					continue
				}
				d := map[string]any{"title": v.Name, "description": v.Description, "severity": graph.Severity(v.Severity), "cvssV3": v.CvssV3,
					"cvssVector": v.CvssVector, "publicExploit": v.PublicExploit, "exploitVerified": v.ExploitVerified,
					"exploitInKit": v.ExploitInKit, "exploitTypes": v.ExploitTypes, "epss": v.Epss, "refreshedAt": p.c.Now()}
				if !v.PublishedOn.IsZero() {
					d["publishedOn"] = v.PublishedOn.Time
				}
				if !v.UpdatedOn.IsZero() {
					d["updatedOn"] = v.UpdatedOn.Time
				}
				details[id] = d
			}
			scanned += int64(len(page))
			matched += int64(len(details))
			pg.Set("scanned", scanned)
			pg.Set("updated", matched)
			pg.Step("reading Defender's CVE catalogue", "via", cli.Tenant.Name, "scanned", scanned, "matched", matched)
			return p.c.Store.SetCVEDetails(ctx, details)
		})
		if err == nil {
			return nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", cli.Tenant.Name, err))
		if ctx.Err() != nil {
			break
		}
	}
	return errors.Join(errs...)
}

// costs copies each resource's recent cost from the cost collector's data
// onto the graph, rolled up to every level above it.
func (p *pass) costs(ctx context.Context, pg *progress) error {
	now := p.c.Now()
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	since := now.AddDate(0, 0, -30).Truncate(24 * time.Hour)
	pg.Step("summing recent cost per resource from the cost collector's data")
	rows, err := p.c.Store.ResourceCosts(ctx, p.c.Cfg.Costs.CostType, since, monthStart)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return fmt.Errorf("%w from %s.%s", errEmpty, p.c.Cfg.Costs.Database, p.c.Cfg.Costs.Collection)
	}
	values := CostFields(rows, p.run.ID, now)
	pg.Set("costRows", int64(len(rows)))
	pg.Set("nodesWithCost", int64(len(values)))
	pg.Step("writing cost onto the graph", "nodes", len(values))
	return p.c.Store.SetNodeField(ctx, "", "cost", p.run.ID, values)
}

// deviceMerge de-duplicates the machine records of every tenant into one
// device each (see graph.BuildDevices), links each device to the Azure
// resource it runs on, and replaces the device nodes.
func (p *pass) deviceMerge(ctx context.Context, pg *progress) error {
	var recs []graph.Device
	var indexes []*graph.Index
	var fetched []string
	for _, t := range p.tenants {
		if t.ix != nil {
			indexes = append(indexes, t.ix)
		}
		if t.machinesOK {
			recs = append(recs, t.machines...)
			fetched = append(fetched, t.t.ID)
		}
	}
	if len(fetched) == 0 {
		return skip("no tenant returned any Defender machine records this run")
	}
	pg.Set("records", int64(len(recs)))
	pg.Step("merging machine records that are the same machine", "records", len(recs), "tenants", len(fetched))
	fallback := p.c.Cfg.HostnameFallback == nil || *p.c.Cfg.HostnameFallback
	groups, err := p.c.Cfg.Grouper()
	if err != nil {
		return err
	}
	g := graph.BuildDevices(graph.DeviceOptions{RunID: p.run.ID, Now: p.c.Now(), HostnameFallback: fallback,
		MatchByHostname: p.c.Cfg.MatchByHostname, Groups: groups}, indexes, recs)
	for k, v := range map[string]int{"devices": len(g.Nodes), "duplicateRecords": len(g.Superseded), "mergedDevices": g.Merged,
		"mergedByHostname": g.MergedByHostname, "linkedByResourceId": g.LinkedByResourceID, "linkedByName": g.LinkedByName} {
		pg.Set(k, int64(v))
	}
	if err := pg.write(ctx, g.Nodes, g.Edges); err != nil {
		return err
	}
	pg.Step("removing devices that are gone")
	var removed int64
	for _, tenant := range fetched {
		n, err := p.c.Store.Sweep(ctx, tenant, graph.SourceDevices, p.run.ID)
		if err != nil {
			return err
		}
		removed += n
	}
	pg.Set("removed", removed)

	// The dashboard reads the groups, their order and which are hidden by
	// default from here; an empty list means grouping is off.
	perGroup := map[string]int{}
	for _, name := range g.Group {
		perGroup[name]++
	}
	defs := groups.Defs()
	docs := make([]DeviceGroup, len(defs))
	for i, d := range defs {
		docs[i] = DeviceGroup{ID: d.Name, GroupDef: d, Order: i, Default: i == len(defs)-1, Devices: perGroup[d.Name], RunID: p.run.ID, UpdatedAt: p.c.Now()}
	}
	if err := p.c.Store.SaveDeviceGroups(ctx, docs); err != nil {
		return err
	}
	pg.Set("groups", int64(len(docs)))
	p.canonical, p.superseded, p.linked, p.devTenant, p.devGroup, p.merged = g.Canonical, g.Superseded, g.Linked, g.Tenant, g.Group, true
	return nil
}

// vulnRollup carries each device's CVE counts up to the resource it runs
// on and that resource's resource group, subscription and tenant - which
// may be a different tenant from the one whose Defender org reported them.
// Figures above a device count device-and-CVE pairs, so one CVE on ten VMs
// counts ten times.
func (p *pass) vulnRollup(ctx context.Context, pg *progress) error {
	failed, ran := 0, 0
	for _, t := range p.tenants {
		p.mu.Lock()
		for _, s := range t.res.Stages {
			if s.Stage == "vulnerabilities" {
				ran++
				if s.Status == monitor.StatusFailed || s.Status == monitor.StatusCancelled {
					failed++
				}
			}
		}
		p.mu.Unlock()
	}
	switch {
	case ran == 0 || !p.merged:
		return skip("vulnerabilities were not collected this run")
	case failed > 0:
		return skip("vulnerabilities failed for %d tenants; the previous roll-up is kept so their devices are not dropped from it", failed)
	}
	// Kept per device group as well as in total, so the dashboard can show
	// figures for just the groups in view.
	up := map[string]map[string]*sevCount{}
	var group string
	bump := func(id string, c *sevCount) {
		if id == "" {
			return
		}
		if up[id] == nil {
			up[id] = map[string]*sevCount{}
		}
		if up[id][group] == nil {
			up[id][group] = &sevCount{}
		}
		up[id][group].merge(c)
	}
	for dev, c := range p.devCounts {
		group = p.devGroup[dev]
		res := p.linked[dev]
		if res == nil {
			bump(graph.TenantID(p.devTenant[dev]), c)
			continue
		}
		bump(res.ID, c)
		if res.SubscriptionID != "" {
			if res.ResourceGroup != "" {
				bump(graph.ResourceGroupID(res.SubscriptionID, res.ResourceGroup), c)
			}
			bump(graph.SubscriptionID(res.SubscriptionID), c)
		}
		bump(graph.TenantID(res.TenantID), c)
	}
	values := make(map[string]map[string]any, len(up))
	for id, byGroup := range up {
		total := &sevCount{}
		names := make([]string, 0, len(byGroup))
		for name := range byGroup {
			names = append(names, name)
		}
		sort.Strings(names)
		groups := make([]map[string]any, 0, len(names))
		for _, name := range names {
			c := byGroup[name]
			total.critical, total.high, total.medium, total.low, total.devices = total.critical+c.critical, total.high+c.high, total.medium+c.medium, total.low+c.low, total.devices+c.devices
			v := c.value(p.run.ID)
			delete(v, "run")
			v["group"] = name
			groups = append(groups, v)
		}
		v := total.value(p.run.ID)
		v["groups"] = groups
		values[id] = v
	}
	pg.Set("devices", int64(len(p.devCounts)))
	pg.Set("nodes", int64(len(values)))
	pg.Step("writing CVE counts onto resources, resource groups, subscriptions and tenants", "nodes", len(values))
	return p.c.Store.SetNodeField(ctx, "", "vulnRollup", p.run.ID, values)
}

// isACRHost reports whether a registry host is an Azure Container Registry
// login server, in any Azure cloud.
func isACRHost(host string) bool {
	for _, suffix := range []string{".azurecr.io", ".azurecr.cn", ".azurecr.us"} {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}
