package graph

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
)

// Container findings come from Defender for Cloud's individual
// vulnerability recommendations in Azure Resource Graph
// (microsoft.security/assessments, category SoftwareUpdate, resource type
// ".containerimage" or "K8s-container"). Microsoft documents the CVE and
// software fields; how the image and the Kubernetes workload are described
// is not documented, so those are harvested leniently: by key name anywhere
// in the finding, and from any image reference or digest found in it.

const (
	KindImage     = "image"
	KindContainer = "container"

	RelRunsImage = "runs_image" // container -> image

	SourceContainers = "defender-containers"
)

// FindingCVE is one CVE listed on a finding.
type FindingCVE struct {
	ID              string
	Severity        string
	Cvss            float64
	ExploitPublic   bool
	ExploitVerified bool
	ExploitInKit    bool
}

// ContainerFinding is one parsed recommendation: a vulnerable package on an
// image in a registry, or on a running container.
type ContainerFinding struct {
	Kind   string // KindImage or KindContainer
	Cloud  string // Azure, AWS, GCP
	Scope  string // ARM ID the finding hangs off: the registry or the cluster
	Entity string // Defender's own identifier for the image or container

	Host, Repo, Digest string
	Tags               []string

	ClusterID, Cluster, Namespace, Workload, WorkloadKind, Pod, Container string
	ResourceName                                                          string

	Software, Vendor string
	Versions         []string
	FixedVersion     string
	Severity         string
	CVEs             []FindingCVE
}

var (
	digestRe = regexp.MustCompile(`sha256:[0-9a-f]{64}`)
	// registry.example.io/team/app:1.2@sha256:... (tag optional)
	imageRefRe = regexp.MustCompile(`(?i)^([a-z0-9][a-z0-9\-]*(?:\.[a-z0-9\-]+)+(?::\d+)?|localhost(?::\d+)?)/([a-z0-9][a-z0-9._/\-]*?)(?::([\w][\w.\-]*))?@(sha256:[0-9a-f]{64})$`)
	// registry.example.io/team/app:1.2 - only with a dotted host, so "a/b:c" is not mistaken for one
	taggedRefRe = regexp.MustCompile(`(?i)^([a-z0-9][a-z0-9\-]*(?:\.[a-z0-9\-]+)+(?::\d+)?)/([a-z0-9][a-z0-9._/\-]*):([\w][\w.\-]{0,127})$`)
	tagRe       = regexp.MustCompile(`^[\w][\w.\-]{0,127}$`)
	cveRe       = regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,}`)
)

// ParseContainerFinding reads one Resource Graph row. ok is false when the
// row is not a container finding.
func ParseContainerFinding(id string, props map[string]any) (f ContainerFinding, ok bool) {
	rd := lowerKeys(get(props, "resourceDetails"))
	switch strings.ToLower(str(rd, "resourcetype")) {
	case ".containerimage":
		f.Kind = KindImage
	case "k8s-container":
		f.Kind = KindContainer
	default:
		return f, false
	}
	f.Cloud = str(rd, "source")
	f.ResourceName = str(rd, "resourcename")
	f.Severity = Severity(str(props, "metadata", "severity"))

	// .../registries/x/providers/microsoft.security/securityentitydata/<entity>/providers/...
	lid := strings.ToLower(id)
	if i := strings.Index(lid, "/securityentitydata/"); i >= 0 {
		f.Scope = strings.TrimSuffix(lid[:i], "/providers/microsoft.security")
		f.Entity, _, _ = strings.Cut(lid[i+len("/securityentitydata/"):], "/")
	} else if i := strings.Index(lid, "/providers/microsoft.security/"); i >= 0 {
		f.Scope = lid[:i]
	}

	// Identity: the dedicated blocks first, so they win over anything looser.
	for _, k := range []string{"resourceAdditionalData", "resourceDetails", "additionalData"} {
		f.harvest(props[k])
	}

	f.fromResourceName()

	ad := lowerKeys(get(props, "additionalData"))
	f.Software, f.Vendor, f.FixedVersion = str(ad, "softwarename"), str(ad, "softwarevendor"), str(ad, "fixedversion")
	f.Versions = stringList(ad["detectedsoftwareversions"])
	for _, c := range anyList(ad["cvesdetails"]) {
		m := lowerKeys(c)
		cve := FindingCVE{ID: strings.ToUpper(str(m, "cveid")), Severity: Severity(str(m, "severity")), Cvss: maxBase(m["cvss"])}
		ex := lowerKeys(m["exploitabilitydetails"])
		cve.ExploitPublic, _ = ex["exploitstepspublished"].(bool)
		cve.ExploitVerified, _ = ex["exploitstepsverified"].(bool)
		cve.ExploitInKit, _ = ex["isinexploitkit"].(bool)
		if cve.Severity == "none" {
			cve.Severity = f.Severity
		}
		if cve.ID != "" {
			f.CVEs = append(f.CVEs, cve)
		}
	}
	if len(f.CVEs) == 0 {
		if m := cveRe.FindString(str(props, "displayName")); m != "" {
			f.CVEs = []FindingCVE{{ID: strings.ToUpper(m), Severity: f.Severity}}
		}
	}
	return f, true
}

// harvest fills identity fields that are still empty from anything under v
// whose key says what it is. Keys are compared lower-case.
func (f *ContainerFinding) harvest(v any) {
	set := func(dst *string, val string) {
		if *dst == "" {
			*dst = strings.TrimSpace(val)
		}
	}
	var walk func(v any, key string)
	walk = func(v any, key string) {
		switch x := v.(type) {
		case map[string]any:
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				walk(x[k], strings.ToLower(k))
			}
		case []any:
			if isTagKey(key) {
				for _, t := range x {
					if s, ok := t.(string); ok && tagRe.MatchString(s) {
						f.Tags = appendUnique(f.Tags, s)
					}
				}
				return
			}
			for _, c := range x {
				walk(c, key)
			}
		case string:
			low := strings.ToLower(strings.TrimSpace(x))
			if m := imageRefRe.FindStringSubmatch(strings.TrimSpace(x)); m != nil {
				set(&f.Host, strings.ToLower(m[1]))
				set(&f.Repo, strings.ToLower(m[2]))
				set(&f.Digest, strings.ToLower(m[4]))
				if m[3] != "" && strings.ToLower(m[2]) == f.Repo {
					f.Tags = appendUnique(f.Tags, m[3])
				}
			}
			if m := taggedRefRe.FindStringSubmatch(strings.TrimSpace(x)); m != nil {
				set(&f.Host, strings.ToLower(m[1]))
				set(&f.Repo, strings.ToLower(m[2]))
				if strings.ToLower(m[2]) == f.Repo {
					f.Tags = appendUnique(f.Tags, m[3])
				}
			}
			if strings.Contains(low, "/managedclusters/") || strings.Contains(low, "/connectedclusters/") {
				if i := strings.Index(low, "/subscriptions/"); i >= 0 {
					set(&f.ClusterID, clusterID(low[i:]))
				}
			}
			switch key {
			case "digest", "imagedigest", "manifestdigest":
				set(&f.Digest, digestRe.FindString(low))
			case "repositoryname", "repository", "reponame":
				set(&f.Repo, low)
			case "registryhost", "registry", "loginserver", "registryname", "registryuri", "registryurl":
				set(&f.Host, strings.TrimSuffix(strings.TrimPrefix(low, "https://"), "/"))
			default:
				// A single tag, or several in one string.
				if isTagKey(key) {
					for _, t := range strings.FieldsFunc(x, func(r rune) bool { return r == ',' || r == ';' || r == ' ' }) {
						if tagRe.MatchString(t) {
							f.Tags = appendUnique(f.Tags, t)
						}
					}
				}
			case "namespace", "namespacename", "kubernetesnamespace":
				set(&f.Namespace, x)
			case "pod", "podname":
				set(&f.Pod, x)
			case "containername", "container":
				set(&f.Container, x)
			case "controllername", "workloadname", "ownername", "workload":
				set(&f.Workload, x)
			case "controllertype", "controllerkind", "workloadkind", "ownerkind":
				set(&f.WorkloadKind, x)
			case "clustername", "cluster":
				set(&f.Cluster, x)
			}
		}
	}
	walk(v, "")
}

// isTagKey reports whether a key names image tags: tag, tags, imageTag,
// repoTags, tagList and the like - but not etag.
func isTagKey(key string) bool {
	return strings.Contains(key, "tag") && key != "etag" && !strings.HasSuffix(key, "_etag") && !strings.Contains(key, "digest")
}

// clusterID trims an ARM ID to the cluster it is in.
func clusterID(id string) string {
	for _, marker := range []string{"/managedclusters/", "/connectedclusters/"} {
		if i := strings.Index(id, marker); i >= 0 {
			rest := id[i+len(marker):]
			name, _, _ := strings.Cut(rest, "/")
			return id[:i+len(marker)] + name
		}
	}
	return ""
}

func lowerKeys(v any) map[string]any {
	m, _ := v.(map[string]any)
	out := make(map[string]any, len(m))
	for k, x := range m {
		out[strings.ToLower(k)] = x
	}
	return out
}

// anyList accepts an array, or a string holding a JSON array (Defender
// stores CvesDetails both ways).
func anyList(v any) []any {
	switch x := v.(type) {
	case []any:
		return x
	case string:
		var out []any
		if json.Unmarshal([]byte(x), &out) == nil {
			return out
		}
	}
	return nil
}

func stringList(v any) []string {
	var out []string
	if s, ok := v.(string); ok && s != "" && !strings.HasPrefix(strings.TrimSpace(s), "[") {
		for _, p := range strings.Split(s, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = appendUnique(out, p)
			}
		}
		return out
	}
	for _, x := range anyList(v) {
		if s, ok := x.(string); ok && s != "" {
			out = appendUnique(out, s)
		}
	}
	return out
}

// maxBase finds the highest CVSS base score anywhere under v, whichever way
// the versions are keyed.
func maxBase(v any) float64 {
	var best float64
	var walk func(v any, key string)
	walk = func(v any, key string) {
		switch x := v.(type) {
		case map[string]any:
			for k, c := range x {
				walk(c, strings.ToLower(k))
			}
		case []any:
			for _, c := range x {
				walk(c, key)
			}
		case float64:
			if key == "base" && x > best {
				best = x
			}
		}
	}
	walk(v, "")
	return best
}

func appendUnique(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}

// fromResourceName fills what is still unknown about an image from the
// finding's resource name, which may be "team/app", "team/app:1.2",
// "registry.io/team/app@sha256:..." or any mix of those.
func (f *ContainerFinding) fromResourceName() {
	name := strings.TrimSpace(f.ResourceName)
	if f.Kind != KindImage || name == "" || strings.ContainsAny(name, " \t") {
		return
	}
	if i := strings.Index(name, "@"); i >= 0 {
		if f.Digest == "" {
			f.Digest = digestRe.FindString(strings.ToLower(name[i:]))
		}
		name = name[:i]
	}
	if d := digestRe.FindString(strings.ToLower(name)); d != "" { // the name is just a digest
		if f.Digest == "" {
			f.Digest = d
		}
		return
	}
	tag := ""
	if i := strings.LastIndex(name, ":"); i > strings.LastIndex(name, "/") {
		name, tag = name[:i], name[i+1:]
	}
	host := ""
	if first, rest, ok := strings.Cut(name, "/"); ok && strings.ContainsAny(first, ".:") {
		host, name = strings.ToLower(first), rest
	}
	name = strings.ToLower(name)
	if f.Repo == "" && name != "" {
		f.Repo = name
	}
	if f.Repo != name {
		return // the name is something else; do not take its host or tag
	}
	if f.Host == "" {
		f.Host = host
	}
	if tagRe.MatchString(tag) {
		f.Tags = appendUnique(f.Tags, tag)
	}
}

// NormaliseFindings settles each image's registry host: Defender may give
// the registry's resource name ("myregistry") or nothing at all, while the
// registry answers on its login server ("myregistry.azurecr.io"). The
// registry resource each finding hangs off knows the login server.
func NormaliseFindings(ix *Index, findings []ContainerFinding) {
	for i := range findings {
		f := &findings[i]
		f.Repo = strings.Trim(f.Repo, "/")
		if f.Host != "" {
			f.Repo = strings.TrimPrefix(f.Repo, f.Host+"/")
		}
		if f.Kind != KindImage {
			continue
		}
		reg := ix.Resolve(f.Scope)
		if reg == nil || reg.Type != typeACR {
			continue
		}
		login, _ := reg.Attrs["loginServer"].(string)
		login = strings.ToLower(login)
		if login == "" {
			continue
		}
		if f.Host == "" || !strings.Contains(f.Host, ".") || strings.HasPrefix(login, f.Host+".") {
			f.Host = login
		}
		f.Repo = strings.TrimPrefix(f.Repo, login+"/")
	}
}

// Reasons an image has no tags.
const (
	UntaggedNoRegistry = "the finding does not say which registry the image is in"
	UntaggedNoRepo     = "the finding does not give the image's repository and digest"
	UntaggedNotAsked   = "the registry is not an Azure Container Registry this tenant can see, so it was not asked"
	UntaggedDenied     = "the registry refused to list tags: the service principal needs AcrPull, or Container Registry Repository Reader on a registry using ABAC repository permissions"
	UntaggedFailed     = "listing the registry's tags failed"
	UntaggedNoTag      = "no tag in the registry points at this digest"
	UntaggedOff        = "tag lookup is turned off (resolveImageTags)"
)

// ImageID identifies an image by registry, repository and digest; one image
// can carry several tags. Without a digest Defender's own identifier is used.
func (f *ContainerFinding) ImageID() string {
	switch {
	case f.Digest != "" && f.Repo != "":
		if f.Host != "" {
			return "image:" + f.Host + "/" + f.Repo + "@" + f.Digest
		}
		return "image:" + f.Repo + "@" + f.Digest
	case f.Digest != "":
		return "image:@" + f.Digest
	case f.Kind == KindImage && f.Entity != "":
		return "image:" + strings.TrimPrefix(f.Scope, "/") + "/" + f.Entity
	}
	return ""
}

func (f *ContainerFinding) containerID(via string) string {
	scope := f.ClusterID
	if scope == "" {
		scope = f.Scope
	}
	if scope == "" {
		scope = "/" + via
	}
	name := f.Entity
	if name == "" {
		name = strings.ToLower(strings.Join([]string{f.Namespace, f.Workload, f.Pod, f.Container, f.ResourceName}, "/"))
	}
	return "container:" + strings.TrimPrefix(scope, "/") + "/" + name
}

// ImageRepo is a registry host and repository whose tags may need looking up.
type ImageRepo struct{ Host, Repo string }

// ReposWithoutTags lists the repositories holding images whose findings
// carried no tags, so the caller can ask the registry.
func ReposWithoutTags(findings []ContainerFinding) []ImageRepo {
	tagged := map[string]bool{}
	seen := map[ImageRepo]bool{}
	for _, f := range findings {
		if id := f.ImageID(); len(f.Tags) > 0 {
			tagged[id] = true
		}
	}
	var out []ImageRepo
	for _, f := range findings {
		r := ImageRepo{f.Host, f.Repo}
		if f.Digest == "" || f.Host == "" || f.Repo == "" || tagged[f.ImageID()] || seen[r] {
			continue
		}
		seen[r] = true
		out = append(out, r)
	}
	return out
}

// CVEExposure is how far one CVE reaches into a tenant's images.
type CVEExposure struct {
	CVE                FindingCVE
	Images, Containers int
	// Tags is how many image tags (repository:tag) the CVE is in.
	Tags         int
	Software     []string
	FixAvailable bool
}

// ContainerGraph is the result of BuildContainers.
type ContainerGraph struct {
	Nodes    []Node
	Edges    []Edge
	Exposure map[string]*CVEExposure // by CVE ID
	// Rollup is CVE counts for the registries, clusters, resource groups,
	// subscriptions and tenants above the images and containers.
	Rollup                             map[string]map[string]any
	Images, Containers, Tagged, NoName int
	// Untagged counts images left without tags, by reason.
	Untagged map[string]int
}

type sevSet struct {
	seen                        map[string]bool
	critical, high, medium, low int
}

func (s *sevSet) add(c FindingCVE) {
	if s.seen == nil {
		s.seen = map[string]bool{}
	}
	if s.seen[c.ID] {
		return
	}
	s.seen[c.ID] = true
	switch c.Severity {
	case "critical":
		s.critical++
	case "high":
		s.high++
	case "medium":
		s.medium++
	case "low":
		s.low++
	}
}

func (s *sevSet) value() map[string]any {
	return map[string]any{"critical": s.critical, "high": s.high, "medium": s.medium, "low": s.low,
		"total": s.critical + s.high + s.medium + s.low, "devices": 0}
}

var rank = map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}

// BuildContainers turns parsed findings into image, container and CVE nodes
// and their edges. registryTags maps repository -> digest -> tags, as read
// from the registries; tags on the findings themselves take precedence.
//
// outcome says why a repository's tags could not be read (one of the
// Untagged reasons); it is recorded on images left without tags.
func BuildContainers(o BuildOptions, ix *Index, findings []ContainerFinding, registryTags map[ImageRepo]map[string][]string, outcome map[ImageRepo]string) *ContainerGraph {
	via := strings.ToLower(o.Via)
	g := &ContainerGraph{Exposure: map[string]*CVEExposure{}, Rollup: map[string]map[string]any{}, Untagged: map[string]int{}}
	nodes := map[string]*Node{}
	var order []string
	edges := map[string]*Edge{}
	var eorder []string
	counts := map[string]*sevSet{}
	byDigest := map[string][]string{} // digest -> images known with a repository
	parentOf := map[string]string{}
	type reach struct{ images, containers map[string]bool }
	reached := map[string]*reach{}

	node := func(n *Node) *Node {
		if old := nodes[n.ID]; old != nil {
			return old
		}
		n.Source, n.Via, n.RunID, n.SeenAt = SourceContainers, via, o.RunID, o.Now
		if n.Tags == nil {
			n.Tags = []Tag{}
		}
		nodes[n.ID] = n
		order = append(order, n.ID)
		return n
	}
	edge := func(from, rel, to, key, fromKind, toKind string, attrs map[string]any) {
		if from == "" || to == "" {
			return
		}
		id := EdgeID(from, rel, to, key)
		if edges[id] == nil {
			edges[id] = &Edge{ID: id, From: from, To: to, Rel: rel, FromKind: fromKind, ToKind: toKind, Key: key, Attrs: attrs,
				Source: SourceContainers, Via: via, RunID: o.RunID, SeenAt: o.Now}
			eorder = append(eorder, id)
		}
	}
	place := func(n *Node, parent *Node) {
		if parent != nil {
			n.SubscriptionID, n.ResourceGroup, n.Location = parent.SubscriptionID, parent.ResourceGroup, parent.Location
		}
	}
	image := func(f *ContainerFinding) *Node {
		id := f.ImageID()
		if id == "" {
			return nil
		}
		if n := nodes[id]; n != nil {
			return n
		}
		name := f.Repo
		if name == "" {
			name = f.ResourceName
		}
		if f.Digest != "" {
			name += "@" + f.Digest[:19]
		}
		if name == "" {
			name = f.Entity
			g.NoName++
		}
		n := node(&Node{ID: id, Kind: KindImage, Type: "container image", Name: name, TenantID: via,
			Attrs: map[string]any{"registry": f.Host, "repository": f.Repo, "digest": f.Digest, "cloud": f.Cloud, "tags": []string{}}})
		if f.Digest != "" && f.Repo != "" {
			byDigest[f.Digest] = append(byDigest[f.Digest], id)
		}
		// The registry: the resource an image finding hangs off, else by host name.
		var reg *Node
		if f.Kind == KindImage {
			reg = ix.Resolve(f.Scope)
		}
		if reg == nil || reg.Kind != KindResource {
			reg = ix.Node(ix.Host(f.Host))
		}
		if reg != nil && reg.Kind == KindResource {
			place(n, reg)
			edge(reg.ID, RelContains, id, "", KindResource, KindImage, nil)
			parentOf[id] = reg.ID
			n.Attrs["registryId"] = reg.ID
		}
		return n
	}
	addTags := func(n *Node, tags []string, from string) {
		if len(tags) == 0 {
			return
		}
		cur, _ := n.Attrs["tags"].([]string)
		for _, t := range tags {
			cur = appendUnique(cur, t)
		}
		sort.Strings(cur)
		n.Attrs["tags"] = cur
		if _, ok := n.Attrs["tagsFrom"]; !ok {
			n.Attrs["tagsFrom"] = from
		}
	}

	// Images first, so containers can be linked to them by digest.
	sort.SliceStable(findings, func(i, j int) bool { return findings[i].Kind == KindImage && findings[j].Kind != KindImage })
	for i := range findings {
		f := &findings[i]
		var subject *Node
		// A container finding that only knows a digest runs whichever known
		// image has that digest, rather than a nameless copy of it.
		var runs []string
		if f.Kind == KindContainer && f.Repo == "" && len(byDigest[f.Digest]) > 0 {
			runs = byDigest[f.Digest]
		} else if img := image(f); img != nil {
			addTags(img, f.Tags, "defender")
			runs = []string{img.ID}
		}
		if f.Kind == KindImage {
			if len(runs) > 0 {
				subject = nodes[runs[0]]
			}
		} else {
			name := f.Container
			if name == "" {
				name = f.ResourceName
			}
			if name == "" {
				name = f.Entity
			}
			c := node(&Node{ID: f.containerID(via), Kind: KindContainer, Type: "container", Name: name, TenantID: via, Attrs: map[string]any{}})
			for k, v := range map[string]string{"namespace": f.Namespace, "workload": f.Workload, "workloadKind": f.WorkloadKind, "pod": f.Pod,
				"cluster": f.Cluster, "cloud": f.Cloud, "resourceName": f.ResourceName} {
				if v != "" {
					c.Attrs[k] = v
				}
			}
			cluster := ix.Resolve(f.ClusterID)
			if cluster == nil || cluster.Kind != KindResource {
				cluster = ix.Resolve(f.Scope)
			}
			if cluster != nil && cluster.Kind == KindResource {
				place(c, cluster)
				edge(cluster.ID, RelContains, c.ID, "", KindResource, KindContainer, nil)
				parentOf[c.ID] = cluster.ID
			}
			for _, t := range runs {
				edge(c.ID, RelRunsImage, t, "", KindContainer, KindImage, nil)
				c.Attrs["image"] = nodes[t].Name
			}
			subject = c
		}
		if subject == nil {
			g.NoName++ // nothing in the finding says which image this is
			continue
		}
		if counts[subject.ID] == nil {
			counts[subject.ID] = &sevSet{}
		}
		version := strings.Join(f.Versions, ", ")
		for _, c := range f.CVEs {
			cid := CVEID(c.ID)
			node(&Node{ID: cid, Kind: KindCVE, Type: c.Severity, Name: c.ID, Q: strings.ToLower(c.ID),
				Attrs: map[string]any{"severity": c.Severity, "severityRank": rank[c.Severity], "cvss": c.Cvss}}).Via = ""
			attrs := map[string]any{"cveId": c.ID, "severity": c.Severity, "severityRank": rank[c.Severity], "cvss": c.Cvss,
				"vendor": f.Vendor, "software": f.Software, "version": version, "fixAvailable": f.FixedVersion != ""}
			if f.FixedVersion != "" {
				attrs["fixedVersion"] = f.FixedVersion
			}
			if c.ExploitPublic || c.ExploitVerified || c.ExploitInKit {
				attrs["exploit"] = true
			}
			edge(subject.ID, RelAffectedBy, cid, f.Software+"/"+version, subject.Kind, KindCVE, attrs)
			counts[subject.ID].add(c)

			e := g.Exposure[c.ID]
			if e == nil {
				e = &CVEExposure{CVE: c}
				g.Exposure[c.ID] = e
				reached[c.ID] = &reach{map[string]bool{}, map[string]bool{}}
			}
			if rank[c.Severity] > rank[e.CVE.Severity] {
				e.CVE.Severity = c.Severity
			}
			e.CVE.Cvss = max(e.CVE.Cvss, c.Cvss)
			e.CVE.ExploitPublic = e.CVE.ExploitPublic || c.ExploitPublic
			e.FixAvailable = e.FixAvailable || f.FixedVersion != ""
			if f.Software != "" {
				e.Software = appendUnique(e.Software, strings.ToLower(f.Vendor+"/"+f.Software))
			}
			if subject.Kind == KindImage {
				reached[c.ID].images[subject.ID] = true
			} else {
				reached[c.ID].containers[subject.ID] = true
			}
		}
	}

	// Tags the registry knows for images Defender did not tag.
	for _, id := range order {
		n := nodes[id]
		if n.Kind != KindImage {
			continue
		}
		host, _ := n.Attrs["registry"].(string)
		repo, _ := n.Attrs["repository"].(string)
		digest, _ := n.Attrs["digest"].(string)
		if cur, _ := n.Attrs["tags"].([]string); len(cur) == 0 {
			addTags(n, registryTags[ImageRepo{host, repo}][digest], "registry")
		}
		tags, _ := n.Attrs["tags"].([]string)
		if len(tags) == 0 {
			why := UntaggedNotAsked
			_, asked := registryTags[ImageRepo{host, repo}]
			switch {
			case repo == "" || digest == "":
				why = UntaggedNoRepo
			case host == "":
				why = UntaggedNoRegistry
			case outcome[ImageRepo{host, repo}] != "":
				why = outcome[ImageRepo{host, repo}]
			case asked:
				why = UntaggedNoTag
			}
			n.Attrs["untaggedReason"] = why
			g.Untagged[why]++
		}
		// Searchable as repo:tag, registry/repo and digest.
		q := []string{strings.ToLower(n.Name), host + "/" + repo, digest}
		for _, t := range tags {
			q = append(q, strings.ToLower(repo+":"+t))
		}
		n.Q = strings.Join(q, " ")
		g.Images++
		if len(tags) > 0 {
			g.Tagged++
		}
	}

	// CVE counts on each image and container, and rolled up above them.
	type roll struct {
		sevSet
		images, containers int
	}
	up := map[string]*roll{}
	bump := func(id string, n *Node, s *sevSet) {
		if id == "" {
			return
		}
		r := up[id]
		if r == nil {
			r = &roll{}
			up[id] = r
		}
		r.critical, r.high, r.medium, r.low = r.critical+s.critical, r.high+s.high, r.medium+s.medium, r.low+s.low
		if n.Kind == KindImage {
			r.images++
		} else {
			r.containers++
		}
	}
	for _, id := range order {
		n := nodes[id]
		switch n.Kind {
		case KindContainer:
			g.Containers++
			if n.Q == "" {
				ns, _ := n.Attrs["namespace"].(string)
				wl, _ := n.Attrs["workload"].(string)
				img, _ := n.Attrs["image"].(string)
				n.Q = strings.ToLower(strings.Join([]string{n.Name, ns, wl, img}, " "))
			}
		case KindImage:
		default:
			continue
		}
		s := counts[id]
		if s == nil {
			s = &sevSet{}
		}
		n.Vuln = s.value()
		bump(parentOf[id], n, s)
		if n.SubscriptionID != "" {
			if n.ResourceGroup != "" {
				bump(ResourceGroupID(n.SubscriptionID, n.ResourceGroup), n, s)
			}
			bump(SubscriptionID(n.SubscriptionID), n, s)
		}
		bump(TenantID(via), n, s)
	}
	for id, r := range up {
		v := r.value()
		delete(v, "devices")
		v["images"], v["containers"], v["run"] = r.images, r.containers, o.RunID
		g.Rollup[id] = v
	}
	for id, r := range reached {
		g.Exposure[id].Images, g.Exposure[id].Containers = len(r.images), len(r.containers)
		for img := range r.images {
			tags, _ := nodes[img].Attrs["tags"].([]string)
			g.Exposure[id].Tags += len(tags)
		}
		sort.Strings(g.Exposure[id].Software)
	}
	// A CVE in an image is a CVE in every tag that points at it: put the
	// tags on the edge itself, so "which tags have this CVE" is one query
	// on the edges with nothing to look up.
	for _, id := range eorder {
		e := edges[id]
		if e.Rel != RelAffectedBy || e.FromKind != KindImage {
			continue
		}
		n := nodes[e.From]
		tags, _ := n.Attrs["tags"].([]string)
		e.Attrs["tags"] = append([]string{}, tags...)
		e.Attrs["repository"], e.Attrs["registry"] = n.Attrs["repository"], n.Attrs["registry"]
	}

	for _, id := range order {
		g.Nodes = append(g.Nodes, *nodes[id])
	}
	for _, id := range eorder {
		g.Edges = append(g.Edges, *edges[id])
	}
	return g
}
