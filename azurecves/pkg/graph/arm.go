package graph

import (
	"net/netip"
	"sort"
	"strings"
	"time"
)

// Resource is a row from Azure Resource Graph.
type Resource struct {
	ID             string         `json:"id"`
	Name           string         `json:"name"`
	Type           string         `json:"type"`
	Kind           string         `json:"kind"`
	Location       string         `json:"location"`
	ResourceGroup  string         `json:"resourceGroup"`
	SubscriptionID string         `json:"subscriptionId"`
	TenantID       string         `json:"tenantId"`
	Tags           map[string]any `json:"tags"`
	Sku            map[string]any `json:"sku"`
	ManagedBy      string         `json:"managedBy"`
	Properties     map[string]any `json:"properties"`
}

const (
	typeSubscription = "microsoft.resources/subscriptions"
	typeRG           = "microsoft.resources/subscriptions/resourcegroups"
	typeVM           = "microsoft.compute/virtualmachines"
	typeArc          = "microsoft.hybridcompute/machines"
	typeNIC          = "microsoft.network/networkinterfaces"
	typePIP          = "microsoft.network/publicipaddresses"
	typeVNet         = "microsoft.network/virtualnetworks"
	typeSubnet       = "microsoft.network/virtualnetworks/subnets"
	typeLB           = "microsoft.network/loadbalancers"
	typeAppGW        = "microsoft.network/applicationgateways"
	typeSite         = "microsoft.web/sites"
	typeACR          = "microsoft.containerregistry/registries"
)

// BuildOptions describes the tenant being collected.
type BuildOptions struct {
	Via             string // configured tenant ID
	TenantName      string
	RunID           string
	Now             time.Time
	StoreProperties bool
}

// Index is what later stages need from the ARM build: resolving a resource
// ID to its node and finding machines by name.
type Index struct {
	nodes  map[string]*Node
	byName map[string][]string
	byHost map[string]string
}

// Host returns the resource (a container registry, an app) answering on a
// host name, or "".
func (ix *Index) Host(host string) string {
	if ix == nil {
		return ""
	}
	return ix.byHost[strings.ToLower(host)]
}

// Node returns the node with exactly this ID, or nil.
func (ix *Index) Node(id string) *Node {
	if ix == nil {
		return nil
	}
	return ix.nodes[id]
}

// Resolve returns the nearest node at or above an ARM ID: an ID for a
// scale-set instance resolves to the scale set, a backend pool to its load
// balancer.
func (ix *Index) Resolve(id string) *Node {
	if ix == nil {
		return nil
	}
	for id = ARMID(id); id != ""; id = ParentID(id) {
		if n := ix.nodes[id]; n != nil {
			return n
		}
	}
	return nil
}

// Machines returns the VM / Arc machine nodes with this computer name.
func (ix *Index) Machines(name string) []string {
	if ix == nil {
		return nil
	}
	return ix.byName[strings.ToLower(name)]
}

type builder struct {
	o     BuildOptions
	ix    *Index
	order []string
	edges map[string]*Edge
	eids  []string
	// linked holds node pairs that already have an edge, so the generic
	// "references" pass does not repeat them.
	linked  map[string]bool
	raw     map[string]*Resource
	pending [][3]string         // load balancer, backend, pool
	nicVM   map[string]string   // NIC -> VM
	nicIPs  map[string][]string // NIC -> IP nodes (private and public)
	ipNIC   map[string]string   // private IP node -> NIC
	byAddr  map[string][]string // address -> IP nodes
	hosts   map[string]string   // host name -> resource
}

// Build turns one tenant's subscriptions, resource groups and resources into
// nodes and edges.
func Build(o BuildOptions, containers, resources []Resource) ([]Node, []Edge, *Index) {
	o.Via = strings.ToLower(o.Via)
	b := &builder{
		o:      o,
		ix:     &Index{nodes: map[string]*Node{}, byName: map[string][]string{}},
		hosts:  map[string]string{},
		edges:  map[string]*Edge{},
		linked: map[string]bool{},
		raw:    map[string]*Resource{},
		nicVM:  map[string]string{},
		nicIPs: map[string][]string{},
		ipNIC:  map[string]string{},
		byAddr: map[string][]string{},
	}
	b.ix.byHost = b.hosts
	b.tenant(o.Via, o.TenantName)
	for i := range containers {
		b.container(&containers[i])
	}
	for i := range resources {
		b.resource(&resources[i])
	}
	b.hierarchy()
	for _, id := range b.order {
		if r := b.raw[id]; r != nil {
			b.network(id, r)
		}
	}
	for _, id := range b.order {
		if r := b.raw[id]; r != nil {
			b.balancer(id, r)
		}
	}
	for _, p := range b.pending {
		b.link(p[0], p[1], p[2])
	}
	b.vmAddresses()
	for _, id := range b.order {
		if r := b.raw[id]; r != nil {
			b.references(id, r)
		}
	}

	nodes := make([]Node, 0, len(b.order))
	for _, id := range b.order {
		nodes = append(nodes, *b.ix.nodes[id])
	}
	edges := make([]Edge, 0, len(b.eids))
	for _, id := range b.eids {
		e := b.edges[id]
		if n := b.ix.nodes[e.From]; n != nil {
			e.FromKind = n.Kind
		}
		if n := b.ix.nodes[e.To]; n != nil {
			e.ToKind = n.Kind
		}
		edges = append(edges, *e)
	}
	return nodes, edges, b.ix
}

func (b *builder) add(n *Node) *Node {
	if old := b.ix.nodes[n.ID]; old != nil {
		return old
	}
	if n.Tags == nil {
		n.Tags = []Tag{}
	}
	if n.Attrs == nil {
		n.Attrs = map[string]any{}
	}
	n.Source, n.Via, n.RunID, n.SeenAt = SourceARM, b.o.Via, b.o.RunID, b.o.Now
	b.ix.nodes[n.ID] = n
	b.order = append(b.order, n.ID)
	return n
}

func (b *builder) edge(from, rel, to, key string, attrs map[string]any) {
	if from == "" || to == "" || from == to {
		return
	}
	id := EdgeID(from, rel, to, key)
	if _, ok := b.edges[id]; ok {
		return
	}
	b.edges[id] = &Edge{ID: id, From: from, To: to, Rel: rel, Key: key, Attrs: attrs,
		Source: SourceARM, Via: b.o.Via, RunID: b.o.RunID, SeenAt: b.o.Now}
	b.eids = append(b.eids, id)
	b.linked[from+"|"+to], b.linked[to+"|"+from] = true, true
}

func (b *builder) tenant(id, name string) string {
	id = strings.ToLower(id)
	if name == "" {
		name = id
	}
	if n := b.ix.nodes[TenantID(id)]; n != nil {
		return n.ID
	}
	return b.add(&Node{ID: TenantID(id), Kind: KindTenant, Type: "tenant", Name: name, Q: strings.ToLower(name + " " + id), TenantID: id}).ID
}

func (b *builder) container(r *Resource) {
	id := ARMID(r.ID)
	tenant := strings.ToLower(r.TenantID)
	if tenant == "" {
		tenant = b.o.Via
	}
	sub := strings.ToLower(r.SubscriptionID)
	switch strings.ToLower(r.Type) {
	case typeSubscription:
		b.add(&Node{ID: id, Kind: KindSubscription, Type: typeSubscription, Name: r.Name, Q: strings.ToLower(r.Name + " " + sub),
			TenantID: tenant, SubscriptionID: sub, Tags: tagList(r.Tags),
			Attrs: map[string]any{"state": str(r.Properties, "state")}})
	case typeRG:
		b.add(&Node{ID: id, Kind: KindResourceGroup, Type: typeRG, Name: r.Name, Q: strings.ToLower(r.Name),
			TenantID: tenant, SubscriptionID: sub, ResourceGroup: strings.ToLower(r.Name), Location: r.Location, Tags: tagList(r.Tags)})
	}
}

func (b *builder) resource(r *Resource) {
	id := ARMID(r.ID)
	if id == "" || b.ix.nodes[id] != nil {
		return
	}
	typ := strings.ToLower(r.Type)
	tenant := strings.ToLower(r.TenantID)
	if tenant == "" {
		tenant = b.o.Via
	}
	n := b.add(&Node{ID: id, Kind: KindResource, Type: typ, Name: r.Name, Q: id,
		TenantID: tenant, SubscriptionID: strings.ToLower(r.SubscriptionID), ResourceGroup: strings.ToLower(r.ResourceGroup),
		Location: r.Location, Tags: tagList(r.Tags), Attrs: map[string]any{}})
	b.raw[id] = r
	p := r.Properties
	set := func(k, v string) {
		if v != "" {
			n.Attrs[k] = v
		}
	}
	set("kind", r.Kind)
	set("sku", str(r.Sku, "name"))
	set("skuTier", str(r.Sku, "tier"))
	set("provisioningState", str(p, "provisioningState"))
	switch typ {
	case typeVM:
		set("vmSize", str(p, "hardwareProfile", "vmSize"))
		set("osType", str(p, "storageProfile", "osDisk", "osType"))
		set("vmId", str(p, "vmId"))
		set("powerState", strings.TrimPrefix(str(p, "extended", "instanceView", "powerState", "code"), "PowerState/"))
		computer := str(p, "osProfile", "computerName")
		if computer == "" {
			computer = str(p, "extended", "instanceView", "computerName")
		}
		set("computerName", computer)
		b.machineName(id, r.Name, computer)
	case typeArc:
		set("osType", str(p, "osType"))
		set("osName", str(p, "osName"))
		set("status", str(p, "status"))
		set("vmId", str(p, "vmId"))
		b.machineName(id, r.Name, str(p, "displayName"), str(p, "dnsFqdn"))
	case typePIP:
		set("ipAddress", str(p, "ipAddress"))
		set("fqdn", str(p, "dnsSettings", "fqdn"))
		b.host(str(p, "dnsSettings", "fqdn"), id)
	case typeSite:
		set("defaultHostName", str(p, "defaultHostName"))
		set("state", str(p, "state"))
		b.host(str(p, "defaultHostName"), id)
		for _, h := range list(p, "enabledHostNames") {
			if s, _ := h.(string); !strings.Contains(s, ".scm.") {
				b.host(s, id)
			}
		}
	case typeACR:
		set("loginServer", str(p, "loginServer"))
		b.host(str(p, "loginServer"), id)
	case typeVNet:
		// Subnets are not rows in Resource Graph; make them nodes so NICs,
		// addresses and load balancers have something to hang off.
		for _, s := range list(p, "subnets") {
			sid := ARMID(str(s, "id"))
			if sid == "" {
				continue
			}
			sn := b.add(&Node{ID: sid, Kind: KindSubnet, Type: typeSubnet, Name: str(s, "name"), Q: sid,
				TenantID: tenant, SubscriptionID: n.SubscriptionID, ResourceGroup: n.ResourceGroup, Location: r.Location,
				Attrs: map[string]any{}})
			if v := str(s, "properties", "addressPrefix"); v != "" {
				sn.Attrs["addressPrefix"] = v
			}
		}
	}
	if b.o.StoreProperties && p != nil {
		n.Attrs["properties"] = p
	}
}

func (b *builder) machineName(id string, names ...string) {
	seen := map[string]bool{}
	for _, name := range names {
		for _, k := range []string{strings.ToLower(name), hostLabel(name)} {
			if k != "" && !seen[k] {
				seen[k] = true
				b.ix.byName[k] = append(b.ix.byName[k], id)
			}
		}
	}
}

// hostLabel is the first label of a DNS name, lower case.
func hostLabel(name string) string {
	name, _, _ = strings.Cut(strings.ToLower(strings.TrimSpace(name)), ".")
	return name
}

func (b *builder) host(name, id string) {
	if name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), ".")); name != "" {
		b.hosts[name] = id
	}
}

// hierarchy adds the "contains" chain: tenant > subscription > resource
// group > resource > child resource.
func (b *builder) hierarchy() {
	for _, id := range append([]string(nil), b.order...) {
		n := b.ix.nodes[id]
		switch n.Kind {
		case KindTenant:
		case KindSubscription:
			b.edge(b.tenant(n.TenantID, ""), RelContains, id, "", nil)
		default:
			parent := b.ix.Resolve(ParentID(id))
			if parent == nil && n.SubscriptionID != "" {
				// A subscription the principal can see resources in but not list.
				sub := b.add(&Node{ID: SubscriptionID(n.SubscriptionID), Kind: KindSubscription, Type: typeSubscription,
					Name: n.SubscriptionID, Q: n.SubscriptionID, TenantID: n.TenantID, SubscriptionID: n.SubscriptionID})
				b.edge(b.tenant(n.TenantID, ""), RelContains, sub.ID, "", nil)
				parent = sub
			}
			if parent != nil {
				b.edge(parent.ID, RelContains, id, "", nil)
			}
		}
	}
}

func (b *builder) props(id string) map[string]any {
	if r := b.raw[id]; r != nil {
		return r.Properties
	}
	return nil
}

// resolve returns the node an ARM ID points at (or sits under), if it is a
// resource or subnet - never a bare resource group or subscription.
func (b *builder) resolve(id string) string {
	if n := b.ix.Resolve(id); n != nil && (n.Kind == KindResource || n.Kind == KindSubnet) {
		return n.ID
	}
	return ""
}

func (b *builder) privateIP(addr, subnet, holder string) string {
	a, err := netip.ParseAddr(strings.TrimSpace(addr))
	if err != nil {
		return ""
	}
	scope, parent := b.o.Via, ""
	if s := b.ix.nodes[ARMID(subnet)]; s != nil {
		parent = s.ID
		scope = ParentID(s.ID) // the virtual network
	}
	id := PrivateIPID(scope, a.String())
	if b.ix.nodes[id] == nil {
		n := b.add(&Node{ID: id, Kind: KindIP, Type: "private", Name: a.String(), Q: a.String(), Attrs: map[string]any{"visibility": "private"}})
		if h := b.ix.nodes[holder]; h != nil {
			n.TenantID, n.SubscriptionID, n.ResourceGroup = h.TenantID, h.SubscriptionID, h.ResourceGroup
		}
		b.byAddr[a.String()] = append(b.byAddr[a.String()], id)
		b.edge(parent, RelContains, id, "", nil)
	}
	return id
}

func (b *builder) publicIP(addr string) string {
	a, err := netip.ParseAddr(strings.TrimSpace(addr))
	if err != nil {
		return ""
	}
	id := PublicIPID(a.String())
	if b.ix.nodes[id] == nil {
		b.add(&Node{ID: id, Kind: KindIP, Type: "public", Name: a.String(), Q: a.String(), TenantID: b.o.Via,
			Attrs: map[string]any{"visibility": "public"}})
		b.byAddr[a.String()] = append(b.byAddr[a.String()], id)
	}
	return id
}

// network handles VMs, NICs and public IP resources.
func (b *builder) network(id string, r *Resource) {
	p := r.Properties
	switch strings.ToLower(r.Type) {
	case typeVM:
		for _, nic := range list(p, "networkProfile", "networkInterfaces") {
			if t := b.resolve(str(nic, "id")); t != "" {
				b.edge(id, RelAttached, t, "", map[string]any{"as": "nic"})
				b.nicVM[t] = id
			}
		}
		if t := b.resolve(str(p, "storageProfile", "osDisk", "managedDisk", "id")); t != "" {
			b.edge(id, RelAttached, t, "", map[string]any{"as": "osDisk"})
		}
		for _, d := range list(p, "storageProfile", "dataDisks") {
			if t := b.resolve(str(d, "managedDisk", "id")); t != "" {
				b.edge(id, RelAttached, t, "", map[string]any{"as": "dataDisk"})
			}
		}
	case typeNIC:
		if vm := b.resolve(str(p, "virtualMachine", "id")); vm != "" {
			b.edge(vm, RelAttached, id, "", map[string]any{"as": "nic"})
			b.nicVM[id] = vm
		}
		if t := b.resolve(str(p, "networkSecurityGroup", "id")); t != "" {
			b.edge(id, RelSecuredBy, t, "", nil)
		}
		var addrs []string
		for _, c := range list(p, "ipConfigurations") {
			cp := get(c, "properties")
			subnet := str(cp, "subnet", "id")
			if t := b.resolve(subnet); t != "" {
				b.edge(id, RelInSubnet, t, "", nil)
			}
			if ip := b.privateIP(str(cp, "privateIPAddress"), subnet, id); ip != "" {
				b.edge(id, RelHasIP, ip, "", map[string]any{"allocation": str(cp, "privateIPAllocationMethod")})
				b.nicIPs[id] = append(b.nicIPs[id], ip)
				b.ipNIC[ip] = id
				addrs = append(addrs, b.ix.nodes[ip].Name)
			}
			if pip := b.resolve(str(cp, "publicIPAddress", "id")); pip != "" {
				b.edge(id, RelAttached, pip, "", map[string]any{"as": "publicIp"})
				if ip := b.publicIP(str(b.props(pip), "ipAddress")); ip != "" {
					b.nicIPs[id] = append(b.nicIPs[id], ip)
				}
			}
			for _, pool := range list(cp, "loadBalancerBackendAddressPools") {
				b.backend(b.resolve(str(pool, "id")), id, str(pool, "id"))
			}
			for _, pool := range list(cp, "applicationGatewayBackendAddressPools") {
				b.backend(b.resolve(str(pool, "id")), id, str(pool, "id"))
			}
		}
		n := b.ix.nodes[id]
		if len(addrs) > 0 {
			n.Attrs["privateIps"] = addrs
			n.Q += " " + strings.Join(addrs, " ")
		}
		if mac := str(p, "macAddress"); mac != "" {
			n.Attrs["macAddress"] = mac
		}
	case typePIP:
		if ip := b.publicIP(str(p, "ipAddress")); ip != "" {
			b.edge(id, RelHasIP, ip, "", map[string]any{"allocation": str(p, "publicIPAllocationMethod")})
			b.ix.nodes[id].Q += " " + b.ix.nodes[ip].Name
		}
	}
}

// backend links a load balancer / application gateway to something behind
// it, and on to the VM when the target is a NIC or one of its addresses.
func (b *builder) backend(lb, target, pool string) {
	if lb != "" && target != "" {
		b.pending = append(b.pending, [3]string{lb, target, pool})
	}
}

func (b *builder) link(lb, target, pool string) {
	attrs := map[string]any{}
	if i := strings.LastIndex(pool, "/"); i >= 0 && pool != "" {
		attrs["pool"] = pool[i+1:]
	}
	b.edge(lb, RelBackend, target, "", attrs)
	if nic, ok := b.ipNIC[target]; ok {
		b.edge(lb, RelBackend, nic, "", attrs)
		target = nic
	}
	if vm, ok := b.nicVM[target]; ok {
		b.edge(lb, RelBackend, vm, "", attrs)
	}
}

// address finds the node for a backend given as an IP address: a known
// address in this tenant, else nothing.
func (b *builder) address(addr string) string {
	a, err := netip.ParseAddr(strings.TrimSpace(addr))
	if err != nil {
		return ""
	}
	if ids := b.byAddr[a.String()]; len(ids) == 1 {
		return ids[0]
	}
	return ""
}

// balancer handles load balancers and application gateways.
func (b *builder) balancer(id string, r *Resource) {
	typ := strings.ToLower(r.Type)
	if typ != typeLB && typ != typeAppGW {
		return
	}
	p := r.Properties
	for _, f := range list(p, "frontendIPConfigurations") {
		fp := get(f, "properties")
		if pip := b.resolve(str(fp, "publicIPAddress", "id")); pip != "" {
			b.edge(id, RelFrontend, pip, "", nil)
			if ip := b.publicIP(str(b.props(pip), "ipAddress")); ip != "" {
				b.edge(id, RelFrontend, ip, "", nil)
			}
		}
		subnet := str(fp, "subnet", "id")
		if t := b.resolve(subnet); t != "" {
			b.edge(id, RelInSubnet, t, "", nil)
		}
		if ip := b.privateIP(str(fp, "privateIPAddress"), subnet, id); ip != "" {
			b.edge(id, RelFrontend, ip, "", nil)
		}
	}
	for _, pool := range list(p, "backendAddressPools") {
		pid, pp := str(pool, "id"), get(pool, "properties")
		for _, c := range list(pp, "backendIPConfigurations") {
			b.backend(id, b.resolve(str(c, "id")), pid)
		}
		// Load balancer pools defined by IP address.
		for _, a := range list(pp, "loadBalancerBackendAddresses") {
			b.backend(id, b.address(str(a, "properties", "ipAddress")), pid)
			b.backend(id, b.resolve(str(a, "properties", "networkInterfaceIPConfiguration", "id")), pid)
		}
		// Application gateway pools: IP addresses or host names.
		for _, a := range list(pp, "backendAddresses") {
			b.backend(id, b.address(str(a, "ipAddress")), pid)
			if h := strings.ToLower(str(a, "fqdn")); h != "" {
				b.backend(id, b.hosts[h], pid)
			}
		}
	}
}

// vmAddresses links each VM straight to the addresses its NICs hold.
func (b *builder) vmAddresses() {
	nics := make([]string, 0, len(b.nicVM))
	for nic := range b.nicVM {
		nics = append(nics, nic)
	}
	sort.Strings(nics)
	for _, nic := range nics {
		vm := b.nicVM[nic]
		for _, ip := range b.nicIPs[nic] {
			b.edge(vm, RelHasIP, ip, "", map[string]any{"via": nic})
			if n, a := b.ix.nodes[vm], b.ix.nodes[ip]; n != nil && a != nil {
				n.Q += " " + a.Name
				key := "privateIps"
				if a.Type == "public" {
					key = "publicIps"
				}
				cur, _ := n.Attrs[key].([]string)
				n.Attrs[key] = append(cur, a.Name)
			}
		}
	}
}

// references adds an edge for every other resource ID found anywhere in a
// resource's properties (private endpoints, app service plans, peerings,
// key vault references, ...), unless a more specific edge already exists.
func (b *builder) references(id string, r *Resource) {
	var walk func(v any, path string)
	walk = func(v any, path string) {
		switch x := v.(type) {
		case map[string]any:
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				walk(x[k], k)
			}
		case []any:
			for _, c := range x {
				walk(c, path)
			}
		case string:
			if len(x) < 15 || !strings.EqualFold(x[:15], "/subscriptions/") {
				return
			}
			if t := b.resolve(x); t != "" && t != id && !b.linked[id+"|"+t] {
				b.edge(id, RelReferences, t, "", map[string]any{"property": path})
			}
		}
	}
	walk(r.Properties, "")
	if t := b.resolve(r.ManagedBy); t != "" && t != id && !b.linked[id+"|"+t] {
		b.edge(id, RelReferences, t, "", map[string]any{"property": "managedBy"})
	}
}
