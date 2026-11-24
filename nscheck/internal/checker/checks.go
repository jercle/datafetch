package checker

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jercle/datafetch/nscheck/internal/config"
	"github.com/jercle/datafetch/nscheck/internal/model"
	"github.com/jercle/datafetch/nscheck/internal/nitro"
	"github.com/jercle/datafetch/nscheck/internal/store"
)

// identityEvery is how often the version, model and serial are re-read.
const identityEvery = time.Hour

// optional reads a resource that an appliance may not have (a feature that
// is not licensed or enabled). It reports false, and no error, when the
// appliance answered with an error; a lost connection is still an error.
func (p *pass) optional(ctx context.Context, api, resource string) ([]nitro.Obj, bool, error) {
	objs, err := p.api.Get(ctx, api, resource)
	if err == nil {
		return objs, true, nil
	}
	var ne *nitro.Error
	if errors.As(err, &ne) && ne.Answered() {
		p.log.Debug("resource not available", "resource", resource, "error", err)
		return nil, false, nil
	}
	return nil, false, err
}

func first(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func num(o nitro.Obj, keys ...string) *float64 {
	for _, k := range keys {
		if v, ok := o.Num(k); ok {
			return &v
		}
	}
	return nil
}

// list names up to five items and counts the rest.
func list(names []string) string {
	const show = 5
	if len(names) <= show {
		return strings.Join(names, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(names[:show], ", "), len(names)-show)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// level compares a percentage with its thresholds.
func (p *pass) level(name, label string, v *float64, t config.Threshold) {
	ch := model.Check{Name: name, Unit: "%", Warning: ptr(t.Warning), Critical: ptr(t.Critical)}
	switch {
	case v == nil:
		ch.Status, ch.Message = model.HealthUnknown, label+" is not reported"
	case *v >= t.Critical:
		ch.Status, ch.Message = model.HealthCritical, fmt.Sprintf("%s is at %.0f%% (critical from %.0f%%)", label, *v, t.Critical)
	case *v >= t.Warning:
		ch.Status, ch.Message = model.HealthWarning, fmt.Sprintf("%s is at %.0f%% (warning from %.0f%%)", label, *v, t.Warning)
	default:
		ch.Status, ch.Message = model.HealthOK, fmt.Sprintf("%s is at %.0f%%", label, *v)
	}
	ch.Value = v
	p.check(ch)
}

// system reads resource use, hardware state and, hourly, the identity.
func (p *pass) system(ctx context.Context) (int, error) {
	stats, err := p.api.Get(ctx, "stat", "system")
	if err != nil {
		return 0, err
	}
	if len(stats) == 0 {
		return 0, errors.New("system: the appliance returned no statistics")
	}
	s := stats[0]
	sys := &model.System{
		CPU:       num(s, "pktcpuusagepcnt", "cpuusagepcnt"),
		MgmtCPU:   num(s, "mgmtcpuusagepcnt"),
		Memory:    num(s, "memusagepcnt"),
		MemoryMB:  num(s, "memuseinmb"),
		DiskFlash: num(s, "disk0perusage"),
		DiskVar:   num(s, "disk1perusage"),
		CPUs:      int(s.Int("numcpus")),
		StartTime: first(s.Str("starttime"), s.Str("starttimelocal")),
	}
	th := p.c.Cfg.Thresholds
	p.level(model.CheckCPU, "Packet CPU", sys.CPU, th.CPU)
	p.level(model.CheckMgmtCPU, "Management CPU", sys.MgmtCPU, th.MgmtCPU)
	p.level(model.CheckMemory, "Memory", sys.Memory, th.Memory)
	p.level(model.CheckDiskFlash, "/flash", sys.DiskFlash, th.Disk)
	p.level(model.CheckDiskVar, "/var", sys.DiskVar, th.Disk)

	if p.c.Cfg.CheckHardware() {
		var failed []string
		for i := 1; i <= 4; i++ {
			st := strings.ToUpper(s.Str(fmt.Sprintf("powersupply%dstatus", i)))
			// Virtual appliances report NOT SUPPORTED; an empty bay NOT PRESENT.
			if st == "" || st == "NOT SUPPORTED" || st == "NOT PRESENT" {
				continue
			}
			name := fmt.Sprintf("Power supply %d", i)
			sys.PowerSupplies = append(sys.PowerSupplies, model.PowerSupply{Name: name, Status: st})
			if st != "NORMAL" {
				failed = append(failed, fmt.Sprintf("%s is %s", name, st))
			}
		}
		ch := model.Check{Name: model.CheckHardware, Status: model.HealthOK}
		switch {
		case len(failed) > 0:
			ch.Status, ch.Message = model.HealthCritical, strings.Join(failed, ", ")
		case len(sys.PowerSupplies) > 0:
			ch.Message = fmt.Sprintf("%s normal", plural(len(sys.PowerSupplies), "power supply", "power supplies"))
		default:
			ch.Message = "No power supply sensors (a virtual appliance)"
		}
		p.check(ch)
	}

	// Identity changes with an upgrade at most: read it now and then.
	m := p.mem
	if m.identity == nil || p.now.Sub(m.identityAt) >= identityEvery {
		id := &model.System{}
		if o, ok, err := p.optional(ctx, "config", "nsversion"); err != nil {
			return 0, err
		} else if ok && len(o) > 0 {
			id.Version = o[0].Str("version")
		}
		if o, ok, err := p.optional(ctx, "config", "nshardware"); err != nil {
			return 0, err
		} else if ok && len(o) > 0 {
			id.Model, id.Serial, id.HostID = o[0].Str("hwdescription"), o[0].Str("serialno"), first(o[0].Str("hostid"), o[0].Str("host"))
		}
		if o, ok, err := p.optional(ctx, "config", "nshostname"); err != nil {
			return 0, err
		} else if ok && len(o) > 0 {
			id.Hostname = o[0].Str("hostname")
		}
		m.identity, m.identityAt = id, p.now
	}
	sys.Version, sys.Model, sys.Serial, sys.HostID, sys.Hostname = m.identity.Version, m.identity.Model, m.identity.Serial, m.identity.HostID, m.identity.Hostname

	if old := p.prev; old != nil && old.System != nil {
		if was := old.System.StartTime; was != "" && sys.StartTime != "" && was != sys.StartTime {
			p.event(model.EventRestart, "", was, sys.StartTime, model.HealthWarning, "The appliance restarted: it reports starting at "+sys.StartTime)
		}
		if was := old.System.Version; was != "" && sys.Version != "" && was != sys.Version {
			p.event(model.EventRestart, "version", was, sys.Version, model.HealthOK, "The firmware changed to "+sys.Version)
		}
	}
	p.doc.System = sys
	return 1, nil
}

// HA node states that are a failure, and those that are someone's choice.
func haLevel(state string) string {
	s := strings.ToUpper(state)
	switch {
	case s == "UP" || s == "ENABLED":
		return model.HealthOK
	case s == "":
		return model.HealthUnknown
	case strings.Contains(s, "FAIL") || strings.Contains(s, "DOWN") || s == "UNKNOWN":
		return model.HealthCritical
	}
	// DISABLED, STAYSECONDARY, STAYPRIMARY, DUMB, INIT...
	return model.HealthWarning
}

// ha reads the high-availability nodes and this node's own HA state.
func (p *pass) ha(ctx context.Context) (int, error) {
	nodes, err := p.api.Get(ctx, "config", "hanode")
	if err != nil {
		return 0, err
	}
	stats, _, err := p.optional(ctx, "stat", "hanode")
	if err != nil {
		return 0, err
	}
	stat := nitro.Obj{}
	if len(stats) > 0 {
		stat = stats[0]
	}

	ha := &model.HA{}
	var local, peer *model.HANode
	for _, n := range nodes {
		ha.Nodes = append(ha.Nodes, model.HANode{
			ID: int(n.Int("id")), Name: n.Str("name"), IP: n.Str("ipaddress"),
			State: n.Str("hastatus"), MasterState: n.Str("state"), Sync: n.Str("hasync"),
		})
	}
	for i := range ha.Nodes {
		if n := &ha.Nodes[i]; n.ID == 0 && local == nil {
			local = n
		} else if peer == nil {
			peer = n
		}
	}
	ha.Configured = peer != nil
	if local != nil {
		ha.State, ha.MasterState = local.State, local.MasterState
	}
	// The statistics are this node's own, current view.
	ha.State = first(stat.Str("hacurstate"), ha.State)
	ha.MasterState = first(stat.Str("hacurmasterstate"), ha.MasterState)
	ha.LastTransition = stat.Str("transtime")
	ha.SyncFailures = stat.Int("haerrsyncfailure")
	for _, n := range ha.Nodes {
		if strings.EqualFold(n.Sync, "FAILED") || ha.SyncState == "" {
			ha.SyncState = n.Sync
		}
	}
	p.doc.HA = ha

	ch := model.Check{Name: model.CheckHA, Status: model.HealthOK}
	if !ha.Configured {
		ch.Message = "Standalone: not in a high-availability pair"
		if p.ap.RequireHA {
			ch.Status, ch.Message = model.HealthCritical, "High availability is required but the appliance is standalone"
		}
		p.check(ch)
		return len(ha.Nodes), nil
	}
	ha.Peer, ha.PeerState = first(peer.IP, peer.Name), peer.State
	p.secondary = strings.EqualFold(ha.MasterState, "Secondary")

	var problems []string
	add := func(level, msg string) {
		ch.Status = model.Worse(ch.Status, level)
		problems = append(problems, msg)
	}
	if l := haLevel(ha.State); l != model.HealthOK {
		add(l, "this node's HA state is "+first(ha.State, "not reported"))
	}
	if l := haLevel(ha.PeerState); l != model.HealthOK {
		add(l, fmt.Sprintf("the peer %s is %s", ha.Peer, first(ha.PeerState, "not reported")))
	}
	switch ms := strings.ToUpper(ha.MasterState); {
	case ms == "PRIMARY" && strings.EqualFold(peer.MasterState, "Primary"):
		add(model.HealthCritical, "both nodes claim to be primary")
	case ms != "PRIMARY" && ms != "SECONDARY":
		add(model.HealthWarning, "the master state is "+first(ha.MasterState, "not reported"))
	}
	if strings.EqualFold(ha.SyncState, "FAILED") {
		add(model.HealthWarning, "configuration synchronisation failed")
	}
	if len(problems) > 0 {
		ch.Message = "High availability: " + strings.Join(problems, "; ")
	} else {
		ch.Message = fmt.Sprintf("%s node, peer %s is %s", ha.MasterState, ha.Peer, ha.PeerState)
	}
	p.check(ch)

	if old := p.prev; old != nil && old.HA != nil && old.HA.MasterState != "" && ha.MasterState != "" &&
		!strings.EqualFold(old.HA.MasterState, ha.MasterState) {
		p.event(model.EventHA, "", old.HA.MasterState, ha.MasterState, model.HealthWarning,
			fmt.Sprintf("Failover: this node is now %s (was %s)", ha.MasterState, old.HA.MasterState))
	}
	return len(ha.Nodes), nil
}

// The layouts NetScaler writes its configuration times in.
var nsTimes = []string{"Mon Jan _2 15:04:05 2006", "Mon Jan 2 15:04:05 2006", time.RFC1123, time.RFC3339}

func parseTime(s string, layouts ...string) (time.Time, bool) {
	s = strings.Join(strings.Fields(s), " ")
	for _, l := range layouts {
		if t, err := time.Parse(l, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// config tells whether the running configuration has been saved.
func (p *pass) config(ctx context.Context) (int, error) {
	if p.secondary {
		// The secondary receives its configuration from the primary.
		p.check(model.Check{Name: model.CheckConfig, Status: model.HealthOK, Message: "Secondary node: the configuration is checked on the primary"})
		return 0, skipped("secondary node")
	}
	objs, err := p.api.Get(ctx, "config", "nsconfig")
	if err != nil {
		return 0, err
	}
	if len(objs) == 0 {
		return 0, errors.New("nsconfig: the appliance returned nothing")
	}
	o := objs[0]
	changed, saved := o.Str("lastconfigchangedtime"), o.Str("lastconfigsavetime")
	ch := model.Check{Name: model.CheckConfig, Status: model.HealthOK, Message: "The running configuration is saved"}
	unsaved, known := false, false
	if o.Has("configchanged") {
		unsaved, known = o.Truthy("configchanged"), true
	} else if c, ok := parseTime(changed, nsTimes...); ok {
		if s, ok := parseTime(saved, nsTimes...); ok {
			unsaved, known = c.After(s), true
		}
	}
	switch {
	case !known:
		ch.Message = "The appliance does not report whether its configuration is saved"
	case unsaved:
		ch.Status = model.HealthWarning
		ch.Message = "The running configuration has changes that are not saved"
		if changed != "" {
			ch.Message += fmt.Sprintf(" (changed %s, saved %s)", changed, first(saved, "never"))
		}
	}
	p.check(ch)
	if sys := p.doc.System; sys != nil {
		sys.ConfigChanged, sys.ConfigSaved, sys.ConfigUnsaved = changed, saved, unsaved
	}
	return 1, nil
}

// interfaces flags enabled, HA-monitored interfaces that are down: each
// one counts against the node in an HA pair.
func (p *pass) interfaces(ctx context.Context) (int, error) {
	objs, err := p.api.Get(ctx, "config", "Interface")
	if err != nil {
		return 0, err
	}
	var down []string
	c := &p.doc.Counts
	for _, o := range objs {
		id := first(o.Str("id"), o.Str("devicename"))
		if id == "" || strings.HasPrefix(strings.ToUpper(id), "LO/") {
			continue
		}
		linkKey := "linkstate"
		if !o.Has(linkKey) {
			linkKey = "intfstate"
		}
		it := model.Interface{
			ID:          id,
			Description: first(o.Str("ifalias"), o.Str("description")),
			Enabled:     !strings.EqualFold(o.Str("state"), "DISABLED"),
			Up:          o.Truthy(linkKey),
			HAMonitor:   o.Truthy("hamonitor"),
			Speed:       o.Str("actspeed"),
		}
		p.doc.Interfaces = append(p.doc.Interfaces, it)
		c.Interfaces++
		if it.Enabled && it.HAMonitor && !it.Up && !config.Matches(p.ap.Ignore.Interfaces, id) {
			down = append(down, id)
			c.InterfacesDown++
		}
	}
	ch := model.Check{Name: model.CheckInterfaces, Status: model.HealthOK, Message: fmt.Sprintf("%s, none of the monitored ones down", plural(c.Interfaces, "interface", "interfaces"))}
	if len(down) > 0 {
		ch.Status = model.HealthWarning
		ch.Message = fmt.Sprintf("%s enabled and HA-monitored but down: %s", plural(len(down), "interface is", "interfaces are"), list(down))
	}
	p.check(ch)
	return c.Interfaces, nil
}

// newSet starts the result of a step for one collection.
func (p *pass) newSet(coll string) *objSet {
	set := &objSet{coll: coll, keep: []string{}, states: map[string]model.ObjectState{}}
	p.sets = append(p.sets, set)
	return set
}

// object fills in what every object document shares, and reports a change
// of status since the last pass. label names the object in that report.
func (p *pass) object(coll, kind, name, state, status, detail string, ignored bool, eventKind, label string, search ...string) model.Object {
	o := model.Object{
		ID: model.NewID(p.ref.ApplianceID, kind, name), Ref: p.ref, Kind: kind, Name: name,
		State: state, Status: status, Detail: detail, Ignored: ignored,
		Search:      strings.ToLower(strings.Join(append([]string{name}, search...), " ")),
		StatusSince: p.now, FirstSeenAt: p.now, UpdatedAt: p.now,
	}
	old, seen := p.mem.objects[coll][o.ID]
	if !seen {
		return o
	}
	o.FirstSeenAt = old.FirstSeen
	if old.Status == status {
		o.StatusSince = old.Since
		return o
	}
	if !ignored {
		msg := fmt.Sprintf("%s is %s", label, first(state, status))
		switch {
		case status == model.HealthOK:
			msg = fmt.Sprintf("%s recovered: %s", label, first(state, status))
		case detail != "":
			msg = fmt.Sprintf("%s: %s", label, detail)
		}
		p.event(eventKind, name, old.Status, status, status, msg)
	}
	return o
}

// add puts a document in the set, to be written if it changed.
func (p *pass) add(set *objSet, doc interface{ Base() *model.Object }) {
	b := doc.Base()
	b.Hash = model.HashOf(doc)
	set.keep = append(set.keep, b.ID)
	set.states[b.ID] = model.ObjectState{Kind: b.Kind, Status: b.Status, Since: b.StatusSince, FirstSeen: b.FirstSeenAt, Hash: b.Hash}
	if old, ok := p.mem.objects[set.coll][b.ID]; !ok || old.Hash != b.Hash {
		set.docs = append(set.docs, store.Doc{ID: b.ID, Body: doc})
	}
}

// offSecondary empties the collection's kinds for a secondary node, whose
// virtual servers and services say nothing: it does not probe them.
func (p *pass) offSecondary(coll string, kinds []string, check, what string) (int, error) {
	set := p.newSet(coll)
	set.kinds = kinds
	p.check(model.Check{Name: check, Status: model.HealthOK, Message: "Secondary node: " + what + " are checked on the primary"})
	return 0, skipped("secondary node")
}

var vserverKinds = []struct {
	kind, resource, label string
	required              bool
}{
	{"lb", "lbvserver", "Load balancing virtual server", true},
	{"cs", "csvserver", "Content switching virtual server", false},
	{"vpn", "vpnvserver", "Gateway virtual server", false},
	{"aaa", "authenticationvserver", "Authentication virtual server", false},
	{"gslb", "gslbvserver", "GSLB virtual server", false},
}

func outOfService(state string) bool {
	return strings.Contains(strings.ToUpper(state), "OUT OF SERVICE")
}

// vservers reads the state of every virtual server.
func (p *pass) vservers(ctx context.Context) (int, error) {
	if p.secondary {
		return p.offSecondary(model.CollVservers, []string{"lb", "cs", "vpn", "aaa", "gslb"}, model.CheckVservers, "virtual servers")
	}
	minHealth := p.c.Cfg.VserverHealth()
	set := &objSet{coll: model.CollVservers, keep: []string{}, states: map[string]model.ObjectState{}}
	c := &p.doc.Counts
	var down, degraded []string
	for _, k := range vserverKinds {
		var objs []nitro.Obj
		var err error
		ok := true
		if k.required {
			objs, err = p.api.Get(ctx, "stat", k.resource)
		} else {
			objs, ok, err = p.optional(ctx, "stat", k.resource)
		}
		if err != nil {
			return 0, err
		}
		if !ok {
			continue // keep what is stored of this kind
		}
		set.kinds = append(set.kinds, k.kind)
		for _, o := range objs {
			name := o.Str("name")
			if name == "" {
				continue
			}
			v := model.Vserver{IP: o.Str("primaryipaddress"), Port: int(o.Int("primaryport")), Protocol: o.Str("type")}
			if k.kind == "lb" || k.kind == "gslb" {
				v.HealthPercent = num(o, "vslbhealth")
				if o.Has("actsvcs") || o.Has("inactsvcs") {
					v.ServicesUp, v.ServicesDown = ptr(int(o.Int("actsvcs"))), ptr(int(o.Int("inactsvcs")))
				}
			}
			state := strings.ToUpper(o.Str("state"))
			status, detail := model.HealthOK, ""
			switch {
			case state == "UP":
				if v.HealthPercent != nil && *v.HealthPercent < minHealth {
					status, detail = model.HealthWarning, fmt.Sprintf("up with %.0f%% of its services", *v.HealthPercent)
				}
			case outOfService(state):
				status = model.HealthDisabled
			case state == "DOWN":
				status, detail = model.HealthCritical, "down"
			case state == "":
				status, detail = model.HealthUnknown, "state not reported"
			default:
				status, detail = model.HealthWarning, "state is "+state
			}
			ignored := config.Matches(p.ap.Ignore.Vservers, name)
			v.Object = p.object(model.CollVservers, k.kind, name, state, status, detail, ignored, model.EventVserver, k.label+" "+name, v.IP)
			p.add(set, &v)
			c.Vservers++
			if ignored {
				continue
			}
			switch status {
			case model.HealthCritical:
				c.VserversDown++
				down = append(down, name)
			case model.HealthWarning, model.HealthUnknown:
				c.VserversDegraded++
				degraded = append(degraded, name)
			case model.HealthDisabled:
				c.VserversDisabled++
			}
		}
	}
	p.sets = append(p.sets, set)

	ch := model.Check{Name: model.CheckVservers, Status: model.HealthOK}
	var parts []string
	if len(down) > 0 {
		ch.Status = model.HealthCritical
		parts = append(parts, fmt.Sprintf("%s of %d down: %s", plural(len(down), "virtual server", "virtual servers"), c.Vservers, list(down)))
	}
	if len(degraded) > 0 {
		ch.Status = model.Worse(ch.Status, model.HealthWarning)
		parts = append(parts, fmt.Sprintf("%s degraded: %s", plural(len(degraded), "virtual server", "virtual servers"), list(degraded)))
	}
	if len(parts) == 0 {
		parts = append(parts, fmt.Sprintf("%s, none down", plural(c.Vservers, "virtual server", "virtual servers")))
		if c.VserversDisabled > 0 {
			parts[0] += fmt.Sprintf(" (%d disabled)", c.VserversDisabled)
		}
	}
	ch.Message = strings.Join(parts, "; ")
	p.check(ch)
	return c.Vservers, nil
}

// services reads the state of every service and service group.
func (p *pass) services(ctx context.Context) (int, error) {
	if p.secondary {
		return p.offSecondary(model.CollServices, []string{"service", "servicegroup"}, model.CheckServices, "services")
	}
	set := &objSet{coll: model.CollServices, kinds: []string{"service"}, keep: []string{}, states: map[string]model.ObjectState{}}
	c := &p.doc.Counts
	var down []string
	count := func(name, status string, ignored bool) {
		c.Services++
		if ignored {
			return
		}
		switch status {
		case model.HealthWarning, model.HealthCritical:
			c.ServicesDown++
			down = append(down, name)
		case model.HealthDisabled:
			c.ServicesDisabled++
		}
	}

	objs, err := p.api.Get(ctx, "stat", "service")
	if err != nil {
		return 0, err
	}
	for _, o := range objs {
		name := o.Str("name")
		if name == "" {
			continue
		}
		s := model.Service{IP: o.Str("primaryipaddress"), Port: int(o.Int("primaryport")), Protocol: o.Str("servicetype")}
		state := strings.ToUpper(o.Str("state"))
		status, detail := model.HealthOK, ""
		switch {
		case state == "UP":
		case outOfService(state):
			status = model.HealthDisabled
		case state == "":
			status, detail = model.HealthUnknown, "state not reported"
		default:
			status, detail = model.HealthWarning, strings.ToLower(state)
		}
		ignored := config.Matches(p.ap.Ignore.Services, name)
		s.Object = p.object(model.CollServices, "service", name, state, status, detail, ignored, model.EventService, "Service "+name, s.IP)
		p.add(set, &s)
		count(name, status, ignored)
	}

	groups, ok, err := p.optional(ctx, "config", "servicegroup")
	if err != nil {
		return 0, err
	}
	if ok {
		set.kinds = append(set.kinds, "servicegroup")
	}
	for _, o := range groups {
		name := o.Str("servicegroupname")
		if name == "" {
			continue
		}
		s := model.Service{Protocol: o.Str("servicetype")}
		state := strings.ToUpper(o.Str("servicegroupeffectivestate"))
		status, detail := model.HealthOK, ""
		switch {
		case strings.EqualFold(o.Str("state"), "DISABLED") || outOfService(state) || state == "DISABLED":
			status, state = model.HealthDisabled, first(state, "DISABLED")
		case state == "UP":
		case state == "":
			// Older firmware does not report it; the members' own state
			// shows on the virtual servers they are bound to.
			status, detail = model.HealthUnknown, "effective state not reported"
		case state == "DOWN":
			status, detail = model.HealthWarning, "every member is down"
		default: // PARTIAL-UP
			status, detail = model.HealthWarning, "some members are down ("+strings.ToLower(state)+")"
		}
		ignored := config.Matches(p.ap.Ignore.Services, name)
		s.Object = p.object(model.CollServices, "servicegroup", name, state, status, detail, ignored, model.EventService, "Service group "+name)
		p.add(set, &s)
		count(name, status, ignored)
	}
	p.sets = append(p.sets, set)

	ch := model.Check{Name: model.CheckServices, Status: model.HealthOK, Message: fmt.Sprintf("%s, none down", plural(c.Services, "service and service group", "services and service groups"))}
	if len(down) > 0 {
		ch.Status = model.HealthWarning
		ch.Message = fmt.Sprintf("%s of %d down or partly down: %s", plural(len(down), "service or service group", "services and service groups"), c.Services, list(down))
	}
	p.check(ch)
	return c.Services, nil
}

// The layouts of a certificate's validity dates: "Nov 24 02:44:00 2027 GMT".
var certTimes = []string{"Jan _2 15:04:05 2006 MST", "Jan 2 15:04:05 2006 MST", "Jan _2 15:04:05 2006", time.RFC3339}

// certificates reads every installed certificate and how long it has left.
func (p *pass) certificates(ctx context.Context) (int, error) {
	objs, err := p.api.Get(ctx, "config", "sslcertkey")
	if err != nil {
		return 0, err
	}
	th := p.c.Cfg.Thresholds.CertificateDays
	set := &objSet{coll: model.CollCertificates, kinds: []string{"certificate"}, keep: []string{}, states: map[string]model.ObjectState{}}
	c := &p.doc.Counts
	var expired, expiring []string
	soonest, critical := -1, false
	for _, o := range objs {
		name := o.Str("certkey")
		if name == "" {
			continue
		}
		cert := model.Certificate{Subject: o.Str("subject"), Issuer: o.Str("issuer"), Serial: o.Str("serial"), Types: o.Strs("certificatetype")}
		if t, ok := parseTime(o.Str("clientcertnotbefore"), certTimes...); ok {
			cert.NotBefore = ptr(t.UTC())
		}
		if t, ok := parseTime(o.Str("clientcertnotafter"), certTimes...); ok {
			cert.NotAfter = ptr(t.UTC())
		}
		if d, ok := o.Num("daystoexpiration"); ok {
			cert.DaysLeft = ptr(int(d))
		} else if cert.NotAfter != nil {
			cert.DaysLeft = ptr(int(cert.NotAfter.Sub(p.now).Hours() / 24))
		}
		state := o.Str("status")
		status, detail := model.HealthOK, ""
		switch {
		case strings.EqualFold(state, "Expired") || (cert.NotAfter != nil && cert.NotAfter.Before(p.now)) || (cert.DaysLeft != nil && *cert.DaysLeft < 0):
			status, detail = model.HealthCritical, "expired"
		case cert.DaysLeft == nil:
			status, detail = model.HealthUnknown, "expiry not reported"
		case float64(*cert.DaysLeft) <= th.Critical:
			status, detail = model.HealthCritical, "expires in "+plural(*cert.DaysLeft, "day", "days")
		case float64(*cert.DaysLeft) <= th.Warning:
			status, detail = model.HealthWarning, "expires in "+plural(*cert.DaysLeft, "day", "days")
		case state != "" && !strings.EqualFold(state, "Valid"):
			status, detail = model.HealthWarning, "status is "+state
		}
		ignored := config.Matches(p.ap.Ignore.Certificates, name)
		cert.Object = p.object(model.CollCertificates, "certificate", name, state, status, detail, ignored, model.EventCertificate, "Certificate "+name, cert.Subject)
		p.add(set, &cert)
		c.Certificates++
		if ignored {
			continue
		}
		if cert.DaysLeft != nil && detail != "expired" && (soonest < 0 || *cert.DaysLeft < soonest) {
			soonest = *cert.DaysLeft
		}
		switch {
		case detail == "expired":
			c.CertsExpired++
			expired = append(expired, name)
		case status == model.HealthCritical || status == model.HealthWarning:
			c.CertsExpiring++
			expiring = append(expiring, fmt.Sprintf("%s (%s)", name, strings.TrimPrefix(detail, "expires in ")))
		}
		if status == model.HealthCritical {
			critical = true
		}
	}
	p.sets = append(p.sets, set)

	ch := model.Check{Name: model.CheckCertificates, Status: model.HealthOK}
	var parts []string
	if len(expired) > 0 {
		ch.Status = model.HealthCritical
		parts = append(parts, fmt.Sprintf("%s expired: %s", plural(len(expired), "certificate has", "certificates have"), list(expired)))
	}
	if len(expiring) > 0 {
		ch.Status = model.Worse(ch.Status, model.HealthWarning)
		if critical {
			ch.Status = model.HealthCritical
		}
		parts = append(parts, fmt.Sprintf("%s soon: %s", plural(len(expiring), "certificate expires", "certificates expire"), list(expiring)))
	}
	if len(parts) == 0 {
		msg := plural(c.Certificates, "certificate", "certificates")
		if soonest >= 0 {
			msg += fmt.Sprintf(", the next expires in %s", plural(soonest, "day", "days"))
		}
		parts = append(parts, msg)
	}
	ch.Message = strings.Join(parts, "; ")
	p.check(ch)
	return c.Certificates, nil
}
