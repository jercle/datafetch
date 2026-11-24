package probe

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/jercle/datafetch/sxgcheck/internal/config"
	"github.com/jercle/datafetch/sxgcheck/internal/model"
)

// SNMPClient is one SNMP session. OIDs are written without a leading dot.
// Values are int64 or string; an object the agent does not have is absent.
type SNMPClient interface {
	Get(oids []string) (map[string]any, error)
	Walk(root string) (map[string]any, error)
	Close() error
}

// SFOS-FIREWALL-MIB (enterprise 2604, Sophos). Scalars: append ".0".
const (
	sfos = "1.3.6.1.4.1.2604.5.1"

	oidDeviceName    = sfos + ".1.1.0"
	oidDeviceType    = sfos + ".1.2.0"
	oidFirmware      = sfos + ".1.3.0"
	oidAppKey        = sfos + ".1.4.0"
	oidWebcatVersion = sfos + ".1.5.0"
	oidIPSVersion    = sfos + ".1.6.0"

	oidUpTime      = sfos + ".2.2.0" // TimeTicks, hundredths of a second
	oidDiskMB      = sfos + ".2.4.1.0"
	oidDiskPercent = sfos + ".2.4.2.0"
	oidMemMB       = sfos + ".2.5.1.0"
	oidMemPercent  = sfos + ".2.5.2.0"
	oidSwapMB      = sfos + ".2.5.3.0"
	oidSwapPercent = sfos + ".2.5.4.0"
	oidLiveUsers   = sfos + ".2.6.0"

	oidServices = sfos + ".3" // .1.0 to .21.0, in config.ServiceNames order
	oidHA       = sfos + ".4"
	oidLicenses = sfos + ".5" // .N.1.0 status, .N.2.0 expiry, in config.LicenseNames order

	// HOST-RESOURCES-MIB hrProcessorLoad: the SFOS MIB has no CPU object.
	oidProcessorLoad = "1.3.6.1.2.1.25.3.3.1.2"
)

var (
	serviceStates = []string{"untouched", "stopped", "initializing", "running", "exiting", "dead", "frozen", "unregistered"}
	haStates      = []string{"notapplicable", "auxiliary", "standalone", "primary", "faulty", "ready"}
	licenseStates = []string{"none", "evaluating", "notsubscribed", "subscribed", "expired", "deactivated"}
)

func enum(names []string, v any) string {
	n, ok := v.(int64)
	if !ok {
		return ""
	}
	if n < 0 || int(n) >= len(names) {
		return fmt.Sprintf("unknown(%d)", n)
	}
	return names[n]
}

func text(vals map[string]any, oid string) string {
	s, _ := vals[oid].(string)
	return strings.TrimSpace(s)
}

func number(vals map[string]any, oid string) *int64 {
	if n, ok := vals[oid].(int64); ok {
		return &n
	}
	return nil
}

func percent(vals map[string]any, oid string) *float64 {
	if n := number(vals, oid); n != nil {
		return f64(float64(*n))
	}
	return nil
}

func level(v float64, t config.Threshold) string {
	switch {
	case t.Critical > 0 && v >= t.Critical:
		return model.HealthCritical
	case t.Warn > 0 && v >= t.Warn:
		return model.HealthWarning
	}
	return model.HealthOK
}

func usage(id, name string, v *float64, t config.Threshold) (model.Check, bool) {
	if v == nil {
		return model.Check{}, false
	}
	c := mk(model.KindSNMP, "snmp/"+id, name, level(*v, t), fmt.Sprintf("%.0f%% used", *v))
	c.Value, c.Unit = v, "%"
	switch c.Status {
	case model.HealthCritical:
		c.Message += fmt.Sprintf(" (critical from %.0f%%)", t.Critical)
	case model.HealthWarning:
		c.Message += fmt.Sprintf(" (warns from %.0f%%)", t.Warn)
	}
	return c, true
}

// checkSNMP reads the SFOS MIB. The first check is always "snmp" itself:
// critical when the firewall does not answer.
func (p *Prober) checkSNMP(ctx context.Context, fw config.Firewall) Result {
	s := fw.SNMP
	base := mk(model.KindSNMP, "snmp", "SNMP", model.HealthOK, "")
	fail := func(what string, err error) Result {
		base.Status, base.Message = model.HealthCritical, what+": "+reason(err)
		return Result{Checks: []model.Check{base}}
	}
	open := p.NewSNMP
	if open == nil {
		open = NewGoSNMP
	}
	start := time.Now()
	cl, err := open(ctx, fw.Host, s, fw.Timeout.D())
	if err != nil {
		return fail("no session", err)
	}
	defer cl.Close()

	vals, err := cl.Get([]string{
		oidDeviceName, oidDeviceType, oidFirmware, oidAppKey, oidWebcatVersion, oidIPSVersion,
		oidUpTime, oidDiskMB, oidDiskPercent, oidMemMB, oidMemPercent, oidSwapMB, oidSwapPercent, oidLiveUsers,
	})
	if err != nil {
		return fail("no answer", err)
	}
	took := time.Since(start)
	base.LatencyMs = ms(took)
	if len(vals) == 0 {
		base.Status = model.HealthWarning
		base.Message = "answered, but without the Sophos Firewall MIB (" + sfos + ")"
		return Result{Checks: []model.Check{base}}
	}
	base.Message = fmt.Sprintf("answered in %d ms", took.Milliseconds())

	res := Result{Device: &model.Device{
		Hostname: text(vals, oidDeviceName), Model: text(vals, oidDeviceType), Firmware: text(vals, oidFirmware),
		AppKey: text(vals, oidAppKey), WebcatVersion: text(vals, oidWebcatVersion), IPSVersion: text(vals, oidIPSVersion),
	}}
	m := &res.Metrics
	m.MemoryPercent, m.SwapPercent, m.DiskPercent = percent(vals, oidMemPercent), percent(vals, oidSwapPercent), percent(vals, oidDiskPercent)
	m.MemoryMB, m.SwapMB, m.DiskMB, m.LiveUsers = number(vals, oidMemMB), number(vals, oidSwapMB), number(vals, oidDiskMB), number(vals, oidLiveUsers)
	if t := number(vals, oidUpTime); t != nil {
		up := *t / 100
		m.UptimeSeconds = &up
	}

	// The rest is read in three more requests. One that fails leaves its
	// checks out and turns "snmp" into a warning.
	var unread []string
	var checks []model.Check

	if cpu, err := cl.Walk(oidProcessorLoad); err != nil {
		unread = append(unread, "CPU")
	} else if len(cpu) > 0 {
		var sum float64
		var n int
		for _, v := range cpu {
			if load, ok := v.(int64); ok {
				sum += float64(load)
				n++
			}
		}
		if n > 0 {
			m.CPUPercent = f64(math.Round(sum / float64(n)))
		}
	}
	if c, ok := usage("cpu", "CPU", m.CPUPercent, s.CPU); ok {
		if c.Status == model.HealthOK {
			c.Message = fmt.Sprintf("%.0f%% busy", *m.CPUPercent)
		} else {
			c.Message = strings.Replace(c.Message, "used", "busy", 1)
		}
		checks = append(checks, c)
	}
	if c, ok := usage("memory", "Memory", m.MemoryPercent, s.Memory); ok {
		checks = append(checks, c)
	}
	// A firewall without swap reports a capacity of 0.
	if m.SwapMB == nil || *m.SwapMB > 0 {
		if c, ok := usage("swap", "Swap", m.SwapPercent, s.Swap); ok {
			checks = append(checks, c)
		}
	}
	if c, ok := usage("disk", "Disk", m.DiskPercent, s.Disk); ok {
		checks = append(checks, c)
	}

	if c, list, err := p.services(cl, s); err != nil {
		unread = append(unread, "services")
	} else if len(list) > 0 {
		res.Services = list
		checks = append(checks, c)
	}
	if c, ha, err := p.ha(cl, s); err != nil {
		unread = append(unread, "HA")
	} else if ha != nil {
		res.HA = ha
		checks = append(checks, c)
	}
	if c, list, err := p.licenses(cl, s); err != nil {
		unread = append(unread, "licences")
	} else if len(list) > 0 {
		res.Licenses = list
		checks = append(checks, c)
	}

	if len(unread) > 0 {
		base.Status = model.HealthWarning
		base.Message += ", but could not read " + strings.Join(unread, ", ")
	}
	res.Checks = append([]model.Check{base}, checks...)
	return res
}

func has(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func (p *Prober) services(cl SNMPClient, s *config.SNMP) (model.Check, []model.Service, error) {
	oids := make([]string, len(config.ServiceNames))
	for i := range oids {
		oids[i] = fmt.Sprintf("%s.%d.0", oidServices, i+1)
	}
	vals, err := cl.Get(oids)
	if err != nil {
		return model.Check{}, nil, err
	}
	var list []model.Service
	var critical []string
	running := 0
	for i, name := range config.ServiceNames {
		state := enum(serviceStates, vals[oids[i]])
		if state == "" {
			continue
		}
		list = append(list, model.Service{Name: name, Status: state})
		if has(s.IgnoreServices, name) {
			continue
		}
		switch {
		case state == "running":
			running++
		case state == "dead" || state == "frozen" || has(s.RequiredServices, name):
			critical = append(critical, name+" is "+state)
		}
	}
	// A required service the firewall does not report at all.
	for _, name := range s.RequiredServices {
		found := false
		for _, sv := range list {
			found = found || sv.Name == name
		}
		if !found && len(list) > 0 {
			critical = append(critical, name+" is not reported")
		}
	}
	c := mk(model.KindSNMP, "snmp/services", "Services", model.HealthOK, plural(running, "service", "services")+" running")
	if len(critical) > 0 {
		c.Status, c.Message = model.HealthCritical, strings.Join(critical, ", ")
	}
	return c, list, nil
}

func (p *Prober) ha(cl SNMPClient, s *config.SNMP) (model.Check, *model.HA, error) {
	const (
		status, peerKey, state, peerState, mode = oidHA + ".1.0", oidHA + ".3.0", oidHA + ".4.0", oidHA + ".5.0", oidHA + ".6.0"
	)
	vals, err := cl.Get([]string{status, peerKey, state, peerState, mode})
	if err != nil {
		return model.Check{}, nil, err
	}
	enabled := number(vals, status)
	if enabled == nil {
		return model.Check{}, nil, nil
	}
	ha := &model.HA{Enabled: *enabled == 1, State: enum(haStates, vals[state]), PeerState: enum(haStates, vals[peerState]), Mode: text(vals, mode), PeerAppKey: text(vals, peerKey)}
	c := mk(model.KindSNMP, "snmp/ha", "High availability", model.HealthOK, "")
	expect := s.ExpectHA
	switch {
	case !ha.Enabled && (expect == "primary" || expect == "auxiliary"):
		c.Status, c.Message = model.HealthWarning, "HA is off, expected "+expect
	case !ha.Enabled:
		c.Message = "HA is off"
	case ha.State == "faulty":
		c.Status, c.Message = model.HealthCritical, "this node is faulty"
	case ha.PeerState == "faulty":
		c.Status, c.Message = model.HealthCritical, "this node is "+ha.State+", the peer is faulty"
	case expect != "" && ha.State != expect:
		c.Status, c.Message = model.HealthWarning, "this node is "+ha.State+", expected "+expect
	default:
		c.Message = "this node is " + ha.State
		if ha.PeerState != "" && ha.PeerState != "notapplicable" {
			c.Message += ", the peer is " + ha.PeerState
		}
	}
	return c, ha, nil
}

var dateLayouts = []string{"Jan 2 2006", "Jan 2, 2006", "2 Jan 2006", "2006-01-02", "Mon Jan 2 2006", "Jan 2 15:04:05 2006", "2006-01-02 15:04:05"}

// parseDate reads a licence expiry date, which the MIB only calls a
// "DisplayString". Anything unreadable is left as text.
func parseDate(s string) *time.Time {
	s = strings.Join(strings.Fields(s), " ")
	for _, layout := range dateLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			t = t.UTC()
			return &t
		}
	}
	return nil
}

func (p *Prober) licenses(cl SNMPClient, s *config.SNMP) (model.Check, []model.License, error) {
	var oids []string
	for i := range config.LicenseNames {
		oids = append(oids, fmt.Sprintf("%s.%d.1.0", oidLicenses, i+1), fmt.Sprintf("%s.%d.2.0", oidLicenses, i+1))
	}
	vals, err := cl.Get(oids)
	if err != nil {
		return model.Check{}, nil, err
	}
	now := p.now()
	var list []model.License
	var critical, warning []string
	active := 0
	for i, name := range config.LicenseNames {
		state := enum(licenseStates, vals[oids[2*i]])
		if state == "" {
			continue
		}
		l := model.License{Name: name, Status: state, Expires: text(vals, oids[2*i+1])}
		l.ExpiresAt = parseDate(l.Expires)
		list = append(list, l)
		if has(s.IgnoreLicenses, name) {
			continue
		}
		switch state {
		case "expired":
			critical = append(critical, name+" has expired")
		case "subscribed", "evaluating":
			active++
			if l.ExpiresAt != nil {
				days := int(math.Floor(l.ExpiresAt.Sub(now).Hours() / 24))
				if days < 0 {
					critical = append(critical, name+" expired on "+l.ExpiresAt.Format("2006-01-02"))
				} else if days <= s.LicenseWarnDays {
					warning = append(warning, fmt.Sprintf("%s expires in %s", name, plural(days, "day", "days")))
				}
			}
		}
	}
	sort.Strings(critical)
	sort.Strings(warning)
	c := mk(model.KindSNMP, "snmp/licenses", "Licences", model.HealthOK, plural(active, "subscription", "subscriptions")+" active")
	switch {
	case len(critical) > 0:
		c.Status, c.Message = model.HealthCritical, strings.Join(append(critical, warning...), ", ")
	case len(warning) > 0:
		c.Status, c.Message = model.HealthWarning, strings.Join(warning, ", ")
	}
	return c, list, nil
}
