package graph

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// GroupDef is one device group from the configuration. A device belongs to
// the first group, in the order given, that any of its rules matches.
type GroupDef struct {
	Name string `json:"name" bson:"name"`
	// Hidden groups are left out of the dashboard unless asked for.
	Hidden bool `json:"hidden" bson:"hidden"`
	// CIDRs match the device's last internal IP address (Defender's lastIpAddress).
	CIDRs []string `json:"cidrs" bson:"cidrs,omitempty"`
	// Names are case-insensitive patterns for the computer name, where *
	// matches any run of characters and ? any single one: "gke-*", "*.ec2.internal".
	Names []string `json:"names" bson:"names,omitempty"`
	// NameRegex are regular expressions for the computer name, for what a
	// pattern cannot express. Case-insensitive, unanchored.
	NameRegex []string `json:"nameRegex" bson:"nameRegex,omitempty"`
	// CloudProviders match the cloud Defender reports for the machine: "Azure", "AWS", "GCP".
	CloudProviders []string `json:"cloudProviders" bson:"cloudProviders,omitempty"`
}

type groupRule struct {
	def   GroupDef
	nets  []netip.Prefix
	names []*regexp.Regexp
}

// Grouper assigns devices to groups. A nil Grouper assigns no group.
type Grouper struct {
	rules         []groupRule
	Default       string
	DefaultHidden bool
}

// NewGrouper checks and compiles the group definitions. def names the group
// for devices that match none.
func NewGrouper(defs []GroupDef, def string, defHidden bool) (*Grouper, error) {
	if len(defs) == 0 {
		return nil, nil
	}
	g := &Grouper{Default: def, DefaultHidden: defHidden}
	seen := map[string]bool{strings.ToLower(def): true}
	var errs []error
	for i, d := range defs {
		who := fmt.Sprintf("deviceGroups[%d] (%s)", i, d.Name)
		d.Name = strings.TrimSpace(d.Name)
		switch {
		case d.Name == "":
			errs = append(errs, fmt.Errorf("%s: name is required", who))
		case strings.Contains(d.Name, ",") || strings.EqualFold(d.Name, "all"):
			errs = append(errs, fmt.Errorf("%s: a name cannot contain a comma or be \"all\"", who))
		case seen[strings.ToLower(d.Name)]:
			errs = append(errs, fmt.Errorf("%s: the name is used twice (the default group is %q)", who, def))
		}
		seen[strings.ToLower(d.Name)] = true
		if len(d.CIDRs)+len(d.Names)+len(d.NameRegex)+len(d.CloudProviders) == 0 {
			errs = append(errs, fmt.Errorf("%s: needs at least one of cidrs, names, nameRegex, cloudProviders", who))
		}
		r := groupRule{def: d}
		for _, c := range d.CIDRs {
			p, err := netip.ParsePrefix(strings.TrimSpace(c))
			if err != nil {
				// A bare address is a /32 (or /128).
				if a, e := netip.ParseAddr(strings.TrimSpace(c)); e == nil {
					p, err = netip.PrefixFrom(a, a.BitLen()), nil
				}
			}
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: cidr %q: %v", who, c, err))
				continue
			}
			r.nets = append(r.nets, p.Masked())
		}
		for _, n := range d.Names {
			pattern := regexp.QuoteMeta(strings.TrimSpace(n))
			pattern = strings.ReplaceAll(strings.ReplaceAll(pattern, `\*`, `.*`), `\?`, `.`)
			r.names = append(r.names, regexp.MustCompile(`(?i)^`+pattern+`$`))
		}
		for _, n := range d.NameRegex {
			re, err := regexp.Compile(`(?i)` + n)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: nameRegex %q: %v", who, n, err))
				continue
			}
			r.names = append(r.names, re)
		}
		g.rules = append(g.rules, r)
	}
	return g, errors.Join(errs...)
}

// Group returns the name of the group a device belongs to.
func (g *Grouper) Group(d Device) string {
	if g == nil {
		return ""
	}
	ip, ipErr := netip.ParseAddr(strings.TrimSpace(d.LastIP))
	name := strings.TrimSpace(d.Name)
	for _, r := range g.rules {
		if ipErr == nil {
			for _, n := range r.nets {
				if n.Contains(ip.Unmap()) {
					return r.def.Name
				}
			}
		}
		if name != "" {
			for _, re := range r.names {
				if re.MatchString(name) {
					return r.def.Name
				}
			}
		}
		for _, p := range r.def.CloudProviders {
			if d.CloudProvider != "" && strings.EqualFold(strings.TrimSpace(p), d.CloudProvider) {
				return r.def.Name
			}
		}
	}
	return g.Default
}

// Defs lists every group in order, the default group last.
func (g *Grouper) Defs() []GroupDef {
	if g == nil {
		return nil
	}
	out := make([]GroupDef, 0, len(g.rules)+1)
	for _, r := range g.rules {
		out = append(out, r.def)
	}
	return append(out, GroupDef{Name: g.Default, Hidden: g.DefaultHidden})
}
