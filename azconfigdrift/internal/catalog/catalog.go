// Package catalog lists what az-config-drift reads: modules (one per
// category of settings) and, within each, sources (one API listing each).
// Adding a source is one entry in azure.go or m365.go, or an extraSources
// entry in the configuration.
package catalog

import (
	"fmt"
	"strings"
	"time"

	"github.com/jercle/datafetch/azconfigdrift/internal/config"
	"github.com/jercle/datafetch/azconfigdrift/internal/model"
	"github.com/jercle/datafetch/azconfigdrift/internal/normalize"
)

// Kinds of source.
const (
	// KindARG is an Azure Resource Graph query.
	KindARG = "arg"
	// KindARM is an Azure Resource Manager list or object.
	KindARM = "arm"
	// KindGraph is a Microsoft Graph list or object.
	KindGraph = "graph"
	// KindEXO is an Exchange Online cmdlet, run through the REST endpoint
	// the Exchange Online PowerShell module uses.
	KindEXO = "exo"
	// KindMDE is a list of the Microsoft Defender for Endpoint API, which
	// has an address and permissions of its own.
	KindMDE = "mde"
	// KindSPO is the SharePoint Online admin site's REST API.
	KindSPO = "spo"
	// KindPP is the Power Platform admin API.
	KindPP = "powerplatform"
	// KindPwsh is a cmdlet of a PowerShell module that has no REST API
	// behind it the collector could call: run with pwsh, by an embedded
	// script. Where pwsh or the module is not installed the source is
	// reported as unsupported.
	KindPwsh = "pwsh"
)

// Source is one thing to read in a tenant.
type Source struct {
	ID   string
	Name string
	Kind string

	// Resource Graph: the table, the resource type prefixes to keep and an
	// optional extra condition. Other takes every type no module claims.
	// Query replaces all of that with a query of its own.
	Table string
	Types []string
	Where string
	Other bool
	Query string

	// Resource Manager: {workspace} repeats the source for every Log
	// Analytics workspace that Microsoft Sentinel is enabled on, and stands
	// for the workspace's resource ID.
	// Resource Manager and Graph: the path. {subscriptionId} repeats a
	// Resource Manager path for every subscription; {tenantId} is replaced.
	Path string
	// Beta reads Graph's beta version. Delegated reads as the tenant's
	// service account (user name and password) instead of as the
	// application, for endpoints without application permissions. Both are
	// defaults: the dashboard has a switch for each, per source.
	Beta      bool
	Delegated bool
	// Single: the path returns one object, not a list.
	Single bool
	// Children are lists read per object and stored inside it.
	Children []Child
	// Attach reads another list once and stores each of its objects inside
	// the object of this source it belongs to.
	Attach []Attach
	// Each, for a Resource Manager path with {resource}: the resource
	// types, in lower case, the source is read once for each resource of.
	// {resource} stands for the resource's ID.
	Each []string
	// Method is the HTTP method where it is not GET (Power Platform).
	Method string
	// Script names the embedded PowerShell script of a pwsh source.
	Script string
	// Nest stores the resources of a child type inside their parent
	// resource instead of as objects of their own (Resource Graph).
	Nest []Nest
	// NameFrom is the path of the property an object is named after, when
	// its own name says nothing (a role definition's is a GUID).
	NameFrom string
	// Roles stores the directory and Azure roles assigned to a principal
	// inside it: RolesPrincipal when the object is the principal,
	// RolesApplication when it is an app registration, whose roles are
	// those of its service principal.
	Roles string
	// Principals makes the source one object per principal that has a
	// role, with its roles, instead of reading Path.
	Principals bool
	// Keep limits a Graph list to the objects whose property has (or, with
	// Not, has not) a value.
	Keep *Keep
	// Refs are the properties that hold an identifier to show a name for.
	Refs []Ref
	// Title names the object after what the identifiers at these paths
	// stand for, for objects whose own name says nothing (a role
	// assignment's name is a GUID).
	Title []string

	// Exchange Online: the cmdlet.
	Cmdlet string

	// Type labels the objects when they do not carry a type themselves.
	Type string
	// KeyField names the property that identifies an object (default: id).
	KeyField string
	// Ignore lists volatile properties of this source.
	Ignore []string
	// Permission the service principal needs.
	Permission string
}

// Child is a list read for each object of a source: GET <path>/<id>/<Suffix>.
type Child struct {
	Field  string
	Suffix string
}

// Attach is a Graph list whose objects belong to the objects of a source:
// each is stored under Field of the object whose id equals its By property.
type Attach struct {
	Field string
	Path  string
	By    string
	// Drop lists properties left out of the attached objects.
	Drop []string
	// Permission the list needs. Without it the source is still read, and
	// Field left out.
	Permission string
}

// Nest is a resource type whose resources belong inside their parent: the
// type, in lower case, and the property of the parent they are stored in.
type Nest struct {
	Type  string
	Field string
}

// Values of Source.Roles.
const (
	RolesPrincipal   = "principal"
	RolesApplication = "application"
)

// RoleRefs are the identifiers in the roles stored inside a principal.
var RoleRefs = []Ref{
	{Path: "directoryRoles.*.roleDefinitionId", Kind: RefEntraRole},
	{Path: "azureRoles.*.roleDefinitionId", Kind: RefAzureRole},
	{Path: "azureRoles.*.scope", Kind: RefAzureScope},
}

// Keep is a condition on a property of a Graph object.
type Keep struct {
	Field string
	Value string
	Not   bool
}

// Kinds of identifier a Ref can hold.
const (
	// RefPrincipal: the object ID of a user, group, service principal or device.
	RefPrincipal = "principal"
	// RefAzureRole: the resource ID of an Azure role definition.
	RefAzureRole = "azure-role"
	// RefEntraRole: the ID of an Entra ID role definition.
	RefEntraRole = "entra-role"
	// RefAzureScope: an Azure scope; a subscription's is named.
	RefAzureScope = "azure-scope"
)

// Ref is a property holding an identifier. Path is from the top of the
// object, with "*" for every element of a list.
type Ref struct {
	Path string
	Kind string
}

// Module is one category of settings.
type Module struct {
	ID             string
	Platform       string
	Name           string
	Description    string
	DefaultEnabled bool
	Sources        []Source
}

// Reads describes where a source's settings come from.
func (s Source) Reads() string {
	switch s.Kind {
	case KindARG:
		switch {
		case s.Query != "":
			return "Resource Graph query"
		case s.Other:
			return "Resource Graph: every resource type no other module reads"
		case len(s.Types) == 0:
			return "Resource Graph: " + s.Table
		}
		return "Resource Graph: " + s.Table + " (" + strings.Join(s.Types, ", ") + ")"
	case KindARM:
		path, _, _ := strings.Cut(s.Path, "?")
		return "Resource Manager: " + path
	case KindGraph:
		// The version is a switch in the dashboard, so it is not named here.
		path, _, _ := strings.Cut(s.Path, "?")
		return "Microsoft Graph: " + path
	case KindEXO:
		return "Exchange Online: " + s.Cmdlet
	case KindMDE:
		path, _, _ := strings.Cut(s.Path, "?")
		return "Defender for Endpoint API: " + path
	case KindSPO:
		return "SharePoint admin site: " + s.Path
	case KindPP:
		path, _, _ := strings.Cut(s.Path, "?")
		return "Power Platform admin API: " + path
	case KindPwsh:
		return "PowerShell (" + s.Script + "): " + s.Cmdlet
	}
	return s.Kind
}

// Doc is the module as stored in acd_modules.
func (m Module) Doc(order int, version string, now time.Time) model.Module {
	d := model.Module{
		ID: m.ID, Platform: m.Platform, Name: m.Name, Description: m.Description,
		Order: order, DefaultEnabled: m.DefaultEnabled, Version: version, UpdatedAt: now,
	}
	for _, s := range m.Sources {
		d.Sources = append(d.Sources, model.ModuleSource{ID: s.ID, Name: s.Name, Kind: s.Kind, Reads: s.Reads(), Permission: s.Permission, Beta: s.Beta, Delegated: s.Delegated})
	}
	return d
}

// Build returns the built-in modules with the configuration applied:
// module defaults and extra sources.
func Build(cfg *config.Config) ([]Module, error) {
	mods := append(azureModules(), m365Modules()...)
	index := map[string]int{}
	for i, m := range mods {
		index[m.ID] = i
	}
	for _, x := range cfg.ExtraSources {
		src := Source{
			ID: x.ID, Name: x.Name, Kind: x.Kind, Query: x.Query, Path: x.Path, Beta: x.Beta, Delegated: x.Delegated, Single: x.Single,
			Type: x.Type, KeyField: x.KeyField, Permission: x.Permission, Table: "resources",
		}
		if src.Type == "" {
			src.Type = x.ID
		}
		i, ok := index[x.Module]
		if !ok {
			platform := model.PlatformAzure
			if x.Kind == KindGraph {
				platform = model.PlatformM365
			}
			name := x.ModuleName
			if name == "" {
				name = x.Module
			}
			mods = append(mods, Module{ID: x.Module, Platform: platform, Name: name, Description: "Sources defined in the configuration file.", DefaultEnabled: true})
			i = len(mods) - 1
			index[x.Module] = i
		}
		if (x.Kind == KindGraph) != (mods[i].Platform == model.PlatformM365) {
			return nil, fmt.Errorf("config: extra source %s/%s: a %s source cannot go in a %s module", x.Module, x.ID, x.Kind, mods[i].Platform)
		}
		for _, s := range mods[i].Sources {
			if s.ID == x.ID {
				return nil, fmt.Errorf("config: extra source %s/%s: the module already has a source of that id", x.Module, x.ID)
			}
		}
		mods[i].Sources = append(mods[i].Sources, src)
	}
	for id, enabled := range cfg.ModuleDefaults {
		i, ok := index[id]
		if !ok {
			return nil, fmt.Errorf("config: moduleDefaults: there is no module %q", id)
		}
		mods[i].DefaultEnabled = enabled
	}
	return mods, nil
}

// ClaimedTypes returns the resource type prefixes that sources reading the
// Resource Graph "resources" table take. The catch-all source reads the
// rest. Switched-off modules still claim their types.
func ClaimedTypes(mods []Module) []string {
	var out []string
	for _, m := range mods {
		for _, s := range m.Sources {
			if s.Kind == KindARG && s.Table == "resources" && !s.Other && s.Query == "" {
				out = append(out, s.Types...)
			}
		}
	}
	return out
}

// globalIgnore: properties that change without anybody changing a setting.
var globalIgnore = []string{
	"etag", "systemData", "provisioningState",
	"lastModifiedDateTime", "modifiedDateTime", "lastModifiedTime", "lastModifiedTimeUtc", "lastModifiedAt", "lastUpdatedDateTime",
	"whenChanged", "whenChangedUTC", "originatingServer", "objectState",
	"earliestRestoreDate", "pausedDate", "resumedDate", "quotaNextResetTime",
	"currentOrchestratorVersion", "nodeImageVersion",
	"onPremisesLastSyncDateTime", "onPremisesLastPasswordSyncDateTime",
}

// typeIgnore: volatile properties of single Azure resource types.
var typeIgnore = []struct {
	Prefix string
	Paths  []string
}{
	{"microsoft.compute/virtualmachines", []string{"properties.extended"}},
	{"microsoft.compute/disks", []string{"properties.diskState", "properties.lastOwnershipUpdateTime"}},
	{"microsoft.containerservice/managedclusters", []string{"properties.powerState", "properties.currentKubernetesVersion"}},
	{"microsoft.web/sites", []string{"properties.state", "properties.usageState", "properties.availabilityState"}},
	{"microsoft.operationalinsights/workspaces", []string{"properties.modifiedDate"}},
	{"microsoft.storage/storageaccounts", []string{"properties.statusOfPrimary", "properties.statusOfSecondary"}},
	{"microsoft.sql/servers/databases", []string{"properties.status"}},
	{"microsoft.network/expressroutecircuits", []string{"properties.serviceProviderProvisioningState", "properties.circuitProvisioningState"}},
	{"microsoft.network/virtualnetworkgateways", []string{"properties.bgpSettings.bgpPeeringAddresses"}},
}

// Ignore decides which properties are left out of an item.
type Ignore struct {
	global *normalize.Rules
	custom []config.IgnoreRule
	cache  map[string]*normalize.Rules
}

func NewIgnore(cfg *config.Config) *Ignore {
	return &Ignore{global: normalize.NewRules(globalIgnore...), custom: cfg.Ignore, cache: map[string]*normalize.Rules{}}
}

// For returns the rules for items of one type from one source. Not safe for
// concurrent use: make one Ignore per goroutine, or call under a lock.
func (g *Ignore) For(module string, src Source, itemType string) *normalize.Rules {
	key := module + "\x00" + src.ID + "\x00" + itemType
	if r, ok := g.cache[key]; ok {
		return r
	}
	r := g.global.Merge(normalize.NewRules(src.Ignore...))
	for _, t := range typeIgnore {
		if strings.HasPrefix(itemType, t.Prefix) {
			r.Add(t.Paths...)
		}
	}
	for _, c := range g.custom {
		if (c.Module == "" || c.Module == module) && (c.Source == "" || c.Source == src.ID) && (c.Type == "" || strings.HasPrefix(itemType, c.Type)) {
			r.Add(c.Paths...)
		}
	}
	g.cache[key] = r
	return r
}
