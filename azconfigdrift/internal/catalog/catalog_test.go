package catalog

import (
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jercle/datafetch/azconfigdrift/internal/config"
	"github.com/jercle/datafetch/azconfigdrift/internal/model"
)

var slug = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

func TestCatalogueIsWellFormed(t *testing.T) {
	mods, err := Build(&config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	sources, other := 0, 0
	for _, m := range mods {
		if !slug.MatchString(m.ID) || ids[m.ID] || m.Name == "" || m.Description == "" {
			t.Errorf("module %q: bad or repeated id, or no name", m.ID)
		}
		ids[m.ID] = true
		if m.Platform != model.PlatformAzure && m.Platform != model.PlatformM365 {
			t.Errorf("%s: platform %q", m.ID, m.Platform)
		}
		seen := map[string]bool{}
		for _, s := range m.Sources {
			sources++
			where := m.ID + "/" + s.ID
			if !slug.MatchString(s.ID) || seen[s.ID] || s.Name == "" || s.Permission == "" {
				t.Errorf("%s: bad or repeated id, no name or no permission", where)
			}
			seen[s.ID] = true
			switch s.Kind {
			case KindARG:
				if s.Table == "" || m.Platform != model.PlatformAzure {
					t.Errorf("%s: arg source", where)
				}
				if s.Other {
					other++
				}
				for _, p := range s.Types {
					if p != strings.ToLower(p) || !strings.HasPrefix(p, "microsoft.") {
						t.Errorf("%s: type prefix %q", where, p)
					}
				}
			case KindARM:
				if strings.Contains(s.Path, "{resource}") != (len(s.Each) > 0) {
					t.Errorf("%s: {resource} goes with Each", where)
				}
				if !(strings.HasPrefix(s.Path, "/") || strings.HasPrefix(s.Path, "{workspace}/") || strings.HasPrefix(s.Path, "{resource}/")) || !strings.Contains(s.Path, "api-version=") || m.Platform != model.PlatformAzure {
					t.Errorf("%s: arm source", where)
				}
			case KindGraph:
				if !strings.HasPrefix(s.Path, "/") || s.Type == "" || m.Platform != model.PlatformM365 {
					t.Errorf("%s: graph source", where)
				}
				if len(s.Children) > 0 && s.Single {
					t.Errorf("%s: children on a single object", where)
				}
			case KindEXO:
				if !strings.HasPrefix(s.Cmdlet, "Get-") || s.KeyField == "" {
					t.Errorf("%s: exo source", where)
				}
			case KindSPO, KindPP:
				if !strings.HasPrefix(s.Path, "/") || s.Type == "" || m.Platform != model.PlatformM365 {
					t.Errorf("%s: %s source", where, s.Kind)
				}
			case KindPwsh:
				if !strings.HasPrefix(s.Cmdlet, "Get-") || s.Script == "" || s.KeyField == "" || m.Platform != model.PlatformM365 {
					t.Errorf("%s: pwsh source", where)
				}
			case KindMDE:
				if !strings.HasPrefix(s.Path, "/api/") || s.Type == "" || m.Platform != model.PlatformM365 {
					t.Errorf("%s: mde source", where)
				}
			default:
				t.Errorf("%s: kind %q", where, s.Kind)
			}
			if s.Reads() == "" || s.Reads() == s.Kind {
				t.Errorf("%s: no description of what it reads", where)
			}
		}
	}
	if other != 1 || sources < 100 {
		t.Errorf("%d catch-all sources, %d sources", other, sources)
	}
	// No resource type is claimed twice, and none is a prefix of another.
	claimed := ClaimedTypes(mods)
	for i, a := range claimed {
		for j, b := range claimed {
			if i != j && strings.HasPrefix(a, b) {
				t.Errorf("type prefixes overlap: %q and %q", a, b)
			}
		}
	}
	d := mods[0].Doc(3, "v1", time.Unix(0, 0))
	if d.ID != "azure-governance" || d.Order != 3 || len(d.Sources) != len(mods[0].Sources) || !strings.HasPrefix(d.Sources[0].Reads, "Resource Graph: resourcecontainers") {
		t.Errorf("doc: %+v", d)
	}
}

func TestBuildAppliesConfiguration(t *testing.T) {
	cfg := &config.Config{
		ModuleDefaults: map[string]bool{"m365-exchange": true, "azure-other": false},
		ExtraSources: []config.ExtraSource{
			{Module: "azure-governance", ID: "exports", Name: "Cost exports", Kind: "arm", Path: "/subscriptions/{subscriptionId}/providers/Microsoft.CostManagement/exports?api-version=2023-08-01"},
			{Module: "custom", ModuleName: "Custom", ID: "flows", Name: "Flows", Kind: "graph", Path: "/identity/b2xUserFlows"},
		},
	}
	mods, err := Build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]Module{}
	for _, m := range mods {
		by[m.ID] = m
	}
	if !by["m365-exchange"].DefaultEnabled || by["azure-other"].DefaultEnabled || !by["azure-network"].DefaultEnabled || by["m365-groups"].DefaultEnabled {
		t.Error("module defaults")
	}
	g := by["azure-governance"].Sources
	if g[len(g)-1].ID != "exports" || g[len(g)-1].Type != "exports" {
		t.Errorf("extra arm source: %+v", g[len(g)-1])
	}
	if c := by["custom"]; c.Platform != model.PlatformM365 || c.Name != "Custom" || len(c.Sources) != 1 || !c.DefaultEnabled {
		t.Errorf("custom module: %+v", c)
	}
	for _, bad := range []*config.Config{
		{ModuleDefaults: map[string]bool{"nope": true}},
		{ExtraSources: []config.ExtraSource{{Module: "azure-network", ID: "x", Kind: "graph", Path: "/x"}}},
		{ExtraSources: []config.ExtraSource{{Module: "azure-network", ID: "resources", Kind: "arg", Query: "resources"}}},
	} {
		if _, err := Build(bad); err == nil {
			t.Errorf("expected an error for %+v", bad)
		}
	}
}

func TestIgnoreRules(t *testing.T) {
	g := NewIgnore(&config.Config{Ignore: []config.IgnoreRule{
		{Type: "microsoft.web/sites", Paths: []string{"properties.outboundIpAddresses"}},
		{Module: "m365-identity", Source: "domains", Paths: []string{"state"}},
	}})
	src := Source{ID: "resources", Ignore: []string{"sourceOnly"}}
	if r := g.For("azure-apps", src, "microsoft.web/sites/slots"); r != g.For("azure-apps", src, "microsoft.web/sites/slots") {
		t.Error("rules are not cached")
	}
	if g.For("azure-apps", src, "microsoft.web/sites") == g.For("azure-apps", src, "microsoft.web/serverfarms") {
		t.Error("types share rules")
	}
}

// The Terraform file in deploy/ must grant every Graph permission the
// built-in modules need, and nothing they do not.
func TestTerraformGrantsWhatTheCatalogueNeeds(t *testing.T) {
	b, err := os.ReadFile("../../deploy/terraform/permissions.tf")
	if err != nil {
		t.Fatal(err)
	}
	tf := string(b)
	listed := func(variable string) map[string]bool {
		_, list, _ := strings.Cut(tf, `variable "`+variable+`"`)
		list, _, _ = strings.Cut(list, "\n}\n")
		out := map[string]bool{}
		for _, m := range regexp.MustCompile(`(?m)^\s+"([A-Za-z0-9.-]+)",$`).FindAllStringSubmatch(list, -1) {
			out[m[1]] = true
		}
		return out
	}
	granted := listed("graph_permissions")
	needed, delegated := map[string]bool{}, map[string]bool{}
	mods, _ := Build(&config.Config{})
	for _, m := range mods {
		for _, s := range m.Sources {
			switch {
			case s.Kind != KindGraph:
			case s.Delegated:
				delegated[s.Permission] = true
			default:
				needed[s.Permission] = true
			}
		}
	}
	// Sources read as the service account by default need theirs delegated.
	if got := listed("delegated_permissions"); len(delegated) == 0 || len(got) != len(delegated) {
		t.Errorf("delegated permissions: the file grants %v, the catalogue needs %v", got, delegated)
	} else {
		for p := range delegated {
			if !got[p] {
				t.Errorf("the Terraform file does not grant %s as a delegated permission", p)
			}
		}
	}
	for p := range needed {
		if !granted[p] {
			t.Errorf("the Terraform file does not grant %s", p)
		}
	}
	for p := range granted {
		if !needed[p] {
			t.Errorf("the Terraform file grants %s, which no source needs", p)
		}
	}
	if len(needed) < 25 {
		t.Errorf("only %d permissions found", len(needed))
	}
}
