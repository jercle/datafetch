package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jercle/datafetch/azurecves/pkg/graph"
)

// ---- Azure Resource Graph ----

const (
	// QueryContainers returns subscriptions and resource groups.
	QueryContainers = `resourcecontainers
| where type in~ ('microsoft.resources/subscriptions', 'microsoft.resources/subscriptions/resourcegroups')
| project id, name, type, location, resourceGroup, subscriptionId, tenantId, tags, properties
| order by id asc`
	// QueryResources returns every resource the principal can read.
	QueryResources = `resources
| project id, name, type, kind, location, resourceGroup, subscriptionId, tenantId, tags, sku, managedBy, properties
| order by id asc`
)

// QueryContainerFindings returns Defender for Cloud's individual
// vulnerability recommendations for registry images and running containers.
const QueryContainerFindings = `securityresources
| where type == 'microsoft.security/assessments'
| where properties.metadata.recommendationCategory == 'SoftwareUpdate'
| where properties.resourceDetails.ResourceType in~ ('.containerimage', 'K8s-container')
| where properties.status.code =~ 'Unhealthy'
| project id, name, subscriptionId, resourceGroup, tenantId, properties
| order by id asc`

// ResourceGraph runs a query across every subscription the principal can
// read in its tenant and calls each with one page of rows at a time.
func (c *Client) ResourceGraph(ctx context.Context, query string, each func([]graph.Resource) error) error {
	return resourceGraph(ctx, c, query, each)
}

// Row is an untyped Resource Graph row.
type Row struct {
	ID         string         `json:"id"`
	Properties map[string]any `json:"properties"`
}

// ResourceGraphRows is ResourceGraph for tables other than resources.
func (c *Client) ResourceGraphRows(ctx context.Context, query string, each func([]Row) error) error {
	return resourceGraph(ctx, c, query, each)
}

func resourceGraph[T any](ctx context.Context, c *Client, query string, each func([]T) error) error {
	u := strings.TrimRight(c.Endpoints.ARM, "/") + "/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01"
	skip := ""
	for {
		opts := map[string]any{"resultFormat": "objectArray", "$top": 1000}
		if skip != "" {
			opts["$skipToken"] = skip
		}
		body, _ := json.Marshal(map[string]any{"query": query, "options": opts})
		var out struct {
			Data      []T    `json:"data"`
			SkipToken string `json:"$skipToken"`
		}
		if err := c.do(ctx, http.MethodPost, u, c.Endpoints.ARMScope, body, &out); err != nil {
			return err
		}
		if err := each(out.Data); err != nil {
			return err
		}
		if out.SkipToken == "" || len(out.Data) == 0 {
			return nil
		}
		skip = out.SkipToken
	}
}

// ---- Defender for Endpoint ----

// Time parses the timestamp formats the Defender APIs use; unparseable or
// empty values become the zero time rather than failing a whole page.
type Time struct{ time.Time }

var timeLayouts = []string{time.RFC3339Nano, "2006-01-02 15:04:05.9999999", "2006-01-02T15:04:05.9999999", "2006-01-02"}

func (t *Time) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) != nil || s == "" {
		return nil
	}
	for _, l := range timeLayouts {
		if v, err := time.Parse(l, s); err == nil {
			t.Time = v.UTC()
			return nil
		}
	}
	return nil
}

// Machine is a device from GET /api/machines.
type Machine struct {
	ID                    string   `json:"id"`
	ComputerDNSName       string   `json:"computerDnsName"`
	OSPlatform            string   `json:"osPlatform"`
	Version               string   `json:"version"`
	OSBuild               int64    `json:"osBuild"`
	HealthStatus          string   `json:"healthStatus"`
	OnboardingStatus      string   `json:"onboardingStatus"`
	RiskScore             string   `json:"riskScore"`
	ExposureLevel         string   `json:"exposureLevel"`
	LastSeen              Time     `json:"lastSeen"`
	FirstSeen             Time     `json:"firstSeen"`
	LastIPAddress         string   `json:"lastIpAddress"`
	LastExternalIPAddress string   `json:"lastExternalIpAddress"`
	AADDeviceID           string   `json:"aadDeviceId"`
	RbacGroupName         string   `json:"rbacGroupName"`
	MachineTags           []string `json:"machineTags"`
	VMMetadata            *struct {
		VMID           string `json:"vmId"`
		ResourceID     string `json:"resourceId"`
		SubscriptionID string `json:"subscriptionId"`
		CloudProvider  string `json:"cloudProvider"`
	} `json:"vmMetadata"`
}

// SoftwareVuln is one row of the software vulnerabilities export: a CVE on a
// device, for one software version.
type SoftwareVuln struct {
	DeviceID                    string  `json:"deviceId"`
	DeviceName                  string  `json:"deviceName"`
	SoftwareVendor              string  `json:"softwareVendor"`
	SoftwareName                string  `json:"softwareName"`
	SoftwareVersion             string  `json:"softwareVersion"`
	CveID                       string  `json:"cveId"`
	VulnerabilitySeverityLevel  string  `json:"vulnerabilitySeverityLevel"`
	CvssScore                   float64 `json:"cvssScore"`
	ExploitabilityLevel         string  `json:"exploitabilityLevel"`
	RecommendedSecurityUpdate   string  `json:"recommendedSecurityUpdate"`
	RecommendedSecurityUpdateID string  `json:"recommendedSecurityUpdateId"`
	SecurityUpdateAvailable     bool    `json:"securityUpdateAvailable"`
	FirstSeenTimestamp          Time    `json:"firstSeenTimestamp"`
	LastSeenTimestamp           Time    `json:"lastSeenTimestamp"`
}

// SoftwareInv is one row of the software inventory export.
type SoftwareInv struct {
	DeviceID                   string   `json:"deviceId"`
	DeviceName                 string   `json:"deviceName"`
	SoftwareVendor             string   `json:"softwareVendor"`
	SoftwareName               string   `json:"softwareName"`
	SoftwareVersion            string   `json:"softwareVersion"`
	NumberOfWeaknesses         int      `json:"numberOfWeaknesses"`
	DiskPaths                  []string `json:"diskPaths"`
	SoftwareFirstSeenTimestamp Time     `json:"softwareFirstSeenTimestamp"`
	EndOfSupportStatus         string   `json:"endOfSupportStatus"`
	EndOfSupportDate           Time     `json:"endOfSupportDate"`
}

// Vulnerability is a CVE catalogue entry from GET /api/Vulnerabilities.
type Vulnerability struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Description     string   `json:"description"`
	Severity        string   `json:"severity"`
	CvssV3          float64  `json:"cvssV3"`
	CvssVector      string   `json:"cvssVector"`
	ExposedMachines int      `json:"exposedMachines"`
	PublishedOn     Time     `json:"publishedOn"`
	UpdatedOn       Time     `json:"updatedOn"`
	PublicExploit   bool     `json:"publicExploit"`
	ExploitVerified bool     `json:"exploitVerified"`
	ExploitInKit    bool     `json:"exploitInKit"`
	ExploitTypes    []string `json:"exploitTypes"`
	Epss            float64  `json:"epss"`
}

// odata follows @odata.nextLink from first until the collection is exhausted.
func odata[T any](ctx context.Context, c *Client, first string, each func([]T) error) error {
	next := first
	for next != "" {
		var out struct {
			Value    []T    `json:"value"`
			NextLink string `json:"@odata.nextLink"`
		}
		if err := c.do(ctx, http.MethodGet, next, c.Endpoints.DefenderScope, nil, &out); err != nil {
			return err
		}
		if err := each(out.Value); err != nil {
			return err
		}
		if len(out.Value) == 0 {
			return nil
		}
		next = out.NextLink
	}
	return nil
}

func (c *Client) defender(path string) string {
	return strings.TrimRight(c.Endpoints.Defender, "/") + path
}

func (c *Client) Machines(ctx context.Context, each func([]Machine) error) error {
	return odata(ctx, c, c.defender("/api/machines"), each)
}

func (c *Client) SoftwareVulnerabilities(ctx context.Context, pageSize int, each func([]SoftwareVuln) error) error {
	return odata(ctx, c, c.defender(fmt.Sprintf("/api/machines/SoftwareVulnerabilitiesByMachine?pageSize=%d", pageSize)), each)
}

func (c *Client) SoftwareInventory(ctx context.Context, pageSize int, each func([]SoftwareInv) error) error {
	return odata(ctx, c, c.defender(fmt.Sprintf("/api/machines/SoftwareInventoryByMachine?pageSize=%d", pageSize)), each)
}

// Vulnerabilities pages through the whole CVE catalogue. The API has no
// nextLink for this collection on every deployment, so it pages with $skip.
func (c *Client) Vulnerabilities(ctx context.Context, each func([]Vulnerability) error) error {
	const top = 8000
	for skip := 0; ; skip += top {
		var out struct {
			Value []Vulnerability `json:"value"`
		}
		u := c.defender(fmt.Sprintf("/api/Vulnerabilities?$top=%d&$skip=%d", top, skip))
		if err := c.do(ctx, http.MethodGet, u, c.Endpoints.DefenderScope, nil, &out); err != nil {
			return err
		}
		if err := each(out.Value); err != nil {
			return err
		}
		if len(out.Value) < top {
			return nil
		}
	}
}
