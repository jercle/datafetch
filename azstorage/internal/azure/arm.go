package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Subscription is one subscription the service principal can see.
type Subscription struct {
	ID    string `json:"subscriptionId"`
	Name  string `json:"displayName"`
	State string `json:"state"`
}

// Subscriptions lists every subscription the principal can read.
func (c *Client) Subscriptions(ctx context.Context) ([]Subscription, error) {
	var all []Subscription
	u := c.arm("/subscriptions?api-version=2022-12-01")
	for u != "" {
		var out struct {
			Value    []Subscription `json:"value"`
			NextLink string         `json:"nextLink"`
		}
		if err := c.do(ctx, http.MethodGet, u, nil, &out); err != nil {
			return nil, err
		}
		for _, s := range out.Value {
			s.ID = strings.ToLower(s.ID)
			all = append(all, s)
		}
		u = out.NextLink
	}
	return all, nil
}

// Row is one Resource Graph row, as the queries below project it.
type Row struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Kind           string   `json:"kind"`
	Location       string   `json:"location"`
	ResourceGroup  string   `json:"resourceGroup"`
	SubscriptionID string   `json:"subscriptionId"`
	Tags           Tags     `json:"tags"`
	ManagedBy      string   `json:"managedBy"`
	Zones          []string `json:"zones"`
	Sku            struct {
		Name string `json:"name"`
		Tier string `json:"tier"`
	} `json:"sku"`
	// Properties is decoded by AccountProperties or DiskProperties.
	Properties json.RawMessage `json:"properties"`
}

// AccountProperties is what the collector uses of a storage account.
type AccountProperties struct {
	AccessTier            string     `json:"accessTier"`
	HNS                   bool       `json:"isHnsEnabled"`
	CreationTime          *time.Time `json:"creationTime"`
	AllowBlobPublicAccess *bool      `json:"allowBlobPublicAccess"`
	MinimumTLSVersion     string     `json:"minimumTlsVersion"`
	PublicNetworkAccess   string     `json:"publicNetworkAccess"`
	NetworkACLs           struct {
		DefaultAction string `json:"defaultAction"`
	} `json:"networkAcls"`
	PrimaryEndpoints struct {
		Blob string `json:"blob"`
	} `json:"primaryEndpoints"`
}

// DiskProperties is what the collector uses of a managed disk.
type DiskProperties struct {
	SizeGB        int64      `json:"diskSizeGB"`
	SizeBytes     int64      `json:"diskSizeBytes"`
	State         string     `json:"diskState"`
	OSType        string     `json:"osType"`
	TimeCreated   *time.Time `json:"timeCreated"`
	IOPS          int64      `json:"diskIOPSReadWrite"`
	MBps          int64      `json:"diskMBpsReadWrite"`
	Tier          string     `json:"tier"`
	NetworkAccess string     `json:"networkAccessPolicy"`
	OwnershipTime *time.Time `json:"LastOwnershipUpdateTime"`
	Encryption    struct {
		Type string `json:"type"`
	} `json:"encryption"`
	CreationData struct {
		CreateOption string `json:"createOption"`
	} `json:"creationData"`
}

// Tags tolerates what Resource Graph returns for tags: an object, null, or
// (for values) something other than a string.
type Tags map[string]string

func (t *Tags) UnmarshalJSON(b []byte) error {
	var raw map[string]any
	if json.Unmarshal(b, &raw) != nil || len(raw) == 0 {
		*t = nil
		return nil
	}
	out := make(Tags, len(raw))
	for k, v := range raw {
		switch s := v.(type) {
		case string:
			out[k] = s
		case nil:
			out[k] = ""
		default:
			out[k] = fmt.Sprint(s)
		}
	}
	*t = out
	return nil
}

// The Resource Graph queries. Each is ordered by id, which paging needs.
const (
	QueryAccounts = `resources
| where type =~ 'microsoft.storage/storageaccounts'
| project id, name, kind, location, resourceGroup, subscriptionId, tags, sku, properties
| order by id asc`

	QueryDisks = `resources
| where type =~ 'microsoft.compute/disks'
| project id, name, location, resourceGroup, subscriptionId, tags, sku, managedBy, zones, properties
| order by id asc`
)

// subscriptionsPerQuery keeps each Resource Graph request well inside its
// limit on subscriptions.
const subscriptionsPerQuery = 200

// ResourceGraph runs a query over the given subscriptions and calls each
// with one page of rows at a time.
func (c *Client) ResourceGraph(ctx context.Context, query string, subscriptions []string, each func([]Row) error) error {
	u := c.arm("/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01")
	for len(subscriptions) > 0 {
		n := min(subscriptionsPerQuery, len(subscriptions))
		subs := subscriptions[:n]
		subscriptions = subscriptions[n:]
		skip := ""
		for {
			opts := map[string]any{"resultFormat": "objectArray", "$top": 1000}
			if skip != "" {
				opts["$skipToken"] = skip
			}
			body, _ := json.Marshal(map[string]any{"query": query, "subscriptions": subs, "options": opts})
			var out struct {
				Data      []Row  `json:"data"`
				SkipToken string `json:"$skipToken"`
			}
			if err := c.do(ctx, http.MethodPost, u, body, &out); err != nil {
				return err
			}
			if err := each(out.Data); err != nil {
				return err
			}
			if out.SkipToken == "" || len(out.Data) == 0 {
				break
			}
			skip = out.SkipToken
		}
	}
	return nil
}

// BlobContainer is one container, as Azure Resource Manager lists it.
type BlobContainer struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Properties struct {
		PublicAccess    string     `json:"publicAccess"`
		LeaseState      string     `json:"leaseState"`
		LastModified    *time.Time `json:"lastModifiedTime"`
		ImmutablePolicy bool       `json:"hasImmutabilityPolicy"`
		LegalHold       bool       `json:"hasLegalHold"`
	} `json:"properties"`
}

// Containers lists a storage account's blob containers through Azure
// Resource Manager, which needs only Reader.
func (c *Client) Containers(ctx context.Context, accountID string) ([]BlobContainer, error) {
	var all []BlobContainer
	u := c.arm(accountID + "/blobServices/default/containers?api-version=2023-05-01")
	for u != "" {
		var out struct {
			Value    []BlobContainer `json:"value"`
			NextLink string          `json:"nextLink"`
		}
		if err := c.do(ctx, http.MethodGet, u, nil, &out); err != nil {
			return nil, err
		}
		all = append(all, out.Value...)
		u = out.NextLink
	}
	return all, nil
}

// Usage is a storage account's capacity, from Azure Monitor. A nil field
// was not asked for or had no value.
type Usage struct {
	UsedBytes  *int64
	BlobBytes  *int64
	FileBytes  *int64
	TableBytes *int64
	QueueBytes *int64
	BlobCount  *int64
	FileShares *int64
	// At is the time of the account's value.
	At *time.Time
}

// metricsSpan is how far back the latest value is looked for. Azure
// refreshes capacity metrics about daily.
const metricsSpan = 48 * time.Hour

// AccountUsage reads the capacity metrics of a storage account. With
// services, it also reads blob, file, table and queue capacity, for the
// services that kind of account has. An error is returned only when the
// account's own value could not be read; a service that fails is left nil
// and reported in warn.
func (c *Client) AccountUsage(ctx context.Context, accountID, kind string, services bool) (u Usage, warn error, err error) {
	vals, at, err := c.metrics(ctx, accountID, "UsedCapacity")
	if err != nil {
		return u, nil, err
	}
	u.UsedBytes, u.At = vals["usedcapacity"], at
	if !services {
		return u, nil, nil
	}
	type service struct {
		path, names string
		set         func(map[string]*int64)
	}
	blob := service{"/blobServices/default", "BlobCapacity,BlobCount", func(m map[string]*int64) { u.BlobBytes, u.BlobCount = m["blobcapacity"], m["blobcount"] }}
	file := service{"/fileServices/default", "FileCapacity,FileShareCount", func(m map[string]*int64) { u.FileBytes, u.FileShares = m["filecapacity"], m["filesharecount"] }}
	table := service{"/tableServices/default", "TableCapacity", func(m map[string]*int64) { u.TableBytes = m["tablecapacity"] }}
	queue := service{"/queueServices/default", "QueueCapacity", func(m map[string]*int64) { u.QueueBytes = m["queuecapacity"] }}
	var list []service
	switch strings.ToLower(kind) {
	case "blobstorage", "blockblobstorage":
		list = []service{blob}
	case "filestorage":
		list = []service{file}
	default:
		list = []service{blob, file, table, queue}
	}
	for _, s := range list {
		vals, _, e := c.metrics(ctx, accountID+s.path, s.names)
		if e != nil {
			if ctx.Err() != nil {
				return u, nil, ctx.Err()
			}
			if warn == nil {
				warn = e
			}
			continue
		}
		s.set(vals)
	}
	return u, warn, nil
}

// metrics returns the latest hourly average of each named metric of a
// resource, keyed by lower-case metric name, and the time of the newest.
func (c *Client) metrics(ctx context.Context, resourceID, names string) (map[string]*int64, *time.Time, error) {
	end := c.Now().UTC().Truncate(time.Minute)
	q := url.Values{
		"api-version": {"2023-10-01"},
		"metricnames": {names},
		"aggregation": {"Average"},
		"interval":    {"PT1H"},
		"timespan":    {end.Add(-metricsSpan).Format(time.RFC3339) + "/" + end.Format(time.RFC3339)},
	}
	var out struct {
		Value []struct {
			Name struct {
				Value string `json:"value"`
			} `json:"name"`
			Timeseries []struct {
				Data []struct {
					TimeStamp time.Time `json:"timeStamp"`
					Average   *float64  `json:"average"`
				} `json:"data"`
			} `json:"timeseries"`
		} `json:"value"`
	}
	if err := c.do(ctx, http.MethodGet, c.arm(resourceID+"/providers/Microsoft.Insights/metrics?"+q.Encode()), nil, &out); err != nil {
		return nil, nil, err
	}
	vals := map[string]*int64{}
	var newest *time.Time
	for _, m := range out.Value {
		for _, ts := range m.Timeseries {
			for i := len(ts.Data) - 1; i >= 0; i-- {
				d := ts.Data[i]
				if d.Average == nil {
					continue
				}
				v := int64(*d.Average + 0.5)
				vals[strings.ToLower(m.Name.Value)] = &v
				if newest == nil || d.TimeStamp.After(*newest) {
					t := d.TimeStamp
					newest = &t
				}
				break
			}
		}
	}
	return vals, newest, nil
}
