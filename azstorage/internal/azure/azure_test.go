package azure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jercle/datafetch/azstorage/internal/config"
)

const account = "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/stapp"

// fake serves Entra ID, Azure Resource Manager and a blob endpoint from one
// test server.
type fake struct {
	t      *testing.T
	srv    *httptest.Server
	tokens atomic.Int64
	scopes []string
	mux    *http.ServeMux
}

func newFake(t *testing.T) (*fake, *Client) {
	f := &fake{t: t, mux: http.NewServeMux()}
	f.mux.HandleFunc("POST /tenant-1/oauth2/v2.0/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("client_id") != "client" || r.Form.Get("client_secret") != "secret" || r.Form.Get("grant_type") != "client_credentials" {
			w.WriteHeader(401)
			fmt.Fprint(w, `{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret.\nTrace ID: x"}`)
			return
		}
		f.scopes = append(f.scopes, r.Form.Get("scope"))
		fmt.Fprintf(w, `{"access_token":"tok-%d","expires_in":3600}`, f.tokens.Add(1))
	})
	f.srv = httptest.NewServer(f.mux)
	t.Cleanup(f.srv.Close)
	c := NewClient(config.Tenant{ID: "tenant-1", ClientID: "client", ClientSecret: "secret"}, nil)
	c.Endpoints = config.Endpoints{Authority: f.srv.URL, ARM: f.srv.URL, ARMScope: "arm/.default", StorageScope: "storage/.default"}
	c.HTTP, c.Data = f.srv.Client(), f.srv.Client()
	c.Backoff = time.Millisecond
	c.Now = func() time.Time { return time.Date(2026, 11, 24, 2, 30, 45, 0, time.UTC) }
	return f, c
}

func TestSubscriptionsPagingAndTokenReuse(t *testing.T) {
	f, c := newFake(t)
	f.mux.HandleFunc("GET /subscriptions", func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer tok-") {
			w.WriteHeader(401)
			return
		}
		if r.URL.Query().Get("page") == "2" {
			fmt.Fprint(w, `{"value":[{"subscriptionId":"BBBB","displayName":"Two","state":"Enabled"}]}`)
			return
		}
		fmt.Fprintf(w, `{"value":[{"subscriptionId":"AAAA","displayName":"One","state":"Enabled"}],"nextLink":"%s/subscriptions?page=2"}`, f.srv.URL)
	})
	subs, err := c.Subscriptions(context.Background())
	if err != nil || len(subs) != 2 || subs[0].ID != "aaaa" || subs[1].Name != "Two" {
		t.Fatalf("%v %+v", err, subs)
	}
	if f.tokens.Load() != 1 || f.scopes[0] != "arm/.default" {
		t.Fatalf("tokens %d, scopes %v", f.tokens.Load(), f.scopes)
	}
}

func TestBadSecretIsReportedOnOneLine(t *testing.T) {
	_, c := newFake(t)
	c.Tenant.ClientSecret = "wrong"
	_, err := c.Subscriptions(context.Background())
	if err == nil || !strings.Contains(err.Error(), "AADSTS7000215") || strings.Contains(err.Error(), "Trace ID") {
		t.Fatalf("%v", err)
	}
}

func TestRetriesThrottlingThenGivesUpOnClientErrors(t *testing.T) {
	f, c := newFake(t)
	var calls atomic.Int64
	f.mux.HandleFunc("GET /subscriptions", func(w http.ResponseWriter, r *http.Request) {
		switch calls.Add(1) {
		case 1:
			w.WriteHeader(429)
		case 2:
			w.WriteHeader(503)
		default:
			fmt.Fprint(w, `{"value":[]}`)
		}
	})
	if _, err := c.Subscriptions(context.Background()); err != nil || calls.Load() != 3 {
		t.Fatalf("%v after %d calls", err, calls.Load())
	}
	f.mux.HandleFunc("GET /denied/blobServices/default/containers", func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(403)
		fmt.Fprint(w, `{"error":{"code":"AuthorizationFailed"}}`)
	})
	calls.Store(0)
	_, err := c.Containers(context.Background(), "/denied")
	var api *APIError
	if !errors.As(err, &api) || api.Status != 403 || calls.Load() != 1 || !strings.Contains(err.Error(), "AuthorizationFailed") {
		t.Fatalf("%v after %d calls", err, calls.Load())
	}
}

func TestResourceGraphPagesAndDecodesRows(t *testing.T) {
	f, c := newFake(t)
	f.mux.HandleFunc("POST /providers/Microsoft.ResourceGraph/resources", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Query         string
			Subscriptions []string
			Options       map[string]any
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if !strings.Contains(req.Query, "microsoft.compute/disks") || len(req.Subscriptions) != 1 || req.Options["resultFormat"] != "objectArray" {
			t.Errorf("request %+v", req)
		}
		if req.Options["$skipToken"] == "next" {
			fmt.Fprint(w, `{"data":[{"id":"/d2","name":"d2","tags":null,"sku":{"name":"StandardSSD_LRS"},"properties":{"diskSizeGB":4,"diskState":"Unattached"}}]}`)
			return
		}
		fmt.Fprint(w, `{"$skipToken":"next","data":[{"id":"/d1","name":"d1","subscriptionId":"s1","resourceGroup":"rg","location":"australiaeast",
			"tags":{"env":"prod","cost":12},"zones":["1"],"managedBy":"/vm/vm1","sku":{"name":"Premium_LRS","tier":"Premium"},
			"properties":{"diskSizeGB":128,"diskSizeBytes":137438953472,"diskState":"Attached","osType":"Windows","timeCreated":"2025-05-06T07:08:09.1234567+00:00",
			"diskIOPSReadWrite":500,"diskMBpsReadWrite":100,"tier":"P10","LastOwnershipUpdateTime":"2025-06-01T00:00:00Z","encryption":{"type":"EncryptionAtRestWithPlatformKey"},"creationData":{"createOption":"FromImage"}}}]}`)
	})
	var rows []Row
	err := c.ResourceGraph(context.Background(), QueryDisks, []string{"s1"}, func(p []Row) error { rows = append(rows, p...); return nil })
	if err != nil || len(rows) != 2 {
		t.Fatalf("%v %d rows", err, len(rows))
	}
	var p DiskProperties
	if err := json.Unmarshal(rows[0].Properties, &p); err != nil {
		t.Fatal(err)
	}
	if rows[0].Tags["cost"] != "12" || rows[0].Sku.Name != "Premium_LRS" || rows[0].Zones[0] != "1" || p.SizeBytes != 128<<30 ||
		p.TimeCreated == nil || p.OwnershipTime == nil || p.Tier != "P10" || p.CreationData.CreateOption != "FromImage" || p.IOPS != 500 {
		t.Fatalf("row %+v props %+v", rows[0], p)
	}
	if rows[1].Tags != nil {
		t.Fatal("null tags")
	}
}

func metric(name string, points ...string) string {
	return fmt.Sprintf(`{"name":{"value":%q},"timeseries":[{"data":[%s]}]}`, name, strings.Join(points, ","))
}

func TestAccountUsageTakesTheLatestValueOfEachService(t *testing.T) {
	f, c := newFake(t)
	var asked []string
	serve := func(path, body string) {
		f.mux.HandleFunc("GET "+account+path+"/providers/Microsoft.Insights/metrics", func(w http.ResponseWriter, r *http.Request) {
			q := r.URL.Query()
			asked = append(asked, q.Get("metricnames"))
			if q.Get("timespan") != "2026-11-22T02:30:00Z/2026-11-24T02:30:00Z" || q.Get("interval") != "PT1H" || q.Get("aggregation") != "Average" {
				t.Errorf("query %v", q)
			}
			if body == "" {
				w.WriteHeader(404)
				return
			}
			fmt.Fprintf(w, `{"value":[%s]}`, body)
		})
	}
	serve("", metric("UsedCapacity", `{"timeStamp":"2026-11-23T00:00:00Z","average":900}`, `{"timeStamp":"2026-11-23T01:00:00Z","average":1000.4}`, `{"timeStamp":"2026-11-23T02:00:00Z"}`))
	serve("/blobServices/default", metric("BlobCapacity", `{"timeStamp":"2026-11-23T01:00:00Z","average":700}`)+","+metric("BlobCount", `{"timeStamp":"2026-11-23T01:00:00Z","average":42}`))
	serve("/fileServices/default", metric("FileCapacity", `{"timeStamp":"2026-11-23T01:00:00Z","average":300}`)+","+metric("FileShareCount", `{"timeStamp":"2026-11-23T01:00:00Z"}`))
	serve("/tableServices/default", "")
	serve("/queueServices/default", metric("QueueCapacity", `{"timeStamp":"2026-11-23T01:00:00Z","average":0}`))

	u, warn, err := c.AccountUsage(context.Background(), account, "StorageV2", true)
	if err != nil {
		t.Fatal(err)
	}
	if warn == nil || !strings.Contains(warn.Error(), "tableServices") {
		t.Fatalf("the table service failed and should be reported: %v", warn)
	}
	if *u.UsedBytes != 1000 || !u.At.Equal(time.Date(2026, 11, 23, 1, 0, 0, 0, time.UTC)) || *u.BlobBytes != 700 || *u.BlobCount != 42 ||
		*u.FileBytes != 300 || u.FileShares != nil || u.TableBytes != nil || *u.QueueBytes != 0 {
		t.Fatalf("%+v", u)
	}

	asked = nil
	if _, _, err := c.AccountUsage(context.Background(), account, "BlockBlobStorage", true); err != nil || len(asked) != 2 {
		t.Fatalf("a blob-only account has only the blob service: %v asked %v", err, asked)
	}
	asked = nil
	if _, _, err := c.AccountUsage(context.Background(), account, "StorageV2", false); err != nil || len(asked) != 1 {
		t.Fatalf("without the breakdown only the account is asked: %v asked %v", err, asked)
	}
}

func TestContainers(t *testing.T) {
	f, c := newFake(t)
	f.mux.HandleFunc("GET "+account+"/blobServices/default/containers", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "2" {
			fmt.Fprint(w, `{"value":[{"id":"/c/$web","name":"$web","properties":{}}]}`)
			return
		}
		fmt.Fprintf(w, `{"value":[{"id":"/c/data","name":"data","properties":{"publicAccess":"Blob","leaseState":"Available","lastModifiedTime":"2026-01-02T03:04:05.0000000Z","hasImmutabilityPolicy":true,"hasLegalHold":false}}],
			"nextLink":"%s%s/blobServices/default/containers?page=2"}`, f.srv.URL, account)
	})
	cs, err := c.Containers(context.Background(), account)
	if err != nil || len(cs) != 2 || cs[0].Properties.PublicAccess != "Blob" || !cs[0].Properties.ImmutablePolicy || cs[0].Properties.LastModified == nil || cs[1].Name != "$web" {
		t.Fatalf("%v %+v", err, cs)
	}
}

func blob(size int, extra, props string) string {
	return fmt.Sprintf(`<Blob><Name>b</Name>%s<Properties><Content-Length>%d</Content-Length><BlobType>BlockBlob</BlobType>%s</Properties></Blob>`, extra, size, props)
}

func page(marker string, blobs ...string) string {
	return `<?xml version="1.0" encoding="utf-8"?><EnumerationResults ServiceEndpoint="https://x/" ContainerName="data"><Blobs>` +
		strings.Join(blobs, "") + `</Blobs><NextMarker>` + marker + `</NextMarker></EnumerationResults>`
}

func TestContainerUsageAddsUpEveryKindOfBlob(t *testing.T) {
	f, c := newFake(t)
	f.mux.HandleFunc("GET /blob/data", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("restype") != "container" || q.Get("comp") != "list" || q.Get("include") != "snapshots,versions,deleted" ||
			r.Header.Get("x-ms-version") != blobAPIVersion || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("request %v %v", q, r.Header)
		}
		if q.Get("marker") == "m2" {
			io.WriteString(w, page("",
				blob(7, `<Deleted>true</Deleted>`, `<AccessTier>Cool</AccessTier>`),
				blob(0, ``, `<ResourceType>directory</ResourceType>`),
				blob(1<<40, ``, ``))) // a page blob: no tier
			return
		}
		io.WriteString(w, page("m2",
			blob(100, `<VersionId>v2</VersionId><IsCurrentVersion>true</IsCurrentVersion>`, `<AccessTier>Hot</AccessTier>`),
			blob(40, `<VersionId>v1</VersionId>`, `<AccessTier>Hot</AccessTier>`),
			blob(30, `<Snapshot>2026-01-01T00:00:00Z</Snapshot>`, `<AccessTier>Archive</AccessTier>`),
			blob(5, ``, `<AccessTier>Hot</AccessTier>`)))
	})
	u, err := c.ContainerUsage(context.Background(), f.srv.URL+"/blob/", "data", ListOptions{Snapshots: true, Versions: true, Deleted: true})
	if err != nil {
		t.Fatal(err)
	}
	want := ContainerUsage{CurrentBytes: 105 + 1<<40, VersionBytes: 40, SnapshotBytes: 30, DeletedBytes: 7, Blobs: 3, Objects: 6}
	if u.CurrentBytes != want.CurrentBytes || u.VersionBytes != want.VersionBytes || u.SnapshotBytes != want.SnapshotBytes ||
		u.DeletedBytes != want.DeletedBytes || u.Blobs != want.Blobs || u.Objects != want.Objects || u.Truncated {
		t.Fatalf("\n got %+v\nwant %+v", u, want)
	}
	if u.Total() != 182+1<<40 || u.Tiers["Hot"] != (Tier{145, 3}) || u.Tiers["Archive"] != (Tier{30, 1}) || u.Tiers["Cool"] != (Tier{7, 1}) || u.Tiers["None"] != (Tier{1 << 40, 1}) {
		t.Fatalf("tiers %+v total %d", u.Tiers, u.Total())
	}
	if f.scopes[len(f.scopes)-1] != "storage/.default" {
		t.Fatalf("scopes %v", f.scopes)
	}

	// The limit is checked between pages.
	u, err = c.ContainerUsage(context.Background(), f.srv.URL+"/blob", "data", ListOptions{Snapshots: true, Versions: true, Deleted: true, MaxBlobs: 3})
	if err != nil || !u.Truncated || u.Objects != 4 {
		t.Fatalf("%v %+v", err, u)
	}
}

func TestContainerUsageFallsBackWhenAnIncludeIsRefused(t *testing.T) {
	f, c := newFake(t)
	f.mux.HandleFunc("GET /blob/$web", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("include") != "" {
			w.Header().Set("x-ms-error-code", "FeatureNotYetSupportedForHierarchicalNamespaceAccounts")
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, page("", blob(9, ``, ``)))
	})
	u, err := c.ContainerUsage(context.Background(), f.srv.URL+"/blob", "$web", ListOptions{Versions: true})
	if err != nil || u.CurrentBytes != 9 {
		t.Fatalf("%v %+v", err, u)
	}
}

func TestContainerUsageReportsTheStorageErrorCode(t *testing.T) {
	f, c := newFake(t)
	f.mux.HandleFunc("GET /blob/data", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("x-ms-error-code", "AuthorizationPermissionMismatch")
		w.WriteHeader(403)
		io.WriteString(w, `<?xml version="1.0"?><Error><Code>AuthorizationPermissionMismatch</Code><Message>This request is not authorized.</Message></Error>`)
	})
	_, err := c.ContainerUsage(context.Background(), f.srv.URL+"/blob", "data", ListOptions{})
	var api *APIError
	if !errors.As(err, &api) || api.Code != "AuthorizationPermissionMismatch" || api.Status != 403 {
		t.Fatalf("%v", err)
	}

	// Nothing listening: a transport error, not an APIError.
	c.Data = &http.Client{Timeout: time.Second}
	_, err = c.ContainerUsage(context.Background(), "http://127.0.0.1:1", "data", ListOptions{})
	if err == nil || errors.As(err, &api) {
		t.Fatalf("%v", err)
	}
}
