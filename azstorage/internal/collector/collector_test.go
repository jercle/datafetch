package collector

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jercle/datafetch/azstorage/internal/azure"
	"github.com/jercle/datafetch/azstorage/internal/config"
	"github.com/jercle/datafetch/azstorage/internal/model"
	"github.com/jercle/datafetch/azstorage/internal/monitor"
)

const (
	sub1 = "11111111-1111-1111-1111-111111111111"
	sub2 = "22222222-2222-2222-2222-222222222222"
)

func accountID(sub, name string) string {
	return "/subscriptions/" + sub + "/resourceGroups/RG-Data/providers/Microsoft.Storage/storageAccounts/" + name
}

func accountRow(sub, name, kind string) azure.Row {
	r := azure.Row{ID: accountID(sub, name), Name: name, Kind: kind, Location: "australiaeast", ResourceGroup: "rg-data", SubscriptionID: sub}
	r.Sku.Name = "Standard_LRS"
	r.Properties = []byte(`{"accessTier":"Hot","isHnsEnabled":false,"creationTime":"2024-03-01T02:03:04.1234567Z","allowBlobPublicAccess":false,
		"minimumTlsVersion":"TLS1_2","networkAcls":{"defaultAction":"Deny"},"primaryEndpoints":{"blob":"https://` + name + `.blob.core.windows.net/"}}`)
	return r
}

func diskRow(sub, name string, gb int, state, vm string) azure.Row {
	r := azure.Row{ID: "/subscriptions/" + sub + "/resourceGroups/rg-vm/providers/Microsoft.Compute/disks/" + name, Name: name,
		Location: "australiaeast", ResourceGroup: "rg-vm", SubscriptionID: sub, ManagedBy: vm}
	r.Sku.Name = "Premium_LRS"
	r.Properties = []byte(fmt.Sprintf(`{"diskSizeGB":%d,"diskState":%q,"osType":"Linux","timeCreated":"2025-01-02T03:04:05Z","encryption":{"type":"EncryptionAtRestWithPlatformKey"}}`, gb, state))
	return r
}

type fakeAPI struct {
	mu         sync.Mutex
	subs       []azure.Subscription
	accounts   []azure.Row
	disks      []azure.Row
	usage      map[string]azure.Usage          // by account name
	usageErr   map[string]error                //
	containers map[string][]string             // account name -> container names
	listErr    map[string]error                //
	sizes      map[string]azure.ContainerUsage // "account/container"
	sizeErr    map[string]error                // "account/container" or "account/*"
	graphErr   map[string]error                // by query
	sized      []string                        // ContainerUsage calls made
	options    azure.ListOptions               // last options seen
}

func name(id string) string { return id[strings.LastIndexByte(id, '/')+1:] }

func (f *fakeAPI) Subscriptions(context.Context) ([]azure.Subscription, error) { return f.subs, nil }

func (f *fakeAPI) ResourceGraph(_ context.Context, q string, subs []string, each func([]azure.Row) error) error {
	if err := f.graphErr[q]; err != nil {
		return err
	}
	rows := f.accounts
	if q == azure.QueryDisks {
		rows = f.disks
	}
	var page []azure.Row
	for _, r := range rows {
		for _, s := range subs {
			if r.SubscriptionID == s {
				page = append(page, r)
			}
		}
	}
	// Two pages, to exercise paging.
	half := len(page) / 2
	if err := each(page[:half]); err != nil {
		return err
	}
	return each(page[half:])
}

func (f *fakeAPI) AccountUsage(_ context.Context, id, _ string, _ bool) (azure.Usage, error, error) {
	if err := f.usageErr[name(id)]; err != nil {
		return azure.Usage{}, nil, err
	}
	return f.usage[name(id)], nil, nil
}

func (f *fakeAPI) Containers(_ context.Context, id string) ([]azure.BlobContainer, error) {
	if err := f.listErr[name(id)]; err != nil {
		return nil, err
	}
	var out []azure.BlobContainer
	for _, n := range f.containers[name(id)] {
		out = append(out, azure.BlobContainer{ID: id + "/blobServices/default/containers/" + n, Name: n})
	}
	return out, nil
}

func (f *fakeAPI) ContainerUsage(_ context.Context, endpoint, container string, o azure.ListOptions) (azure.ContainerUsage, error) {
	account := strings.Split(strings.TrimPrefix(endpoint, "https://"), ".")[0]
	key := account + "/" + container
	f.mu.Lock()
	f.sized = append(f.sized, key)
	f.options = o
	f.mu.Unlock()
	for _, k := range []string{key, account + "/*"} {
		if err := f.sizeErr[k]; err != nil {
			return azure.ContainerUsage{}, err
		}
	}
	return f.sizes[key], nil
}

type fakeStore struct {
	mu         sync.Mutex
	accounts   map[string]model.Account
	containers map[string]model.Container
	disks      map[string]model.Disk
	subs       []model.Subscription
	tenants    []model.Tenant
	pruned     []string
	keep       []string
	failDisks  bool
}

func newStore() *fakeStore {
	return &fakeStore{accounts: map[string]model.Account{}, containers: map[string]model.Container{}, disks: map[string]model.Disk{}}
}

func (s *fakeStore) SaveAccounts(_ context.Context, docs []model.Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range docs {
		s.accounts[d.Name] = d
	}
	return nil
}
func (s *fakeStore) SaveContainers(_ context.Context, docs []model.Container) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range docs {
		s.containers[d.Search] = d
	}
	return nil
}
func (s *fakeStore) SaveDisks(_ context.Context, docs []model.Disk) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failDisks {
		return errors.New("mongo is down")
	}
	for _, d := range docs {
		s.disks[d.Name] = d
	}
	return nil
}
func (s *fakeStore) prune(what string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruned = append(s.pruned, what)
	return nil
}
func (s *fakeStore) PruneAccounts(context.Context, model.Scope, string) error {
	return s.prune("accounts")
}
func (s *fakeStore) PruneDisks(context.Context, model.Scope, string) error { return s.prune("disks") }
func (s *fakeStore) PruneContainers(_ context.Context, _ model.Scope, _ string, keep []string) error {
	s.keep = keep
	return s.prune("containers")
}
func (s *fakeStore) SaveSubscriptions(_ context.Context, _ model.Scope, _ string, docs []model.Subscription, prune bool) error {
	s.subs = docs
	if prune {
		return s.prune("subscriptions")
	}
	return nil
}
func (s *fakeStore) SaveTenant(_ context.Context, t *model.Tenant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tenants = append(s.tenants, *t)
	return nil
}
func (s *fakeStore) WriteLogs(context.Context, []model.LogEntry) error { return nil }
func (s *fakeStore) SaveRun(context.Context, *model.Run) error         { return nil }
func (s *fakeStore) Heartbeat(context.Context, *model.Instance) error  { return nil }
func (s *fakeStore) Close(context.Context) error                       { return nil }

func i64(v int64) *int64 { return &v }

func world() *fakeAPI {
	at := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	return &fakeAPI{
		subs: []azure.Subscription{{ID: sub1, Name: "Production", State: "Enabled"}, {ID: sub2, Name: "Dev", State: "Enabled"}, {ID: "33333333-3333-3333-3333-333333333333", Name: "Old", State: "Disabled"}},
		accounts: []azure.Row{
			accountRow(sub1, "stapp", "StorageV2"), accountRow(sub1, "stlocked", "StorageV2"),
			accountRow(sub2, "stfiles", "FileStorage"), accountRow(sub2, "stnew", "StorageV2"),
		},
		disks: []azure.Row{
			diskRow(sub1, "vm1-os", 128, "Attached", "/subscriptions/"+sub1+"/resourceGroups/rg-vm/providers/Microsoft.Compute/virtualMachines/vm1"),
			diskRow(sub1, "orphan", 1024, "Unattached", ""),
			diskRow(sub2, "vm2-data", 32, "Reserved", ""),
		},
		usage: map[string]azure.Usage{
			"stapp":    {UsedBytes: i64(5000), BlobBytes: i64(4000), FileBytes: i64(900), TableBytes: i64(60), QueueBytes: i64(40), BlobCount: i64(12), At: &at},
			"stlocked": {UsedBytes: i64(700), BlobBytes: i64(700), At: &at},
			"stfiles":  {UsedBytes: i64(300), FileBytes: i64(300), FileShares: i64(2), At: &at},
			"stnew":    {}, // no value yet
		},
		containers: map[string][]string{"stapp": {"data", "logs", "$web"}, "stlocked": {"a", "b", "c"}, "stnew": {}},
		sizes: map[string]azure.ContainerUsage{
			"stapp/data": {CurrentBytes: 3000, VersionBytes: 500, Blobs: 10, Objects: 12, Tiers: map[string]azure.Tier{"Hot": {Bytes: 3500, Count: 12}}},
			"stapp/logs": {CurrentBytes: 400, Blobs: 2, Objects: 2, Truncated: true},
		},
		sizeErr: map[string]error{
			"stapp/$web": &azure.APIError{Status: 403, Code: "AuthorizationPermissionMismatch"},
			"stlocked/*": &azure.APIError{Status: 403, Code: "AuthorizationFailure"},
		},
	}
}

func run(t *testing.T, api *fakeAPI, st *fakeStore, edit func(*config.Config)) *model.Run {
	t.Helper()
	cfg, err := config.Parse([]byte(`{"concurrency":{"containers":1},"tenants":[{"tenantName":"Contoso","tenantId":"00000000-0000-0000-0000-000000000001","clientId":"c","clientSecret":"s"}]}`),
		func(string) string { return "" }, nil)
	if err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		edit(cfg)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	c := &Collector{Cfg: cfg, Store: st, Log: log, Mon: monitor.New(st, log, model.Instance{ID: "test"}),
		NewClient: func(config.Tenant) AzureAPI { return api }}
	return c.Run(context.Background(), "manual", nil)
}

func steps(tr model.TenantRun) string {
	var out []string
	for _, s := range tr.Steps {
		out = append(out, fmt.Sprintf("%s:%s:%d:%d", s.Name, s.Status, s.Count, s.Skipped))
	}
	return strings.Join(out, " ")
}

func TestPass(t *testing.T) {
	api, st := world(), newStore()
	r := run(t, api, st, nil)

	if r.Status != model.StatusSuccess {
		t.Fatalf("status %s: %+v", r.Status, r.Tenants)
	}
	if got, want := steps(r.Tenants[0]), "subscriptions:success:2:0 accounts:success:4:0 usage:success:3:1 containers:success:6:4 disks:success:3:0 store:success:7:0"; got != want {
		t.Fatalf("steps\n got %s\nwant %s", got, want)
	}
	want := model.Counts{
		Subscriptions: 2, Accounts: 4, AccountsUnknown: 1, UsedBytes: 6000, BlobBytes: 4700, FileBytes: 1200, TableBytes: 60, QueueBytes: 40,
		Containers: 6, ContainersMeasured: 2, ContainerBytes: 3900, Blobs: 12,
		Disks: 3, DiskBytes: (128 + 1024 + 32) << 30, DisksUnattached: 1, UnattachedBytes: 1024 << 30,
	}
	if r.Counts != want {
		t.Fatalf("counts\n got %+v\nwant %+v", r.Counts, want)
	}

	a := st.accounts["stapp"]
	if a.UsageStatus != model.UsageKnown || a.UsedBytes != 5000 || a.Containers != 3 || a.ContainersMeasured != 2 || a.ContainerBytes != 3900 ||
		a.ContainersStatus != model.StatusSuccess || a.SizeStatus != "" || a.SubscriptionName != "Production" || a.ResourceGroup != "rg-data" ||
		a.AllowBlobPublicAccess || a.NetworkDefaultAction != "Deny" || a.CreatedAt == nil || a.BlobEndpoint == "" {
		t.Fatalf("stapp %+v", a)
	}
	if a := st.accounts["stnew"]; a.UsageStatus != model.UsageMissing || a.UsedBytes != 0 {
		t.Fatalf("stnew %+v", a)
	}
	if a := st.accounts["stfiles"]; a.Containers != 0 || a.ContainersStatus != model.StatusSuccess || a.FileShares != 2 {
		t.Fatalf("stfiles %+v", a)
	}

	data := st.containers["stapp/data"]
	if data.SizeStatus != model.SizeMeasured || data.UsedBytes != 3500 || data.CurrentBytes != 3000 || data.VersionBytes != 500 ||
		data.Blobs != 10 || data.Tiers["Hot"].Bytes != 3500 || data.SizedAt == nil || data.AccountID != a.ID || data.PublicAccess != "None" {
		t.Fatalf("data %+v", data)
	}
	if c := st.containers["stapp/logs"]; c.SizeStatus != model.SizePartial || c.UsedBytes != 400 || !strings.Contains(c.SizeError, "maxBlobs") {
		t.Fatalf("logs %+v", c)
	}
	if c := st.containers["stapp/$web"]; c.SizeStatus != model.SizeDenied || !strings.Contains(c.SizeError, "Storage Blob Data Reader") || c.SizedAt != nil {
		t.Fatalf("$web %+v", c)
	}

	// The firewall refused the first container; the other two were not tried.
	locked := st.accounts["stlocked"]
	if locked.SizeStatus != model.SizeBlocked || locked.ContainersMeasured != 0 || locked.Containers != 3 {
		t.Fatalf("stlocked %+v", locked)
	}
	tried := 0
	for _, k := range api.sized {
		if strings.HasPrefix(k, "stlocked/") {
			tried++
		}
	}
	for _, n := range []string{"a", "b", "c"} {
		if c := st.containers["stlocked/"+n]; c.SizeStatus != model.SizeBlocked {
			t.Fatalf("stlocked/%s %+v", n, c)
		}
	}
	if tried != 1 {
		t.Fatalf("tried %d containers of a blocked account", tried)
	}
	if o := api.options; !o.Snapshots || !o.Versions || !o.Deleted || o.MaxBlobs != 2_000_000 {
		t.Fatalf("options %+v", o)
	}

	if d := st.disks["vm1-os"]; !d.Attached || d.AttachedTo != "vm1" || d.SizeBytes != 128<<30 || d.Sku != "Premium_LRS" || d.Encryption == "" || d.CreatedAt == nil {
		t.Fatalf("vm1-os %+v", d)
	}
	if d := st.disks["orphan"]; d.Attached || d.State != "Unattached" {
		t.Fatalf("orphan %+v", d)
	}
	if d := st.disks["vm2-data"]; !d.Attached {
		t.Fatal("a reserved disk belongs to a deallocated machine")
	}

	sort.Strings(st.pruned)
	if got := strings.Join(st.pruned, ","); got != "accounts,containers,disks,subscriptions" {
		t.Fatalf("pruned %s", got)
	}
	if len(st.keep) != 0 {
		t.Fatalf("kept %v", st.keep)
	}
	var prod model.Subscription
	for _, s := range st.subs {
		if s.SubscriptionID == sub1 {
			prod = s
		}
	}
	if len(st.subs) != 2 || prod.Counts.Accounts != 2 || prod.Counts.UsedBytes != 5700 || prod.Counts.Disks != 2 || prod.Counts.DisksUnattached != 1 {
		t.Fatalf("subscriptions %+v", st.subs)
	}
	tn := st.tenants[0]
	if tn.LastStatus != model.StatusSuccess || tn.LastSuccessAt == nil || tn.Counts != want || len(tn.Missing) != 0 {
		t.Fatalf("tenant %+v", tn)
	}
}

func TestFailuresKeepWhatIsStored(t *testing.T) {
	api, st := world(), newStore()
	api.listErr = map[string]error{"stapp": errors.New("HTTP 500")}
	api.usageErr = map[string]error{"stlocked": errors.New("HTTP 403")}
	api.graphErr = map[string]error{azure.QueryDisks: errors.New("throttled")}
	r := run(t, api, st, nil)

	tr := r.Tenants[0]
	if r.Status != model.StatusPartial || tr.Status != model.StatusPartial {
		t.Fatalf("status %s / %s", r.Status, tr.Status)
	}
	if got, want := steps(tr), "subscriptions:success:2:0 accounts:success:4:0 usage:success:2:2 containers:failed:3:3 disks:failed:0:0 store:success:4:0"; got != want {
		t.Fatalf("steps\n got %s\nwant %s", got, want)
	}
	a := st.accounts["stapp"]
	if a.ContainersStatus != model.StatusFailed || a.ContainersError == "" {
		t.Fatalf("stapp %+v", a)
	}
	if l := st.accounts["stlocked"]; l.UsageStatus != model.UsageFailed || l.UsageError == "" {
		t.Fatalf("stlocked %+v", l)
	}
	// Disks were not listed, so none may be removed; nor the containers of
	// the account that could not be listed.
	sort.Strings(st.pruned)
	if got := strings.Join(st.pruned, ","); got != "accounts,containers" {
		t.Fatalf("pruned %s", got)
	}
	if len(st.keep) != 1 || st.keep[0] != a.ID {
		t.Fatalf("kept %v", st.keep)
	}
	tn := st.tenants[0]
	if strings.Join(tn.Missing, ",") != "containers,disks" || tn.LastSuccessAt == nil || tn.Counts.AccountsUnknown != 2 {
		t.Fatalf("tenant %+v", tn)
	}
}

func TestSwitches(t *testing.T) {
	api, st := world(), newStore()
	r := run(t, api, st, func(c *config.Config) {
		off := false
		c.Collect.Usage, c.Collect.ContainerSizes, c.Collect.Disks = &off, &off, &off
		c.Tenants[0].ExcludeSubscriptions = []string{sub2}
	})
	if got, want := steps(r.Tenants[0]), "subscriptions:success:1:0 accounts:success:2:0 containers:success:6:6 store:success:2:0"; got != want {
		t.Fatalf("steps\n got %s\nwant %s", got, want)
	}
	if len(api.sized) != 0 {
		t.Fatalf("measured %v with sizes off", api.sized)
	}
	if c := st.containers["stapp/data"]; c.SizeStatus != model.SizeSkipped {
		t.Fatalf("data %+v", c)
	}
	if a := st.accounts["stapp"]; a.UsageStatus != model.UsageSkipped || a.SizeStatus != model.SizeSkipped {
		t.Fatalf("stapp %+v", a)
	}
	// Disks were not listed, so nothing about them is removed.
	for _, p := range st.pruned {
		if p == "disks" || p == "subscriptions" {
			t.Fatalf("pruned %v", st.pruned)
		}
	}
}

func TestExcludedAndUnreachableAccounts(t *testing.T) {
	api, st := world(), newStore()
	api.sizeErr["stlocked/*"] = errors.New("dial tcp: i/o timeout")
	run(t, api, st, func(c *config.Config) { c.ContainerSizes.ExcludeAccounts = []string{"stapp"} })
	if c := st.containers["stapp/data"]; c.SizeStatus != model.SizeSkipped || !strings.Contains(c.SizeError, "excludeAccounts") {
		t.Fatalf("data %+v", c)
	}
	if c := st.containers["stlocked/b"]; c.SizeStatus != model.SizeUnreachable {
		t.Fatalf("b %+v", c)
	}
	if a := st.accounts["stlocked"]; a.SizeStatus != model.SizeUnreachable {
		t.Fatalf("stlocked %+v", a)
	}
}

func TestNoSubscriptionsFailsTheTenant(t *testing.T) {
	api, st := world(), newStore()
	api.subs = nil
	r := run(t, api, st, nil)
	if r.Status != model.StatusFailed || !strings.Contains(r.Tenants[0].Error, "Reader") {
		t.Fatalf("%s %+v", r.Status, r.Tenants[0])
	}
	if len(st.pruned) != 0 {
		t.Fatalf("pruned %v after a failed pass", st.pruned)
	}
	if tn := st.tenants[0]; tn.LastStatus != model.StatusFailed || tn.LastSuccessAt != nil {
		t.Fatalf("tenant %+v", tn)
	}
}

func TestStoreFailureFailsTheStep(t *testing.T) {
	api, st := world(), newStore()
	st.failDisks = true
	r := run(t, api, st, nil)
	tr := r.Tenants[0]
	if tr.Status != model.StatusPartial || !strings.Contains(steps(tr), "disks:failed") {
		t.Fatalf("%s %s", tr.Status, steps(tr))
	}
	for _, p := range st.pruned {
		if p == "disks" {
			t.Fatal("disks pruned although they could not be written")
		}
	}
}
