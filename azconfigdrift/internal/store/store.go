// Package store is where the collector keeps what it reads. The MongoDB
// implementation is in the mongostore subpackage. Memory keeps everything
// in the process, for tests and for -dry-run, which prints instead.
package store

import (
	"context"
	"encoding/json"
	"io"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/jercle/datafetch/azconfigdrift/internal/model"
)

// Store receives the settings, their changes, and the collector's own
// monitoring, and answers what the dashboard decided: which baseline is
// current, whether a pass was asked for.
type Store interface {
	// SyncModules writes the catalogue and the switches this pass uses.
	SyncModules(ctx context.Context, mods []model.Module, states map[string]model.ModuleState) error
	// ModuleSwitches returns the switches set in the dashboard.
	ModuleSwitches(ctx context.Context) ([]model.ModuleSwitches, error)
	// ActiveBaseline returns the newest complete baseline, or nil.
	ActiveBaseline(ctx context.Context) (*model.Baseline, error)
	// BaselineHashes returns item id → settings hash for one source.
	BaselineHashes(ctx context.Context, baselineID, tenantID, module, source string) (map[string]string, error)
	// RunRequested is when the dashboard last asked for a pass (zero: never).
	RunRequested(ctx context.Context) (time.Time, error)

	// ItemIndex returns what is stored for one source, without settings.
	ItemIndex(ctx context.Context, tenantID, module, source string) (map[string]model.ItemRef, error)
	// ItemConfig returns one item's stored settings JSON.
	ItemConfig(ctx context.Context, id string) (string, error)
	// SaveItems stores new and changed items. FirstSeenAt of an item that
	// exists is kept, and so is its ChangedAt when the item's is zero.
	SaveItems(ctx context.Context, items []model.Item) error
	// TouchItems marks unchanged items as seen and sets how they compare
	// with the baseline.
	TouchItems(ctx context.Context, ids []string, at time.Time, runID string, drift model.Drift) error
	// TombstoneItems keeps items that are gone but still in the baseline.
	TombstoneItems(ctx context.Context, ids []string, at time.Time, runID string, drift model.Drift) error
	DeleteItems(ctx context.Context, ids []string) error
	// DropOtherSources deletes a tenant's items of sources that are not in
	// keep (module → source ids), and returns how many.
	DropOtherSources(ctx context.Context, tenantID string, keep map[string][]string) (int, error)
	SaveChanges(ctx context.Context, changes []model.Change) error

	LoadTenant(ctx context.Context, id string) (*model.Tenant, error)
	SaveTenant(ctx context.Context, t *model.Tenant) error

	WriteLogs(ctx context.Context, entries []model.LogEntry) error
	SaveRun(ctx context.Context, r *model.Run) error
	Heartbeat(ctx context.Context, i *model.Instance) error

	Close(ctx context.Context) error
}

// Memory is a Store held in the process.
type Memory struct {
	mu sync.Mutex
	// Out, when set, receives each stored item, change, tenant and finished
	// run as a line of JSON (-dry-run).
	Out io.Writer

	Modules map[string]model.Module
	States  map[string]model.ModuleState
	Items   map[string]model.Item
	Changes []model.Change
	// Switches stands for what the dashboard stored in acd_module_settings.
	Switches  []model.ModuleSwitches
	Tenants   map[string]model.Tenant
	Runs      map[string]model.Run
	Logs      []model.LogEntry
	Instances map[string]model.Instance
	// Baselines, oldest first, and their items: baseline id → item id.
	Baselines     []model.Baseline
	BaselineItems map[string]map[string]model.Item
	Requested     time.Time
	// Fail makes every call return this error.
	Fail error
}

func NewMemory() *Memory {
	return &Memory{
		Modules: map[string]model.Module{}, States: map[string]model.ModuleState{}, Items: map[string]model.Item{},
		Tenants: map[string]model.Tenant{}, Runs: map[string]model.Run{}, Instances: map[string]model.Instance{},
		BaselineItems: map[string]map[string]model.Item{},
	}
}

// emit must be called with the lock held.
func (m *Memory) emit(collection string, doc any) {
	if m.Out != nil {
		_ = json.NewEncoder(m.Out).Encode(map[string]any{"collection": collection, "doc": doc})
	}
}

func (m *Memory) SyncModules(_ context.Context, mods []model.Module, states map[string]model.ModuleState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	for _, d := range mods {
		m.Modules[d.ID] = d
		m.States[d.ID] = states[d.ID]
	}
	return nil
}

func (m *Memory) ModuleSwitches(context.Context) ([]model.ModuleSwitches, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return nil, m.Fail
	}
	return append([]model.ModuleSwitches(nil), m.Switches...), nil
}

func (m *Memory) ActiveBaseline(context.Context) (*model.Baseline, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return nil, m.Fail
	}
	if len(m.Baselines) == 0 {
		return nil, nil
	}
	b := m.Baselines[len(m.Baselines)-1]
	return &b, nil
}

func (m *Memory) BaselineHashes(_ context.Context, baselineID, tenantID, module, source string) (map[string]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return nil, m.Fail
	}
	out := map[string]string{}
	for id, it := range m.BaselineItems[baselineID] {
		if it.TenantID == tenantID && it.Module == module && it.Source == source {
			out[id] = it.Hash
		}
	}
	return out, nil
}

func (m *Memory) RunRequested(context.Context) (time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.Requested, m.Fail
}

func (m *Memory) ItemIndex(_ context.Context, tenantID, module, source string) (map[string]model.ItemRef, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return nil, m.Fail
	}
	out := map[string]model.ItemRef{}
	for id, it := range m.Items {
		if it.TenantID == tenantID && it.Module == module && it.Source == source {
			out[id] = model.ItemRef{ID: id, Hash: it.Hash, Present: it.Present, Drift: it.Drift, Type: it.Type, Key: it.Key, Name: it.Name, RefsHash: it.RefsHash, ResourceGroup: it.ResourceGroup}
		}
	}
	return out, nil
}

func (m *Memory) ItemConfig(_ context.Context, id string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.Items[id].Config, m.Fail
}

func (m *Memory) SaveItems(_ context.Context, items []model.Item) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	for _, it := range items {
		if old, ok := m.Items[it.ID]; ok {
			it.FirstSeenAt = old.FirstSeenAt
			if it.ChangedAt.IsZero() {
				it.ChangedAt = old.ChangedAt
			}
		}
		m.Items[it.ID] = it
		m.emit(model.CollItems, it)
	}
	return nil
}

func (m *Memory) TouchItems(_ context.Context, ids []string, at time.Time, runID string, drift model.Drift) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	for _, id := range ids {
		if it, ok := m.Items[id]; ok {
			it.LastSeenAt, it.RunID, it.Drift = at, runID, drift
			m.Items[id] = it
		}
	}
	return nil
}

func (m *Memory) TombstoneItems(_ context.Context, ids []string, at time.Time, runID string, drift model.Drift) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	for _, id := range ids {
		if it, ok := m.Items[id]; ok {
			if it.Present {
				when := at
				it.RemovedAt, it.Present = &when, false
			}
			it.RunID, it.Drift = runID, drift
			m.Items[id] = it
		}
	}
	return nil
}

func (m *Memory) DeleteItems(_ context.Context, ids []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	for _, id := range ids {
		delete(m.Items, id)
	}
	return nil
}

func (m *Memory) DropOtherSources(_ context.Context, tenantID string, keep map[string][]string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return 0, m.Fail
	}
	n := 0
	for id, it := range m.Items {
		if it.TenantID == tenantID && !slices.Contains(keep[it.Module], it.Source) {
			delete(m.Items, id)
			n++
		}
	}
	return n, nil
}

func (m *Memory) SaveChanges(_ context.Context, changes []model.Change) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	for _, c := range changes {
		m.Changes = append(m.Changes, c)
		m.emit(model.CollChanges, c)
	}
	return nil
}

func (m *Memory) LoadTenant(_ context.Context, id string) (*model.Tenant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return nil, m.Fail
	}
	t, ok := m.Tenants[id]
	if !ok {
		return nil, nil
	}
	return &t, nil
}

func (m *Memory) SaveTenant(_ context.Context, t *model.Tenant) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	m.Tenants[t.ID] = *t
	m.emit(model.CollTenants, t)
	return nil
}

func (m *Memory) WriteLogs(_ context.Context, entries []model.LogEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	m.Logs = append(m.Logs, entries...)
	return nil
}

func (m *Memory) SaveRun(_ context.Context, r *model.Run) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	m.Runs[r.ID] = *r
	if r.Status != model.StatusRunning {
		m.emit(model.CollRuns, r)
	}
	return nil
}

func (m *Memory) Heartbeat(_ context.Context, i *model.Instance) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	m.Instances[i.ID] = *i
	return nil
}

func (m *Memory) Close(context.Context) error { return nil }

// SaveBaseline does what the dashboard does when a baseline is saved: it
// copies every present item, records which sources had been read, marks
// the items as matching, and forgets items that were only kept for the
// baseline before. For tests.
func (m *Memory) SaveBaseline(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b := model.Baseline{ID: id}
	for _, t := range m.Tenants {
		for _, mod := range t.Modules {
			for _, s := range mod.Sources {
				if s.LastSuccessAt != nil {
					b.Covered = append(b.Covered, model.CoverKey(t.ID, mod.Module, s.Source))
				}
			}
		}
	}
	sort.Strings(b.Covered)
	covered := map[string]bool{}
	for _, c := range b.Covered {
		covered[c] = true
	}
	items := map[string]model.Item{}
	for itemID, it := range m.Items {
		if !it.Present {
			delete(m.Items, itemID)
			continue
		}
		items[itemID] = it
		it.Drift = model.Drift{BaselineID: id, Status: model.DriftSame}
		if !covered[model.CoverKey(it.TenantID, it.Module, it.Source)] {
			it.Drift.Status = model.DriftUntracked
		}
		m.Items[itemID] = it
	}
	m.Baselines = append(m.Baselines, b)
	m.BaselineItems[id] = items
}
