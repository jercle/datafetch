// Package store is where the checker sends what it finds. The MongoDB
// implementation is in the mongostore subpackage; DryRun prints instead.
package store

import (
	"context"
	"encoding/json"
	"io"
	"sync"

	"github.com/jercle/datafetch/sxgcheck/internal/model"
)

// Store receives the firewalls' state and history, and the checker's own
// monitoring.
type Store interface {
	// LoadFirewalls returns the stored state of this instance's firewalls,
	// so a restarted checker knows since when each state has lasted.
	LoadFirewalls(ctx context.Context, instance string) ([]model.Firewall, error)
	// SaveFirewall replaces the firewall's current state.
	SaveFirewall(ctx context.Context, f *model.Firewall) error
	// SaveResult adds one pass to the firewall's history.
	SaveResult(ctx context.Context, r *model.Result) error
	SaveEvents(ctx context.Context, events []model.Event) error
	// PruneFirewalls deletes this instance's firewalls that are no longer
	// configured. History and events are left to their retention.
	PruneFirewalls(ctx context.Context, instance string, keep []string) error

	WriteLogs(ctx context.Context, entries []model.LogEntry) error
	SaveRun(ctx context.Context, r *model.Run) error
	Heartbeat(ctx context.Context, i *model.Instance) error

	Close(ctx context.Context) error
}

// DryRun writes every document as a line of JSON instead of storing it.
type DryRun struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func NewDryRun(w io.Writer) *DryRun { return &DryRun{enc: json.NewEncoder(w)} }

func (d *DryRun) emit(collection string, doc any) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.enc.Encode(map[string]any{"collection": collection, "doc": doc})
}

func (d *DryRun) LoadFirewalls(context.Context, string) ([]model.Firewall, error) { return nil, nil }
func (d *DryRun) SaveFirewall(_ context.Context, f *model.Firewall) error {
	return d.emit(model.CollFirewalls, f)
}
func (d *DryRun) SaveResult(context.Context, *model.Result) error { return nil } // the firewall line says it all
func (d *DryRun) SaveEvents(_ context.Context, events []model.Event) error {
	for i := range events {
		if err := d.emit(model.CollEvents, events[i]); err != nil {
			return err
		}
	}
	return nil
}
func (d *DryRun) PruneFirewalls(context.Context, string, []string) error { return nil }
func (d *DryRun) WriteLogs(context.Context, []model.LogEntry) error      { return nil } // already on stderr
func (d *DryRun) SaveRun(_ context.Context, r *model.Run) error {
	if r.Status == model.StatusRunning {
		return nil
	}
	return d.emit(model.CollRuns, r)
}
func (d *DryRun) Heartbeat(context.Context, *model.Instance) error { return nil }
func (d *DryRun) Close(context.Context) error                      { return nil }
