// Package store is where the checker sends what it finds. The MongoDB
// implementation is in the mongostore subpackage; DryRun prints instead.
package store

import (
	"context"
	"encoding/json"
	"io"
	"sync"

	"github.com/jercle/datafetch/nscheck/internal/model"
)

// Doc is a document to write to one of the object collections
// (nsc_vservers, nsc_services, nsc_certificates).
type Doc struct {
	ID   string
	Body any
}

// Store receives the documents and the checker's own monitoring.
type Store interface {
	// LoadState returns what earlier passes stored about an appliance.
	LoadState(ctx context.Context, applianceID string) (*model.State, error)

	// SaveAppliance replaces the appliance's document. When full is false
	// (the appliance could not be read) only the status of this attempt is
	// written, and the system, HA, interface and count fields are left as
	// the last good pass stored them.
	SaveAppliance(ctx context.Context, a *model.Appliance, full bool) error
	// SaveObjects replaces the given documents of a collection by _id.
	SaveObjects(ctx context.Context, collection string, docs []Doc) error
	// PruneObjects deletes the appliance's documents of the given kinds in
	// a collection, other than those whose _id is in keep.
	PruneObjects(ctx context.Context, collection, applianceID string, kinds, keep []string) error
	SaveSample(ctx context.Context, s *model.Sample) error
	SaveEvents(ctx context.Context, events []model.Event) error

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

func (d *DryRun) LoadState(context.Context, string) (*model.State, error) {
	return &model.State{}, nil
}
func (d *DryRun) SaveAppliance(_ context.Context, a *model.Appliance, _ bool) error {
	return d.emit(model.CollAppliances, a)
}
func (d *DryRun) SaveObjects(_ context.Context, collection string, docs []Doc) error {
	for _, doc := range docs {
		if err := d.emit(collection, doc.Body); err != nil {
			return err
		}
	}
	return nil
}
func (d *DryRun) PruneObjects(context.Context, string, string, []string, []string) error { return nil }
func (d *DryRun) SaveSample(context.Context, *model.Sample) error                        { return nil }
func (d *DryRun) SaveEvents(_ context.Context, events []model.Event) error {
	for i := range events {
		if err := d.emit(model.CollEvents, events[i]); err != nil {
			return err
		}
	}
	return nil
}
func (d *DryRun) WriteLogs(context.Context, []model.LogEntry) error { return nil } // already on stderr
func (d *DryRun) SaveRun(_ context.Context, r *model.Run) error {
	if r.Status == model.StatusRunning {
		return nil
	}
	return d.emit(model.CollRuns, r)
}
func (d *DryRun) Heartbeat(context.Context, *model.Instance) error { return nil }
func (d *DryRun) Close(context.Context) error                      { return nil }
