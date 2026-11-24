// Package store is where the collector sends what it finds. The MongoDB
// implementation is in the mongostore subpackage; DryRun prints instead.
package store

import (
	"context"
	"encoding/json"
	"io"
	"sync"

	"github.com/jercle/datafetch/azstorage/internal/model"
)

// Store receives the collected documents and the collector's monitoring.
//
// The Save methods upsert by _id and keep each document's firstSeenAt. They
// also keep what an earlier pass measured when this one could not:
//
//   - an account's sizes, unless its UsageStatus is known;
//   - an account's container totals, unless its ContainersStatus is success;
//   - a container's size, unless this pass measured it (Container.Sized).
//
// The status and error fields are always those of the latest attempt.
type Store interface {
	SaveAccounts(ctx context.Context, docs []model.Account) error
	SaveContainers(ctx context.Context, docs []model.Container) error
	SaveDisks(ctx context.Context, docs []model.Disk) error

	// PruneAccounts and PruneDisks delete the tenant's documents that this
	// run did not write. The collector only asks after a complete listing.
	PruneAccounts(ctx context.Context, scope model.Scope, runID string) error
	PruneDisks(ctx context.Context, scope model.Scope, runID string) error
	// PruneContainers does the same for containers, leaving alone those of
	// the accounts (by document _id) whose containers could not be listed.
	PruneContainers(ctx context.Context, scope model.Scope, runID string, keepAccounts []string) error

	// SaveSubscriptions upserts, and with prune removes the tenant's
	// subscriptions that are gone.
	SaveSubscriptions(ctx context.Context, scope model.Scope, runID string, docs []model.Subscription, prune bool) error
	// SaveTenant records the outcome for a tenant. LastSuccessAt is only
	// overwritten when it is set, and a failed pass keeps the stored counts.
	SaveTenant(ctx context.Context, t *model.Tenant) error

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

func emitAll[T any](d *DryRun, collection string, docs []T) error {
	for i := range docs {
		if err := d.emit(collection, docs[i]); err != nil {
			return err
		}
	}
	return nil
}

// SaveAccounts prints only the final write of each account, the one made
// after its containers were looked at.
func (d *DryRun) SaveAccounts(_ context.Context, docs []model.Account) error {
	for i := range docs {
		if docs[i].ContainersStatus == "" {
			continue
		}
		if err := d.emit(model.CollAccounts, docs[i]); err != nil {
			return err
		}
	}
	return nil
}
func (d *DryRun) SaveContainers(_ context.Context, docs []model.Container) error {
	return emitAll(d, model.CollContainers, docs)
}
func (d *DryRun) SaveDisks(_ context.Context, docs []model.Disk) error {
	return emitAll(d, model.CollDisks, docs)
}
func (d *DryRun) PruneAccounts(context.Context, model.Scope, string) error             { return nil }
func (d *DryRun) PruneDisks(context.Context, model.Scope, string) error                { return nil }
func (d *DryRun) PruneContainers(context.Context, model.Scope, string, []string) error { return nil }
func (d *DryRun) SaveSubscriptions(_ context.Context, _ model.Scope, _ string, docs []model.Subscription, _ bool) error {
	return emitAll(d, model.CollSubscriptions, docs)
}
func (d *DryRun) SaveTenant(_ context.Context, t *model.Tenant) error {
	return d.emit(model.CollTenants, t)
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
