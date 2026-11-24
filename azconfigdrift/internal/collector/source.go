package collector

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jercle/datafetch/azconfigdrift/internal/catalog"
	"github.com/jercle/datafetch/azconfigdrift/internal/cloud"
	"github.com/jercle/datafetch/azconfigdrift/internal/model"
	"github.com/jercle/datafetch/azconfigdrift/internal/normalize"
)

// sourceResult is a SourceRun plus what only the module total needs.
type sourceResult struct {
	model.SourceRun
	drifted int
}

// keysLen bounds the setting names stored per item for search.
const keysLen = 3000

// collectSource reads one source of one tenant and brings the stored items
// in line with it. first says the source has never been read completely:
// then everything is new, and no changes are recorded.
func (c *Collector) collectSource(ctx context.Context, env *tenantEnv, m catalog.Module, src catalog.Source, first bool, log *slog.Logger) sourceResult {
	start := time.Now().UTC()
	res := sourceResult{SourceRun: model.SourceRun{Source: src.ID}}
	fail := func(err error, what string) sourceResult {
		res.Status = cloud.Status(err)
		if ctx.Err() == context.DeadlineExceeded {
			res.Status = model.SourceFailed
		}
		res.Error = errText(err, src, res.Status)
		res.DurationMs = time.Since(start).Milliseconds()
		level := slog.LevelWarn
		if res.Status == model.SourceFailed {
			level = slog.LevelError
		}
		log.Log(ctx, level, what, "status", res.Status, "error", err, "items", res.Items, "reads", src.Reads(), "permission", src.Permission)
		return res
	}

	p := env.pass
	covered := p.baseline != nil && p.covered[model.CoverKey(env.scope.TenantID, m.ID, src.ID)]
	baselineID := ""
	if p.baseline != nil {
		baselineID = p.baseline.ID
	}
	index, err := c.Store.ItemIndex(ctx, env.scope.TenantID, m.ID, src.ID)
	var base map[string]string
	if err == nil && covered {
		base, err = c.Store.BaselineHashes(ctx, baselineID, env.scope.TenantID, m.ID, src.ID)
	}
	if err != nil {
		res.Status, res.Error = model.SourceFailed, "reading what is stored: "+err.Error()
		res.DurationMs = time.Since(start).Milliseconds()
		log.Error("source not read: what is stored could not be loaded", "error", err)
		return res
	}
	drift := func(id, hash string) model.Drift {
		d := model.Drift{BaselineID: baselineID, Status: model.DriftUntracked}
		if covered {
			switch h, ok := base[id]; {
			case !ok:
				d.Status = model.DriftAdded
			case h == hash:
				d.Status = model.DriftSame
			default:
				d.Status = model.DriftChanged
			}
		}
		return d
	}

	seen := make(map[string]bool, len(index))
	excluded := 0
	write := func(batch []raw) error {
		var items []model.Item
		var changes []model.Change
		touch := map[string][]string{}
		if src.NameFrom != "" {
			for i := range batch {
				values(batch[i].Body, strings.Split(src.NameFrom, "."), func(n string) { batch[i].Name = n })
			}
		}
		env.fetcher.resolve(ctx, src, batch)
		for _, r := range batch {
			id := model.ItemID(env.scope.TenantID, m.ID, src.ID, r.Key)
			if seen[id] {
				continue
			}
			// Left out by the configuration: as if it were not there.
			if c.Cfg.Excluded(env.scope.TenantID, m.ID, r.Type, r.ResourceGroup, r.Name) {
				excluded++
				continue
			}
			seen[id] = true
			env.mu.Lock()
			rules := env.ignore.For(m.ID, src, r.Type)
			env.mu.Unlock()
			settings := normalize.Clean(r.Body, rules)
			b, err := normalize.Canonical(settings)
			if err != nil {
				log.Warn("object skipped: its settings could not be written as JSON", "key", r.Key, "error", err)
				continue
			}
			hash := normalize.Hash(b)
			d := drift(id, hash)
			if d.Status == model.DriftChanged || d.Status == model.DriftAdded {
				res.drifted++
			}
			res.Items++
			ref, stored := index[id]
			name := r.Name
			if name == "" {
				name = r.Key
			}
			refs := refsHash(r.Refs)
			// Only what the object is called changed (a principal was
			// renamed, or names are resolved for the first time): the item
			// is rewritten, but nothing about its settings changed.
			relabel := stored && ref.Present && ref.Hash == hash && (ref.Name != name || ref.RefsHash != refs)
			if stored && ref.Present && ref.Hash == hash && !relabel {
				touch[d.Status] = append(touch[d.Status], id)
				continue
			}
			props, keys := normalize.Describe(settings, keysLen)
			config := string(b)
			if len(config) > c.Cfg.Limits.MaxItemBytes {
				log.Warn("settings too large to store; changes are still detected", "key", r.Key, "bytes", len(config), "limit", c.Cfg.Limits.MaxItemBytes)
				config = fmt.Sprintf(`{"_notStored":"the settings are %d bytes, over limits.maxItemBytes (%d)"}`, len(config), c.Cfg.Limits.MaxItemBytes)
			}
			it := model.Item{
				ID: id, Scope: env.scope, Platform: m.Platform, Module: m.ID, Source: src.ID,
				Type: r.Type, Key: r.Key, Name: r.Name,
				SubscriptionID: r.SubscriptionID, SubscriptionName: env.fetcher.subNames[strings.ToLower(r.SubscriptionID)],
				ResourceGroup: r.ResourceGroup, Location: r.Location,
				Config: config, Hash: hash, Props: props, Refs: r.Refs, RefsHash: refs,
				Present: true, FirstSeenAt: start, LastSeenAt: start, ChangedAt: start, RunID: p.run.ID, Drift: d,
			}
			if it.Name == "" {
				it.Name = r.Key
			}
			it.SortName = strings.ToLower(it.Name)
			search := strings.Join(nonEmpty(it.Name, it.Type, it.ResourceGroup, it.SubscriptionName, it.Location, src.Name), " ")
			it.Text = strings.ToLower(strings.ReplaceAll(search, "\t", " ")) + "\t" + keys
			if relabel {
				// ChangedAt is kept by the store when it is not set.
				it.ChangedAt = time.Time{}
				items = append(items, it)
				continue
			}
			items = append(items, it)

			was := stored && ref.Present
			if was {
				res.Changed++
			} else if !first {
				res.Added++
			}
			if first {
				continue
			}
			ch := model.Change{
				ID: model.NewID(), At: start, RunID: p.run.ID, Scope: env.scope, Platform: m.Platform, Module: m.ID, Source: src.ID,
				Type: it.Type, ItemID: id, Key: it.Key, Name: it.Name, Kind: model.ChangeAdded, HashAfter: hash, Paths: []model.PathChange{}, Refs: r.Refs,
			}
			if was {
				ch.Kind, ch.HashBefore = model.ChangeChanged, ref.Hash
				old, err := c.Store.ItemConfig(ctx, id)
				if err != nil {
					return err
				}
				if before, err := normalize.Decode(old); err == nil {
					ch.Paths, ch.PathCount = normalize.Diff(before, settings, c.Cfg.Limits.ChangePaths)
				}
			} else {
				ch.PathCount = props
			}
			changes = append(changes, ch)
		}
		// Changes first: if the items are stored and the changes are not,
		// the change would never be recorded.
		if err := c.saveChanges(ctx, p, baselineID, changes); err != nil {
			return err
		}
		if err := c.Store.SaveItems(ctx, items); err != nil {
			return err
		}
		for status, ids := range touch {
			if err := c.Store.TouchItems(ctx, ids, start, p.run.ID, model.Drift{BaselineID: baselineID, Status: status}); err != nil {
				return err
			}
		}
		return nil
	}

	if err := env.fetcher.fetch(ctx, src, write); err != nil {
		// What was read is stored; what was not seen is left alone.
		return fail(err, "source not read completely")
	}

	// Everything was read: what was not seen is gone.
	var gone, forget []string
	var changes []model.Change
	for id, ref := range index {
		if seen[id] {
			continue
		}
		// Left out by the configuration since it was stored: forgotten,
		// not recorded as removed from the tenant.
		if c.Cfg.Excluded(env.scope.TenantID, m.ID, ref.Type, ref.ResourceGroup, ref.Name) {
			forget = append(forget, id)
			continue
		}
		if ref.Present {
			res.Removed++
			changes = append(changes, model.Change{
				ID: model.NewID(), At: start, RunID: p.run.ID, Scope: env.scope, Platform: m.Platform, Module: m.ID, Source: src.ID,
				Type: ref.Type, ItemID: id, Key: ref.Key, Name: ref.Name, Kind: model.ChangeRemoved, HashBefore: ref.Hash, Paths: []model.PathChange{},
			})
		}
		if _, inBaseline := base[id]; covered && inBaseline {
			res.drifted++
			if ref.Present || ref.Drift.BaselineID != baselineID || ref.Drift.Status != model.DriftRemoved {
				gone = append(gone, id)
			}
		} else {
			forget = append(forget, id)
		}
	}
	err = c.saveChanges(ctx, p, baselineID, changes)
	if err == nil {
		err = c.Store.TombstoneItems(ctx, gone, start, p.run.ID, model.Drift{BaselineID: baselineID, Status: model.DriftRemoved})
	}
	if err == nil {
		err = c.Store.DeleteItems(ctx, forget)
	}
	if err != nil {
		return fail(err, "source read, but removed objects could not be recorded")
	}
	res.Status = model.SourceOK
	res.DurationMs = time.Since(start).Milliseconds()
	log.Info("source read", "items", res.Items, "excluded", excluded, "added", res.Added, "changed", res.Changed, "removed", res.Removed,
		"drifted", res.drifted, "first", first, "duration", time.Since(start).Round(time.Millisecond).String())
	return res
}

func nonEmpty(parts ...string) []string {
	out := parts[:0]
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// saveChanges records what changed between this pass and the one before:
// as change records, and in the history of each setting since the
// baseline.
func (c *Collector) saveChanges(ctx context.Context, p *pass, baselineID string, changes []model.Change) error {
	if len(changes) == 0 {
		return nil
	}
	if err := c.Store.SaveChanges(ctx, changes); err != nil {
		return err
	}
	if err := c.Store.RecordHistory(ctx, baselineID, changes); err != nil {
		return err
	}
	p.objects.Add(int64(len(changes)))
	for _, ch := range changes {
		p.settings.Add(int64(max(1, len(ch.Paths))))
	}
	return nil
}
