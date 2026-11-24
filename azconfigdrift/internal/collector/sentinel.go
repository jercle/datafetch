package collector

import (
	"context"
	"strings"

	"github.com/jercle/datafetch/azconfigdrift/internal/catalog"
	"github.com/jercle/datafetch/azconfigdrift/internal/cloud"
)

// sentinelWorkspaces returns the resource IDs of the Log Analytics
// workspaces Microsoft Sentinel is enabled on: every workspace Resource
// Graph knows, asked for its onboarding state. Found once per pass.
func (f *fetcher) sentinelWorkspaces(ctx context.Context) ([]string, error) {
	f.sentinelOnce.Do(func() {
		var all []string
		q := "resources | where type =~ 'microsoft.operationalinsights/workspaces' | project id, name, type | order by id asc"
		f.sentinelErr = f.arg(ctx, catalog.Source{ID: "sentinel-workspaces", Kind: catalog.KindARG, Query: q}, func(rows []raw) error {
			for _, r := range rows {
				all = append(all, r.Key)
			}
			return nil
		})
		if f.sentinelErr != nil {
			return
		}
		base := strings.TrimRight(f.client.Endpoints.ARM, "/")
		for _, ws := range all {
			var out struct {
				Value []any `json:"value"`
			}
			err := f.client.Do(ctx, cloud.Request{URL: base + ws + "/providers/Microsoft.SecurityInsights/onboardingStates?api-version=2025-09-01", Scope: f.client.Endpoints.ARMScope}, &out)
			switch {
			case err == nil && len(out.Value) > 0:
				f.sentinel = append(f.sentinel, ws)
			case err != nil && ctx.Err() != nil:
				f.sentinelErr = err
				return
			case err != nil && !cloud.NotFound(err):
				// Not readable is not the same as not enabled: say so, and
				// carry on with the workspaces that can be read.
				f.log.Warn("could not tell whether Microsoft Sentinel is enabled on a workspace", "workspace", ws, "error", err)
			}
		}
		f.log.Info("Microsoft Sentinel workspaces", "workspaces", len(all), "withSentinel", len(f.sentinel))
	})
	return f.sentinel, f.sentinelErr
}
