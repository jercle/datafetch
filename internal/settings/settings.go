// Package settings is how every datafetch tool is configured from Azure
// App Configuration, the way az-config-drift always was: the settings kept
// there are laid over the tool's configuration file. A setting that is
// present and valid wins; one that is absent or invalid leaves the file's
// value, or the built-in default, in place and is named in a warning.
//
// Every tool has its own sub-key under one root:
//
//	datafetching.azConfigDrift.interval          = 6h
//	datafetching.nsCheck.appliances.ns1.address  = https://10.0.0.10
//	datafetching.azStorage.concurrency.tenants   = 4
//
// The keys beneath a tool's sub-key are the paths of its configuration
// file, joined with ".". Values may be typed (content type
// application/json) or plain text: "4", "true" and "a, b" are read as the
// number, the boolean and the list. Key Vault references are resolved.
package settings

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/jercle/datafetch/internal/appconfig"
)

// Root is the key every tool's settings live under in App Configuration.
const Root = "datafetching"

// The sub-key of each tool under Root.
const (
	AzConfigDrift  = "azConfigDrift"
	AzStorage      = "azStorage"
	AzureCVEs      = "azureCves"
	DMARCReporting = "dmarcReporting"
	MDETracker     = "mdeTracker"
	NSCheck        = "nsCheck"
	SXGCheck       = "sxgCheck"
)

// Key is the full key of a tool's settings: datafetching.<tool>.
func Key(tool string) string { return Root + "." + tool }

// Nest turns flat "."-separated keys into the nested object. A key that is
// both a value and a parent ("a" and "a.b") keeps the children.
func Nest(flat map[string]any) map[string]any {
	keys := make([]string, 0, len(flat))
	for k := range flat {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	root := map[string]any{}
	for _, k := range keys {
		parts := strings.Split(k, ".")
		node := root
		for _, p := range parts[:len(parts)-1] {
			child, ok := node[p].(map[string]any)
			if !ok {
				child = map[string]any{}
				node[p] = child
			}
			node = child
		}
		node[parts[len(parts)-1]] = flat[k]
	}
	return root
}

// Under returns a tool's settings object from the object itself, from the
// object under the root ({"azStorage": {...}}), or from a whole
// configuration object ({"datafetching": {"azStorage": {...}}}).
func Under(obj map[string]any, tool string) map[string]any {
	if root, ok := obj[Root].(map[string]any); ok {
		if inner, ok := root[tool].(map[string]any); ok {
			return inner
		}
		return map[string]any{}
	}
	if inner, ok := obj[tool].(map[string]any); ok {
		return inner
	}
	return obj
}

// Fetch returns a tool's current settings object, and what could not be
// read of it (Key Vault references that did not resolve).
type Fetch func(ctx context.Context) (settings map[string]any, warnings []string, err error)

// AppConfig returns a Fetch that reads a tool's settings from Azure App
// Configuration, signed in as the environment says: AZURE_APPCONFIG_ENDPOINT
// with AZURE_APPCONFIG_TENANT_ID, AZURE_APPCONFIG_CLIENT_ID and
// AZURE_APPCONFIG_CLIENT_SECRET, or AZURE_APPCONFIG_MANAGED_IDENTITY, and
// optionally AZURE_APPCONFIG_LABEL. ok is false when no endpoint is set.
func AppConfig(getenv func(string) string, tool string) (fetch Fetch, ok bool, err error) {
	o, ok, err := appconfig.FromEnv(getenv)
	if !ok || err != nil {
		return nil, ok, err
	}
	client := appconfig.New(o)
	return func(ctx context.Context) (map[string]any, []string, error) {
		ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		kv, warnings, err := client.Load(ctx, Key(tool)+".")
		if err != nil {
			return nil, nil, err
		}
		return Under(Nest(kv), tool), warnings, nil
	}, true, nil
}
