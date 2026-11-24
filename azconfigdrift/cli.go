// Package azconfigdrift is the az-config-drift command. It takes snapshots
// of the configuration of Azure and Microsoft 365 tenants: every Azure
// resource, policy and role assignment, and the Entra ID, Conditional
// Access, Intune, SharePoint, Teams and Exchange Online settings that the
// APIs expose. The settings, every change between two passes and how each
// object compares with a saved baseline go to MongoDB, with the collector's
// own logs and run history.
//
// It is configured from the dashboard: the settings live in Azure App
// Configuration under the key datafetching.azConfigDrift and win over the
// configuration file, which fills in the rest. This command is a thin
// wrapper around the driftchecker package.
package azconfigdrift

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/jercle/datafetch/azconfigdrift/driftchecker"
	"github.com/jercle/datafetch/internal/cli"
	"github.com/jercle/datafetch/internal/version"
)

// Name is the command: datafetch az-config-drift.
const Name = "az-config-drift"

// Main runs the command with its arguments, until it is done or ctx is
// cancelled.
func Main(ctx context.Context, args []string) error {
	fs := cli.Flags(Name)
	var (
		configPath  = fs.String("config", cli.DefaultConfig(Name), "path to the configuration file; optional when App Configuration has the tenants and the MongoDB address")
		loop        = fs.Bool("loop", false, "keep running: collect, wait for the configured interval or a request from the dashboard, collect again")
		dryRun      = fs.Bool("dry-run", false, "collect once and print what would be stored as JSON lines; reads and writes no database")
		initDB      = fs.Bool("init-db", false, "create the MongoDB indexes (and apply retention changes), then exit")
		only        = fs.String("modules", "", "comma-separated module ids to collect, whatever their switches say")
		tenantName  = fs.String("tenant", "", "collect only the tenant of this name")
		noAppConfig = fs.Bool("no-app-config", false, "ignore AZURE_APPCONFIG_ENDPOINT and run on the configuration file alone")
		listModules = fs.Bool("list-modules", false, "print the modules and their sources, then exit")
		logFile     = fs.String("log-file", "", "append the local log to this file instead of stderr")
		showVersion = fs.Bool("version", false, "print the version and exit")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		fmt.Println(version.Version)
		return nil
	}
	if *listModules {
		return driftchecker.ListModules(os.Stdout, *configPath)
	}

	logOut, done, err := cli.LogOutput(*logFile)
	if err != nil {
		return err
	}
	defer done()

	o := driftchecker.Options{
		ConfigFile: *configPath, Loop: *loop, DryRun: *dryRun, InitDB: *initDB, Tenant: *tenantName,
		Version: version.Version, LogOutput: logOut,
	}
	for _, id := range strings.Split(*only, ",") {
		if id = strings.TrimSpace(id); id != "" {
			o.Modules = append(o.Modules, id)
		}
	}
	if !*noAppConfig {
		// The settings the dashboard edits, when the environment says where.
		fn, ok, err := driftchecker.AppConfig(os.Getenv)
		if err != nil {
			return err
		}
		if ok {
			o.Settings, o.SettingsSource = fn, "appconfig"
		}
	}
	if !cli.Given(fs, "config") {
		// The default path is a place to look, not a file that must exist.
		if _, err := os.Stat(*configPath); err != nil {
			o.ConfigFile = ""
		}
	}
	return driftchecker.Run(ctx, o)
}
