// datafetch is the data collectors and health checkers behind the
// dashboard, in one program:
//
//	datafetch <tool> [flags]
//
// Each tool writes to MongoDB what its part of the dashboard reads, and is
// configured from Azure App Configuration under its own key beneath
// "datafetching" (see the README).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/jercle/datafetch/azconfigdrift"
	"github.com/jercle/datafetch/azstorage"
	"github.com/jercle/datafetch/azurecves"
	"github.com/jercle/datafetch/dmarcreporting"
	"github.com/jercle/datafetch/internal/settings"
	"github.com/jercle/datafetch/internal/version"
	"github.com/jercle/datafetch/mdetracker"
	"github.com/jercle/datafetch/nscheck"
	"github.com/jercle/datafetch/sxgcheck"
)

type tool struct {
	name string
	// key is the tool's sub-key under "datafetching" in App Configuration.
	key  string
	what string
	main func(ctx context.Context, args []string) error
}

var tools = []tool{
	{azconfigdrift.Name, settings.AzConfigDrift, "snapshots of Azure and Microsoft 365 configuration, with baselines and drift", azconfigdrift.Main},
	{azstorage.Name, settings.AzStorage, "storage accounts, blob containers and managed disks, with their sizes", azstorage.Main},
	{azurecves.Name, settings.AzureCVEs, "Azure resources, Defender devices, their software and CVEs, as a graph", azurecves.Main},
	{dmarcreporting.Name, settings.DMARCReporting, "DMARC failure and aggregate reports from an Exchange Online mailbox", dmarcreporting.Main},
	{mdetracker.Name, settings.MDETracker, "which Defender for Endpoint org each VM is onboarded to", mdetracker.Main},
	{nscheck.Name, settings.NSCheck, "health checks of Citrix NetScaler appliances", nscheck.Main},
	{sxgcheck.Name, settings.SXGCheck, "health checks of Sophos XG firewalls and proxies", sxgcheck.Main},
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage: datafetch <tool> [flags]")
	fmt.Fprintln(w, "\ntools:")
	for _, t := range tools {
		fmt.Fprintf(w, "  %-16s %s\n", t.name, t.what)
	}
	fmt.Fprintln(w, "\nApp Configuration keys (with AZURE_APPCONFIG_ENDPOINT set):")
	for _, t := range tools {
		fmt.Fprintf(w, "  %-16s %s.*\n", t.name, settings.Key(t.key))
	}
	fmt.Fprintln(w, "\ndatafetch <tool> -h lists a tool's flags; datafetch version prints the version.")
}

func find(name string) *tool {
	for i := range tools {
		if tools[i].name == name {
			return &tools[i]
		}
	}
	return nil
}

func main() {
	args := os.Args[1:]
	// A link or copy named after a tool runs that tool: az-storage -loop.
	name := filepath.Base(os.Args[0])
	if ext := filepath.Ext(name); ext == ".exe" {
		name = name[:len(name)-len(ext)]
	}
	t := find(name)
	if t == nil {
		if len(args) == 0 {
			usage(os.Stderr)
			os.Exit(2)
		}
		switch args[0] {
		case "-h", "-help", "--help", "help":
			usage(os.Stdout)
			return
		case "version", "-version", "--version":
			fmt.Println(version.Version)
			return
		}
		if t = find(args[0]); t == nil {
			fmt.Fprintf(os.Stderr, "datafetch: there is no tool %q\n\n", args[0])
			usage(os.Stderr)
			os.Exit(2)
		}
		args = args[1:]
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := t.main(ctx, args)
	stop()
	switch {
	case err == nil:
	case errors.Is(err, flag.ErrHelp):
		// The flag set has printed its usage.
	default:
		fmt.Fprintf(os.Stderr, "%s: %v\n", t.name, err)
		os.Exit(1)
	}
}
