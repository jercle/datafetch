# datafetch

The Go data collectors and health checkers behind the dashboard, in one
module and one program. Each used to be a repository of its own; each still
writes to the same MongoDB collections its part of the dashboard reads.

| Command | What it does | App Configuration key | Merged from | Its own documentation |
|---|---|---|---|---|
| `datafetch az-config-drift` | Snapshots of Azure and Microsoft 365 configuration, with baselines and drift | `datafetching.azConfigDrift` | `jercle/az-config-drift` at `adde807` | [azconfigdrift/README.md](azconfigdrift/README.md) |
| `datafetch az-storage` | Storage accounts, blob containers and managed disks, with their sizes | `datafetching.azStorage` | `jercle/az-storage` at `49359f1` | [azstorage/README.md](azstorage/README.md) |
| `datafetch azure-cves` | Azure resources, Defender devices, their software and CVEs, as a graph | `datafetching.azureCves` | `jercle/azure-cves` at `7f871ff` | [azurecves/README.md](azurecves/README.md) |
| `datafetch dmarc-reporting` | DMARC failure and aggregate reports from an Exchange Online mailbox | `datafetching.dmarcReporting` | `jercle/dmarc-reporting` at `55f8b76` | [dmarcreporting/README.md](dmarcreporting/README.md) |
| `datafetch mde-tracker` | Which Defender for Endpoint org each VM is onboarded to | `datafetching.mdeTracker` | `jercle/mde-tracker` at `05c0a4d` | [mdetracker/README.md](mdetracker/README.md) |
| `datafetch ns-check` | Health checks of Citrix NetScaler appliances | `datafetching.nsCheck` | `jercle/ns-check` at `da41fba` | [nscheck/README.md](nscheck/README.md) |
| `datafetch sxg-check` | Health checks of Sophos XG firewalls and proxies | `datafetching.sxgCheck` | `jercle/sxg-check` at `abb1bd9` | [sxgcheck/README.md](sxgcheck/README.md) |

```
datafetch <tool> [flags]      # datafetch <tool> -h lists a tool's flags
datafetch help                # the tools and their App Configuration keys
datafetch version
```

A link or copy of the program named after a tool runs that tool, so
`az-storage -loop` keeps working where a unit or a script calls it that way.

## Configuration: Azure App Configuration

Every tool is configured the way az-config-drift always was. Before every
pass a tool puts its configuration together from, in this order:

1. **Its settings in Azure App Configuration**, under its own key beneath
   the root `datafetching`.
2. **Its configuration file** (`-config`), for whatever the settings do not
   say. The file is optional when the settings supply everything.
3. **Built-in defaults.**

It works setting by setting. A setting that is not valid (an interval of
"soon", a key that is not a setting) is left out with a warning in the log,
and the file's value or the default stands. If the settings cannot be read
at all when a tool starts, or the result is not a usable configuration, it
starts on the file alone and says why. Once a tool is running, settings
that cannot be read or used leave the configuration it has in place: a
store that is out of reach for a moment does not take away what only the
settings define.

Each tool reads the MongoDB address, its logging settings and its heartbeat
when it starts. Everything else applies from the next pass.

### Where the settings are read from

App Configuration is read when `AZURE_APPCONFIG_ENDPOINT` is set. The
variables are the ones cloudini and the dashboard use:

| Variable | |
|---|---|
| `AZURE_APPCONFIG_ENDPOINT` | `https://<store>.azconfig.io` |
| `AZURE_APPCONFIG_TENANT_ID`, `_CLIENT_ID`, `_CLIENT_SECRET` | A service principal, or |
| `AZURE_APPCONFIG_MANAGED_IDENTITY` | the client ID of a user-assigned identity, or `system` |
| `AZURE_APPCONFIG_LABEL` | Optional. Values with this label win over those without |

The identity needs App Configuration Data Reader on the store, and Key
Vault Secrets User on any vault a setting refers to. A Key Vault reference
is resolved, and only followed to an Azure Key Vault address. Every tool
has `-no-app-config` to ignore the endpoint.

### The keys

A key is `datafetching.<tool key>.` followed by the path of the setting in
the tool's configuration file, joined with ".":

```
datafetching.azStorage.interval                              = 12h
datafetching.azStorage.concurrency.accounts                  = 16
datafetching.azStorage.tenants.<tenant id>.clientSecret      = (Key Vault reference)
datafetching.nsCheck.appliances.ns-prod-01.address           = https://10.0.0.10
datafetching.sxgCheck.defaults.tcp.ports                     = 4444, 3128
datafetching.mdeTracker.tenants.Contoso.auth.clientId        = ...
datafetching.dmarcReporting.pollInterval                     = 10m
```

Values may be typed (content type `application/json`) or plain text: `4`,
`true` and `a, b` are read as the number, the switch and the list either
way. A list or an object can also be stored whole, as JSON.

**Lists of objects** (tenants, appliances, firewalls) can be given one
group of keys per entry, by the field that identifies it. The entry is
merged into the file's entry of that identity, field by field, or added.
Given as a JSON array instead, the list replaces the file's.

| Tool | List | One group of keys per |
|---|---|---|
| az-config-drift, az-storage, azure-cves | `tenants` | tenant ID: `tenants.<tenant id>.<field>` |
| mde-tracker | `tenants` | tenant name: `tenants.<name>.<field>` |
| ns-check | `appliances` | appliance name |
| sxg-check | `firewalls` | firewall name |

"." separates the parts of a key, so a name with a "." in it can only be
set through the JSON array form or the file.

A secret given in App Configuration replaces the environment variable the
file names for it (`clientSecret` over `clientSecretEnv`).

### What differs between the tools

- **az-config-drift** validates its settings against its own list, with
  ranges, and reports them on the dashboard's Collector page; its module
  switches are in MongoDB. Its settings used to be under
  `azureDriftChecker`: that key is still read while
  `datafetching.azConfigDrift` has nothing, with a warning. See
  [its README](azconfigdrift/README.md).
- **dmarc-reporting** has no configuration file: the environment variables
  are its file, and the settings win over them.
- **azure-cves** also reads its environment variables (`MONGO_URI`,
  `AZCVES_*`), which override both the settings and the file, as they
  overrode the file before.
- **mde-tracker** expands `${ENV_VAR}` references in its file, not in
  values from App Configuration.
- The other tools' own variables (`AZSTORAGE_MONGO_URI`,
  `NSCHECK_APPLIANCES`, ...) work as before, and override the settings.

## Build

```sh
make test       # go vet and go test -race
make build      # ./datafetch
make linux      # dist/datafetch, static
make windows    # dist/datafetch.exe
docker build -t datafetch --build-arg VERSION=1.2.3 .
```

The image's entry point is `datafetch`: the tool is the first argument
(`args: ["mde-tracker", "-once"]`). `go.mod` asks for Go 1.27.4 or later.

## Moving from the separate repositories

- The programs `az-config-drift`, `az-storage`, `ns-check`, `sxg-check`,
  `azure-cves-collector`, `mde-collector` and `dmarc-collector` are now
  `datafetch <tool>`, with the flags they had. Each gained `-no-app-config`,
  and those that had none gained `-version`.
- Without `-config`, a tool looks for `<tool>.json` next to the executable
  (`az-storage.json`) rather than `config.json`, and does not mind when it
  is not there. mde-tracker still reads `MDE_CONFIG`, azure-cves
  `AZCVES_CONFIG`.
- Collections, document shapes, MongoDB application names and environment
  variables are unchanged, so the dashboard modules read what they read
  before.
- The version is one for all tools, set at build time
  (`-X github.com/jercle/datafetch/internal/version.Version=...`).
- All tools now build against the same libraries: azure-cves, mde-tracker
  and dmarc-reporting moved from MongoDB driver v2.2.2 to v2.3.0.
- The Svelte dashboard modules were not merged. They are in the original
  repositories. az-config-drift's dashboard module writes its settings to
  `azureDriftChecker` until it is pointed at `datafetching.azConfigDrift`.

## Layout

```
cmd/datafetch        the program: one subcommand per tool
internal/appconfig   Azure App Configuration reader (REST, Key Vault references)
internal/settings    the root key, the tools' keys, laying settings over a file
internal/cli         what the commands share
<tool>/cli.go        the tool's command and its settings (Spec)
<tool>/internal      the tool's packages, as they were in its repository
<tool>/deploy        example configuration, systemd unit or Kubernetes manifest, Terraform
```

`azconfigdrift/driftchecker` and `azurecves/pkg` are importable, for a
program that runs those collectors in-process.

## What has and has not been run

- **Tested** (`go test -race ./...`): every tool's own tests as they were,
  the shared settings package, and each tool's settings laid over its
  example configuration and used with no file at all.
- **Run** in `-dry-run` and `-check` against a stand-in for App
  Configuration and the managed identity endpoint: settings read, a
  setting changed between two passes of `ns-check -loop` picked up, an
  invalid one ignored with a warning.
- **Compiled, not run:** the MongoDB stores of all seven tools, against the
  real driver. Nothing here has been run against MongoDB, Azure, Microsoft
  365, a NetScaler or a Sophos firewall; each tool's README says what that
  means for it.
