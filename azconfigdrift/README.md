# az-config-drift

> **Part of [datafetch](../README.md).** Merged from `jercle/az-config-drift` at `adde807`.
> Run it as `datafetch az-config-drift`. Its settings in Azure App Configuration are
> under `datafetching.azConfigDrift` and win over the configuration file; how that works,
> the environment variables and how to build are in the root README.
> The dashboard modules this document mentions were not merged: they are
> still in `jercle/az-config-drift`.

A Go service that takes snapshots of the configuration of Azure and
Microsoft 365 tenants and writes them to MongoDB:

- every **Azure** resource with its properties, plus policy, role
  assignments, locks and Defender for Cloud settings;
- the **Microsoft 365** settings the APIs expose: Entra ID, Conditional
  Access, roles and PIM, applications, identity governance, Intune,
  SharePoint, Teams apps, information protection and Exchange Online.

It is split into **modules**, one per category of settings. Each module can
be switched on and off from the dashboard, and so can each source inside it.
The whole collector is configured from the dashboard. Its general and
tenant settings live in **Azure App Configuration** under the key
`datafetching.azConfigDrift`, the module and source switches in **MongoDB**, and
both win over the configuration file. Every change made in the dashboard is
recorded in its audit log.
Every pass records what changed since the pass before, and marks how each
object compares with the **baseline** saved in the dashboard. Its own logs,
run history and heartbeat go to MongoDB too.

Two SvelteKit / Svelte 5 modules in [`dashboard/`](dashboard/README.md) show
the settings, the drift against the baseline, the changes, the baselines,
the module switches and the collector's configuration, and the collector's
logs.

It follows the layout of the other collectors (az-storage, sxg-check,
tf-ingest): standard library plus the MongoDB driver, a tenants array,
`acd_*` collections, a log sink that survives MongoDB being down.

## What has and has not been run

Written without network access, so:

- **Tested** (`go test -race ./...`, against a stand-in for Entra ID,
  Resource Manager, Resource Graph, Microsoft Graph and Exchange Online, and
  an in-memory store): configuration, the catalogue, normalisation and
  diffing, every kind of source, paging, the whole pass including changes,
  drift against a baseline, failures, switches, the log sink and run
  records.
- **Compiled, not run**: `internal/store/mongostore`, `driftchecker.Run` and
  the command are built against the real MongoDB driver (v2.3.0) in
  datafetch, but have not been run against a database. Loading and merging
  the configuration is tested; the loop that reloads it before each pass is
  not.
- **App Configuration:** the reader (`internal/appconfig`) is tested against
  a stand-in for the REST API, Entra ID, the managed identity endpoint and
  Key Vault, not against a real store. What the dashboard writes is checked
  against what the collector reads through a shared fixture.
- **Never run against a tenant.** The paths, API versions and permissions in
  the catalogue are from memory of the documentation. Expect some sources to
  come back "Not available" or "No permission" on the first pass; the
  dashboard shows the error for each, and each can be switched off or
  corrected in one line of `internal/catalog`.
- **The Exchange Online module** uses the REST endpoint behind the Exchange
  Online PowerShell module (`/adminapi/beta/<tenant>/InvokeCommand`), which
  Microsoft does not document for direct use. It is off by default.

Start with a dry run, which reads the tenants and prints what would be
stored without touching a database:

```
datafetch az-config-drift -dry-run -tenant "Contoso Production" -modules m365-conditional-access,azure-network
```

## What "all configuration" means here

| Module | On | Reads |
|---|---|---|
| `azure-governance` | yes | Management groups, subscriptions, resource groups, policy assignments, custom policy and initiative definitions, exemptions, locks |
| `azure-access` | yes | Role assignments at every scope, custom roles, classic administrators, managed identities |
| `azure-network` | yes | Everything under `Microsoft.Network`, `Microsoft.Cdn` |
| `azure-compute` | yes | VMs, scale sets, disks, AKS, container apps, registries, Virtual Desktop, Arc |
| `azure-data` | yes | Storage, SQL, Cosmos DB, PostgreSQL, MySQL, Redis, Data Factory, Synapse, Databricks, backup vaults |
| `azure-security` | yes | Key vaults, Defender for Cloud plans, settings, contacts, Sentinel resources |
| `azure-monitoring` | yes | Log Analytics, alerts, action groups, data collection rules, Automation, subscription diagnostic settings |
| `azure-apps` | yes | App Service, API Management, Logic Apps, Service Bus, Event Hubs, Event Grid, AI and IoT services |
| `azure-other` | yes | **Every resource type no other module reads** |
| `m365-identity` | yes | Organisation, domains, authorisation and authentication-method policies, security defaults, cross-tenant access, consent, token and app policies, directory settings |
| `m365-conditional-access` | yes | Policies, named locations, authentication contexts and strengths |
| `m365-roles` | yes | Role definitions, active and eligible assignments, PIM role settings |
| `m365-applications` | yes | App registrations, enterprise applications each with the delegated permissions granted to it, managed identities (a type of their own) |
| `m365-groups` | no | The settings of every group (not members), expiry policy |
| `m365-governance` | yes | Access reviews, entitlement management, terms of use, lifecycle workflows |
| `m365-intune` | yes | Compliance and configuration policies, settings catalogue, administrative templates, endpoint security, enrolment, Autopilot, update profiles, scripts, app protection and configuration |
| `m365-collaboration` | yes | SharePoint and OneDrive tenant settings, Teams app settings and organisation apps, Microsoft 365 apps and org-wide settings |
| `m365-information-protection` | yes | Sensitivity labels, label policy settings, retention labels |
| `m365-exchange` | no | Organisation and transport configuration, mail flow rules, connectors, domains, anti-spam, anti-malware, anti-phishing, Safe Links, Safe Attachments, DKIM, sharing and device policies |

`datafetch az-config-drift -list-modules` prints all 144 sources with what each
reads and the permission it needs.

**Azure is complete by construction.** Azure Resource Graph returns the
properties of every resource in a tenant, and the catch-all module takes
whatever the others do not claim. What Resource Graph does not hold is not
collected: settings of child objects that are not resources of their own
(blob service properties, App Service app settings, per-resource diagnostic
settings), and anything in the data plane (key vault secrets, storage
contents).

**Microsoft 365 is limited to what has an API.** Not collected, because
there is no application-permission API for them: Teams policies (meeting,
messaging, calling), data loss prevention and retention policies, Defender
XDR settings, Power Platform. Those need PowerShell modules.

To add something without changing code, use `extraSources` in the
configuration: a Resource Graph query, a Resource Manager path or a Graph
path. See `deploy/config.example.json`.

## How a pass works

For every tenant, modules that are switched on run side by side
(`concurrency.modules`), their sources one after another. For each source:

1. Read everything, following pages. A Resource Manager list may answer as
   `{"value": [...]}`, as a bare array or as a single object
   (`securityContacts` does all three, depending on the version); each is
   read the same way. Throttling (429, `Retry-After`), 5xx
   and transport errors are retried up to seven times.
2. **Normalise** each object so that it can be compared: remove properties
   that change by themselves (etags, `provisioningState`, modification
   times, VM power state — the list is in `internal/catalog/catalog.go`,
   extended by `ignore` in the configuration), remove nulls and OData
   annotations, replace anything named like a secret by a fingerprint, sort
   lists of plain values and lists of objects that each have an id or name,
   and write the result as JSON with sorted keys.
3. Hash it. An object whose hash is unchanged is only marked as seen. A new
   or changed one is stored, and a **change record** is written with the
   settings that differ (`added`, `changed`, `removed`).
4. When the source was read to the end, objects that were not seen are
   gone: a `removed` change is recorded. If the source fails part-way,
   nothing is removed.
5. Set how each object compares with the baseline (below).

A source read for the first time records no changes: everything would be
"added".

A source that fails does not stop the others. Its outcome is one of:

| Outcome | Meaning | Makes the pass "partial" |
|---|---|---|
| `ok` | Read completely | |
| `denied` | 401 or 403: the permission is missing | no |
| `unsupported` | 400, 404 or 501: not available in this tenant (no licence, not in this cloud) | no |
| `failed` | Anything else, or took longer than `limits.sourceTimeout` | yes |
| `disabled` | Switched off | |

Missing permissions and licences do not make a pass partial, because they
would do so for ever. They are counted, shown on the monitor, and listed
per source under Modules in the dashboard, where the source can be switched
off. A tenant none of whose sources could be read has failed.

### Sorting lists

Sorting makes `["b","a"]` and `["a","b"]` equal, which is right for sets
(member ids, scopes, address prefixes) and what stops an API's changing
order from showing as drift. It also hides a reordering that matters: DNS
servers, for example. Lists of objects without an id or name keep their
order.

### Expect noise at first

The built-in ignore list is a starting point. After the second pass, open
Changes in the dashboard: a property that changes on every pass without
anyone touching it belongs in `ignore`. Changing the ignore list changes
the stored settings, so the next pass records one change for every object
it affects.

### Names for identifiers

Role assignments, permission grants and the like hold identifiers, not
names. The collector looks the names up once per pass and stores them
beside the settings, so the dashboard shows `f5116e97-… (Microsoft Graph)`
wherever such an identifier is a value:

- **Principals** (users, groups, service principals, devices) from
  Microsoft Graph, which needs `Directory.Read.All`, also for a tenant
  collected for Azure only;
- **Azure role definitions** from Resource Graph, **Entra ID role
  definitions** from Graph, and a subscription scope from the
  subscription list.

A role assignment is titled after them: `Alice Smith · Contributor ·
Production`. The names are not part of the settings that are compared: a
principal being renamed relabels the objects that name it without
recording a change. A name that cannot be looked up is left out, with one
warning in the log, and the identifier shows as it is.

**Delegated permission grants** are not objects of their own. Each is
stored inside the enterprise application (or managed identity) it was
granted to, under `oauth2PermissionGrants`, with the resource it is for
named. Reading them needs `Directory.Read.All`; without it the
applications are stored without that property.

### Leaving objects out

`exclude` lists objects that should not be checked at all: the network
watchers Azure makes by itself, the resource groups AKS manages, anything
another team owns. Set it on the dashboard's Collector page ("Objects to
leave out") or in the file:

```json
"exclude": [
  { "module": "azure-network", "type": "microsoft.network/networkwatchers" },
  { "resourceGroup": "mc_*" },
  { "type": "microsoft.network/privateendpoints", "resourceGroup": "rg-shared-*" }
]
```

An object is left out when every field of a rule matches, in any letter
case: `type` by how the type starts, `resourceGroup` and `name` exactly,
and `*` stands for any text in all three. `module` narrows a rule to one
module. From the next pass such objects are no longer stored or compared
with the baseline, and they are not recorded as removed. To leave out a
property rather than an object, use `ignore`.

### After upgrading

The pass after an upgrade that changes what a source stores records those
differences as changes, once. With this version: enterprise applications
gain `oauth2PermissionGrants`, managed identities move from "Enterprise
applications" to a source of their own (removed there, added here), and
the objects of the former "Delegated permission grants" source are
deleted. Save a new baseline afterwards. Objects of any source that is no
longer in the catalogue, such as an extra source taken out of the
configuration, are deleted at the next pass.

## Baselines and drift

A baseline is saved from the dashboard. It is a copy of every object's
settings at that moment (`acd_baseline_items`), made inside MongoDB. The
newest complete baseline is the one in use; saving a new one replaces it.

After each pass, and when a baseline is saved, every object has one state:

| State | Meaning |
|---|---|
| `same` | Its settings are those of the baseline |
| `changed` | They differ |
| `added` | The object is not in the baseline, though its source was read before the baseline was saved |
| `removed` | In the baseline, gone from the tenant. The object is kept, marked `present: false`, so it can still be shown |
| `untracked` | No baseline, or the baseline was saved before this source was first read (a module switched on later). The next baseline includes it |

Changes between passes (`acd_changes`) are a separate record: they say what
happened and when, whatever the baseline.

Switching a module off stops it being read. What it stored stays, with the
state it had.

## Beta or v1.0, application or service account

Each source has its choices under Modules in the dashboard (open a module
to see its sources), with a default in the catalogue:

- **Service account**, on every source, Azure and Microsoft 365. Read as a
  user instead of as the application, for endpoints that have no
  application permission. Only terms of use defaults to it (Microsoft
  documents its list as delegated only); switch any other source that is
  refused as the application.
- **Beta API**, on Microsoft Graph sources. Read from `/beta` or from
  `/v1.0`. Sources that only exist in beta default to beta. Switch one to
  v1.0 when the endpoint has reached it, or to beta when v1.0 returns less
  than you need. Resource Manager, Resource Graph and Exchange Online have
  no beta version, so their sources show "No beta".

The versions return different properties, so switching one usually records
a change for each of the source's objects on the next pass, and shows them
as differing from the baseline until a new one is saved.

For the service account, give the tenant a `username` and a `password` on
the dashboard's Collector page (or `username` with `password` or
`passwordEnv` in the file). The collector signs in with them
directly (the OAuth resource owner password flow), which sets conditions:

- the account **cannot have MFA** or any Conditional Access policy that
  needs interaction: exclude it and restrict it another way, for example to
  the collector's address;
- it must be a cloud-only or password-hash-synchronised account, not
  federated;
- the delegated permission of each such source needs **admin consent** on
  the application, and the account needs a directory role that may read
  the data: Global Reader covers everything here;
- for an Azure source, the application needs the delegated permission
  `user_impersonation` on Azure Service Management, and the account needs
  Reader on the subscriptions. The list of subscriptions itself is still
  read as the application; for an Exchange Online source the account needs
  an Exchange role that may run the cmdlet;
- by default it signs in to the collector's own application, with its
  secret. To use a separate public client application instead, set
  `delegatedClientId` and turn on "Allow public client flows" on it.

The password is never logged or stored in MongoDB. Set from the dashboard,
it is stored in App Configuration: use a Key Vault reference. A source set to the
service account in a tenant without one, or whose sign-in fails, is
recorded as `denied` with the reason, like a missing permission.

## Configuration: the dashboard first, then the file

Before every pass the collector puts its configuration together from three
places, in this order:

1. **The settings in Azure App Configuration**, under
   `datafetching.azConfigDrift`.
   The dashboard creates any key that is missing there with the value the
   collector already runs with (never secrets), so after the first pass the
   whole configuration is in App Configuration to see and edit.
   This is what the dashboard's Collector page edits.
2. **The configuration file** (`-config`), for whatever the settings do not
   say. It is optional when the settings supply the tenants and the MongoDB
   address.
3. **Built-in defaults.**

The **module and source switches** are apart from this: the dashboard
stores them in MongoDB (`acd_module_settings`), and the collector reads
them before every pass and lays them over whatever the three places above
say. See "Modules and the dashboard".

It works setting by setting. A tenant in the file can have one field
overridden from the dashboard and keep its credentials from the file; a
setting that is not valid (an interval of "soon", a tenant without
credentials) is left out with a warning and the file's value or the default
stands. If the settings cannot be read at all, or the result is not a
usable configuration, the collector runs on the file alone. Either way it
says so: in its log, and on the dashboard's Collector page, which shows
where each collector got its configuration from, when, and which settings
it did not use.

The MongoDB address, the log levels and the heartbeat are read when the
collector starts. Everything else applies from the next pass.

### The keys

Keys are "."-separated under the root. Values may be typed (content type
`application/json`, which is what the dashboard writes for numbers,
switches and lists) or plain text: `4`, `true` and `azure, m365` are read
either way. A secret can be a Key Vault reference.

| Key under `datafetching.azConfigDrift.` | |
|---|---|
| `interval`, `heartbeatInterval` | Durations: `6h`, `30s` |
| `concurrency.tenants`, `concurrency.modules` | |
| `retention.logsDays`, `.runsDays`, `.changesDays` | |
| `logging.level`, `.mongoLevel`, `.format` | |
| `limits.maxItemBytes`, `.changePaths`, `.sourceTimeout` | |
| `mongo.uri`, `mongo.database`, `mongo.ensureIndexes` | |
| `tenants.<tenant id>.tenantName`, `.clientId`, `.clientSecret`, `.cloud`, `.platforms`, `.subscriptions`, `.excludeSubscriptions`, `.initialDomain`, `.username`, `.password`, `.delegatedClientId`, `.enabled` | One group per tenant, by its ID. `enabled` = `false` leaves a tenant out, including one from the file |
| `modules.<module>.enabled`, `modules.<module>.sources.<source>.enabled`, `.beta`, `.delegated` | The switches, as earlier versions stored them. The dashboard no longer writes these: the switches are in MongoDB. A collector still reads them, for a switch MongoDB does not set |
| `ignore`, `exclude`, `extraSources` | JSON lists, as in the file. They replace the file's lists |
| `skipSources` | A list of `module/source` |

The same structure works in the file: `"modules": {"m365-exchange":
{"enabled": true}}`.

**Moved from `azureDriftChecker`.** Before the merge into datafetch these
keys were under `azureDriftChecker.`. While nothing exists under
`datafetching.azConfigDrift.`, the collector still reads the old key and
says so in a warning (in its log and on the dashboard's Collector page). As
soon as the new key has any setting, the old one is ignored. The dashboard
module in `jercle/az-config-drift` writes to the old key until it is
pointed at the new one.

### Where the collector gets the settings

**The standalone command** reads App Configuration itself when
`AZURE_APPCONFIG_ENDPOINT` is set, signed in as the environment says. The
variables are the ones cloudini uses:

| Variable | |
|---|---|
| `AZURE_APPCONFIG_ENDPOINT` | `https://<store>.azconfig.io` |
| `AZURE_APPCONFIG_TENANT_ID`, `_CLIENT_ID`, `_CLIENT_SECRET` | A service principal, or |
| `AZURE_APPCONFIG_MANAGED_IDENTITY` | the client ID of a user-assigned identity, or `system` |
| `AZURE_APPCONFIG_LABEL` | Optional. Values with this label win over those without. The dashboard never writes a label: it saves settings unlabelled, and removes a labelled value of a key it saves |

It needs App Configuration Data Reader on the store, and Key Vault Secrets
User on any vault a setting refers to. A reference is only followed to an
Azure Key Vault address. `-no-app-config` ignores the endpoint.

**Another program** that already has the configuration object passes it
in. The `driftchecker` package is the collector's public entry point:

```go
import "github.com/jercle/datafetch/azconfigdrift/driftchecker"

// In cloudini, with CldConfigRoot given a field
//   Datafetching map[string]any `json:"datafetching,omitempty"`
err := driftchecker.Run(ctx, driftchecker.Options{
	Loop:       true,
	ConfigFile: "", // optional fallback
	Settings: func(context.Context) (driftchecker.Settings, error) {
		// Called before every pass, so dashboard changes are picked up.
		return driftchecker.SettingsOf(lib.GetCldConfig(nil).Datafetching["azConfigDrift"])
	},
})
```

`Settings` is the object under `datafetching.azConfigDrift` as an App Configuration
provider builds it (nested objects from the "."-separated keys), or the
whole configuration object with that key in it. It is not modified.
`driftchecker.SettingsOf` turns a struct or JSON bytes into it, and
`driftchecker.FromKeyValues` a flat map of keys. This has not been wired
into cloudini; the field and the command there are yours to add.

## Modules and the dashboard

The switches are kept in MongoDB, in `acd_module_settings`: one document
per module, holding only the switches someone set in the dashboard.

```json
{ "_id": "m365-identity", "enabled": true,
  "sources": { "ca-policies": { "enabled": true, "beta": false, "delegated": true } },
  "updatedAt": "…", "updatedBy": "ann@contoso.com" }
```

Before every pass the collector reads them and, switch by switch, uses the
first of: this collection, the configuration (`modules` in the file, or
the `modules.*` keys an earlier version wrote to App Configuration), the
catalogue's default. If the collection cannot be read the pass does not
start, so that a module that was switched off is never collected by
mistake.

Earlier versions kept the switches in App Configuration. The first time
the Modules page opens with nothing in `acd_module_settings`, the dashboard
copies them over; the Collector page then offers to remove the old keys.

`acd_modules` in MongoDB holds one document per module: the catalogue and
the switches as the last pass used them, both rewritten by the collector at
every pass. Nothing reads switches from there; the dashboard uses it to
show the catalogue, and to tell when a switch has not taken effect yet.

With `-loop`, the collector also checks `acd_control` every heartbeat and
starts a pass when the dashboard's "Collect now" asked for one.

## Permissions

`deploy/terraform/permissions.tf` grants everything below to the collector's
service principal. It has not been planned or applied.

- **Azure:** Reader on the root management group. Reader on less sees less.
- **Microsoft 365:** Microsoft Graph application permissions, all read-only.
  The file lists the 32 the built-in modules use; `-list-modules` shows
  which source needs which. A missing one only makes its sources show as
  "No permission".
- **Service account:** the file also consents to the delegated permissions
  of the sources read that way by default (`delegated_permissions`, one so
  far). Add the permission of any source you switch over. Assigning the
  account a directory role is left to you.
- **Exchange Online** (if switched on): the `Exchange.ManageAsApp`
  permission of Office 365 Exchange Online, and the Global Reader directory
  role.

The collector only ever sends GET requests, Resource Graph queries, and the
Exchange `Get-` cmdlets in the catalogue.

## Build and run

```sh
make test      # from the repository root
make build     # ./datafetch
```

```
datafetch az-config-drift -config config.json              # one pass, then exit
datafetch az-config-drift -config config.json -loop        # a pass every `interval`, and on request
datafetch az-config-drift -dry-run                         # print what would be stored
datafetch az-config-drift -init-db                         # create the indexes, then exit
datafetch az-config-drift -list-modules                    # the catalogue
datafetch az-config-drift -no-app-config                   # the configuration file alone
datafetch az-config-drift -modules azure-network,m365-intune -tenant Contoso   # one-off, whatever the switches say
```

`deploy/az-config-drift.service` is a systemd unit for `-loop`.

Exit status is 1 when the pass failed (no tenant could be collected, or the
store could not be read), 0 otherwise.

## Configuration

This is the configuration file, the fallback for what App Configuration
does not set. `deploy/config.example.json` has every setting. Unknown
settings in the file are refused. Without `-config`,
`az-config-drift.json` next to the executable is read if it is there.

| Setting | Default | |
|---|---|---|
| `mongo.uri`, `mongo.database` | –, `azconfigdrift` | Or `AZCONFIGDRIFT_MONGO_URI`, `AZCONFIGDRIFT_MONGO_DATABASE` |
| `interval` | `6h` | Between passes with `-loop` |
| `concurrency.tenants`, `.modules` | 2, 3 | |
| `retention.logsDays`, `.runsDays`, `.changesDays` | 30, 90, 365 | TTL indexes; a negative value keeps for ever |
| `logging.level`, `.mongoLevel`, `.format` | `info`, `info`, `text` | Local log, what goes to `acd_logs`, `text` or `json` |
| `tenants[]` | – | `tenantName`, `tenantId`, `clientId`, `clientSecret` or `clientSecretEnv`; optional `cloud`, `platforms`, `subscriptions`, `excludeSubscriptions`, `initialDomain`, and for the service account `username`, `password` or `passwordEnv`, `delegatedClientId`. Or `AZCONFIGDRIFT_TENANTS` (JSON) / `AZCONFIGDRIFT_TENANTS_FILE` |
| `modules` | – | The switches: `{"<module>": {"enabled": false, "sources": {"<source>": {"enabled": false, "beta": true, "delegated": true}}}}` |
| `moduleDefaults` | – | Older, shorter form: `{"<module>": true}`. Counts where `modules` says nothing |
| `skipSources` | – | `module/source` never to read, whatever else says so |
| `ignore[]` | – | Properties to leave out: `paths`, optionally narrowed by `module`, `source`, `type` (prefix) |
| `exclude[]` | – | Objects to leave out: `type` (prefix), `resourceGroup`, `name`, with `*` for any text; optionally narrowed by `module` |
| `extraSources[]` | – | Sources of your own |
| `limits.maxItemBytes` | 4 MiB | Larger settings are not stored; changes are still detected |
| `limits.changePaths` | 100 | Differing settings listed per change |
| `limits.sourceTimeout` | `2h` | |

An ignore path without a dot (`etag`) matches a property of that name at any
depth; a dotted path (`properties.extended`) is from the top of the object,
with `*` for any one name. Names are compared without regard to case.

A tenant restricted with `subscriptions` or `excludeSubscriptions` is
queried per subscription, which leaves out what sits above subscriptions
(management groups, policy and role assignments at management-group scope).

## Logging

Every line goes to the local log (stderr or `-log-file`) and, at
`logging.mongoLevel` and above, to `acd_logs` with its tenant, module,
source and run. If MongoDB is unreachable the last 2,000 lines are kept and
sent when it returns; if more are lost, a line says how many.

Per pass: start and finish with totals; per tenant: subscriptions and
totals; per module: start and finish; per source: items read, added,
changed, removed, how many differ from the baseline, and the duration, or
the failure with the endpoint and the permission it needs. Long Resource
Graph reads log progress every minute, and waits of 30 seconds or more
before a retry are logged.

## Collections

Database `azconfigdrift` by default.

| Collection | One document per | Written by |
|---|---|---|
| `acd_modules` | module | collector: the catalogue and the switches the last pass used |
| `acd_module_settings` | module | dashboard: the module and source switches. Read by the collector before every pass |
| `acd_tenants` | tenant: outcome of each module and source | collector |
| `acd_items` | configuration object | collector; dashboard resets `drift` when a baseline is saved |
| `acd_changes` | object added, changed or removed between passes | collector |
| `acd_baselines`, `acd_baseline_items` | baseline, and object in it | dashboard |
| `acd_control` | (one document) | dashboard |
| `acd_runs`, `acd_logs`, `acd_instances` | pass, log line, collector (with where its configuration came from) | collector |

`acd_items`:

| Field | |
|---|---|
| `_id` | Hash of tenant, module, source and key: the same object always has the same id |
| `tenantId`, `tenantName`, `platform`, `module`, `source` | |
| `type`, `key`, `name` | Resource type or kind of object; resource ID or Graph id |
| `subscriptionId`, `subscriptionName`, `resourceGroup`, `location` | Azure only |
| `config` | The settings as canonical JSON, **a string**: setting names may contain `.` and `$`, which MongoDB field names handle badly |
| `hash`, `props` | SHA-256 of `config`; number of settings |
| `text`, `sortName` | For the dashboard's search and sorting |
| `present`, `firstSeenAt`, `lastSeenAt`, `changedAt`, `removedAt`, `runId` | |
| `drift` | `{ baselineId, status }` |

`acd_changes`: `at`, `runId`, the object's identity, `kind`, `paths[]`
(`path`, `kind`, `before`, `after` as JSON, shortened at 400 characters),
`pathCount`, `hashBefore`, `hashAfter`.

The Go types in `internal/model/model.go` are the full reference.

## Regenerating the dashboard's test fixtures

The dashboard lives in `jercle/az-config-drift`. Two of its files are
copied to `internal/settings/testdata` (`settings.fields.ts` and the
`settings.json` fixture) so that the tests here still check what the
dashboard writes against what the collector reads: copy them again when the
dashboard's settings change.

```
ACD_DUMP=<az-config-drift checkout>/dashboard/test/fixtures go test ./azconfigdrift/internal/collector -run TestDumpForDashboard
```
