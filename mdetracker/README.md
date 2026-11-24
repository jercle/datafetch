# mde-tracker

> **Part of [datafetch](../README.md).** Merged from `jercle/mde-tracker` at `05c0a4d`.
> Run it as `datafetch mde-tracker`. Its settings in Azure App Configuration are
> under `datafetching.mdeTracker` and win over the configuration file; how that works,
> the environment variables and how to build are in the root README.
> The dashboard modules this document mentions were not merged: they are
> still in `jercle/mde-tracker`.

Collects onboarded VMs from several Microsoft Defender for Endpoint (MDE) tenants, works out
which **Defender org ID** each VM currently reports to, and writes the result, a run history and
structured logs to MongoDB.

## Setup

```bash
make build           # from the repository root: ./datafetch
cp mdetracker/deploy/config.example.json mde-tracker.json   # then edit
./datafetch mde-tracker -config mde-tracker.json -once
```

The config file is `-config`, or `MDE_CONFIG`, or `mde-tracker.json` next
to the executable. `${ENV_VAR}` references in it are replaced from the
environment.

### Settings in App Configuration

Every setting of the config file can also be set in Azure App
Configuration, under `datafetching.mdeTracker.` and by the same path:
`datafetching.mdeTracker.interval = 6h`,
`datafetching.mdeTracker.tenants.<name>.auth.clientSecret` (a Key Vault
reference works). They are read before every run and win over the file;
what is not valid is left out with a warning in the log. A tenant is one
group of keys under `tenants.<name>`, merged into the file's tenant of that
name or added (a name with a "." in it cannot be written this way);
`tenants` as a JSON array replaces the file's list. Values from App
Configuration are taken as they are: `${...}` in them is not expanded. The
MongoDB settings and the log levels are read at the start; a change to them
applies at the next restart. With App Configuration supplying the tenants
and `mongo.uri`, the file is optional. `-no-app-config` runs on the file
alone. See the root README.

`-once` runs one collection and exits (for a Kubernetes CronJob or Container App Job). Without it,
the service runs every `interval`. A non-zero exit code means the run failed or was partial.

### Per-tenant permissions

In each tenant, the app registration needs the **WindowsDefenderATP** API (`api.securitycenter.microsoft.com`)
application permission **`Machine.Read.All`**, with admin consent. One multi-tenant app consented
in every tenant works, as do separate apps per tenant.

Auth types per tenant: `secret`, `certificate` (PEM/PFX), `workload` (k8s workload identity
with a multi-tenant app and federated credential), and `default` (DefaultAzureCredential pinned to the tenant).
Use `${ENV_VAR}` in the config for secrets; a missing variable stops startup.

### Org IDs

The MDE machines API doesn't return the org ID, so each tenant's `orgId` is set in config.
You can find it in the Defender portal's settings, or in the `orgId` field of that tenant's
onboarding package. Every VM found in a tenant's API is attributed to that tenant's org ID.

## How "current org" is decided

1. Machines are fetched from every tenant (no `$filter` by default, so offboarded records left in
   the old org are captured too; set a tenant's `filter` to narrow it) and filtered by `mode`: `vms` (Defender has Azure `vmMetadata`), `servers` (Azure VMs + any
   server OS), or `all`.
2. Records are merged into one VM when they share an **Azure resource ID**, **Azure VM ID** or
   **Entra device ID**, across tenants. As a fallback (`hostnameFallback`, on by default),
   records still separate after that are merged when their `computerDnsName` is identical
   (case-insensitive), unless both sides have Azure VM IDs and they differ, which means two
   machines that share a name. VMs merged this way have `mergedByHostname: true`.
   The fallback also keeps machines the `mode` filter would drop (for example no Azure
   `vmMetadata` yet in a newly onboarded tenant) when their name matches a collected VM.
   `matchByHostname: true` goes further and treats the hostname as an identifier with no VM ID check.
3. The **current** record is the onboarded one with the most recent `lastSeen`. Its tenant's org
   ID becomes `currentOrgId`.
4. Status per VM:
   - `conflict`: a record in another org is still reporting (within `activeWindow`, default 48h)
     **and** kept reporting after the current onboarding began.
   - `inactive`: the current record hasn't reported within `inactiveAfter` (default 7d).
   - `migrated`: older, superseded records exist in another org.
   - `ok`: everything else.
5. Each VM gets a `tenants` array with one entry per Defender tenant/org: **latest contact**
   (`lastSeen`, the newest across that tenant's machine records), `firstSeen`, health,
   onboarding status, machine IDs and `state` (`current` / `superseded` / `conflict`).
   Entries are **kept after the old org stops returning the device**, marked `present: false`
   with their last known contact. So the migration trail survives Defender ageing out or deleting the
   old record. `previousOrgId` / `previousTenantName` / `previousLastSeen` point at the most
   recent other org.
6. If `currentOrgId` differs from the previous run, the change is logged and added to
   `orgHistory` on the VM (last 50 kept).

If any tenant fails, **no VM documents are written** by default (`writeOnPartial: false`).
Otherwise a missing tenant could make its VMs look like they had moved org or disappeared.
VMs are only marked `active: false` after a run where every tenant succeeded.

API calls follow `@odata.nextLink` paging (`$top` up to 10,000) and retry on 429/5xx, honouring
`Retry-After`.

## MongoDB collections

| Collection | Contents |
|---|---|
| `mde_vms` | One doc per VM, `_id` = `res:<resourceId>` / `vm:<vmId>` / `aad:<deviceId>`. Current org fields, `status`, `tenants[]` (latest contact per tenant, incl. historical), `previousOrgId`, `onboardings[]` (this run's machine records), `orgHistory[]`, `active`. |
| `mde_runs` | One doc per run: status, per-tenant fetch counts / errors / duration, totals. |
| `mde_logs` | slog output: `ts`, `level`, `msg`, `runId`, `tenant`, `vm`, `attrs`. TTL index on `ts` (`logRetentionDays`, default 30; negative = keep forever). |

Logs also go to stdout as JSON. The Mongo log handler is asynchronous and never blocks collection.
If its buffer fills up, it drops entries and reports how many on stderr at shutdown.

To change log retention after the first run, drop the `ts_1` index on `mde_logs` and let the
collector recreate it.

## Troubleshooting dump

Set `dumpDir` in the config, or pass `-dump-dir <dir>` / `MDE_DUMP_DIR`, to write everything a run
collected as JSON under `<dumpDir>/<runId>/`. The last `dumpKeep` runs (default 5) are kept.

```bash
./datafetch mde-tracker -once -dump-dir ./dump
```

| File | Contents |
|---|---|
| `tenants/<tenant>.machines.json` | Every machine exactly as that tenant's Defender API returned it, before any filtering, plus the filter used and any error. |
| `tenants/<tenant>.records.json` | One entry per machine: `included` or `excludedReason`, the `identifiers` used for matching, and the `vmKey` it was merged into. |
| `unlinked-hostnames.json` | Hostnames seen in two or more tenants whose records did **not** end up as one VM, with the reason. |
| `vms.json`, `org-changes.json` | The merged VM documents as written to MongoDB, and org changes detected. |
| `run.json` | The run summary. |

If a migrated VM isn't showing in its new tenant, look it up in the new tenant's files:

- **Not in `machines.json`**: Defender isn't returning it. Check it is onboarded in that tenant
  and that the app can see its device group.
- **In `records.json` with `included: false`**: the default `mode: "vms"` only keeps machines
  that Defender has Azure `vmMetadata` for. The hostname fallback keeps such a machine when its
  `computerDnsName` exactly matches a collected VM (`includedByHostname: true`); if the names
  differ, use `"mode": "servers"` or `"all"`.
- **Listed in `unlinked-hostnames.json` as sharing no identifier**: the old and new records
  have no Azure resource ID, VM ID or Entra device ID in common, so they are tracked as two
  VMs. The hostname fallback normally merges these; it doesn't when the full `computerDnsName`
  differs (e.g. a different domain suffix) or the two records have different Azure VM IDs.
  `"matchByHostname": true` forces a merge on identical names regardless of VM IDs.

The dump contains device inventory data, so keep the directory private. Dump errors are logged
and never fail a run.

## Deploy

The image is datafetch's (the `Dockerfile` in the repository root), run with the argument
`mde-tracker`; `deploy/cronjob.yaml` is a Kubernetes CronJob using workload identity, with the
config in a ConfigMap and secrets in a Secret.

## Migration tracking queries

```js
// VMs that have left Contoso's org (seen there at some point, now elsewhere)
db.mde_vms.find({ active: true, "tenants.orgId": "<source-org>", currentOrgId: { $ne: "<source-org>" } })

// Still in the source org, not yet migrated
db.mde_vms.find({ active: true, currentOrgId: "<source-org>" })

// Migrated but the old org has had contact in the last 7 days (old sensor not offboarded)
db.mde_vms.find({ active: true, tenants: { $elemMatch: {
  orgId: { $ne: "<target-org>" }, state: { $ne: "current" },
  lastSeen: { $gte: new Date(Date.now() - 7 * 864e5) } } } })
```

### When a tenant itself moves to a new Defender org

Update that tenant's `orgId` in the config to the new org ID and keep the same `name` and
`tenantId`. On the next run every VM in the tenant is logged as an org change (old org → new org),
the change is added to `orgHistory`, and the old org stays in the VM's `tenants` array as a
historical entry (`present: false`) with its last known contact. Those VMs then show as
`migrated` with `previousOrgId` set to the old org.

Only contacts this collector has seen are tracked. A record Defender had already removed from
the old org before the first run can't be recovered, so start collecting before you migrate.
