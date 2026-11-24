# azure-cves

> **Part of [datafetch](../README.md).** Merged from `jercle/azure-cves` at `7f871ff`.
> Run it as `datafetch azure-cves`. Its settings in Azure App Configuration are
> under `datafetching.azureCves` and win over the configuration file; how that works,
> the environment variables and how to build are in the root README.
> The dashboard modules this document mentions were not merged: they are
> still in `jercle/azure-cves`.

Collects, for any number of Azure tenants, into one MongoDB database:

- every subscription, resource group and resource, and how they are linked
  (parents, VMs to NICs and disks, NICs and VMs to IP addresses, load
  balancers and application gateways to what is behind them, and any other
  resource one resource refers to);
- Defender for Endpoint devices, the software and versions installed on
  them, and the CVEs affecting them;
- CVEs in container images and running containers from Defender for Cloud,
  with each image's registry, repository, digest and tags;
- each resource's recent cost, read from the data `azcost-collector` writes.

Everything is stored as a graph (`graph_nodes`, `graph_edges`) so it can be
searched and walked in any direction: CVE → devices → VM → NIC → IP →
load balancer, or tenant → subscription → resource group → resource.

```
cli.go                     the command: datafetch azure-cves
pkg/                       its packages; importable if you want to embed it
```

## Status

Written without network access to the Go module proxy or npm, so:

- **Tested here:** config parsing, the Azure / Defender HTTP client (paging and
  throttling), graph building, device linking, every
  collection stage and the cost roll-up, against a fake Azure and Defender
  server with an in-memory store (`go test ./pkg/...`).
- **Compiled, not run:** `pkg/mongostore` and the command are built against
  the real MongoDB driver (v2.3.0) in datafetch, but have not been run
  against a database. The Svelte components were not compiled.
- **Never run against real Azure, Defender or MongoDB.** Expect small fixes
  on first run.
- **Container findings are the least certain part.** See
  [Containers](#containers) before relying on them.

First build:

```sh
make test      # from the repository root
make build     # ./datafetch
```

## Collector

### Tenants

Tenants are a JSON array in the shape of the App Configuration object:

```json
[
  { "tenantName": "Contoso", "tenantId": "…", "clientId": "…", "clientSecret": "…" },
  { "tenantName": "Fabrikam", "tenantId": "…", "clientId": "…", "clientSecret": "…" }
]
```

Pass it as the `AZCVES_TENANTS` environment variable, as a file named by
`AZCVES_TENANTS_FILE`, under `tenants` in the config file, or in App
Configuration under `datafetching.azureCves.tenants` (see
[Settings in App Configuration](#settings-in-app-configuration)). Key names are
case-insensitive and `name` is accepted for `tenantName`. To embed the
collector instead, build a `config.Config` yourself (`config.ParseTenants`
decodes the array) and call `collector.New(...).Run(ctx, "manual")`.

Each service principal needs, in its own tenant:

| For | Permission |
|---|---|
| Resources | **Reader** on the subscriptions (or a management group above them) |
| Devices, software, CVEs | Application permissions on **WindowsDefenderATP**, admin-consented: `Machine.Read.All`, `Software.Read.All`, `Vulnerability.Read.All` |
| Container findings | The same **Reader** role (it covers Defender for Cloud's recommendations). Defender for Containers or Defender CSPM must be scanning the registries and clusters |
| Image tags | Data-plane read access on each Azure Container Registry: **AcrPull**, or **Container Registry Repository Reader** if the registry uses ABAC repository permissions. **Reader is not enough** |

### Running

```sh
export MONGO_URI='mongodb://…'
export AZCVES_TENANTS="$(az appconfig kv show -n my-config --key tenants --query value -o tsv)"

./datafetch azure-cves                 # collect now, then every 6 hours
./datafetch azure-cves -once           # collect once and exit (CronJob / Container App Job)
./datafetch azure-cves -check          # validate configuration and exit; says which settings were not used
./datafetch azure-cves -config config.json -log-level debug
```

| Environment | Meaning | Default |
|---|---|---|
| `MONGO_URI` | MongoDB connection string | required |
| `AZCVES_DB` | Database | `azcves` |
| `AZCVES_TENANTS` / `AZCVES_TENANTS_FILE` | Tenant array | required |
| `AZCVES_INTERVAL` | Time between runs (`90m`, `6h`, `1d`) | `6h` |
| `AZCVES_CONFIG` | Config file path | none |

`deploy/config.example.json` shows every setting. Sovereign clouds: set
`endpoints.authority`, `endpoints.arm` and `endpoints.defender`.

### Settings in App Configuration

Every setting of the config file can also be set in Azure App
Configuration, under `datafetching.azureCves.` and by the same path:
`datafetching.azureCves.interval = 6h`. They are read before every collection and win over the file and the environment; what is
not valid is left out with a warning in the log. A tenant is `tenants.<tenant id>.clientId` and so on, merged into the
tenant of that ID or added; `tenants` or `deviceGroups` as a JSON array
replaces the whole list. The environment variables above still override
both. The MongoDB address, the
cost source and the monitoring settings are read at the start; a change to
them applies at the next restart. `-no-app-config` runs on the file and the environment alone.
See the root README.


### Stages

A run has two per-tenant phases with a merge between them (tenants run in
parallel within a phase, `tenantConcurrency` at a time):

| Stage | Source | Writes |
|---|---|---|
| `resources` | Azure Resource Graph | tenant, subscription, resource group, resource, subnet and IP nodes; all Azure edges |
| `devices` | Defender `GET /api/machines` | nothing yet: the tenant's machine records are held for the merge |
| `deviceMerge` (all tenants) | the machine records of every tenant | one device node per machine; `runs_on` edge to the Azure resource. See [Duplicate devices](#duplicate-devices) |
| `software` | Defender software inventory export | `has_software` edges, shared software nodes, `software_summary` |
| `vulnerabilities` | Defender software vulnerabilities export | `affected_by` edges, shared CVE nodes, `cve_exposure`, CVE counts rolled up the hierarchy |
| `containers` | Defender for Cloud recommendations in Resource Graph; tags from each registry | image and container nodes, their `affected_by` edges, `cve_exposure` (source `containers`), counts rolled up as `containerVuln` |

Then once for all tenants:

| Stage | Source | Writes |
|---|---|---|
| `vulnRollup` | the vulnerabilities stages | each device's CVE counts carried up to its resource, resource group, subscription and tenant (`vulnRollup`) |
| `cveDetails` | Defender `GET /api/Vulnerabilities` | description, dates and exploit flags on CVE nodes. Daily (`cveDetailsEvery`), through whichever tenant answers |
| `costs` | `azcost.resource_costs` | `cost` on every node: last 30 days and month to date, own cost plus everything beneath it |

Behaviour worth knowing:

- **A stage replaces its own data.** After a stage succeeds for a tenant,
  whatever it wrote in earlier runs and did not see this time is deleted.
- **A failed stage deletes nothing.** The previous data stays and the stage
  shows as failing in the monitor. The same applies when an API answers with
  no rows at all, which is reported as "No data returned" rather than
  wiping a tenant (that is nearly always a missing permission).
- **Devices are matched to resources** by the resource ID Defender reports,
  else by computer name when exactly one VM or Arc machine has that name.
  The resource is looked for in every tenant, so a VM in one tenant
  onboarded to another tenant's Defender org is still linked. Unmatched
  devices hang off the tenant.
- **Scale-set instances** are not separate rows in Resource Graph; anything
  pointing at one is linked to the scale set.
- **Skip stages** with `"disable": ["software", "costs"]`.

### Duplicate devices

Defender often holds several records for one machine: re-onboarding leaves
the old record behind, and a machine moved to another Defender org has a
record in each tenant. `deviceMerge` turns them into one device, with the
same rules as mde-tracker:

1. Records are merged when they share an **Azure resource ID**, **Azure VM
   ID** or **Entra device ID**, within a tenant and across tenants.
2. As a fallback (`hostnameFallback`, on by default), records still
   separate after that are merged when their `computerDnsName` is identical
   (case-insensitive), unless both sides have Azure VM IDs and they differ,
   which means two machines that share a name. Devices merged this way have
   `attrs.mergedByHostname: true`. `matchByHostname: true` goes further and
   treats the hostname as an identifier with no VM ID check.
3. The **current** record is the onboarded one with the most recent
   `lastSeen`. The device takes its details and tenant from it.
4. **Software and CVEs come from the current record only.** Rows the
   exports return for a superseded record are dropped and counted as
   `duplicateRecordRows` on the stage, so nothing is counted twice.

A device's `_id` is `device:res:<resource id>`, else `device:vm:<vm id>`,
else `device:aad:<entra id>`, else `device:mde:<tenant>:<machine id>`.
Merged devices list every record under `attrs.records` (tenant, machine ID,
last seen, `current` or `superseded`), and the device page shows them.

If a tenant's machine list cannot be read in a run, its existing devices are
kept as they are and the merge covers the other tenants. If no tenant's can,
the merge, `software` and `vulnerabilities` are skipped for that run.

Upgrading from a version without the merge needs nothing: the first run
replaces the old per-record device nodes and their edges.

### Device groups

Devices can be split into named groups, and groups can be hidden from the
dashboard by default:

```json
"deviceGroups": [
  { "name": "GCP", "hidden": true, "cidrs": ["10.128.0.0/9"], "names": ["gke-*", "*.c.my-project.internal"], "cloudProviders": ["GCP"] },
  { "name": "AWS", "hidden": true, "cidrs": ["172.31.0.0/16"], "nameRegex": ["^ip-\\d+-\\d+-\\d+-\\d+"], "cloudProviders": ["AWS"] }
],
"defaultDeviceGroup": "Azure"
```

- A device goes into the **first** group, in the order listed, that any of
  its rules matches. Devices that match none go into `defaultDeviceGroup`
  (default `"Other"`; set `defaultDeviceGroupHidden` to hide that one).
- `cidrs` match the device's last internal IP address (Defender's
  `lastIpAddress`); a bare address is allowed.
- `names` are case-insensitive patterns for the computer name where `*` is
  any run of characters and `?` any one. `nameRegex` are regular
  expressions (case-insensitive, unanchored) for anything else.
- `cloudProviders` match the cloud Defender itself reports for the machine
  (`Azure`, `AWS`, `GCP`), which needs no address ranges or naming scheme
  where Defender knows it.
- With no `deviceGroups`, nothing is grouped and the dashboard shows no
  group controls.

Grouping happens during collection, in `deviceMerge`, so the dashboard
never has to work it out per request:

| Where | What is stored |
|---|---|
| device nodes | `group` (indexed with `kind`) |
| edges from or to a device (`affected_by`, `has_software`, `runs_on`, tenant `contains`) | `group`, so a list of devices can leave groups out without loading the devices |
| `cve_exposure`, `software_summary` | one document per tenant, **group** and CVE / product |
| `vulnRollup` on resources, resource groups, subscriptions, tenants | the total plus `groups: [{group, critical, …, devices}]` |
| `device_groups` | the groups in order, which are hidden by default, their rules and device counts; this is what the dashboard reads |

**Changing the groups needs no special re-ingest.** Every run assigns
groups afresh, so edit the config and the next run regroups everything
(`./datafetch azure-cves -once` to do it immediately). The same goes for
upgrading to this version. Changing only which groups are `hidden` also
takes effect at the next run.

### Containers

The `containers` stage reads Defender for Cloud's individual vulnerability
recommendations (`microsoft.security/assessments`, category `SoftwareUpdate`)
for registry images (`.containerimage`) and running containers
(`K8s-container`). These replaced the grouped sub-assessments Microsoft
retired on 31 July 2026.

- **CVEs are tied to every image tag.** Unlike devices, where only the
  latest Defender record counts, nothing is collapsed here: each tag keeps
  its CVEs. An image node is one digest and carries every tag pointing at
  it (`attrs.tags`); each of its `affected_by` edges carries those tags
  too (`attrs.tags`, with `attrs.repository` and `attrs.registry`), and
  `cve_exposure` counts the tags a CVE is in (`tags`). The Images view and
  the CVE page list one row per tag, and search works on `repository:tag`.
- **Tags.** If a finding carries tags they are used (`attrs.tagsFrom:
  "defender"`). Otherwise the collector asks the registry which tags point
  at each digest (`"registry"`), per repository, for Azure Container
  Registries. Turn the lookup off with `"resolveImageTags": false`.
  - *Multi-platform images.* Defender reports the digest of one platform's
    manifest, while the tag points at the index above it. The collector
    gives each index's tags to the platform manifests it lists, reading
    the index itself where the registry's listing does not name them.
  - *Registry host.* Where a finding names the registry by resource name
    or not at all, the login server is taken from the registry resource the
    finding belongs to.
  - *Permissions.* The service principal needs **AcrPull** on the registry,
    or **Container Registry Repository Reader** where the registry uses
    ABAC repository permissions. Reader alone cannot list tags.
- **Untagged images say why.** An image left without tags has
  `attrs.untaggedReason`, shown in the Images view and logged with a count
  per reason at the end of the stage: the registry refused, the lookup
  failed, the registry is not one this tenant can see, the finding did not
  identify the registry or repository, or no tag points at that digest any
  more (an old build). The stage also counts `untaggedImages`,
  `tagLookups`, `tagLookupsFailed` and `tagLookupsSkipped`.
- **Each finding** is one vulnerable package on one image or container, with
  its CVEs, detected version and fixed version. These are on the
  `affected_by` edge.
- **Running containers** are linked to the cluster they are in and to the
  image they run (`runs_image`), matched by digest.

**What is and is not confirmed.** Microsoft documents the query filters and
the fields `properties.metadata.severity`,
`properties.additionalData.{SoftwareName, DetectedSoftwareVersions,
FixedVersion, CvesDetails[].CveId}`. It does not document how a finding
names the image (registry, repository, digest, tags) or the Kubernetes
workload. The collector therefore looks for those by key name anywhere in
the finding (`digest`, `repositoryName`, `registry`, `tags`, `namespace`,
`containerName`, `controllerName`, …) and parses any
`registry/repo:tag@sha256:…` reference it finds. The tests use synthetic
findings, not real ones. To check against yours:

```sh
./datafetch azure-cves -sample-containers 3    # prints raw findings per tenant, no database needed
```

If images come out as `unidentified` (a count on the stage in the monitor)
or without a repository, compare that output with `harvest()` in
`pkg/graph/containers.go` and add the key names your findings use. The ACR
tag lookup (token exchange, then `/acr/v1/<repository>/_manifests`, falling
back to `_tags` and `/v2/<repository>/manifests/<digest>`) is likewise
untested against a real registry.

### Data model

`graph_nodes` — `_id` is the lower-cased ARM ID for Azure things, otherwise
`/tenants/<id>`, `device:…` (see [Duplicate devices](#duplicate-devices)), `cve:CVE-…`,
`software:<vendor>/<name>`, `ip:public/<addr>` or `ip:<vnet id>/<addr>`.

| Field | |
|---|---|
| `kind` | `tenant`, `subscription`, `resourceGroup`, `resource`, `subnet`, `ip`, `device`, `image`, `container`, `cve`, `software` |
| `type` | ARM type (lower case), device OS platform, `public` / `private` for IPs, severity for CVEs |
| `name`, `q` | display name; lower-case search text (name, ID, IP addresses) |
| `tenantId`, `subscriptionId`, `resourceGroup`, `location`, `tags[{k,v}]` | scope |
| `attrs` | per-type summary (VM size, OS, power state, addresses, device health, …) |
| `details` | CVE nodes only: description, CVSS vector, published date, exploit flags |
| `vuln` | `{critical, high, medium, low, total}` on a device, image or container: its distinct CVEs |
| `vulnRollup` | The same summed over the devices at or below a resource, resource group, subscription or tenant, with a `devices` count. A CVE on ten VMs counts ten times |
| `containerVuln` | The same for images and containers, on the registry, cluster, resource group, subscription and tenant above them, with `images` and `containers` counts |
| `software` | devices only: `{products}` |
| `cost` | `{currency, last30d, mtd, last30dUsd, mtdUsd, asOf}` |
| `source`, `via`, `runId`, `seenAt` | which stage and which tenant's service principal wrote it, and when |

`graph_edges` — `{from, to, rel, fromKind, toKind, key, attrs, source, via, runId, seenAt}`

| `rel` | From → to |
|---|---|
| `contains` | tenant → subscription → resource group → resource → child; subnet → private IP; registry → image; cluster → container |
| `attached` | VM → NIC, VM → disk, NIC → public IP resource |
| `has_ip` | NIC, VM or public IP resource → IP address |
| `in_subnet` | NIC or load balancer → subnet |
| `secured_by` | NIC → network security group |
| `frontend` | load balancer / application gateway → public IP resource or address |
| `backend` | load balancer / application gateway → NIC, VM, scale set, IP address, App Service |
| `references` | any other resource ID found in a resource's properties (`attrs.property` names it) |
| `runs_on` | Defender device → Azure resource |
| `has_software` | device → software, one edge per version (`attrs.version`) |
| `affected_by` | device, image or container → CVE, one edge per vulnerable package version (`attrs.fixedVersion` for images and containers) |
| `runs_image` | container → image |

Siblings are the other targets of a node's parent's `contains` edges.

Traversal examples:

```js
// Everything two hops from a VM
db.graph_edges.find({ $or: [{ from: vmId }, { to: vmId }] })

// Which VMs sit behind a load balancer
db.graph_edges.find({ from: lbId, rel: "backend", toKind: "resource" })

// Every resource affected by a CVE, with its subscription
db.graph_edges.aggregate([
  { $match: { to: "cve:CVE-2024-3094", rel: "affected_by" } },
  { $lookup: { from: "graph_edges", let: { d: "$from" }, as: "host",
      pipeline: [{ $match: { $expr: { $and: [{ $eq: ["$from", "$$d"] }, { $eq: ["$rel", "runs_on"] }] } } }] } },
  { $unwind: "$host" },
  { $lookup: { from: "graph_nodes", localField: "host.to", foreignField: "_id", as: "resource" } }
])

// Walk up from anything to its tenant
db.graph_edges.aggregate([
  { $match: { to: nodeId, rel: "contains" } },
  { $graphLookup: { from: "graph_edges", startWith: "$from", connectFromField: "from", connectToField: "to",
      as: "ancestors", restrictSearchWithMatch: { rel: "contains" } } }
])
```

```js
// Every image tag affected by a CVE
db.graph_edges.aggregate([
  { $match: { to: "cve:CVE-2024-3094", rel: "affected_by", fromKind: "image" } },
  { $unwind: "$attrs.tags" },
  { $project: { _id: 0, registry: "$attrs.registry", repository: "$attrs.repository", tag: "$attrs.tags",
      package: "$attrs.software", version: "$attrs.version", fixedVersion: "$attrs.fixedVersion" } }
])
```

`cve_exposure` (one document per tenant, CVE and source: `devices` or
`containers`) and `software_summary` (per tenant and product) are
pre-aggregated for the list views.

### Monitoring

Unless `monitoring.enabled` is `false`, the collector records itself in the
same database. Writes are best-effort: if they fail, collection carries on
and stdout still has every log line (JSON).

| Collection | Contents |
|---|---|
| `cve_collector_runs` | One document per run: status, timings, totals, and per tenant → stage results with counts and errors. `heartbeatAt` is refreshed every 30 s, so a run whose heartbeat stops was killed |
| `cve_collector_logs` | Log entries at or above `monitoring.logLevel`; `runId`, `tenant`, `stage`, `error` are top-level fields |
| `cve_collector_instances` | One document per host: version, mode, state, heartbeat, last and next run |
| `cve_collector_state` | Latest outcome of each stage per tenant, with `lastSuccessAt` (always written) |

Logs are kept 30 days and runs 180 by default (TTL indexes; change the
numbers and restart).

What a long stage is doing is visible three ways:

- **Steps.** Each stage logs every step it moves to ("requesting the
  software vulnerabilities export from Defender", "page received, writing
  it", "waiting for the next page", "removing findings that are resolved"),
  with running totals and the time since the stage started. Large writes to
  MongoDB log how long they took.
- **Reminders.** A stage still running logs `stage still running` with its
  current step and counters every `progressEvery` (default `1m`).
- **Throttling.** When an API makes the collector wait 5 seconds or more
  before a retry, that is logged as a warning with the wait, so a stage
  that is idle because of rate limits says so.

The run record carries the same thing live: every stage appears as
`running` from the moment it starts, with its current `step` and counters,
refreshed when the step changes (at most every few seconds) and on the
30-second heartbeat.

## Dashboard modules

`dashboard/src` adds, and touches nothing else:

```
src/lib/azure-cves/               CVE, software and resource graph views
src/lib/cve-collector-monitor/    collector monitoring (uses helpers from azure-cves)
src/routes/cves/+page.svelte           -> /cves
src/routes/cves/collector/+page.svelte -> /cves/collector
```

Both pages inherit your `+layout.svelte`. Move the routes freely, or mount
`<AzureCves search={page.url.search} />` and
`<CollectorMonitor search={page.url.search} />` in pages you already have.

### Setup

1. Copy `dashboard/src` into the dashboard's `src` (merge directories).
2. Components used (skip those you have):

   ```sh
   npx shadcn-svelte@latest add alert badge breadcrumb button card input select skeleton table
   ```

   `mongodb` is the only npm dependency, and the cost modules already need it.
3. Remote functions must be enabled, as for the cost module.
4. Environment:

   ```
   AZCVES_DB=azcves            # optional, this is the default
   AZCVES_COSTS_PATH=/costs    # optional: where the cost explorer is mounted
   AZCVES_STALE_HOURS=24       # optional: when the monitor calls a stage stale
   ```

5. **Check two assumptions**, each isolated to one place:
   - `authorize` is imported from `$lib/utils.server` and called as
     `await authorize()` at the top of every remote function
     (`cves.remote.ts`, `monitor.remote.ts`). If yours takes arguments,
     change those calls.
   - `db.server.ts` takes the dashboard's MongoDB `client` from `svrHooks`
     and returns `client.db(AZCVES_DB)` from `getDb()`.

### Views

All state is in the query string, so every drill-down is a link.

- **Overview** — CVE counts by severity, devices exposed, the worst CVEs,
  the most exposed devices, and a row per tenant with CVE counts and cost.
- **CVEs** — filter by severity, tenant, text and where found (devices or
  containers); sort by severity, CVSS, devices or images. A CVE page lists
  every affected image with its tags and where it is running, every
  affected container, and every affected device with the Azure resource it
  runs on, the vulnerable software versions and the fix.
- **Images** — container images with CVEs, one row per tag, searchable by
  `repository:tag` or digest, with severity counts and how many containers
  run each. An image page lists its CVEs with the package, detected version
  and fixed version, and the containers running it.
- **Software** — products by install count or weaknesses. A product page
  shows the version spread, the devices on each version and its CVEs.
- **Resources** — search by name, resource ID or IP address, or drill down
  from a tenant. Every node page has a breadcrumb, CVE counts, cost (with a
  link into the cost explorer), a drawing of everything within two hops
  where each node is a link, what it contains (sorted by CVEs then cost),
  every relationship grouped by kind, and its siblings. A VM's page includes
  the CVEs and software of the Defender device on it.
- **Device groups** — when groups are configured, a bar under the tabs
  lists them with device counts. Groups hidden by default start switched
  off; select a group to switch it on or off, "Show all devices" for
  everything, "Reset to default" to go back. The choice is in the URL
  (`?groups=`), follows every link and can be bookmarked. It applies to
  the overview, CVE and software lists and pages, search, the resource
  drill-down, CVE counts on resources and above, and the graph drawing. A
  hidden device opened directly is still shown in full, with a note.
  Container images are not devices and are never hidden.
- **Collector** (`/cves/collector`) — health with reasons, collectors and
  their heartbeats, what the run in progress is doing right now (stage,
  current step, counts so far, how long), run history, freshness of every
  stage per tenant, run detail and a log filterable by level, tenant, stage
  and text. Whichever view is open reloads every 30 seconds while the
  browser tab is visible; the header shows how long ago and at what time
  it last updated, a countdown to the next update, and an "Update now"
  button.

## Not covered

- Other Defender for Cloud findings (SQL, agentless VM scanning, AKS node
  upgrades).
- Tags for images in registries other than Azure Container Registry, unless
  the finding itself carries them.
- Software without a CPE (Defender's separate "non product code" export).
- Front Door and Traffic Manager backends are linked only where they hold a
  resource ID (as `references`), not by host name.
- AKS pods and services, and addresses assigned inside a guest OS.
- Costs are not converted between currencies; a node with several shows the
  largest and the USD total.
