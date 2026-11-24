# az-storage

> **Part of [datafetch](../README.md).** Merged from `jercle/az-storage` at `49359f1`.
> Run it as `datafetch az-storage`. Its settings in Azure App Configuration are
> under `datafetching.azStorage` and win over the configuration file; how that works,
> the environment variables and how to build are in the root README.
> The dashboard modules this document mentions were not merged: they are
> still in `jercle/az-storage`.

A Go service that collects, for one or more Azure tenants:

- every **storage account**, with its used size;
- every **blob container**, with its used size;
- every **managed disk**, with its provisioned size;

and writes it to MongoDB, together with its own logs, run history and
heartbeat. Two SvelteKit / Svelte 5 modules in [`dashboard/`](dashboard/README.md)
show the data and the collector's logs in the existing dashboard.

It follows the layout of the other collectors (tf-ingest, azure-cves,
mde-tracker): standard library plus the MongoDB driver, a tenants array,
`azs_*` collections, a log sink that survives MongoDB being down.

## What has and has not been run

Written without network access, so:

- **Tested** (`go test -race ./...`, against fake Azure endpoints and a fake
  store): configuration, token handling and retries, Resource Graph paging,
  the metrics and container calls, blob listing and its error handling, the
  whole pass including failures and pruning, the log sink and run records.
- **Compiled, not run**: `internal/store/mongostore` and the command are
  built against the real MongoDB driver (v2.3.0) in datafetch, but have not
  been run against a database.
- **Never run against Azure.** The request shapes are from the REST
  documentation, not from a live tenant.

## Where the sizes come from

| | Source | Needs |
|---|---|---|
| Storage account used size | Azure Monitor metric `UsedCapacity`, plus `BlobCapacity`, `FileCapacity`, `TableCapacity`, `QueueCapacity` per service | Reader |
| Container list | Azure Resource Manager | Reader |
| Container used size | Listing every blob through the account's blob endpoint and adding up the lengths | Storage Blob Data Reader, and network access to the account |
| Managed disks | Azure Resource Graph | Reader |

Three things follow from this.

**Azure does not report a container's size.** The capacity metrics stop at
the account. Listing the blobs is the only way to get it without setting up
blob inventory on every account, and it is the only part of the collector
that touches the data plane. It can be switched off
(`collect.containerSizes: false`), in which case only Reader is needed.

- A container that cannot be measured keeps the size from the last pass that
  could, with the reason for the latest failure: `denied` (no blob role),
  `blocked` (the account's network rules), `unreachable` (a private endpoint
  the collector cannot resolve or reach), `failed`.
- When an account is blocked or unreachable, its remaining containers are
  not tried.
- Listing stops at `containerSizes.maxBlobs` (default 2,000,000, about 400
  requests) or `containerSizes.timeout` (default 30m). The size is then
  stored as a lower bound (`partial`).
- Snapshots, earlier versions and soft-deleted blobs are counted, each at
  its full length. Azure bills snapshots and versions only for the blocks
  that differ, so this can exceed the billed size.

**Account sizes are up to a day old.** Azure refreshes capacity metrics
about daily; the collector stores the time of the value it used. A new
account has none for its first day (`usageStatus: missing`). The default
interval is therefore 24h.

**Disks have no used size.** Azure knows what is provisioned, not what the
file system inside uses. The collector stores the provisioned size, which is
what is billed, and whether the disk is attached.

## Build and run

```sh
make test      # from the repository root
make build     # ./datafetch
```

```sh
datafetch az-storage -config az-storage.json -dry-run    # collect once, print JSON lines, write nothing
datafetch az-storage -config az-storage.json -init-db    # create the indexes and exit
datafetch az-storage -config az-storage.json             # collect once
datafetch az-storage -config az-storage.json -loop       # collect every `interval`
```

`deploy/az-storage.service` is a systemd unit for `-loop`. For a scheduler
(cron, a Kubernetes CronJob), run it without `-loop`.

## Permissions

Per tenant, an app registration with a client secret, and on the
subscriptions (or a management group above them):

- **Reader**
- **Storage Blob Data Reader**, if containers are measured. It lets the
  principal read every blob in scope, which is more than the collector uses.

`deploy/terraform/roles.tf` assigns both at a management group. It has not
been planned or applied.

Storage accounts with a firewall must also allow the collector's address, or
the collector must run where their private endpoints resolve.

## Configuration

`deploy/config.example.json` has every setting. Unknown fields are rejected.
Without `-config`, `az-storage.json` next to the executable is read if it
is there.

### Settings in App Configuration

Every setting in the table below can also be set in Azure App
Configuration, under `datafetching.azStorage.` and by the same path:
`datafetching.azStorage.concurrency.accounts = 16`. They are read before every pass and win over the file; what is
not valid is left out with a warning in the log. A tenant is `tenants.<tenant id>.clientId` and so on, merged into the
file's tenant of that ID or added; `tenants` as a JSON array replaces the
file's list. The MongoDB address,
the logging settings and the heartbeat are read at the start; a change to
them applies at the next restart. `-no-app-config` runs on the file alone.
See the root README.


| Setting | Default | |
|---|---|---|
| `mongo.uri`, `mongo.database` | –, `azstorage` | Or `AZSTORAGE_MONGO_URI`, `AZSTORAGE_MONGO_DATABASE` |
| `tenants[]` | – | `tenantName`, `tenantId`, `clientId`, `clientSecret` or `clientSecretEnv`; optional `cloud` (`public`, `usgovernment`, `china`), `subscriptions`, `excludeSubscriptions`. Or `AZSTORAGE_TENANTS` (JSON array) / `AZSTORAGE_TENANTS_FILE` |
| `interval` | `24h` | Between passes with `-loop`; at least 15m |
| `concurrency` | tenants 2, accounts 8, containers 4 | Containers is per storage account |
| `collect.usage` | on | Account used size |
| `collect.serviceBreakdown` | on | Blob / file / table / queue split: up to four more metric calls per account |
| `collect.containers` | on | Container list |
| `collect.containerSizes` | on | Blob listing |
| `collect.disks` | on | |
| `containerSizes.snapshots`, `.versions`, `.deleted` | on | What is counted besides current blobs |
| `containerSizes.maxBlobs` | 2000000 | `-1` for no limit |
| `containerSizes.timeout` | `30m` | Per container |
| `containerSizes.excludeAccounts` | – | Account name patterns, `*` wildcard |
| `retention.logsDays`, `.runsDays` | 30, 90 | TTL indexes; changed in place |
| `logging.level`, `.mongoLevel`, `.format` | `info`, `info`, `text` | |

## Collections

Every document has `tenantName` and `tenantId`. `_id` is a hash of the
tenant and the resource ID, so a resource keeps its document between passes.
Sizes are bytes.

**`azs_accounts`** – `name`, `resourceId`, `subscriptionId`,
`subscriptionName`, `resourceGroup`, `location`, `kind`, `sku`, `accessTier`,
`hns`, `tags`, `createdAt`, `blobEndpoint`, `publicNetworkAccess`,
`networkDefaultAction`, `allowBlobPublicAccess`, `minimumTls`;
`usageStatus` (`known`, `missing`, `failed`, `skipped`), `usageError`,
`usageAt`, `usedBytes`, `blobBytes`, `fileBytes`, `tableBytes`, `queueBytes`,
`blobCount`, `fileShares`; `containers`, `containersStatus`,
`containersError`, `containersMeasured`, `containerBytes`, `sizeStatus`;
`firstSeenAt`, `lastSeenAt`.

**`azs_containers`** – `name`, `accountId`, `accountName`, `resourceId`,
`subscriptionId`, `subscriptionName`, `resourceGroup`, `publicAccess`,
`leaseState`, `lastModifiedAt`, `immutablePolicy`, `legalHold`; `sizeStatus`
(`measured`, `partial`, `denied`, `blocked`, `unreachable`, `failed`,
`skipped`), `sizeError`, `sizedAt`, `usedBytes`, `currentBytes`,
`snapshotBytes`, `versionBytes`, `deletedBytes`, `blobs`, `objects`,
`tiers.<tier>.bytes|count`; `firstSeenAt`, `lastSeenAt`.

**`azs_disks`** – `name`, `resourceId`, `subscriptionId`, `subscriptionName`,
`resourceGroup`, `location`, `tags`, `sku`, `tier`, `sizeGb`, `sizeBytes`,
`state`, `attached`, `managedBy`, `attachedTo`, `osType`, `iops`, `mbps`,
`zones`, `encryption`, `createOption`, `networkAccessPolicy`, `createdAt`,
`ownershipChangedAt`; `firstSeenAt`, `lastSeenAt`.

**`azs_subscriptions`**, **`azs_tenants`** – totals (`counts`), and for
tenants `lastStatus`, `lastError`, `lastAttemptAt`, `lastSuccessAt`,
`missing`.

**`azs_runs`**, **`azs_logs`**, **`azs_instances`** – one document per pass
with each tenant's steps; structured log lines (`time`, `level`, `msg`,
`runId`, `tenantName`, `step`, `account`, `error`, `attrs`); one heartbeat
document per collector host.

Sizes that a pass did not measure are left as stored, with their `usageAt` /
`sizedAt`; the status fields always describe the latest attempt. Accounts,
containers and disks that are gone are deleted, but only after the listing
they would have appeared in succeeded.

## Logging

Every line goes to stderr (or `-log-file`) and, at `logging.mongoLevel` and
above, to `azs_logs` in batches. If MongoDB is unreachable the collector
keeps going, queues up to 2,000 entries and writes them when it returns.
Failures that repeat for every account (a missing role, say) are logged as
warnings 20 times per step and at debug level after that.
