# ns-check

> **Part of [datafetch](../README.md).** Merged from `jercle/ns-check` at `da41fba`.
> Run it as `datafetch ns-check`. Its settings in Azure App Configuration are
> under `datafetching.nsCheck` and win over the configuration file; how that works,
> the environment variables and how to build are in the root README.
> The dashboard modules this document mentions were not merged: they are
> still in `jercle/ns-check`.

A Go service that health-checks Citrix NetScaler (ADC) appliances over the
NITRO API and writes what it finds to MongoDB, together with its own logs,
run history and heartbeat. Two SvelteKit / Svelte 5 modules in
[`dashboard/`](dashboard/README.md) show the health and the checker's logs in
the existing dashboard.

It follows the layout of the other tools (az-storage, tf-ingest, azure-cves):
standard library plus the MongoDB driver, `nsc_*` collections, a log sink
that survives MongoDB being down, run records and a heartbeat.

## What has and has not been run

Written without network access and without a NetScaler, so:

- **Tested** (`go test -race ./...`): the configuration; the NITRO client
  against a stand-in appliance over TLS (login, session cookie, logout,
  error replies); every check, the change detection, a secondary node,
  unreachable appliances, failed steps and a store that goes away, with the
  real client talking to the stand-in; the log sink and run records.
- **Run end to end** in `-dry-run` against the stand-in: the binary logs in,
  checks, and prints the documents. The dashboard's server functions were
  then run on those documents.
- **Compiled, not run**: `internal/store/mongostore` and the command are
  built against the real MongoDB driver (v2.3.0) in datafetch, but have not
  been run against a database.
- **Never run against a real NetScaler.** The resource and field names are
  from the NITRO documentation. Firmware differs in what it returns, so the
  first thing to do is a dry run with a dump (below) and a look at any check
  that reads "not reported".

## What is checked

One pass logs in to each appliance, reads the resources below, and logs out.
An appliance is as bad as its worst check: `ok`, `warning`, `critical`, or
`unknown` when something could not be read.

| Check | NITRO resource | Warning | Critical |
|---|---|---|---|
| `api` | `config/login` | | cannot connect, or the login is refused |
| `cpu` | `stat/system` `pktcpuusagepcnt` | ≥ 75% | ≥ 90% |
| `mgmt-cpu` | `stat/system` `mgmtcpuusagepcnt` | ≥ 80% | ≥ 95% |
| `memory` | `stat/system` `memusagepcnt` | ≥ 80% | ≥ 90% |
| `disk-flash`, `disk-var` | `stat/system` `disk0perusage`, `disk1perusage` | ≥ 80% | ≥ 90% |
| `hardware` | `stat/system` `powersupplyNstatus` | | a power supply that is not NORMAL |
| `ha` | `config/hanode`, `stat/hanode` | node disabled or forced, sync FAILED | node or peer down or unknown, both primary, standalone with `requireHA` |
| `config` | `config/nsconfig` | running configuration not saved | |
| `interfaces` | `config/Interface` | an enabled, HA-monitored interface is down | |
| `vservers` | `stat/lbvserver`, `csvserver`, `vpnvserver`, `authenticationvserver`, `gslbvserver` | up with fewer services than `vserverHealthPercent`, or an odd state | DOWN |
| `services` | `stat/service`, `config/servicegroup` | a service is down, a group is down or partly up | |
| `certificates` | `config/sslcertkey` | ≤ 30 days left | ≤ 7 days left, or expired |

The thresholds are in the configuration. Things worth knowing:

- **List both nodes of a pair**, each by its own NSIP. Resource use, HA
  state and certificates are per node.
- **A secondary node's virtual servers and services are not judged.** It
  does not probe them, so they all read as down there. They are checked on
  the primary, and the documents move with a failover.
- **Disabled is not down.** An OUT OF SERVICE virtual server or service is
  stored as `disabled` and never counts against the appliance.
- **`vserverHealthPercent` is 100 by default**, so a load balancer with any
  bound service down is a warning. Lower it, or set 0 to switch it off.
- **Ignore patterns** (`ignore.vservers`, `services`, `certificates`,
  `interfaces`; `*` wildcards, global or per appliance) keep an object in the
  lists but stop it counting. The example ignores the appliance's own
  default certificates.
- **A check that cannot be read is `unknown`, not down**, and what the last
  good pass stored for it is kept. Content switching, gateway,
  authentication and GSLB virtual servers and service groups are optional:
  if the appliance answers with an error (feature off), that kind is left
  out without failing the step.
- **An unreachable appliance is `critical`** and keeps the system, HA and
  object data of the last pass that reached it.

Changes are stored as events: an appliance or check changing status, a
virtual server, service or certificate changing status, an HA failover, a
restart, a firmware change. A first sighting is not an event.

## Run it

```sh
make build                                           # from the repository root
cp nscheck/deploy/config.example.json ns-check.json  # then edit; read from next to the executable

./datafetch ns-check -dry-run -appliance ns-prod-01 -dump-dir ./dump   # one appliance, nothing written
./datafetch ns-check -init-db      # create the indexes
./datafetch ns-check               # one pass
./datafetch ns-check -loop         # keep checking, every `interval`
```

`-dry-run` prints the documents as JSON lines and needs no MongoDB.
`-dump-dir` (or `dumpDir`) saves every NITRO response as
`<dir>/<appliance>/<api>_<resource>.json`, replaced each pass: use it to see
what a firmware actually returns. The login is never dumped, but the
responses describe the appliance's configuration, so treat the folder as
sensitive.

`deploy/ns-check.service` is a systemd unit for `-loop`.

### The account on the NetScaler

A local or external user with the built-in `read-only` command policy:

```
add system user nscheck <password>
bind system user nscheck read-only 100
```

The checker only sends GET requests besides the login and logout. It opens
one session per appliance per pass and closes it; the session also times out
by itself after five minutes.

### TLS

The management certificate is verified. For an appliance with a certificate
from an internal CA set `caFile` to a PEM bundle; `tlsSkipVerify: true`
accepts anything. Both can be set once under `defaults`. An `http://`
address works and logs a warning: the password would travel in clear text.

## Configuration

### Settings in App Configuration

Every setting in the table below can also be set in Azure App
Configuration, under `datafetching.nsCheck.` and by the same path:
`datafetching.nsCheck.thresholds.cpu.warning = 70`. They are read before every pass and win over the file; what is
not valid is left out with a warning in the log. An appliance is `appliances.<name>.address` and so on, merged into the
file's appliance of that name or added (a name with a "." in it cannot be
written this way); `appliances` as a JSON array replaces the file's list. The MongoDB address,
the logging settings and the heartbeat are read at the start; a change to
them applies at the next restart. `-no-app-config` runs on the file alone.
See the root README.


See [`deploy/config.example.json`](deploy/config.example.json). Unknown
fields are rejected.

| Field | Default | |
|---|---|---|
| `mongo.uri`, `mongo.database` | –, `nscheck` | or `NSCHECK_MONGO_URI`, `NSCHECK_MONGO_DATABASE` |
| `interval` | `1m` | between passes with `-loop`; at least 15s |
| `timeout` | `20s` | per request to an appliance |
| `concurrency` | 8 | appliances checked at once |
| `retention` | logs 30, runs 14, samples 30, events 180 days | TTL indexes; `-init-db` applies a change |
| `thresholds` | as in the table above | |
| `checks` | all on | `hardware`, `config`, `ha`, `interfaces`, `vservers`, `services`, `certificates` |
| `ignore` | none | name patterns, global |
| `defaults` | | `username`, `password` / `passwordEnv`, `tlsSkipVerify`, `caFile` for appliances that set none |
| `appliances[]` | | `name`, `address`, optional `tenantName`, `username`, `password` / `passwordEnv`, `tlsSkipVerify`, `caFile`, `requireHA`, `ignore` |

`appliances` can also come from `NSCHECK_APPLIANCES` (a JSON array) or
`NSCHECK_APPLIANCES_FILE`. `tenantName` is only a label to group and filter
by in the dashboard. With `checks.ha` off the checker cannot tell a
secondary node, and will report its virtual servers as down.

## Collections

Database `nscheck`. `_id`s are derived from the names, so they are stable.

| Collection | One document per | Main fields |
|---|---|---|
| `nsc_appliances` | appliance | `name`, `tenantName`, `address`, `status`, `statusSince`, `summary`, `reachable`, `error`, `latencyMs`, `checkedAt`, `lastSuccessAt`, `intervalSeconds`, `checks[]` (`name`, `status`, `message`, `value`, `warning`, `critical`, `since`), `system` (`hostname`, `version`, `model`, `serial`, `cpu`, `mgmtCpu`, `memory`, `diskFlash`, `diskVar`, `startTime`, `powerSupplies`, `configUnsaved`), `ha` (`configured`, `state`, `masterState`, `syncState`, `peer`, `peerState`, `nodes[]`), `interfaces[]`, `counts` |
| `nsc_vservers` | virtual server | `applianceId`, `appliance`, `tenantName`, `kind` (`lb`, `cs`, `vpn`, `aaa`, `gslb`), `name`, `ip`, `port`, `protocol`, `state`, `status`, `statusSince`, `detail`, `healthPercent`, `servicesUp`, `servicesDown`, `ignored` |
| `nsc_services` | service, service group | as above, `kind` `service` or `servicegroup` |
| `nsc_certificates` | certificate | as above, plus `subject`, `issuer`, `serial`, `types`, `notBefore`, `notAfter`, `daysLeft` |
| `nsc_samples` | appliance and pass | `time`, `status`, `reachable`, `latencyMs`, `cpu`, `mgmtCpu`, `memory`, `diskFlash`, `diskVar`, `vserversDown`, `servicesDown` |
| `nsc_events` | change | `time`, `applianceId`, `appliance`, `kind`, `name`, `from`, `to`, `severity`, `message` |
| `nsc_runs` | pass | `status`, `startedAt`, `finishedAt`, `durationMs`, `appliancesTotal/Done/Failed`, `counts`, `appliances[]` with `steps[]` |
| `nsc_logs` | log line | `time`, `level`, `severity`, `msg`, `appliance`, `tenantName`, `step`, `runId`, `error`, `attrs` |
| `nsc_instances` | running checker | heartbeat, mode, interval, last and next run |

Object documents are only rewritten when they change (`updatedAt`), so a
quiet pass writes one appliance document, one sample and the run record.
A run's `status` says how the checker did (`partial`: a step failed or
something could not be stored; `failed`: no appliance was reached). What it
found is in `counts` and on the appliances.

## Logging

Everything goes to stderr (or `-log-file`) and, from `logging.mongoLevel`
up, to `nsc_logs`. Entries queue while MongoDB is away. At `info` a pass
logs one summary line; an appliance logs when its status changes, and a
failing step logs once and again when it recovers. An appliance that stays
as it is logs at `debug`.
