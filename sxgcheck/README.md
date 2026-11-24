# sxg-check

> **Part of [datafetch](../README.md).** Merged from `jercle/sxg-check` at `abb1bd9`.
> Run it as `datafetch sxg-check`. Its settings in Azure App Configuration are
> under `datafetching.sxgCheck` and win over the configuration file; how that works,
> the environment variables and how to build are in the root README.
> The dashboard modules this document mentions were not merged: they are
> still in `jercle/sxg-check`.

Health checks on Sophos XG / Sophos Firewall (SFOS) appliances and their web
proxy. A Go service checks every configured firewall on an interval and
writes to MongoDB:

- the **current state** of each firewall and each check,
- a **history** of every pass (health and numbers, for charts),
- an **event** for every change of health,
- its own **logs, run records and heartbeat**.

`dashboard/` holds two SvelteKit / Svelte 5 modules (Tailwind, shadcn-svelte,
remote functions) that show the firewalls and the checker in the existing
dashboard. See `dashboard/README.md`.

## What has and has not been run

- **Tested** (`go test -race`): configuration, every check, and the pass
  logic. The network checks ran against local fake servers (TCP, TLS with
  generated certificates, an HTTPS console, an XML API, a forward proxy
  including CONNECT and proxy authentication). The SNMP evaluation ran against
  a fake SNMP session.
- **Compiled, not run**: the MongoDB store, the gosnmp adapter
  (`internal/probe/snmp_gosnmp.go`) and the command are built against the
  real libraries in datafetch (MongoDB driver v2.3.0, gosnmp v1.38.0), but
  have not been run against a database or an SNMP agent.
- **Never run against a real Sophos firewall or a real MongoDB.** Start with
  `-dry-run` (below) and compare what it prints with the firewall's own
  console before trusting an alert.

## The checks

A check runs when its block is present in the firewall's settings or in
`defaults`. Each check is `ok`, `warning` or `critical`; a firewall is as bad
as its worst check. A check that comes back critical is tried again
(`retries`, default 1) before it counts.

| Block | What it does | Critical when | Warning when |
|---|---|---|---|
| `tcp` | Connects to each port in `ports` | the port does not accept | |
| `tls` | Reads the certificate on each port (default 4444) | expired, not yet valid, or `criticalDays` (7) or fewer left | `warnDays` (30) or fewer left |
| `webAdmin` | `GET https://host:4444/` | no answer, or HTTP 5xx | |
| `proxy` | Requests each URL in `urls` through the web proxy (default port 3128) | no answer, HTTP 403/407, or a status outside 200–399 (or `expectStatus`) | slower than `warnLatency` (2s) |
| `api` | Signs in to the XML API (`/webconsole/APIController`) | sign-in refused, API off, or address not allowed | |
| `snmp` | Reads the SFOS MIB (below) | no answer | answers without the SFOS MIB, or part could not be read |

The certificate check reads dates only and does not verify the chain, so it
works on self-signed console certificates. `webAdmin`, `api` and `proxy` skip
certificate verification unless `verifyCertificate` is true (with HTTPS
decryption on, the proxy re-signs sites with the firewall's CA).

The API check sends only a `<Login>` block: it reads and changes nothing.
It needs an administrator account, API access switched on
(Backup & firmware > API) and the checker's address in the allowed list.

The proxy check is for an explicit proxy (clients configured with the
firewall's address and port). A transparent proxy cannot be tested this way.
Add an `https://` URL to exercise CONNECT.

### SNMP

Reads `SFOS-FIREWALL-MIB` (`1.3.6.1.4.1.2604.5.1`) over SNMP v2c or v3, and
`hrProcessorLoad` from `HOST-RESOURCES-MIB` for CPU, because the SFOS MIB has
no CPU object. SNMP has to be enabled on the firewall and allowed from the
checker's address.

| Check | Source | Default thresholds |
|---|---|---|
| CPU | mean of `hrProcessorLoad` | warn 85%, critical 95% |
| Memory | `sfosMemoryPercentUsage` | 85%, 95% |
| Swap | `sfosSwapPercentUsage` (skipped when there is no swap) | 50%, 80% |
| Disk | `sfosDiskPercentUsage` | 80%, 90% |
| Services | the 21 `sfos…Service` objects | critical if any is `dead` or `frozen`, or one in `requiredServices` is not `running` |
| High availability | `sfosHAStatus`, node and peer state | critical if a node is `faulty`; warning if the state is not `expectHa` |
| Licences | status and expiry of the 9 subscriptions | critical if `expired`; warning `licenseWarnDays` (30) before expiry |

A threshold pair of `-1` switches a level off. Service names:
`pop3 imap4 smtp ftp http av as dns ha ips apache ntp tomcat sslvpn ipsec
database network garner drouting sshd dgd`. Licence names: `base network web
mail webserver sandstorm enhancedsupport enhancedplussupport
centralorchestration`.

Also stored: model, firmware, appliance key, uptime, signed-in users, and the
memory, swap and disk capacity as the firewall reports them.

Two things to check on a real firewall, because the MIB does not say:
the expiry date is a free-text string (several date formats are understood;
anything else is shown as text and not counted down), and capacities are
taken to be megabytes.

## Build and run

```sh
make test      # from the repository root
make build     # ./datafetch
```

```sh
datafetch sxg-check -config sxg-check.json -dry-run   # check once, print JSON lines, store nothing
datafetch sxg-check -config sxg-check.json -init-db   # create the indexes
datafetch sxg-check -config sxg-check.json            # one pass, then exit (cron, pipeline)
datafetch sxg-check -config sxg-check.json -loop      # keep checking every `interval`
```

`deploy/sxg-check.service` is a systemd unit for `-loop`.

Run the checker where clients are: the proxy check then measures what users
get. Checkers in different network zones can write to the same database; give
each its own `instance` name. Each one only removes the firewalls it owns.

## Configuration

### Settings in App Configuration

Every setting in the table below can also be set in Azure App
Configuration, under `datafetching.sxgCheck.` and by the same path:
`datafetching.sxgCheck.defaults.snmp.cpu.warn = 90`. They are read before every pass and win over the file; what is
not valid is left out with a warning in the log. A firewall is `firewalls.<name>.host`, `firewalls.<name>.tcp.ports` and so
on, merged into the file's firewall of that name or added (a name with a
"." in it cannot be written this way); `firewalls` as a JSON array replaces
the file's list. The MongoDB address,
the logging settings, the heartbeat and the instance name are read at the start; a change to
them applies at the next restart. `-no-app-config` runs on the file alone.
See the root README.


`deploy/config.example.json` is a full example. In short:

```json
{
  "mongo": { "uri": "mongodb://…", "database": "sxgcheck" },
  "interval": "1m",
  "defaults": {
    "tcp": { "ports": [4444, 3128] },
    "tls": {},
    "proxy": { "urls": ["http://www.msftconnecttest.com/connecttest.txt"] },
    "snmp": { "communityEnv": "SXG_SNMP_COMMUNITY", "requiredServices": ["http", "dns"] }
  },
  "firewalls": [
    { "name": "syd-fw01", "host": "10.10.0.1", "tenantName": "Production", "site": "Sydney" },
    { "name": "syd-fw02", "host": "10.10.0.2", "tenantName": "Production", "proxy": { "enabled": false } }
  ]
}
```

- A firewall's own settings are laid over `defaults` field by field.
  `"enabled": false` switches a check off for that firewall.
- `name` is the firewall's identity in the database. Renaming one starts a new
  history.
- `tenantName`, `site` and `tags` are labels for grouping in the dashboard.
- Secrets can come from the environment: `communityEnv`, `passwordEnv`,
  `authPasswordEnv`, `privPasswordEnv` name the variable to read.
- `SXGCHECK_MONGO_URI` and `SXGCHECK_MONGO_DATABASE` override the MongoDB
  settings. `SXGCHECK_FIREWALLS` (a JSON array) or `SXGCHECK_FIREWALLS_FILE`
  replace the `firewalls` list.
- Other settings: `timeout` (5s, per network operation), `retries` (1),
  `concurrency` (8 firewalls at once), `heartbeatInterval` (30s), `retention`
  in days (`logsDays` 30, `runsDays` 14, `resultsDays` 30, `eventsDays` 180),
  `logging.level` / `logging.mongoLevel` / `logging.format`.

Unknown fields are rejected, so a typo does not silently disable a check.

## What is stored

Database `sxgcheck` by default.

| Collection | One document per | Notes |
|---|---|---|
| `sxg_firewalls` | firewall (`_id` = name) | current `status`, `statusSince`, `summary`, `checks[]`, `metrics`, `device`, `ha`, `services[]`, `licenses[]`, `lastCheckedAt`, `lastOkAt` |
| `sxg_results` | firewall per pass | `at`, `status`, `counts`, `metrics`, `failing[]`; expires after `resultsDays` |
| `sxg_events` | change of health | `at`, `firewall`, `check` (absent for the firewall as a whole), `from`, `to`, `message`, `previousMs`; expires after `eventsDays` |
| `sxg_runs` | pass | `status`, counts of firewalls and checks by health, `changes`, `firewalls[]` |
| `sxg_logs` | log line | `time`, `level`, `severity`, `msg`, `firewall`, `check`, `runId`, `attrs` |
| `sxg_instances` | checker | heartbeat, mode, interval, last and next run |

A run's `status` is about the checker, not the firewalls: a run that found
every firewall down and stored that is a `success`. `partial` and `failed`
mean results could not be stored.

At `info` the checker logs when a check or a firewall changes health, not on
every pass: an error for critical, a warning for warning, info for recovery.
A restarted checker reads the stored state first, so it does not report
standing problems as new. While MongoDB is unreachable, changes are held and
recorded once it is back.

With the one-minute default, 20 firewalls add about 29,000 history documents
a day. Raise `interval` or lower `retention.resultsDays` if that is too much.
