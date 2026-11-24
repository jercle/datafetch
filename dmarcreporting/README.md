# dmarc-reporting

> **Part of [datafetch](../README.md).** Merged from `jercle/dmarc-reporting` at `55f8b76`.
> Run it as `datafetch dmarc-reporting`. Its settings in Azure App Configuration are
> under `datafetching.dmarcReporting` and win over the environment variables; how that works,
> the environment variables and how to build are in the root README.
> The dashboard modules this document mentions were not merged: they are
> still in `jercle/dmarc-reporting`.

Polls an Exchange Online mailbox for **DMARC failure (RUF / forensic) reports** and **aggregate (RUA) reports**, parses them, enriches the sending IPs (GeoIP, ASN, reverse DNS), and upserts them into MongoDB.

```
Exchange Online ──Graph API──▶ MIME walk ──▶ ARF / inline parser ──▶ enrich ──▶ MongoDB
  (mailbox folder)              ($value)     RUA XML (.xml/.gz/.zip)  (geo/ASN/   dmarc_failures
        ▲                                                             rDNS/PSL)   dmarc_aggregate_*
                                                                                  dmarc_ingest
        └──────── move to Processed / Failed (or mark read + category) ◀──────────┘
```

It uses Microsoft Graph rather than EWS. EWS for Exchange Online is being retired, so new tooling shouldn't depend on it.

## What it parses

| Shape | `format` | Example sources |
|---|---|---|
| RFC 6591 ARF: a `message/feedback-report` part with the original as `message/rfc822` or `text/rfc822-headers` | `arf` | Most RUF senders |
| The same parts **relabelled** on the way. Exchange returns them as base64 `ATT00001` attachments and the declared type is not reliable, so parts are recognised by content as well as by type | `arf` | Anything read through Exchange |
| Reports **attached** to another mail (`.eml`, `message/rfc822`, forwarded or digested), including inside `.zip` / `.gz` | as found | Forwarded reports, digest senders |
| ARF field names (`Feedback-Type:`, `Source-IP:` ...) and the original headers in a text **or HTML** body, quoted (`> `) or not | `inline` | Appliances, inline forwards |
| Plain-text or HTML-table summaries with their own labels (`Sender Domain:`, `Sender IP Address:`, `SPF Alignment:` ...) | `text` | Exim / SpamExperts gateways, hosted filters |
| Bounces (DSNs) saying the message was refused because of DMARC, with the refused message attached | `bounce` | Receivers that reject instead of reporting |
| The failing message attached to a mail that says it is a DMARC/authentication failure, with no fields | `headers` | Manual forwards |

### When a message is not recognised

It is recorded in `dmarc_ingest` with status `no_reports` and a `structure` list: every MIME part, its declared type, name, encoding, size, first line, and what the parser took it for. The dashboard shows this under **Collector → Messages needing a look → Message structure**, and it is logged as a warning. That is the evidence needed to add a format.

* `DMARC_SAVE_UNPARSED_DIR=/some/dir` also writes each such message there as an `.eml`, which can be run through `dmarc-collector -parse file.eml` (it prints the same structure).
* `dmarc-collector -reprocess` re-reads the Failed folder once: messages that now parse are stored and moved to Processed, the rest stay. Use it after updating the collector. (In `markread` mode, mark the messages unread instead.)


### Aggregate (RUA) reports

XML reports are found wherever they turn up: `.xml`, `.xml.gz` or `.zip` attachments (detected by content type, file name *or* magic bytes), bare XML parts, and inside forwarded `.eml`s. Both RFC 7489 and DMARCbis (namespaced, `np`, `testing`) formats are accepted, including Latin-1/Windows-1252 encodings.

They are stored in two collections:

* `dmarc_aggregate_reports`: one document per report (reporter, report ID, period, published policy, totals).
* `dmarc_aggregate_records`: one document per `<record>` row, with the source IP enriched like failure reports and the report metadata copied in so the dashboard needs no joins.

**Duplicates are skipped.** A report is identified by `reportKey = sha256(org_name, report_id, policy domain, begin, end)`. `report_id` is unique per reporter (RFC 7489 §7.2.1.1), so the same report arriving twice (several `rua=` addresses, resends, the same report zipped and unzipped, or the mailbox being reprocessed) is recognised. A byte-identical XML (`contentHash`) is also treated as a duplicate. The check happens *before* enrichment, so duplicates cost almost nothing. Rows are written first and the report document last, so an interrupted write is completed on the next attempt rather than being mistaken for a duplicate.

Aggregate and failure reports describe different things (message counts vs individual messages), so neither is deduplicated against the other.

When `Source-IP` is missing, the IP comes from `Received-SPF: client-ip=` and then from the top public `Received:` hop. Those reports are flagged with `source.derived: true`.

Each report gets a **fingerprint** (a SHA-256 of the reporter, domain, IP, original Message-ID and the report fields). Re-ingesting the same mail is a no-op, so you can run it more than once safely.

## Enrichment

* **GeoIP and ASN**: offline MaxMind GeoLite2 City + ASN `.mmdb` files (free account, keep them fresh with `maxmindinc/geoipupdate`).
* **ipinfo Lite** (optional, `IPINFO_TOKEN`): fills country/ASN gaps and adds the AS domain.
* **Reverse DNS**: PTR lookup plus forward confirmation (FCrDNS). `source.ptrOrgDomain` is the registrable domain of the PTR, which the dashboard's "Server org" grouping uses.
* **Org domains**: computed via the Public Suffix List for the reported, From and reporter domains, so `mail.contoso.com.au` groups under `contoso.com.au`.

Lookups are cached in memory for 12 h.

## Entra ID / Exchange setup

1. Create an app registration. Under **API permissions → Microsoft Graph → Application**, add `Mail.ReadWrite` (needed to move or flag messages) and grant admin consent.
2. **Scope it to the DMARC mailbox only.** Without this the app can read every mailbox in the tenant. Use Exchange *RBAC for Applications*:
   ```powershell
   New-ServicePrincipal -AppId <client-id> -ObjectId <enterprise-app-object-id> -DisplayName "dmarc-collector"
   New-ManagementScope -Name "DMARC mailbox" -RecipientRestrictionFilter "PrimarySmtpAddress -eq 'dmarc-reports@contoso.com.au'"
   New-ManagementRoleAssignment -App <client-id> -Role "Application Mail.ReadWrite" -CustomResourceScope "DMARC mailbox"
   ```
   If you use RBAC for Applications, remove the tenant-wide Graph `Mail.ReadWrite` consent. (An `ApplicationAccessPolicy` also works but is the legacy approach.)
3. Authenticate with **either** a client secret (`AZURE_CLIENT_SECRET`) **or** AKS workload identity. For workload identity, add a federated credential for the service account. The webhook then injects `AZURE_CLIENT_ID`, `AZURE_TENANT_ID` and `AZURE_FEDERATED_TOKEN_FILE`.

## Run

```bash
make build                                  # from the repository root: ./datafetch
cp dmarcreporting/deploy/env.example .env   # fill in

# Parse local samples and print JSON (no mailbox, Mongo or App Configuration needed):
./datafetch dmarc-reporting -parse dmarcreporting/internal/parser/testdata/arf.eml dmarcreporting/internal/parser/testdata/aggregate.xml

# Continuous (Deployment): polls every DMARC_POLL_INTERVAL, health on :8080/healthz
set -a; . ./.env; set +a; ./datafetch dmarc-reporting

# One-shot (CronJob)
./datafetch dmarc-reporting -once
```

Docker: the image is datafetch's (`docker build -t datafetch .` in the repository root), run with the argument `dmarc-reporting`. For Kubernetes, see `deploy/kubernetes.yaml` (Deployment with workload identity, probes, and a GeoIP PVC). Keep it at **1 replica** because the mailbox is the queue.

### Post-processing modes

* `DMARC_POST_PROCESS=move` (default): moves messages to `DMARC_PROCESSED_FOLDER` or `DMARC_FAILED_FOLDER` and creates those folders if they're missing.
* `markread`: leaves messages in place, marks them read and adds the category `DMARC-Processed` or `DMARC-Failed`. Only unread mail is polled.

If Mongo is down, nothing is moved and the poll retries next interval. If a move fails *after* the write, the ingest log stops the message being processed twice.

## Monitoring

Unless `MONITORING_ENABLED=false`, the collector records itself in the same database. Writes are best-effort: if MongoDB is unreachable, collection carries on and stdout still has every log line.

| Collection | Contents |
|---|---|
| `dmarc_collector_runs` | One document per poll of the mailbox: status (`running`, `success`, `partial`, `failed`, `cancelled`), timings, error, and totals (messages, failure and aggregate reports found / stored / duplicate, messages without a report, messages that could not be moved). `heartbeatAt` is refreshed every 30 s while running, so a run whose heartbeat stops was killed. |
| `dmarc_collector_logs` | Structured log entries at or above `MONITORING_LOG_LEVEL`. `runId`, `graphId`, `subject`, `from` and `error` are top-level fields; other attributes are under `attrs`. |
| `dmarc_collector_instances` | One document per host (pod): version, mode (`schedule` / `once`), state (`idle`, `running`, `exited`), heartbeat, last run and next scheduled run. |

`dmarc_ingest` rows (one per mailbox message) now carry the `runId` of the poll that handled them, which is how the dashboard lists a run's messages.

`partial` means the poll finished but some messages could not be moved or flagged afterwards (they are retried after an hour). Retention defaults to 30 days for logs and 180 days for runs, enforced with TTL indexes; changing `MONITORING_LOG_RETENTION_DAYS` / `MONITORING_RUN_RETENTION_DAYS` updates them on the next start. The version shown in the dashboard is datafetch's, set at build time (`make build VERSION=1.2.3`, or the Dockerfile's `VERSION` argument).

## Configuration

The environment variables are this tool's configuration file: see
`deploy/env.example` for all of them. Each can also be set in Azure App
Configuration under `datafetching.dmarcReporting.`, where it wins over the
variable. The settings are read before every poll; what is not valid is
left out with a warning in the log, and if the result is not a usable
configuration the collector starts on the environment alone and says why.
`-no-app-config` ignores App Configuration, and `-parse` never reads it.

The poll interval, the batch size, the folders, `postProcess`,
`saveUnparsedDir` and the three privacy switches apply from the next poll.
Everything else (the app registration, the mailbox, the endpoints,
MongoDB, enrichment, monitoring, the health address and the log level) is
read at the start and applies at the next restart.

| Setting under `datafetching.dmarcReporting.` | Environment variable |
|---|---|
| `tenantId` | `AZURE_TENANT_ID` |
| `clientId` | `AZURE_CLIENT_ID` |
| `clientSecret` | `AZURE_CLIENT_SECRET` |
| `federatedTokenFile` | `AZURE_FEDERATED_TOKEN_FILE` |
| `authorityHost` | `AZURE_AUTHORITY_HOST` |
| `graphEndpoint` | `GRAPH_ENDPOINT` |
| `mailbox` | `DMARC_MAILBOX` |
| `sourceFolder` | `DMARC_SOURCE_FOLDER` |
| `processedFolder` | `DMARC_PROCESSED_FOLDER` |
| `failedFolder` | `DMARC_FAILED_FOLDER` |
| `postProcess` | `DMARC_POST_PROCESS` |
| `pollInterval` | `DMARC_POLL_INTERVAL` |
| `batchSize` | `DMARC_BATCH_SIZE` |
| `mongo.uri` | `MONGODB_URI` |
| `mongo.database` | `MONGODB_DATABASE` |
| `mongo.collection` | `MONGODB_COLLECTION` |
| `mongo.ingestCollection` | `MONGODB_INGEST_COLLECTION` |
| `mongo.aggregateReportsCollection` | `MONGODB_AGGREGATE_REPORTS_COLLECTION` |
| `mongo.aggregateRecordsCollection` | `MONGODB_AGGREGATE_RECORDS_COLLECTION` |
| `mongo.runsCollection` | `MONGODB_RUNS_COLLECTION` |
| `mongo.logsCollection` | `MONGODB_LOGS_COLLECTION` |
| `mongo.instancesCollection` | `MONGODB_INSTANCES_COLLECTION` |
| `geoipCityDb` | `GEOIP_CITY_DB` |
| `geoipAsnDb` | `GEOIP_ASN_DB` |
| `ipinfoToken` | `IPINFO_TOKEN` |
| `reverseDns` | `REVERSE_DNS` |
| `dnsTimeout` | `DNS_TIMEOUT` |
| `saveUnparsedDir` | `DMARC_SAVE_UNPARSED_DIR` |
| `redactSubject` | `REDACT_SUBJECT` |
| `storeOriginalHeaders` | `STORE_ORIGINAL_HEADERS` |
| `storeRawFields` | `STORE_RAW_FIELDS` |
| `monitoring.enabled` | `MONITORING_ENABLED` |
| `monitoring.logLevel` | `MONITORING_LOG_LEVEL` |
| `monitoring.logRetentionDays` | `MONITORING_LOG_RETENTION_DAYS` |
| `monitoring.runRetentionDays` | `MONITORING_RUN_RETENTION_DAYS` |
| `instanceName` | `INSTANCE_NAME` |
| `healthAddr` | `HEALTH_ADDR` |
| `logLevel` | `LOG_LEVEL` |

Durations are text (`5m`, `3s`); switches are `true` or `false`.

Privacy-related ones:

| Variable | Default | Effect |
|---|---|---|
| `REDACT_SUBJECT` | `false` | Store `[redacted]` instead of original subjects |
| `STORE_ORIGINAL_HEADERS` | `false` | Also store the full original header map |
| `STORE_RAW_FIELDS` | `true` | Keep the raw ARF field map (handy for the detail view) |

Failure reports can contain recipient addresses and subjects (personal data). Set retention to suit your policy, e.g. a TTL index:
`db.dmarc_failures.createIndex({ ingestedAt: 1 }, { expireAfterSeconds: 31536000 })`.

## Layout

```
cli.go                the command: datafetch dmarc-reporting (-once, -parse, -reprocess)
internal/config       the environment, and its JSON shape for App Configuration
internal/graph        Graph client: token (secret or federated), folders, list, $value, move, throttling
internal/parser       lenient header parser, MIME walker, ARF/inline extraction, Authentication-Results
internal/enrich       MaxMind / ipinfo / rDNS / PSL
internal/store        Mongo upsert + indexes + ingest log
internal/collector    poll loop and post-processing
internal/monitor      run records, log sink (slog handler), instance heartbeat, TTL indexes
internal/model        document schema (shared contract with the dashboard)
```
