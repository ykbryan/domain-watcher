# domainwatch

Domain risk intelligence for SMBs in Southeast Asia.

Given a domain, domainwatch generates typosquat/lookalike permutations, filters to the ones that are actually live via DNS, enriches every live permutation with up to 11 threat-intel sources, and scores each from 0–100 with a severity band. Continuous monitoring fires diff-based alerts to Lark, Telegram, or email when new threats emerge.

## Quick start

Zero-config local stack:

```bash
docker compose up --build
```

Wait for the `api` container to log `api listening`, then:

```bash
curl -X POST http://localhost:8080/api/v1/scans/quick \
  -H "Content-Type: application/json" \
  -d '{"domain":"example.com"}' | jq
```

Expected shape (sync, ~10–30s):

```json
{
  "scan_id": "…",
  "target_domain": "example.com",
  "elapsed_ms": 18728,
  "permutation_count": 424,
  "live_count": 134,
  "enriched_count": 20,
  "aggregate_score": 0,
  "aggregate_band": "CLEAN",
  "findings_by_severity": {},
  "top_live_domains": [ … ]
}
```

`aggregate_score=0` is expected for a clean target like `example.com` without keyed sources configured. See [API keys](#api-keys) for how to light up the rest.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/healthz` | Liveness + DB ping |
| `GET` | `/api/v1/openapi.yaml` | Full OpenAPI 3.0 spec |
| `POST` | `/api/v1/scans/quick` | Synchronous demo scan (~30s budget) |
| `POST` | `/api/v1/scans` | Enqueue async scan |
| `GET` | `/api/v1/scans/{id}` | Scan status + progress |
| `GET` | `/api/v1/scans/{id}/results` | Paginated permutations ordered by score |
| `GET` | `/api/v1/scans/{id}/report` | Aggregate report with top domains + severity breakdown |
| `POST` | `/api/v1/monitors` | Create a monitored domain |
| `GET` | `/api/v1/monitors` | List monitors |
| `DELETE` | `/api/v1/monitors/{id}` | Delete a monitor (cascades to alerts) |
| `GET` | `/api/v1/monitors/{id}/alerts` | List alerts for a monitor |

Full request/response schemas in [api/handlers/openapi.yaml](api/handlers/openapi.yaml) or served live at `/api/v1/openapi.yaml`.

### Example: async scan

```bash
SCAN_ID=$(curl -sS -X POST http://localhost:8080/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"domain":"example.com"}' | jq -r .scan_id)

# poll
curl -sS http://localhost:8080/api/v1/scans/$SCAN_ID | jq

# when completed
curl -sS "http://localhost:8080/api/v1/scans/$SCAN_ID/results?risk_band=HIGH,CRITICAL" | jq
curl -sS "http://localhost:8080/api/v1/scans/$SCAN_ID/report" | jq
```

### Example: monitoring with Lark

```bash
curl -X POST http://localhost:8080/api/v1/monitors \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "check_interval_hours": 24,
    "alert_channels": {"lark_webhook": "https://open.larksuite.com/…"}
  }'
```

The scheduler (ticks every `MONITOR_TICK_SECONDS`, default 60) will enqueue scans on due monitors, diff each completed scan against its baseline, and dispatch a Lark Interactive Card when new HIGH/CRITICAL permutations emerge. The first scan establishes the baseline — no alerts fire on it.

## Architecture

Directory layout:

```
cmd/
  api/         HTTP server entrypoint
  scanner/     CLI: permutation + DNS only (no DB)
internal/
  permutation/ 15 typosquat strategies (wraps zntr.io/typogenerator)
  resolver/    concurrent DNS (miekg/dns) with upstream rotation
  enricher/    Source interface + FanOut runner
    sources/
      rdap certwatch abusech openphish urlscan
      virustotal safebrowsing otx ipinfo abuseipdb
  ratelimit/   per-source token-bucket registry
  scorer/      severity weights + band thresholds + multipliers
  pipeline/    the shared scan pipeline (used by sync + async)
  worker/      in-process worker pool for async scans
  monitor/     scheduler + differ
  alert/       Lark, Telegram, Email channels + dispatcher
  store/       pgx/v5 queries + embedded migrations
api/handlers/  HTTP handlers (thin; they call pipeline/worker)
```

Scan pipeline:

```
generate → resolve (DNS) → persist permutations →
  enrich top-N (async: all live) → score → persist findings →
  update risk_score/band → return aggregate
```

Monitoring loop (per scheduler tick):

```
diff completed scans → emit alerts → promote current→last →
  dispatch via configured channels → MarkSent
  (then) find due monitors → enqueue scans
```

## Configuration

All via environment variables. See [.env.example](.env.example) for a full list.

Required:

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | `postgres://…` connection string |

Core tunables (all have sensible defaults):

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `8080` | HTTP listen port |
| `DNS_UPSTREAMS` | `8.8.8.8:53,1.1.1.1:53,9.9.9.9:53` | DNS resolvers; set to `127.0.0.11:53` when running inside Docker on macOS |
| `DNS_WORKER_COUNT` | `50` | Concurrent DNS lookups |
| `ENRICHER_WORKER_COUNT` | `10` | Concurrent enrichment goroutines |
| `MAX_PERMUTATIONS` | `2000` | Cap per scan |
| `SCAN_TIMEOUT_SECONDS` | `120` | Per-scan budget (async only) |
| `SCAN_WORKER_COUNT` | `3` | Async scan worker pool size |
| `MONITOR_TICK_SECONDS` | `60` | Scheduler tick cadence |

## API keys

All enricher API keys are optional — without them, only the no-key sources run. **Every source degrades gracefully**: a missing key means the source isn't registered; a bad key or upstream failure means the individual finding is recorded with `finding.error` but the scan still succeeds.

Registration priority (biggest impact first):

| # | Env var | Register at | Tier | Notes |
|---|---|---|---|---|
| 1 | `ABUSECH_AUTH_KEY` | https://auth.abuse.ch | Free, no cap | Single key unlocks **both** URLhaus and ThreatFox |
| 2 | `VIRUSTOTAL_API_KEY` | https://www.virustotal.com/gui/join-us | 4 req/min, 500/day | Drives the scorer's ×1.5 multiplier on confirmed-malicious |
| 3 | `GOOGLE_SAFE_BROWSING_KEY` | https://developers.google.com/safe-browsing/v4/get-started | 10K/day | Google's ground truth |
| 4 | `IPINFO_TOKEN` | https://ipinfo.io/signup | 50K/month | IP org / country / ASN |
| 5 | `OTX_API_KEY` | https://otx.alienvault.com/signup | No cap | Community IOC pulses |
| 6 | `ABUSEIPDB_API_KEY` | https://www.abuseipdb.com/register | 1K/day | IP abuse confidence |
| 7 | `URLSCAN_API_KEY` | https://urlscan.io/user/signup | 100/day | **Optional** — search works without |

Alert channel env (all optional):

| Variable | Purpose |
|---|---|
| `TELEGRAM_BOT_TOKEN` | Registers the Telegram channel |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` / `SMTP_PASS` / `SMTP_FROM` | Registers the email channel |

Lark needs no global config — the webhook URL is per-monitor.

## Development

```bash
# run tests
go test -race -cover ./...

# run the CLI (permutation + DNS only; no DB)
go run ./cmd/scanner --domain example.com --resolve

# run the API against a local postgres
docker compose up -d postgres
DATABASE_URL="postgres://domainwatch:domainwatch@localhost:5432/domainwatch?sslmode=disable" \
  go run ./cmd/api

# apply migrations manually (usually handled on startup)
# migrations live embedded in internal/store/migrations/*.sql
```

Integration tests that need a real Postgres:

```bash
TEST_DATABASE_URL="postgres://…" go test ./internal/store/...
```

Tests skip gracefully when `TEST_DATABASE_URL` is unset.

## Deployment

domainwatch is designed to run on Coolify with a managed Postgres (Supabase or equivalent). Nothing in the code assumes local docker:

1. Build the image: `docker build -t domainwatch .`
2. Set `DATABASE_URL` to your Coolify-hosted Postgres connection string (likely with `?sslmode=require`).
3. Set whichever API keys you've registered.
4. Migrations run on every startup — they're embedded in the binary via `//go:embed`.

The container runs as non-root user 65532 (nobody convention), has no shell or interpreter, and expects outbound HTTPS to the configured enricher endpoints.

## What's out of scope

Explicitly not in this repo:

- **UI / frontend** — lives in a separate Next.js repo.
- **PDF report generation** — JSON report via `/api/v1/scans/{id}/report`; PDF is post-MVP.
- **Dark web / app-store monitoring** — post-MVP.
- **Automated takedown workflows** — post-MVP.
- **Auth / multi-tenancy** — API is currently open; protect with a reverse-proxy auth layer (oauth2-proxy, etc.) in prod.

## License

TBD.
