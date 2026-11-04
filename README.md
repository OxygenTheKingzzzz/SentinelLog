# SentinelLog

Local SOC / Linux log intelligence platform. It ingests historical syslog into PostgreSQL, runs a rule engine and an experimental anomaly scorer, and serves a React dashboard. It can tail an allowlisted local file into a separate live source, and it can export an investigation as JSON or PDF. The bundled sample is the [Loghub](https://github.com/logpai/loghub) Linux_2k log (about 2,000 lines from host `combo`). That file has no malicious or benign labels. Alerts are rule findings, not confirmed compromise.

A longer map of the system is in `/cursor/stores/self/docs/delivery.md`.

## Setup

Python 3.12 (this machine used 3.12.3; the package requires `>=3.12`) and Node.js 22 (this machine used 22.23.4). PostgreSQL 16.

Unpack the archive and start the sample from the repo root:

```bash
bash scripts/run-local.sh
```

That command creates `.env` and a virtualenv, starts Postgres with Docker when it is installed, loads Linux_2k, fits the anomaly model and the risk bands, then serves the API on http://127.0.0.1:8000 and the dashboard on http://127.0.0.1:5173. Ctrl-C stops those two processes. The BGL and HDFS corpora are not in the archive. Their measured results are already in `src/sentinellog/risk/published_results.json` and `src/sentinellog/risk/realistic_results.json`.

Without Docker, create the `sentinellog` role and database first. The script prints those commands if it cannot connect.

### Postgres with Docker

`docker-compose.yml` starts Postgres 16 and creates the `sentinellog` database. It does not create the test database.

```bash
docker compose up -d
docker compose exec postgres psql -U sentinellog -d sentinellog -c "CREATE DATABASE sentinellog_test"
```

### Postgres without Docker

This VM had no Docker daemon. PostgreSQL 16 from apt (`postgresql-16` and `postgresql-client-16`) was started with `pg_ctlcluster` because the package init script was blocked:

```bash
sudo apt-get install -y postgresql-16 postgresql-client-16
sudo pg_ctlcluster 16 main start
sudo -u postgres psql -c "CREATE ROLE sentinellog LOGIN PASSWORD 'sentinellog' CREATEDB"
sudo -u postgres psql -c "CREATE DATABASE sentinellog OWNER sentinellog"
sudo -u postgres psql -c "CREATE DATABASE sentinellog_test OWNER sentinellog"
```

### Environment

Copy `.env.example` to `.env`. Do not commit `.env`. The example file sets:

- `DATABASE_URL` — `postgresql+psycopg://sentinellog:sentinellog@127.0.0.1:5432/sentinellog`
- `SOURCE_YEAR` — optional default only when a new source omits a year. Leave it unset for arbitrary sources. It is not how Linux_2k gets 2005.
- `MAX_UPLOAD_BYTES` — default 33554432
- `LOG_LEVEL` — `INFO`
- `CORS_ORIGINS` — `http://127.0.0.1:5173,http://localhost:5173`. Add the public dashboard origin when the UI is hosted elsewhere. A wildcard is rejected.
- `VITE_API_BASE_URL` — optional public API origin for the dashboard, set in `web/.env` (see `web/.env.example`). Empty keeps the Vite proxy. It is not a secret and must not contain credentials.
- `RATE_LIMIT_REQUESTS` — 30
- `RATE_LIMIT_WINDOW_SECONDS` — 60
- `DEBUG` — `false`
- `ANOMALY_ARTIFACT_DIR` — optional, default `var/anomaly-models`
- `SENTINELLOG_TEST_DATABASE_URL` — `postgresql+psycopg://sentinellog:sentinellog@127.0.0.1:5432/sentinellog_test`

`LIVE_ALLOW_ROOTS` is optional. Empty means no live file can be authorized. It is a path-separator list of absolute directories.

### Install, migrate, and load Linux_2k

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
export DATABASE_URL=postgresql+psycopg://sentinellog:sentinellog@127.0.0.1:5432/sentinellog
alembic upgrade head
python -m sentinellog.cli import-bundled
python -m sentinellog.cli detect --source-name linux-2k
python -m sentinellog.cli anomaly-train --source-name linux-2k
python -m sentinellog.cli anomaly-score --source-name linux-2k
```

`import-bundled` loads templates, imports `datasets/Linux_2k.log` with source year 2005, validates stored rows against `datasets/Linux_2k.log_structured.csv`, then backfills null timestamps. A second run reports 2000 duplicates and still exits 0 when validation matches. `detect` evaluates the enabled rules and does not insert a second copy of the same finding. Train writes an Isolation Forest artifact. Score writes `anomaly_scores`. Neither writes `security_alerts`.

### API and UI

In one shell, from the repo root with the virtualenv active:

```bash
export DATABASE_URL=postgresql+psycopg://sentinellog:sentinellog@127.0.0.1:5432/sentinellog
python -m sentinellog.cli serve --host 127.0.0.1 --port 8000
```

In another shell:

```bash
cd web
npm ci
npm run dev -- --host 127.0.0.1 --port 5173
```

Open http://127.0.0.1:5173 . Vite proxies `/api` and `/health` to port 8000.

### Tests

These commands passed on this machine. `pytest` truncates `sentinellog_test`. It does not touch the dev database unless `SENTINELLOG_TEST_DATABASE_URL` points there.

```bash
export SENTINELLOG_TEST_DATABASE_URL=postgresql+psycopg://sentinellog:sentinellog@127.0.0.1:5432/sentinellog_test
pytest
ruff check src tests
cd web && npm test && npm run build
```

`npm test` is Vitest. `npm run build` is `tsc --noEmit` and the Vite production build. `.github/workflows/ci.yml` runs the same checks against a Postgres service. That workflow has not run on GitHub: this repo has no remote.

## What the Level column is

In `datasets/Linux_2k.log_structured.csv`, `Level` is the syslog hostname. In this file every value is `combo`. It is stored as `log_events.hostname`. It is not a severity.

## Dedup

Identity of a stored line:

`{source_id}:{line_number}:{sha256(raw_line)}`

`raw_line` is the line body with the CR/LF terminator removed and trailing spaces kept. Re-importing the same bytes increments `duplicates_skipped` and does not insert another row. The same source and line number with a different hash is a conflict: the original row stays, and the job records a conflict. Every input line is one of: parsed (inserted), parse error, duplicate, or conflict.

## Timestamps

Month, day, and time are always stored. At ingest, `event_timestamp` stays null unless the log source has `source_year` set (the API field, the CLI `--year`, or `SOURCE_YEAR` as the default only when a new source omits a year). These lines have no timezone. A configured year is interpreted as UTC. The year is not read from message text, FTP banners, or kernel audit epochs.

`import-bundled` is the exception for this dataset only: it defaults the bundled source year to 2005 (override with `--year`). That default is not `SOURCE_YEAR` and is not applied to other sources. If the bundled source already exists with a null year, the command sets 2005. If it already has a different year, the command refuses. After import it backfills null timestamps. A timestamp that is already set is left alone.

For a source that was imported earlier with a null year:

```bash
python -m sentinellog.cli backfill --source-name linux-2k --year 2005
```

`backfill` without `--year` uses the year already stored on that source. It does not assume 2005. Pass `--year` only to fill a null `source_year`. A different stored year is refused, and existing timestamps are not rewritten.

## API

Routes are under `/api/v1` unless noted. `GET /health` checks the database.

- Sources and ingest: `POST/GET /sources`, `POST /sources/{id}/ingest/raw|templates|structured`
- Search: `GET /events`, `GET /events/facets`, `GET /events/{id}`, `GET /overview`, `GET /sources/{id}/quality`, `GET /templates`
- Jobs: `GET /jobs`, `GET /jobs/{id}`, `GET /jobs/{id}/errors`
- Rules and alerts: `GET /detection/status`, `POST /detection/run`, `GET/PATCH /rules`, `GET /alerts`, `POST /alerts/{id}/status`
- Anomalies: `GET /ml/status`, `POST /ml/train`, `POST /ml/score`, `GET /ml/models`, `GET /ml/models/latest`, `GET /ml/scores`
- Risk: `GET /risk/experiments`, `GET /risk/predictions`, `GET /risk/distribution`, `POST /risk/bands`, `POST /risk/labels`, `POST /risk/labels/import`, `POST /risk/weak-labels`, `POST /risk/train`
- Investigations: `GET/POST /investigations`, `POST /{id}/links`, `PATCH /{id}/status`, `POST /{id}/notes`, `GET /{id}/graph`, `GET /{id}/evidence`, `GET /{id}/report.pdf`
- Live: `GET /live/status`, `GET /live/collectors`, `POST /live/files`, `POST /live/collectors/{id}/start|stop`, `GET /live/stream`
- Other: `GET /audit`, `GET /settings`, `GET /incidents/status`, `GET /reports/status`

`GET /settings` returns the database driver, host, port, and name. It does not return the password. `/incidents/status` stays unimplemented. `/reports/status` points at the investigation JSON and PDF exports.

Uploads are size-limited, must be UTF-8 text without NUL bytes, and must use an allowed extension. Filenames that contain a path or `..` are rejected. Log bytes are not passed to a shell.

## Layout

- `src/sentinellog/ingestion/` parsing, template match, validation, jobs
- `src/sentinellog/normalization/` timestamps, optional IP/username, search and quality queries
- `src/sentinellog/detection/` builtin rules, windows, backfill, alert lifecycle
- `src/sentinellog/ml/` hourly features, Isolation Forest, robust-z baseline
- `src/sentinellog/risk/` four-level risk bands, verified labels, and per-dataset evaluation
- `src/sentinellog/investigations/` workspaces, graph, JSON and PDF reports
- `src/sentinellog/live/` allowlisted file tail and SSE
- `web/` React dashboard
- `incidents` remains a status stub

Tables are created by Alembic. `6a757cd7ca97` is the initial schema. `ed1cc76d8439` adds rule versions and alert notes. `c4e8b1a09d27` adds anomaly models and scores. `d5f2a8c13e40` adds investigation links and notes. `e7b1c4d09a52` adds live collectors. `f3a91c2e8b17` adds risk labels, models, and predictions. Later revisions do not delete events, alerts, or scores.

## Risk classification

`POST /api/v1/risk/bands` fits an Isolation Forest on stored Linux logs and assigns LOW, MEDIUM, HIGH, or CRITICAL from training-score quantiles. The anomaly score is not a class probability. Loghub Linux has no verified risk labels, so that page shows `Not evaluated — ground-truth labels required`.

Reviewers can save a verified label with `POST /api/v1/risk/labels` or import `line_number,risk_level,note` as `verified_import`. `POST /api/v1/risk/weak-labels` copies alert severity onto events and marks those rows `weak_rule`. Training on weak labels stores agreement only in the model config. It does not fill the accuracy field.

`python -m sentinellog.risk.experiments <dataset-dir> --out src/sentinellog/risk/published_results.json` evaluates BGL, HDFS, OpenStack, Hadoop, and Thunderbird with their own parsers when those files are present. Metrics in that file are held-out scores on each dataset's own unit. A dataset that does not contain both classes is left unevaluated.

BGL and HDFS numbers in `published_results.json` describe a seeded sample of at most 28,000 examples. Whole template groups are drawn round-robin by class before the split, and each group contributes at most 40 rows, so the test base rate is not the corpus base rate. That file is the rebalanced benchmark.

`python -m sentinellog.risk.realistic <dataset-dir> --out src/sentinellog/risk/realistic_results.json --report docs/realistic-prevalence-evaluation.md` assigns groups to train, validation, and test before sampling, keeps each side's own anomaly rate, and chooses thresholds on validation only. The dashboard lists that run separately from the benchmark. OpenStack supervised models stay unevaluated when the anomalous instances share one normalized template. Thunderbird_2k and Linux stay unevaluated. Binary datasets are scored as normal versus anomaly. That is not four-class LOW/MEDIUM/HIGH/CRITICAL accuracy. Linux bands remain estimated score quantiles.

## Public deployment security

The dashboard permits public reads of shared log data. Uploads and all other mutations
require `Authorization: Bearer <API_ADMIN_TOKEN>`; configuration, audit, and collector
metadata are also restricted. Set a long random `API_ADMIN_TOKEN` on the API service.
Enter it in the dashboard Settings page; it stays in session storage for that tab.
Clearing the token in Settings removes access. Rotate it in Railway to revoke existing tokens.
Do not put it in a `VITE_` variable or commit it.

For Railway, `scripts/cloud-start.py` runs migrations using `DATABASE_ADMIN_URL`,
then starts the API as `sentinel_app`, using `DATABASE_APP_PASSWORD`. The runtime
role has table read/write access but cannot create schemas, roles, or databases.
The owner URL and separate password copy are removed from the API process environment.
Keep Postgres on Railway's private network and keep public TCP proxies disabled.

Request sizes, database connection pools, query durations, and per-process request
rates are bounded. The rate limiter is not distributed; horizontal scaling needs a
shared limiter or gateway. Public reads are shared across visitors: this is not
multi-tenant log storage. These protections do not make confidential uploads private.
