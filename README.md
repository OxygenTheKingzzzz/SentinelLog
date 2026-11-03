# SentinelLog

Local SOC / Linux log intelligence platform. It ingests historical syslog into PostgreSQL, runs a rule engine and an experimental anomaly scorer, and serves a React dashboard. It can tail an allowlisted local file into a separate live source, and it can export an investigation as JSON or PDF. The bundled sample is the [Loghub](https://github.com/logpai/loghub) Linux_2k log (about 2,000 lines from host `combo`). That file has no malicious or benign labels. Alerts are rule findings, not confirmed compromise.

A longer map of the system is in `/cursor/stores/self/docs/delivery.md`.

## Setup

Python 3.12 (this machine used 3.12.3; the package requires `>=3.12`) and Node.js 22 (this machine used 22.23.4). PostgreSQL 16.

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
- `CORS_ORIGINS` — `http://127.0.0.1:5173,http://localhost:5173`
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
- `src/sentinellog/investigations/` workspaces, graph, JSON and PDF reports
- `src/sentinellog/live/` allowlisted file tail and SSE
- `web/` React dashboard
- `incidents` remains a status stub

Tables are created by Alembic. `6a757cd7ca97` is the initial schema. `ed1cc76d8439` adds rule versions and alert notes. `c4e8b1a09d27` adds anomaly models and scores. `d5f2a8c13e40` adds investigation links and notes. `e7b1c4d09a52` adds live collectors. Later revisions do not delete events, alerts, or scores.
