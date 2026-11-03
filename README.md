# SentinelLog

Local SOC / Linux log intelligence platform. It ingests historical syslog, stores it in PostgreSQL, runs a rule-based detection engine and an experimental anomaly scorer, and serves a React dashboard over those stored rows. It can also tail an explicitly allowlisted local file, read-only, into a separate live source. It does not write PDF reports.

The bundled sample is the [Loghub](https://github.com/logpai/loghub) Linux_2k log (about 2,000 historical lines from host `combo`). There are no malicious/benign labels in that dataset. Detection alerts are rule findings on those unlabeled logs, not confirmed compromise.

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

## Run

Python 3.12+, then PostgreSQL 16.

With Docker (preferred when a daemon is available):

```bash
docker compose up -d
docker compose exec postgres psql -U sentinellog -d sentinellog -c "CREATE DATABASE sentinellog_test"
python3 -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
export DATABASE_URL=postgresql+psycopg://sentinellog:sentinellog@127.0.0.1:5432/sentinellog
alembic upgrade head
python -m sentinellog.cli import-bundled
python -m sentinellog.cli detect --source-name linux-2k
python -m sentinellog.cli anomaly-train --source-name linux-2k
python -m sentinellog.cli anomaly-score --source-name linux-2k
python -m sentinellog.cli serve
```

This VM had no Docker daemon. Postgres 16 was installed with apt and started with `pg_ctlcluster` because the package init script was blocked. Tests ran against that local server, using database `sentinellog_test`:

```bash
sudo pg_ctlcluster 16 main start
sudo -u postgres psql -c "CREATE ROLE sentinellog LOGIN PASSWORD 'sentinellog' CREATEDB"
sudo -u postgres psql -c "CREATE DATABASE sentinellog OWNER sentinellog"
sudo -u postgres psql -c "CREATE DATABASE sentinellog_test OWNER sentinellog"
python3 -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
export DATABASE_URL=postgresql+psycopg://sentinellog:sentinellog@127.0.0.1:5432/sentinellog
alembic upgrade head
python -m sentinellog.cli import-bundled
python -m sentinellog.cli detect --source-name linux-2k
python -m sentinellog.cli anomaly-train --source-name linux-2k
python -m sentinellog.cli anomaly-score --source-name linux-2k
export SENTINELLOG_TEST_DATABASE_URL=postgresql+psycopg://sentinellog:sentinellog@127.0.0.1:5432/sentinellog_test
pytest
ruff check src tests
ruff format --check src tests
```

`pytest` truncates `SENTINELLOG_TEST_DATABASE_URL`. It does not use the dev database unless you point that variable at it.

`import-bundled` loads templates, imports `datasets/Linux_2k.log` with source year 2005, validates every stored row against `datasets/Linux_2k.log_structured.csv`, then backfills null timestamps. A second run reports 2000 duplicates and still exits 0 when validation matches. `detect` evaluates the enabled rules. Running it again does not insert a second copy of the same finding.

Copy `.env.example` to `.env` for local defaults. Do not commit `.env`.

## API

- `POST /api/v1/sources`
- `POST /api/v1/sources/{id}/ingest/raw` multipart field `file` (`.log` / `.txt`)
- `POST /api/v1/sources/{id}/ingest/templates` (`.csv`)
- `POST /api/v1/sources/{id}/ingest/structured?mode=validate|import` (`.csv`)
- `GET /api/v1/events` filters: `component`, `event_id`, `hostname`, `month`, `day`, `q`, `occurred_from`, `occurred_to`, `line_number`
- `GET /api/v1/events/facets` and `GET /api/v1/overview` (optional `source_id`)
- `GET /api/v1/audit` and `GET /api/v1/settings` (database host and name only; no password)
- `GET /api/v1/sources/{id}/quality`
- `GET /api/v1/jobs/{id}` and `GET /api/v1/jobs/{id}/errors`
- `GET /api/v1/rules` and `PATCH /api/v1/rules/{id}` (`enabled`, `threshold`, `window_seconds`, `window_type`)
- `POST /api/v1/detection/run?source_id=` optional source; omit it to run every source
- `GET /api/v1/alerts` filters: `severity`, `status`, `rule` (name or id), `source_id`; `sort` is `window_start`, `created_at`, or `severity`
- `GET/POST /api/v1/investigations`, plus `/{id}`, `/{id}/links`, `/{id}/status`, `/{id}/notes`, `/{id}/graph`, `/{id}/evidence`
- `POST /api/v1/alerts/{id}/status` with `status` and a non-empty `note`
- `POST /api/v1/ml/train` and `POST /api/v1/ml/score` (optional `source_id` / required `source_id`)
- `GET /api/v1/ml/models`, `GET /api/v1/ml/models/latest`, `GET /api/v1/ml/models/{id}`
- `GET /api/v1/ml/scores` filters: `source_id`, `model_id`, `flagged` (`isolation`, `baseline`, or `either`)
- `GET /health`

`occurred_from` / `occurred_to` apply to `event_timestamp`, which is null until a year is configured or backfilled. `month` and `day` filter the syslog calendar fields without a year.

Alert lifecycle values are `open`, `investigating`, `resolved`, and `false_positive`. A status change stores the note and an `audit_logs` row. Changing a rule's threshold or window bumps `detection_rules.version` and writes an audit row. Enabling or disabling a rule is audited and does not bump the version. Severity on a rule or alert is an analyst priority (`low`, `medium`, `high`, `critical`), not a verified incident.

Uploads are size-limited (`MAX_UPLOAD_BYTES`, default 32 MiB), must be UTF-8 text without NUL bytes, and must use an allowed extension. Filenames that contain a path or `..` are rejected. Log bytes are stored and parsed. They are not executed and are not passed to a shell.

`GET /api/v1/detection/status` reports that the rule engine is implemented. `GET /api/v1/ml/status` reports that anomaly scoring is implemented and that the dataset has no ground truth (`metrics` is null). Analyst workspaces live at `/api/v1/investigations`. `GET /api/v1/live/status` reports that file tailing is implemented. `GET /api/v1/reports/status` reports that investigation JSON and PDF export is implemented. `/incidents` still reports that confirmed incidents are not implemented. Anomaly scores are stored in `anomaly_scores`, not in `security_alerts`. Live lines are stored with `origin=live_file` on their own source. They are not inserted into `linux-2k`.

The dashboard is `web/`. How to run it is in `/cursor/stores/self/docs/milestone-4.md`. How to authorize a live file is in `/cursor/stores/self/docs/milestone-5.md`.

## Layout

- `src/sentinellog/ingestion/` parsing, template match, validation, jobs
- `src/sentinellog/normalization/` timestamps, optional IP/username, search and quality queries
- `src/sentinellog/detection/` builtin rules, tumbling and sliding windows, backfill, alert lifecycle
- `src/sentinellog/ml/` hourly features, Isolation Forest, robust-z baseline, model artifacts
- `src/sentinellog/investigations/` analyst workspaces, correlation graph, JSON and PDF reports
- `src/sentinellog/live/` allowlisted file tail, checkpoints, collector health, SSE
- `web/` React dashboard (Vite). It reads the API and does not invent counts
- Package boundaries only: `incidents`, `reports`

Tables are created by Alembic. Revision `6a757cd7ca97` is the initial schema. Revision `ed1cc76d8439` adds rule versions, alert evidence, the four-status lifecycle, and `alert_notes`. Revision `c4e8b1a09d27` adds `anomaly_models` and `anomaly_scores`. Revision `d5f2a8c13e40` adds `investigation_alerts` and `investigation_notes`. Revision `e7b1c4d09a52` adds `live_collectors` and `live_positions` and the `live_file` source kind. It does not delete events, alerts, or scores.
