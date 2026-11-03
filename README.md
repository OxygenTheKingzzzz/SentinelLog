# SentinelLog

Local SOC / Linux log intelligence platform. Milestone 1 ingests historical syslog, stores it in PostgreSQL, and serves search plus data-quality reports. It does not score detections, train models, collect live logs, or render a dashboard.

The bundled sample is the [Loghub](https://github.com/logpai/loghub) Linux_2k log (about 2,000 historical lines from host `combo`). There are no malicious/benign labels in that dataset, and SentinelLog does not invent any.

## What the Level column is

In `datasets/Linux_2k.log_structured.csv`, `Level` is the syslog hostname. In this file every value is `combo`. It is stored as `log_events.hostname`. It is not a severity.

## Dedup

Identity of a stored line:

`{source_id}:{line_number}:{sha256(raw_line)}`

`raw_line` is the line body with the CR/LF terminator removed and trailing spaces kept. Re-importing the same bytes increments `duplicates_skipped` and does not insert another row. The same source and line number with a different hash is a conflict: the original row stays, and the job records a conflict. Every input line is one of: parsed (inserted), parse error, duplicate, or conflict.

## Timestamps

Month, day, and time are always stored. `event_timestamp` stays null unless the log source has `source_year` set (the API field, the CLI `--year`, or `SOURCE_YEAR` as the default only when a new source omits a year). These lines have no timezone. A configured year is interpreted as UTC. The year is not read from message text.

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
export SENTINELLOG_TEST_DATABASE_URL=postgresql+psycopg://sentinellog:sentinellog@127.0.0.1:5432/sentinellog_test
pytest
ruff check src tests
ruff format --check src tests
```

`pytest` truncates `SENTINELLOG_TEST_DATABASE_URL`. It does not use the dev database unless you point that variable at it.

`import-bundled` loads templates, imports `datasets/Linux_2k.log`, then validates every stored row against `datasets/Linux_2k.log_structured.csv`. A second run reports 2000 duplicates and still exits 0 when validation matches.

Copy `.env.example` to `.env` for local defaults. Do not commit `.env`.

## API

- `POST /api/v1/sources`
- `POST /api/v1/sources/{id}/ingest/raw` multipart field `file` (`.log` / `.txt`)
- `POST /api/v1/sources/{id}/ingest/templates` (`.csv`)
- `POST /api/v1/sources/{id}/ingest/structured?mode=validate|import` (`.csv`)
- `GET /api/v1/events` filters: `component`, `event_id`, `hostname`, `month`, `day`, `q`, `occurred_from`, `occurred_to`
- `GET /api/v1/sources/{id}/quality`
- `GET /api/v1/jobs/{id}` and `GET /api/v1/jobs/{id}/errors`
- `GET /health`

`occurred_from` / `occurred_to` apply to `event_timestamp`, which is null until a year is configured. `month` and `day` filter the syslog calendar fields without a year.

Uploads are size-limited (`MAX_UPLOAD_BYTES`, default 32 MiB), must be UTF-8 text without NUL bytes, and must use an allowed extension. Filenames that contain a path or `..` are rejected. Log bytes are stored and parsed. They are not executed and are not passed to a shell.

`/api/v1/detection`, `/ml`, `/incidents`, `/reports`, and `/live` only report that those modules are not implemented. They do not emit alerts.

## Layout

- `src/sentinellog/ingestion/` parsing, template match, validation, jobs
- `src/sentinellog/normalization/` timestamps, optional IP/username, search and quality queries
- Later milestones have package boundaries only: `detection`, `ml`, `incidents`, `reports`, `live`

Tables are created by Alembic revision `0001_initial`. `detection_rules`, `security_alerts`, `investigations`, and `investigation_events` are empty on purpose.
