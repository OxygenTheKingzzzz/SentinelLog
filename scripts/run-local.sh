#!/usr/bin/env bash
# Start SentinelLog on this computer.
# Needs Python 3.12+, Node.js 22, and either Docker or a local Postgres 16.
# Ctrl-C stops the API and the dashboard. A Docker Postgres container keeps running
# until you stop it with: docker compose stop

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-python3}"
API_HOST="${SENTINELLOG_HOST:-127.0.0.1}"
API_PORT="${SENTINELLOG_API_PORT:-8000}"
UI_PORT="${SENTINELLOG_UI_PORT:-5173}"

if ! "$PYTHON" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)'; then
  echo "Python 3.12 or newer is required. Found: $("$PYTHON" --version 2>&1)" >&2
  exit 1
fi
if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
  echo "Node.js and npm are required. This project was tested with Node.js 22." >&2
  exit 1
fi

if [[ ! -f .env ]]; then
  cp .env.example .env
  echo "Created .env from .env.example"
fi
set -a
# shellcheck disable=SC1091
source .env
set +a
export DATABASE_URL="${DATABASE_URL:-postgresql+psycopg://sentinellog:sentinellog@127.0.0.1:5432/sentinellog}"

if [[ ! -d .venv ]]; then
  "$PYTHON" -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"

db_ready() {
  python - <<'PY'
import sys
from sqlalchemy import create_engine, text
from sentinellog.config import get_settings
try:
    with create_engine(get_settings().database_url, pool_pre_ping=True).connect() as conn:
        conn.execute(text("select 1"))
except Exception:
    sys.exit(1)
PY
}

if ! db_ready; then
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    echo "Starting Postgres with Docker"
    docker compose up -d
  else
    cat >&2 <<'EOF'
Postgres is not reachable, and Docker is not available.
Install Docker and rerun this script, or create the database yourself:

  sudo apt-get install -y postgresql-16 postgresql-client-16
  sudo pg_ctlcluster 16 main start
  sudo -u postgres psql -c "CREATE ROLE sentinellog LOGIN PASSWORD 'sentinellog' CREATEDB"
  sudo -u postgres psql -c "CREATE DATABASE sentinellog OWNER sentinellog"
EOF
    exit 1
  fi
  ready=0
  for _ in $(seq 1 30); do
    if db_ready; then
      ready=1
      break
    fi
    sleep 1
  done
  if [[ "$ready" -ne 1 ]]; then
    echo "Postgres did not accept connections on ${DATABASE_URL}" >&2
    exit 1
  fi
fi

alembic upgrade head

read -r EVENTS ALERTS SCORES BANDS < <(python - <<'PY'
from sqlalchemy import func, select

from sentinellog.db import SessionLocal
from sentinellog.models import AnomalyScore, LogEvent, LogSource, RiskModel, SecurityAlert

session = SessionLocal()
try:
    source = session.scalar(select(LogSource).where(LogSource.name == "linux-2k"))
    if source is None:
        print("0 0 0 0")
    else:
        def count(model):
            return session.scalar(
                select(func.count()).select_from(model).where(model.source_id == source.id)
            ) or 0

        bands = session.scalar(select(func.count()).select_from(RiskModel)) or 0
        print(f"{count(LogEvent)} {count(SecurityAlert)} {count(AnomalyScore)} {bands}")
finally:
    session.close()
PY
)

if [[ "$EVENTS" -eq 0 ]]; then
  python -m sentinellog.cli import-bundled
fi
if [[ "$EVENTS" -eq 0 || "$ALERTS" -eq 0 ]]; then
  python -m sentinellog.cli detect --source-name linux-2k
fi
if [[ "$EVENTS" -eq 0 || "$SCORES" -eq 0 ]]; then
  python -m sentinellog.cli anomaly-train --source-name linux-2k
  python -m sentinellog.cli anomaly-score --source-name linux-2k
fi
if [[ "$BANDS" -eq 0 ]]; then
  python - <<'PY'
from sqlalchemy import select

from sentinellog.db import SessionLocal
from sentinellog.models import LogSource
from sentinellog.risk.service import train_bands

session = SessionLocal()
try:
    source = session.scalar(select(LogSource).where(LogSource.name == "linux-2k"))
    if source is None:
        raise SystemExit("linux-2k was not imported")
    train_bands(session, source_id=source.id, actor="local-setup")
finally:
    session.close()
PY
fi

echo "SentinelLog data is loaded. Starting the API and the dashboard."
echo "Open http://${API_HOST}:${UI_PORT}"

python -m sentinellog.cli serve --host "$API_HOST" --port "$API_PORT" &
API_PID=$!

if [[ ! -d web/node_modules ]]; then
  (cd web && npm ci)
fi
(cd web && npm run dev -- --host "$API_HOST" --port "$UI_PORT") &
UI_PID=$!

cleanup() {
  kill "$API_PID" "$UI_PID" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM
wait "$API_PID" "$UI_PID"
