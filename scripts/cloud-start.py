"""Migrate as owner, then run the API with a restricted database login."""

import os
import subprocess
import sys

import psycopg
from psycopg import sql
from sqlalchemy.engine import make_url

admin_url = os.environ["DATABASE_ADMIN_URL"]
password = os.environ["DATABASE_APP_PASSWORD"]
url = make_url(admin_url)
subprocess.run(
    [sys.executable, "-m", "alembic", "upgrade", "head"],
    env=dict(os.environ, DATABASE_URL=admin_url),
    check=True,
)
with psycopg.connect(
    url.set(drivername="postgresql").render_as_string(hide_password=False)
) as conn:
    with conn.cursor() as cur:
        cur.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", ("sentinel_app",))
        if cur.fetchone() is None:
            cur.execute(
                sql.SQL("CREATE ROLE sentinel_app LOGIN PASSWORD {}").format(sql.Literal(password))
            )
        else:
            cur.execute(
                sql.SQL("ALTER ROLE sentinel_app PASSWORD {}").format(sql.Literal(password))
            )
        cur.execute("ALTER ROLE sentinel_app NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION")
        cur.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
        cur.execute("GRANT USAGE ON SCHEMA public TO sentinel_app")
        cur.execute(
            "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO sentinel_app"
        )
        cur.execute("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO sentinel_app")
        cur.execute("ALTER ROLE sentinel_app SET statement_timeout = 30000")
        cur.execute("ALTER ROLE sentinel_app SET idle_in_transaction_session_timeout = 30000")
os.environ["DATABASE_URL"] = url.set(username="sentinel_app", password=password).render_as_string(
    hide_password=False
)
os.environ.pop("DATABASE_ADMIN_URL", None)
os.environ.pop("DATABASE_APP_PASSWORD", None)
os.execv(
    sys.executable,
    [
        sys.executable,
        "-m",
        "uvicorn",
        "sentinellog.main:app",
        "--host",
        "0.0.0.0",
        "--port",
        os.environ.get("PORT", "8080"),
    ],
)
