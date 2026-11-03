import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "datasets"
TEST_DATABASE_URL = os.environ.get(
    "SENTINELLOG_TEST_DATABASE_URL",
    "postgresql+psycopg://sentinellog:sentinellog@127.0.0.1:5432/sentinellog_test",
)
os.environ["DATABASE_URL"] = TEST_DATABASE_URL
os.environ["LOG_LEVEL"] = "WARNING"
os.environ.pop("SOURCE_YEAR", None)

import pytest  # noqa: E402
from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from sqlalchemy import create_engine, text  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from sentinellog.config import get_settings  # noqa: E402
from sentinellog.db import reset_engine  # noqa: E402

TABLES = (
    "audit_logs",
    "investigation_events",
    "investigations",
    "security_alerts",
    "detection_rules",
    "ingestion_errors",
    "log_events",
    "ingestion_jobs",
    "event_templates",
    "log_sources",
)


@pytest.fixture(scope="session")
def migrated() -> None:
    get_settings.cache_clear()
    reset_engine()
    config = Config(str(ROOT / "alembic.ini"))
    command.upgrade(config, "head")
    yield
    reset_engine()


@pytest.fixture
def db(migrated: None) -> Session:
    engine = create_engine(TEST_DATABASE_URL, pool_pre_ping=True)
    with engine.begin() as connection:
        connection.execute(text("TRUNCATE " + ", ".join(TABLES) + " RESTART IDENTITY CASCADE"))
    session = Session(engine, autoflush=False, expire_on_commit=False)
    try:
        yield session
    finally:
        session.close()
        engine.dispose()
        reset_engine()
        get_settings.cache_clear()


@pytest.fixture
def client(db: Session):
    from fastapi.testclient import TestClient

    from sentinellog.main import create_app

    with TestClient(create_app()) as test_client:
        yield test_client
