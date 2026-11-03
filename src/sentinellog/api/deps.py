from collections.abc import Iterator

from sqlalchemy.orm import Session

from sentinellog.db import SessionLocal


def get_db() -> Iterator[Session]:
    session = SessionLocal()
    try:
        yield session
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
