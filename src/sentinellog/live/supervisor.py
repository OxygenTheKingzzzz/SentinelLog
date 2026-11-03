"""Background poll of enabled file collectors. Tests leave this off."""

import logging
import threading

from sqlalchemy import select

from sentinellog.db import SessionLocal
from sentinellog.live.service import poll_collector
from sentinellog.models import LiveCollector

logger = logging.getLogger(__name__)


def supervisor_loop(stop: threading.Event) -> None:
    while not stop.wait(0.5):
        session = SessionLocal()
        try:
            ids = list(
                session.scalars(
                    select(LiveCollector.id).where(LiveCollector.enabled.is_(True))
                ).all()
            )
        except Exception:
            logger.exception("live supervisor query failed")
            session.rollback()
            ids = []
        finally:
            session.close()
        for collector_id in ids:
            poll_session = SessionLocal()
            try:
                poll_collector(poll_session, collector_id)
            except Exception:
                logger.exception("live poll failed collector_id=%s", collector_id)
                poll_session.rollback()
            finally:
                poll_session.close()
