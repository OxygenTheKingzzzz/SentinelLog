"""Fill null event timestamps from the source year. Never overwrite one already set.

These syslog lines have no timezone. Month, day, and time_of_day plus the
source's configured year are stored as UTC. The year is not read from message
text, FTP banners, or kernel audit epochs.
"""

from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from sentinellog.clock import utcnow
from sentinellog.models import AuditLog, LogEvent, LogSource
from sentinellog.normalization.timestamps import build_timestamp


class YearConflict(Exception):
    """The source already has a different configured year."""


@dataclass(frozen=True)
class BackfillResult:
    updated: int
    already_set: int
    skipped_no_year: int
    skipped_invalid: int

    def as_dict(self) -> dict[str, int]:
        return {
            "updated": self.updated,
            "already_set": self.already_set,
            "skipped_no_year": self.skipped_no_year,
            "skipped_invalid": self.skipped_invalid,
        }


def assign_source_year(session: Session, source: LogSource, year: int, *, actor: str) -> bool:
    """Set ``source_year`` when it is null. Refuse a different stored year.

    Does not rewrite ``event_timestamp``. Returns True when the year was written.
    """
    if year < 1970 or year > 2100:
        raise ValueError("source_year must be between 1970 and 2100")
    if source.source_year is None:
        source.source_year = year
        source.updated_at = utcnow()
        session.add(
            AuditLog(
                actor=actor,
                action="log_source.year_set",
                entity_type="log_source",
                entity_id=str(source.id),
                details={"name": source.name, "source_year": year},
            )
        )
        return True
    if source.source_year != year:
        raise YearConflict(
            f"source {source.name} already has source_year {source.source_year}, not {year}"
        )
    return False


def backfill_timestamps(
    session: Session,
    *,
    source_id: UUID | None = None,
    actor: str,
) -> BackfillResult:
    """Set null timestamps from month/day/time and the source year. Leave others alone."""
    scope = []
    if source_id is not None:
        scope.append(LogEvent.source_id == source_id)
    already_set = session.scalar(
        select(func.count())
        .select_from(LogEvent)
        .where(LogEvent.event_timestamp.is_not(None), *scope)
    )
    pending = session.scalars(
        select(LogEvent).where(LogEvent.event_timestamp.is_(None), *scope)
    ).all()
    sources: dict[UUID, LogSource | None] = {}
    updated = 0
    skipped_no_year = 0
    skipped_invalid = 0
    for event in pending:
        if event.source_id not in sources:
            sources[event.source_id] = session.get(LogSource, event.source_id)
        source = sources[event.source_id]
        if source is None or source.source_year is None:
            skipped_no_year += 1
            continue
        stamped = build_timestamp(source.source_year, event.month, event.day, event.time_of_day)
        if stamped is None:
            skipped_invalid += 1
            continue
        event.event_timestamp = stamped
        updated += 1
    result = BackfillResult(
        updated=updated,
        already_set=int(already_set or 0),
        skipped_no_year=skipped_no_year,
        skipped_invalid=skipped_invalid,
    )
    session.add(
        AuditLog(
            actor=actor,
            action="log_event.backfill",
            entity_type="log_source",
            entity_id=str(source_id) if source_id is not None else None,
            details=result.as_dict(),
        )
    )
    session.commit()
    return result
