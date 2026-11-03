"""Read-side queries over stored events. Writes live in the ingestion service."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from sentinellog.models import IngestionError, IngestionJob, LogEvent, LogSource

QUALITY_NOTES = [
    "Missing PID, IP, username, or timestamp is data quality. Those lines are still stored.",
    "event_timestamp is null unless the log source has source_year set. "
    "These syslog lines have no timezone; a configured year is interpreted as UTC.",
    "hostname is the syslog host. In the Linux_2k structured CSV, column Level is this "
    "hostname (always 'combo' in that file), not a severity.",
    "Dedup key is source_id:line_number:sha256(raw_line). An identical key is skipped. "
    "The same source and line number with a different hash is a conflict and is not inserted.",
]


def dedup_key(source_id: UUID, line_number: int, raw_line_sha256: str) -> str:
    return f"{source_id}:{line_number}:{raw_line_sha256}"


def like_contains(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def event_filters(
    *,
    source_id: UUID | None = None,
    component: str | None = None,
    event_id: str | None = None,
    hostname: str | None = None,
    q: str | None = None,
    month: str | None = None,
    day: int | None = None,
    occurred_from: datetime | None = None,
    occurred_to: datetime | None = None,
    line_number: int | None = None,
) -> list[object]:
    filters: list[object] = []
    if source_id is not None:
        filters.append(LogEvent.source_id == source_id)
    if component:
        filters.append(LogEvent.component == component)
    if event_id:
        filters.append(LogEvent.event_id == event_id)
    if hostname:
        filters.append(LogEvent.hostname == hostname)
    if month:
        filters.append(LogEvent.month == month)
    if day is not None:
        filters.append(LogEvent.day == day)
    if occurred_from is not None:
        filters.append(LogEvent.event_timestamp >= occurred_from)
    if occurred_to is not None:
        filters.append(LogEvent.event_timestamp <= occurred_to)
    if line_number is not None:
        filters.append(LogEvent.line_number == line_number)
    if q:
        pattern = like_contains(q)
        filters.append(
            or_(
                LogEvent.content.ilike(pattern, escape="\\"),
                LogEvent.raw_line.ilike(pattern, escape="\\"),
            )
        )
    return filters


def search_events(
    session: Session,
    *,
    source_id: UUID | None = None,
    component: str | None = None,
    event_id: str | None = None,
    hostname: str | None = None,
    q: str | None = None,
    month: str | None = None,
    day: int | None = None,
    occurred_from: datetime | None = None,
    occurred_to: datetime | None = None,
    line_number: int | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[LogEvent], int]:
    filters = event_filters(
        source_id=source_id,
        component=component,
        event_id=event_id,
        hostname=hostname,
        q=q,
        month=month,
        day=day,
        occurred_from=occurred_from,
        occurred_to=occurred_to,
        line_number=line_number,
    )
    total = session.scalar(select(func.count()).select_from(LogEvent).where(*filters)) or 0
    rows = session.scalars(
        select(LogEvent)
        .where(*filters)
        .order_by(LogEvent.line_number, LogEvent.id)
        .limit(limit)
        .offset(offset)
    ).all()
    return list(rows), int(total)


def quality_report(session: Session, source_id: UUID) -> dict[str, object] | None:
    source = session.get(LogSource, source_id)
    if source is None:
        return None

    def _count(*extra: object) -> int:
        return int(session.scalar(select(func.count()).select_from(LogEvent).where(*extra)) or 0)

    base = LogEvent.source_id == source_id
    jobs = session.scalars(
        select(IngestionJob)
        .where(IngestionJob.source_id == source_id)
        .order_by(IngestionJob.created_at)
    ).all()
    recent = session.execute(
        select(
            IngestionError.line_number,
            IngestionError.error_kind,
            IngestionError.message,
            IngestionError.job_id,
        )
        .join(IngestionJob, IngestionError.job_id == IngestionJob.id)
        .where(IngestionJob.source_id == source_id)
        .order_by(IngestionError.created_at.desc())
        .limit(50)
    ).all()
    parse_errors = int(
        session.scalar(
            select(func.count())
            .select_from(IngestionError)
            .join(IngestionJob, IngestionError.job_id == IngestionJob.id)
            .where(IngestionJob.source_id == source_id, IngestionError.error_kind == "parse")
        )
        or 0
    )
    return {
        "source_id": str(source.id),
        "source_name": source.name,
        "hostname": source.hostname,
        "source_year": source.source_year,
        "events": _count(base),
        "parse_errors": parse_errors,
        "events_missing_pid": _count(base, LogEvent.pid.is_(None)),
        "events_missing_ip": _count(base, LogEvent.source_ip.is_(None)),
        "events_missing_username": _count(base, LogEvent.username.is_(None)),
        "events_missing_timestamp": _count(base, LogEvent.event_timestamp.is_(None)),
        "events_unmatched_template": _count(base, LogEvent.event_id.is_(None)),
        "jobs": [
            {
                "id": str(job.id),
                "kind": job.kind,
                "status": job.status,
                "filename": job.filename,
                "lines_total": job.lines_total,
                "lines_parsed": job.lines_parsed,
                "lines_errored": job.lines_errored,
                "duplicates_skipped": job.duplicates_skipped,
                "conflicts": job.conflicts,
                "stats": job.stats,
            }
            for job in jobs
        ],
        "recent_errors": [
            {
                "job_id": str(row.job_id),
                "line_number": row.line_number,
                "error_kind": row.error_kind,
                "message": row.message,
            }
            for row in recent
        ],
        "notes": QUALITY_NOTES,
    }


def _facet(session: Session, column: object, filters: list[object], limit: int = 40) -> list[dict]:
    rows = session.execute(
        select(column, func.count())
        .where(*filters, column.is_not(None))
        .group_by(column)
        .order_by(func.count().desc(), column)
        .limit(limit)
    ).all()
    return [{"value": value, "count": int(count)} for value, count in rows]


def event_facets(session: Session, **filters_kwargs: object) -> dict[str, object]:
    filters = event_filters(**filters_kwargs)  # type: ignore[arg-type]
    total = int(session.scalar(select(func.count()).select_from(LogEvent).where(*filters)) or 0)
    return {
        "total": total,
        "components": _facet(session, LogEvent.component, filters),
        "event_ids": _facet(session, LogEvent.event_id, filters),
        "hostnames": _facet(session, LogEvent.hostname, filters),
    }
