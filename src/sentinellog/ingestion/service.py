"""Persist parsed logs. Each input line is inserted, rejected, skipped, or marked a conflict."""

import hashlib
import logging
import re
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from sentinellog.clock import utcnow
from sentinellog.config import get_settings
from sentinellog.ingestion.csv_inputs import (
    canonical_structured_line,
    read_structured_rows,
    read_template_rows,
)
from sentinellog.ingestion.matcher import TemplateMatcher
from sentinellog.ingestion.parsing import (
    LineError,
    ParsedLine,
    decode_text,
    parse_syslog_line,
    sha256_text,
    split_log_lines,
)
from sentinellog.ingestion.validation import (
    CSV_SUFFIXES,
    RAW_SUFFIXES,
    FileRejected,
    ensure_text_bytes,
    validate_filename,
)
from sentinellog.models import (
    AuditLog,
    EventTemplate,
    IngestionError,
    IngestionJob,
    LogEvent,
    LogSource,
)
from sentinellog.normalization.entities import extract_ip, extract_username
from sentinellog.normalization.storage import dedup_key
from sentinellog.normalization.timestamps import build_timestamp, parse_hms

logger = logging.getLogger(__name__)

_EVENT_ID = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,31}$")
_BATCH = 500
_RAW_ERROR_CAP = 4000


class SourceNotFound(Exception):
    pass


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _start_job(
    session: Session, *, source_id: UUID, kind: str, filename: str, data: bytes
) -> IngestionJob:
    job = IngestionJob(
        source_id=source_id,
        kind=kind,
        filename=filename,
        status="running",
        file_size_bytes=len(data),
        file_sha256=_sha256_bytes(data),
        started_at=utcnow(),
        stats={},
    )
    session.add(job)
    session.commit()
    return job


def _fail_job(session: Session, job_id: UUID) -> None:
    session.rollback()
    job = session.get(IngestionJob, job_id)
    if job is None or job.status != "running":
        return
    job.status = "failed"
    job.error_message = "ingestion failed"
    job.finished_at = utcnow()
    session.commit()


def _add_error(
    session: Session,
    job: IngestionJob,
    *,
    line_number: int | None,
    error_kind: str,
    raw_line: str | None,
    message: str,
) -> None:
    clipped = raw_line[:_RAW_ERROR_CAP] if raw_line else None
    session.add(
        IngestionError(
            job_id=job.id,
            line_number=line_number,
            error_kind=error_kind,
            raw_line=clipped,
            message=message[:2000],
        )
    )


def _audit(
    session: Session,
    *,
    actor: str,
    action: str,
    entity_type: str,
    entity_id: str,
    details: dict,
) -> None:
    session.add(
        AuditLog(
            actor=actor,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            details=details,
        )
    )


def _assert_accounted(job: IngestionJob) -> None:
    accounted = job.lines_parsed + job.lines_errored + job.duplicates_skipped + job.conflicts
    if accounted != job.lines_total:
        raise RuntimeError(
            f"ingestion accounting mismatch for job {job.id}: {accounted} != {job.lines_total}"
        )


def _finish(session: Session, job: IngestionJob, *, actor: str, stats: dict) -> None:
    _assert_accounted(job)
    job.stats = stats
    job.status = "completed"
    job.finished_at = utcnow()
    _audit(
        session,
        actor=actor,
        action="ingestion.completed",
        entity_type="ingestion_job",
        entity_id=str(job.id),
        details={
            "kind": job.kind,
            "filename": job.filename,
            "file_sha256": job.file_sha256,
            "lines_total": job.lines_total,
            "lines_parsed": job.lines_parsed,
            "lines_errored": job.lines_errored,
            "duplicates_skipped": job.duplicates_skipped,
            "conflicts": job.conflicts,
        },
    )
    session.commit()
    logger.info(
        "ingestion completed job_id=%s kind=%s parsed=%s errors=%s duplicates=%s conflicts=%s",
        job.id,
        job.kind,
        job.lines_parsed,
        job.lines_errored,
        job.duplicates_skipped,
        job.conflicts,
    )


def _require_source(session: Session, source_id: UUID) -> LogSource:
    source = session.get(LogSource, source_id)
    if source is None:
        raise SourceNotFound(str(source_id))
    return source


def _matcher(session: Session) -> TemplateMatcher:
    pairs = session.execute(select(EventTemplate.event_id, EventTemplate.template)).all()
    return TemplateMatcher([(event_id, template) for event_id, template in pairs])


def _existing_hashes(session: Session, source_id: UUID) -> dict[int, str]:
    rows = session.execute(
        select(LogEvent.line_number, LogEvent.raw_line_sha256).where(
            LogEvent.source_id == source_id
        )
    ).all()
    return {line_number: digest for line_number, digest in rows}


def _attach_template(parsed: ParsedLine, matcher: TemplateMatcher) -> None:
    matched = matcher.match(parsed.content)
    if matched is not None:
        parsed.event_id, parsed.event_template = matched


def _maybe_commit(session: Session, pending: int) -> int:
    if pending >= _BATCH:
        session.commit()
        return 0
    return pending


def import_raw_log(
    session: Session,
    *,
    source_id: UUID,
    filename: str,
    data: bytes,
    actor: str,
) -> IngestionJob:
    safe_name = validate_filename(filename, RAW_SUFFIXES)
    ensure_text_bytes(data, max_bytes=get_settings().max_upload_bytes)
    source = _require_source(session, source_id)
    job = _start_job(session, source_id=source.id, kind="raw_log", filename=safe_name, data=data)
    try:
        _import_raw_body(session, source, job, data, actor)
    except Exception:
        logger.exception("ingestion failed job_id=%s", job.id)
        _fail_job(session, job.id)
        raise
    return job


def _import_raw_body(
    session: Session,
    source: LogSource,
    job: IngestionJob,
    data: bytes,
    actor: str,
) -> None:
    lines = split_log_lines(decode_text(data))
    job.lines_total = len(lines)
    matcher = _matcher(session)
    existing = _existing_hashes(session, source.id)
    unmatched = with_ip = with_username = with_timestamp = missing_pid = 0
    pending = 0
    for line_number, raw_line in enumerate(lines, start=1):
        parsed = parse_syslog_line(line_number, raw_line)
        if isinstance(parsed, LineError):
            job.lines_errored += 1
            _add_error(
                session,
                job,
                line_number=line_number,
                error_kind="parse",
                raw_line=parsed.raw_line,
                message=parsed.message,
            )
            pending = _maybe_commit(session, pending + 1)
            continue
        _attach_template(parsed, matcher)
        outcome = _place_event(
            session,
            source=source,
            job=job,
            existing=existing,
            line_number=line_number,
            raw_line=parsed.raw_line,
            digest=parsed.raw_line_sha256,
            origin="raw_log",
            month=parsed.month,
            day=parsed.day,
            time_text=parsed.time_text,
            hostname=parsed.hostname,
            component=parsed.component,
            pid=parsed.pid,
            content=parsed.content,
            event_id=parsed.event_id,
            event_template=parsed.event_template,
            source_ip=parsed.source_ip,
            username=parsed.username,
        )
        if outcome == "inserted":
            job.lines_parsed += 1
            unmatched += int(parsed.event_id is None)
            with_ip += int(parsed.source_ip is not None)
            with_username += int(parsed.username is not None)
            missing_pid += int(parsed.pid is None)
            clock = parse_hms(parsed.time_text)
            timestamp = (
                build_timestamp(source.source_year, parsed.month, parsed.day, clock)
                if clock is not None
                else None
            )
            with_timestamp += int(timestamp is not None)
        elif outcome == "duplicate":
            job.duplicates_skipped += 1
        else:
            job.conflicts += 1
        pending = _maybe_commit(session, pending + 1)

    hostnames = set(
        session.scalars(select(LogEvent.hostname).where(LogEvent.source_id == source.id)).all()
    )
    if len(hostnames) == 1:
        source.hostname = next(iter(hostnames))
        source.updated_at = utcnow()
    _finish(
        session,
        job,
        actor=actor,
        stats={
            "source_year": source.source_year,
            "unmatched_templates": unmatched,
            "with_ip": with_ip,
            "with_username": with_username,
            "with_timestamp": with_timestamp,
            "missing_pid": missing_pid,
            "distinct_hostnames": sorted(hostnames),
        },
    )


def _place_event(
    session: Session,
    *,
    source: LogSource,
    job: IngestionJob,
    existing: dict[int, str],
    line_number: int,
    raw_line: str,
    digest: str,
    origin: str,
    month: str,
    day: int,
    time_text: str,
    hostname: str,
    component: str,
    pid: int | None,
    content: str,
    event_id: str | None,
    event_template: str | None,
    source_ip: str | None,
    username: str | None,
) -> str:
    prior = existing.get(line_number)
    if prior == digest:
        return "duplicate"
    if prior is not None:
        _add_error(
            session,
            job,
            line_number=line_number,
            error_kind="conflict",
            raw_line=raw_line,
            message="line number already stored with a different raw hash; existing event kept",
        )
        return "conflict"
    clock = parse_hms(time_text)
    if clock is None:
        raise RuntimeError("parsed time failed validation")
    session.add(
        LogEvent(
            source_id=source.id,
            job_id=job.id,
            line_number=line_number,
            raw_line=raw_line,
            raw_line_sha256=digest,
            dedup_key=dedup_key(source.id, line_number, digest),
            origin=origin,
            month=month,
            day=day,
            time_of_day=clock,
            event_timestamp=build_timestamp(source.source_year, month, day, clock),
            hostname=hostname,
            component=component,
            pid=pid,
            content=content,
            event_id=event_id,
            event_template=event_template,
            source_ip=source_ip,
            username=username,
        )
    )
    existing[line_number] = digest
    return "inserted"


def import_template_csv(
    session: Session,
    *,
    source_id: UUID,
    filename: str,
    data: bytes,
    actor: str,
) -> IngestionJob:
    safe_name = validate_filename(filename, CSV_SUFFIXES)
    ensure_text_bytes(data, max_bytes=get_settings().max_upload_bytes)
    source = _require_source(session, source_id)
    rows = read_template_rows(data)
    job = _start_job(
        session, source_id=source.id, kind="template_csv", filename=safe_name, data=data
    )
    try:
        _import_templates_body(session, job, rows, actor)
    except Exception:
        logger.exception("ingestion failed job_id=%s", job.id)
        _fail_job(session, job.id)
        raise
    return job


def _import_templates_body(
    session: Session,
    job: IngestionJob,
    rows: list[tuple[int, str, str]],
    actor: str,
) -> None:
    job.lines_total = len(rows)
    catalog = {item.event_id: item for item in session.scalars(select(EventTemplate)).all()}
    seen: set[str] = set()
    inserted = updated = unchanged = 0
    for line_number, event_id, template in rows:
        if not _EVENT_ID.match(event_id) or template.strip() == "" or len(template) > 8000:
            job.lines_errored += 1
            _add_error(
                session,
                job,
                line_number=line_number,
                error_kind="template",
                raw_line=template,
                message="invalid template row",
            )
            continue
        if event_id in seen:
            job.lines_errored += 1
            _add_error(
                session,
                job,
                line_number=line_number,
                error_kind="template",
                raw_line=event_id,
                message="duplicate EventId in file",
            )
            continue
        seen.add(event_id)
        current = catalog.get(event_id)
        if current is None:
            current = EventTemplate(event_id=event_id, template=template)
            session.add(current)
            catalog[event_id] = current
            inserted += 1
        elif current.template != template:
            current.template = template
            current.updated_at = utcnow()
            updated += 1
        else:
            unchanged += 1
        job.lines_parsed += 1
    _finish(
        session,
        job,
        actor=actor,
        stats={"inserted": inserted, "updated": updated, "unchanged": unchanged},
    )


def import_structured_csv(
    session: Session,
    *,
    source_id: UUID,
    filename: str,
    data: bytes,
    actor: str,
    mode: str,
) -> IngestionJob:
    if mode not in {"import", "validate"}:
        raise FileRejected("mode must be import or validate")
    safe_name = validate_filename(filename, CSV_SUFFIXES)
    ensure_text_bytes(data, max_bytes=get_settings().max_upload_bytes)
    source = _require_source(session, source_id)
    rows = read_structured_rows(data)
    kind = "structured_import" if mode == "import" else "structured_validate"
    job = _start_job(session, source_id=source.id, kind=kind, filename=safe_name, data=data)
    try:
        if mode == "import":
            _import_structured_body(session, source, job, rows, actor)
        else:
            _validate_structured_body(session, source, job, rows, actor)
    except Exception:
        logger.exception("ingestion failed job_id=%s", job.id)
        _fail_job(session, job.id)
        raise
    return job


def _import_structured_body(
    session: Session,
    source: LogSource,
    job: IngestionJob,
    rows: list[tuple[int, dict[str, str] | str]],
    actor: str,
) -> None:
    job.lines_total = len(rows)
    existing = _existing_hashes(session, source.id)
    catalog = {item.event_id: item for item in session.scalars(select(EventTemplate)).all()}
    seen_templates: dict[str, str] = {}
    template_conflicts = 0
    pending = 0
    for line_number, row in rows:
        if isinstance(row, str):
            job.lines_errored += 1
            _add_error(
                session,
                job,
                line_number=line_number,
                error_kind="parse",
                raw_line=None,
                message=row,
            )
            pending = _maybe_commit(session, pending + 1)
            continue
        event_id = row["EventId"]
        template = row["EventTemplate"]
        previous = seen_templates.get(event_id)
        if previous is not None and previous != template:
            template_conflicts += 1
        else:
            seen_templates[event_id] = template
        # The structured Level column is the hostname, never a severity.
        hostname = row["Level"]
        canonical = canonical_structured_line(row)
        outcome = _place_event(
            session,
            source=source,
            job=job,
            existing=existing,
            line_number=int(row["LineId"]),
            raw_line=canonical,
            digest=sha256_text(canonical),
            origin="structured_csv",
            month=row["Month"],
            day=int(row["Date"]),
            time_text=row["Time"],
            hostname=hostname,
            component=row["Component"],
            pid=int(row["PID"]) if row["PID"] else None,
            content=row["Content"],
            event_id=event_id,
            event_template=template,
            source_ip=extract_ip(row["Content"]),
            username=extract_username(row["Content"]),
        )
        if outcome == "inserted":
            job.lines_parsed += 1
        elif outcome == "duplicate":
            job.duplicates_skipped += 1
        else:
            job.conflicts += 1
        pending = _maybe_commit(session, pending + 1)
    inserted = updated = unchanged = 0
    for event_id, template in seen_templates.items():
        current = catalog.get(event_id)
        if current is None:
            session.add(EventTemplate(event_id=event_id, template=template))
            inserted += 1
        elif current.template != template:
            current.template = template
            current.updated_at = utcnow()
            updated += 1
        else:
            unchanged += 1
    _finish(
        session,
        job,
        actor=actor,
        stats={
            "source_year": source.source_year,
            "templates_inserted": inserted,
            "templates_updated": updated,
            "templates_unchanged": unchanged,
            "template_conflicts": template_conflicts,
        },
    )


def _validate_structured_body(
    session: Session,
    source: LogSource,
    job: IngestionJob,
    rows: list[tuple[int, dict[str, str] | str]],
    actor: str,
) -> None:
    job.lines_total = len(rows)
    events = {
        event.line_number: event
        for event in session.scalars(select(LogEvent).where(LogEvent.source_id == source.id)).all()
    }
    for line_number, row in rows:
        if isinstance(row, str):
            job.lines_errored += 1
            _add_error(
                session,
                job,
                line_number=line_number,
                error_kind="mismatch",
                raw_line=None,
                message=row,
            )
            continue
        event = events.get(int(row["LineId"]))
        diffs = _structured_diffs(event, row)
        if diffs:
            job.lines_errored += 1
            _add_error(
                session,
                job,
                line_number=int(row["LineId"]),
                error_kind="mismatch",
                raw_line=None,
                message="mismatch: " + ",".join(diffs),
            )
        else:
            job.lines_parsed += 1
    _finish(session, job, actor=actor, stats={"compared_to": "stored_events"})


def _structured_diffs(event: LogEvent | None, row: dict[str, str]) -> list[str]:
    if event is None:
        return ["missing_event"]
    diffs: list[str] = []
    if event.month != row["Month"]:
        diffs.append("month")
    if event.day != int(row["Date"]):
        diffs.append("day")
    if event.time_of_day.strftime("%H:%M:%S") != row["Time"]:
        diffs.append("time")
    if event.hostname != row["Level"]:
        diffs.append("hostname")
    if event.component != row["Component"]:
        diffs.append("component")
    expected_pid = int(row["PID"]) if row["PID"] else None
    if event.pid != expected_pid:
        diffs.append("pid")
    if event.content != row["Content"]:
        diffs.append("content")
    if (event.event_id or "") != row["EventId"]:
        diffs.append("event_id")
    if (event.event_template or "") != row["EventTemplate"]:
        diffs.append("event_template")
    return diffs


def create_source(
    session: Session,
    *,
    name: str,
    description: str | None,
    source_year: int | None,
) -> LogSource:
    source = LogSource(name=name.strip(), description=description, source_year=source_year)
    session.add(source)
    session.commit()
    return source
