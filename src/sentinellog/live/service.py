"""Authorize and tail a local text file. The process stays unprivileged and does not use a shell."""

import hashlib
import logging
import os
import stat
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from sentinellog.clock import utcnow
from sentinellog.ingestion.matcher import TemplateMatcher
from sentinellog.ingestion.parsing import LineError, parse_syslog_line
from sentinellog.ingestion.service import _add_error
from sentinellog.live.hub import hub
from sentinellog.live.paths import resolve_allowed_path
from sentinellog.models import (
    AuditLog,
    EventTemplate,
    IngestionJob,
    LiveCollector,
    LivePosition,
    LogEvent,
    LogSource,
)
from sentinellog.normalization.storage import dedup_key
from sentinellog.normalization.timestamps import build_timestamp, parse_hms

logger = logging.getLogger(__name__)

READ_BUFFER = 8192
MAX_PARTIAL = 8192
MAX_LINES_PER_POLL = 200


class CollectorNotFound(Exception):
    pass


class SourceNameTaken(Exception):
    pass


def _audit(session: Session, *, actor: str, action: str, entity_id: str, details: dict) -> None:
    session.add(
        AuditLog(
            actor=actor,
            action=action,
            entity_type="live_collector",
            entity_id=entity_id,
            details=details,
        )
    )


def _matcher(session: Session) -> TemplateMatcher:
    pairs = session.execute(select(EventTemplate.event_id, EventTemplate.template)).all()
    return TemplateMatcher([(event_id, template) for event_id, template in pairs])


def collector_health(session: Session) -> list[dict[str, object]]:
    rows = session.execute(
        select(LiveCollector, LogSource)
        .join(LogSource, LogSource.id == LiveCollector.source_id)
        .order_by(LogSource.name)
    ).all()
    payload = []
    for collector, source in rows:
        payload.append(
            {
                "id": str(collector.id),
                "source_id": str(source.id),
                "source_name": source.name,
                "source_kind": source.kind,
                "kind": collector.kind,
                "path": collector.path,
                "enabled": collector.enabled,
                "status": collector.status,
                "byte_offset": collector.byte_offset,
                "inode": collector.inode,
                "lines_read": collector.lines_read,
                "lines_imported": collector.lines_imported,
                "duplicates_skipped": collector.duplicates_skipped,
                "lines_errored": collector.lines_errored,
                "last_error": collector.last_error,
                "last_event_at": collector.last_event_at,
                "updated_at": collector.updated_at,
            }
        )
    return payload


def authorize_file(
    session: Session,
    *,
    actor: str,
    name: str,
    path: str,
    description: str | None,
    source_year: int | None,
) -> LiveCollector:
    resolved = resolve_allowed_path(path)
    source = LogSource(
        name=name.strip(),
        description=description,
        source_year=source_year,
        kind="live_file",
    )
    session.add(source)
    try:
        session.flush()
    except IntegrityError as exc:
        session.rollback()
        raise SourceNameTaken(name.strip()) from exc
    digest = hashlib.sha256(str(resolved).encode("utf-8")).hexdigest()
    size = resolved.stat().st_size if resolved.is_file() else 0
    job = IngestionJob(
        source_id=source.id,
        kind="live_file",
        filename=resolved.name[:255],
        status="running",
        file_size_bytes=size,
        file_sha256=digest,
        started_at=utcnow(),
        stats={"path": str(resolved), "read_only": True},
    )
    session.add(job)
    session.flush()
    collector = LiveCollector(
        source_id=source.id,
        job_id=job.id,
        kind="file",
        path=str(resolved),
        enabled=True,
        status="running",
    )
    session.add(collector)
    session.flush()
    _audit(
        session,
        actor=actor,
        action="live.authorize",
        entity_id=str(collector.id),
        details={"path": str(resolved), "source_id": str(source.id)},
    )
    session.commit()
    return collector


def set_enabled(
    session: Session, collector_id: UUID, *, actor: str, enabled: bool
) -> LiveCollector:
    collector = session.get(LiveCollector, collector_id)
    if collector is None:
        raise CollectorNotFound(str(collector_id))
    job = session.get(IngestionJob, collector.job_id)
    collector.enabled = enabled
    collector.status = "running" if enabled else "stopped"
    collector.last_error = None if enabled else collector.last_error
    collector.updated_at = utcnow()
    if job is not None:
        job.status = "running" if enabled else "completed"
        job.finished_at = None if enabled else utcnow()
    _audit(
        session,
        actor=actor,
        action="live.start" if enabled else "live.stop",
        entity_id=str(collector.id),
        details={"enabled": enabled},
    )
    session.commit()
    if enabled:
        poll_collector(session, collector.id)
    return collector


def _remember(
    session: Session,
    collector: LiveCollector,
    *,
    device: int,
    inode: int,
    offset: int,
    digest: str,
) -> bool:
    """Return True when this raw-line hash was already imported for the collector."""
    seen = session.scalar(
        select(LivePosition.id).where(
            LivePosition.collector_id == collector.id,
            LivePosition.line_sha256 == digest,
        )
    )
    if seen is not None:
        return True
    session.add(
        LivePosition(
            collector_id=collector.id,
            device=device,
            inode=inode,
            byte_offset=offset,
            line_sha256=digest,
        )
    )
    return False


def _consume_line(
    session: Session,
    collector: LiveCollector,
    job: IngestionJob,
    source: LogSource,
    matcher: TemplateMatcher,
    *,
    raw: bytes,
    device: int,
    inode: int,
    offset: int,
) -> dict[str, object] | None:
    collector.lines_read += 1
    job.lines_total += 1
    digest = hashlib.sha256(raw).hexdigest()
    if _remember(session, collector, device=device, inode=inode, offset=offset, digest=digest):
        collector.duplicates_skipped += 1
        job.duplicates_skipped += 1
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        collector.lines_errored += 1
        job.lines_errored += 1
        _add_error(
            session,
            job,
            line_number=collector.next_line_number,
            error_kind="parse",
            raw_line=None,
            message="live line is not valid UTF-8",
        )
        return None
    if "\x00" in text:
        collector.lines_errored += 1
        job.lines_errored += 1
        _add_error(
            session,
            job,
            line_number=collector.next_line_number,
            error_kind="parse",
            raw_line=text[:200],
            message="live line contains NUL",
        )
        return None
    parsed = parse_syslog_line(collector.next_line_number, text)
    if isinstance(parsed, LineError):
        collector.lines_errored += 1
        job.lines_errored += 1
        _add_error(
            session,
            job,
            line_number=collector.next_line_number,
            error_kind="parse",
            raw_line=parsed.raw_line,
            message=parsed.message,
        )
        return None
    matched = matcher.match(parsed.content)
    if matched is not None:
        parsed.event_id, parsed.event_template = matched
    clock = parse_hms(parsed.time_text)
    if clock is None:
        collector.lines_errored += 1
        job.lines_errored += 1
        _add_error(
            session,
            job,
            line_number=collector.next_line_number,
            error_kind="parse",
            raw_line=text[:200],
            message="live line has no parseable time",
        )
        return None
    event = LogEvent(
        source_id=source.id,
        job_id=job.id,
        line_number=collector.next_line_number,
        raw_line=parsed.raw_line,
        raw_line_sha256=parsed.raw_line_sha256,
        dedup_key=dedup_key(source.id, collector.next_line_number, parsed.raw_line_sha256),
        origin="live_file",
        month=parsed.month,
        day=parsed.day,
        time_of_day=clock,
        event_timestamp=build_timestamp(source.source_year, parsed.month, parsed.day, clock),
        hostname=parsed.hostname,
        component=parsed.component,
        pid=parsed.pid,
        content=parsed.content,
        event_id=parsed.event_id,
        event_template=parsed.event_template,
        source_ip=parsed.source_ip,
        username=parsed.username,
    )
    session.add(event)
    session.flush()
    collector.next_line_number += 1
    collector.lines_imported += 1
    job.lines_parsed += 1
    collector.last_event_at = utcnow()
    if source.hostname is None:
        source.hostname = parsed.hostname
        source.updated_at = utcnow()
    return {
        "type": "live_line",
        "source_id": str(source.id),
        "source_name": source.name,
        "event_id": str(event.id),
        "line_number": event.line_number,
        "origin": "live_file",
    }


def poll_collector(session: Session, collector_id: UUID) -> int:
    collector = session.get(LiveCollector, collector_id)
    if collector is None:
        raise CollectorNotFound(str(collector_id))
    if not collector.enabled:
        return 0
    source = session.get(LogSource, collector.source_id)
    job = session.get(IngestionJob, collector.job_id)
    if source is None or job is None or source.kind != "live_file":
        collector.status = "error"
        collector.last_error = "live source is missing"
        collector.updated_at = utcnow()
        session.commit()
        return 0
    path = collector.path
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        collector.status = "waiting"
        collector.last_error = "file is not present; will retry"
        collector.updated_at = utcnow()
        session.commit()
        return 0
    except PermissionError:
        collector.status = "error"
        collector.last_error = "permission denied"
        collector.updated_at = utcnow()
        session.commit()
        return 0
    except OSError as exc:
        collector.status = "error"
        collector.last_error = exc.strerror or "open failed"
        collector.updated_at = utcnow()
        session.commit()
        return 0

    published: list[dict[str, object]] = []
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            collector.status = "error"
            collector.last_error = "path is not a regular file"
            collector.updated_at = utcnow()
            session.commit()
            return 0
        if collector.inode is None:
            collector.device = info.st_dev
            collector.inode = info.st_ino
        elif info.st_dev != collector.device or info.st_ino != collector.inode:
            collector.device = info.st_dev
            collector.inode = info.st_ino
            collector.byte_offset = 0
            collector.partial = ""
        elif info.st_size < collector.byte_offset:
            collector.byte_offset = 0
            collector.partial = ""
        pending = collector.partial.encode("latin-1")
        line_start = collector.byte_offset
        cursor = collector.byte_offset + len(pending)
        os.lseek(fd, cursor, os.SEEK_SET)
        matcher = _matcher(session)
        produced = 0
        while produced < MAX_LINES_PER_POLL:
            if b"\n" not in pending:
                chunk = os.read(fd, READ_BUFFER)
                if not chunk:
                    break
                cursor += len(chunk)
                pending += chunk
            if b"\n" not in pending:
                if len(pending) > MAX_PARTIAL:
                    collector.lines_errored += 1
                    job.lines_errored += 1
                    job.lines_total += 1
                    _add_error(
                        session,
                        job,
                        line_number=None,
                        error_kind="parse",
                        raw_line=None,
                        message="live line exceeded the read buffer before a newline",
                    )
                    pending = b""
                    line_start = cursor
                break
            raw, pending = pending.split(b"\n", 1)
            consumed = len(raw) + 1
            start = line_start
            line_start += consumed
            if raw.endswith(b"\r"):
                raw = raw[:-1]
            event = _consume_line(
                session,
                collector,
                job,
                source,
                matcher,
                raw=raw,
                device=int(collector.device or info.st_dev),
                inode=int(collector.inode or info.st_ino),
                offset=start,
            )
            produced += 1
            if event is not None:
                published.append(event)
        collector.partial = pending.decode("latin-1")
        collector.byte_offset = line_start
        if len(collector.partial) > MAX_PARTIAL:
            collector.partial = ""
            collector.byte_offset = cursor
        job.file_size_bytes = info.st_size
        collector.status = "running"
        collector.last_error = None
        collector.updated_at = utcnow()
        session.commit()
    except Exception:
        session.rollback()
        logger.exception("live poll failed collector_id=%s", collector_id)
        failed = session.get(LiveCollector, collector_id)
        if failed is not None:
            failed.status = "error"
            failed.last_error = "read failed"
            failed.updated_at = utcnow()
            session.commit()
        return 0
    finally:
        os.close(fd)
    for event in published:
        hub.publish(event)
    return len(published)
