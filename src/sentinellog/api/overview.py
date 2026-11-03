"""Aggregate counts for the dashboard. Every number is a query, not a constant."""

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from sentinellog.ml.constants import AUTH_FAILURE_EVENT_IDS
from sentinellog.models import (
    AnomalyModel,
    AnomalyScore,
    EventTemplate,
    IngestionError,
    IngestionJob,
    Investigation,
    InvestigationAlert,
    InvestigationEvent,
    LogEvent,
    LogSource,
    SecurityAlert,
)


def _auth_clause() -> object:
    return (
        (LogEvent.component == "sshd(pam_unix)")
        & LogEvent.event_id.in_(tuple(AUTH_FAILURE_EVENT_IDS))
        & LogEvent.content.contains("authentication failure")
    )


def _day_label(value: datetime) -> str:
    if value.tzinfo is None:
        return value.strftime("%Y-%m-%d")
    return value.astimezone(UTC).strftime("%Y-%m-%d")


def _investigation_count(session: Session, source_id: UUID | None) -> int:
    if source_id is None:
        return int(session.scalar(select(func.count()).select_from(Investigation)) or 0)
    via_alert = (
        select(InvestigationAlert.investigation_id)
        .join(SecurityAlert, SecurityAlert.id == InvestigationAlert.alert_id)
        .where(SecurityAlert.source_id == source_id)
    )
    via_event = (
        select(InvestigationEvent.investigation_id)
        .join(LogEvent, LogEvent.id == InvestigationEvent.log_event_id)
        .where(LogEvent.source_id == source_id)
    )
    linked = via_alert.union(via_event).subquery()
    return int(session.scalar(select(func.count()).select_from(linked)) or 0)


def overview(session: Session, source_id: UUID | None) -> dict[str, object] | None:
    if source_id is not None and session.get(LogSource, source_id) is None:
        return None
    event_filters = []
    alert_filters = []
    score_filters = []
    job_filters = []
    if source_id is not None:
        event_filters.append(LogEvent.source_id == source_id)
        alert_filters.append(SecurityAlert.source_id == source_id)
        score_filters.append(AnomalyScore.source_id == source_id)
        job_filters.append(IngestionJob.source_id == source_id)

    events = int(
        session.scalar(select(func.count()).select_from(LogEvent).where(*event_filters)) or 0
    )
    alerts = int(
        session.scalar(select(func.count()).select_from(SecurityAlert).where(*alert_filters)) or 0
    )
    investigations = _investigation_count(session, source_id)
    templates = int(session.scalar(select(func.count()).select_from(EventTemplate)) or 0)
    auth = int(
        session.scalar(
            select(func.count()).select_from(LogEvent).where(*event_filters, _auth_clause())
        )
        or 0
    )

    span = session.execute(
        select(func.min(LogEvent.event_timestamp), func.max(LogEvent.event_timestamp)).where(
            *event_filters, LogEvent.event_timestamp.is_not(None)
        )
    ).one()
    bucket = func.date_trunc("day", LogEvent.event_timestamp)
    auth_flag = case((_auth_clause(), 1), else_=0)
    daily_rows = session.execute(
        select(bucket, func.count(), func.sum(auth_flag))
        .where(*event_filters, LogEvent.event_timestamp.is_not(None))
        .group_by(bucket)
        .order_by(bucket)
    ).all()
    severity_rows = session.execute(
        select(SecurityAlert.severity, func.count())
        .where(*alert_filters)
        .group_by(SecurityAlert.severity)
        .order_by(func.count().desc(), SecurityAlert.severity)
    ).all()
    recent = session.scalars(
        select(SecurityAlert)
        .where(*alert_filters)
        .order_by(SecurityAlert.created_at.desc(), SecurityAlert.id)
        .limit(8)
    ).all()
    sources = []
    source_rows = session.scalars(select(LogSource).order_by(LogSource.name)).all()
    for source in source_rows:
        if source_id is not None and source.id != source_id:
            continue
        count = int(
            session.scalar(
                select(func.count()).select_from(LogEvent).where(LogEvent.source_id == source.id)
            )
            or 0
        )
        alert_count = int(
            session.scalar(
                select(func.count())
                .select_from(SecurityAlert)
                .where(SecurityAlert.source_id == source.id)
            )
            or 0
        )
        sources.append(
            {
                "id": str(source.id),
                "name": source.name,
                "hostname": source.hostname,
                "source_year": source.source_year,
                "events": count,
                "alerts": alert_count,
            }
        )

    latest = session.scalar(select(AnomalyModel).order_by(AnomalyModel.version.desc()).limit(1))
    anomaly = {
        "model_id": None,
        "model_version": None,
        "windows": 0,
        "flagged_isolation": 0,
        "flagged_baseline": 0,
        "flagged_either": 0,
    }
    if latest is not None:
        scoped = [AnomalyScore.model_id == latest.id, *score_filters]
        anomaly = {
            "model_id": str(latest.id),
            "model_version": latest.version,
            "windows": int(
                session.scalar(select(func.count()).select_from(AnomalyScore).where(*scoped)) or 0
            ),
            "flagged_isolation": int(
                session.scalar(
                    select(func.count())
                    .select_from(AnomalyScore)
                    .where(*scoped, AnomalyScore.flagged_isolation.is_(True))
                )
                or 0
            ),
            "flagged_baseline": int(
                session.scalar(
                    select(func.count())
                    .select_from(AnomalyScore)
                    .where(*scoped, AnomalyScore.flagged_baseline.is_(True))
                )
                or 0
            ),
            "flagged_either": int(
                session.scalar(
                    select(func.count())
                    .select_from(AnomalyScore)
                    .where(
                        *scoped,
                        (AnomalyScore.flagged_isolation.is_(True))
                        | (AnomalyScore.flagged_baseline.is_(True)),
                    )
                )
                or 0
            ),
        }

    jobs = int(
        session.scalar(select(func.count()).select_from(IngestionJob).where(*job_filters)) or 0
    )
    completed = int(
        session.scalar(
            select(func.count())
            .select_from(IngestionJob)
            .where(*job_filters, IngestionJob.status == "completed")
        )
        or 0
    )
    failed = int(
        session.scalar(
            select(func.count())
            .select_from(IngestionJob)
            .where(*job_filters, IngestionJob.status == "failed")
        )
        or 0
    )
    error_query = select(func.count()).select_from(IngestionError)
    if source_id is not None:
        error_query = error_query.join(
            IngestionJob, IngestionError.job_id == IngestionJob.id
        ).where(IngestionJob.source_id == source_id)
    parse_errors = int(session.scalar(error_query) or 0)
    lines_errored = int(
        session.scalar(select(func.sum(IngestionJob.lines_errored)).where(*job_filters)) or 0
    )
    last_job = session.scalar(
        select(IngestionJob).where(*job_filters).order_by(IngestionJob.created_at.desc()).limit(1)
    )
    return {
        "events": events,
        "alerts": alerts,
        "investigations": investigations,
        "templates": templates,
        "auth_failures": auth,
        "time_min": span[0],
        "time_max": span[1],
        "daily": [
            {
                "day": _day_label(day),
                "events": int(event_count),
                "auth_failures": int(auth_count or 0),
            }
            for day, event_count, auth_count in daily_rows
            if day is not None
        ],
        "severity": [
            {"severity": severity, "count": int(count)} for severity, count in severity_rows
        ],
        "recent_alerts": [
            {
                "id": str(alert.id),
                "title": alert.title,
                "severity": alert.severity,
                "status": alert.status,
                "source_address": alert.source_address,
                "rule_id": str(alert.rule_id),
                "first_event_at": alert.first_event_at,
                "last_event_at": alert.last_event_at,
                "line_numbers": list(alert.line_numbers),
            }
            for alert in recent
        ],
        "sources": sources,
        "anomaly": anomaly,
        "ingestion": {
            "jobs": jobs,
            "jobs_completed": completed,
            "jobs_failed": failed,
            "parse_errors": parse_errors,
            "lines_errored": lines_errored,
            "last_job": None
            if last_job is None
            else {
                "id": str(last_job.id),
                "filename": last_job.filename,
                "kind": last_job.kind,
                "status": last_job.status,
                "lines_parsed": last_job.lines_parsed,
                "lines_errored": last_job.lines_errored,
                "created_at": last_job.created_at,
            },
        },
    }
