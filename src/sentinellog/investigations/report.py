"""Investigation report with three labeled sections. No compromise claim is generated."""

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from sentinellog.detection.catalog import DISCLAIMER
from sentinellog.investigations.pdf import render_lines, wrap_text
from sentinellog.ml.constants import NO_GROUND_TRUTH
from sentinellog.models import (
    AnomalyModel,
    AnomalyScore,
    DetectionRule,
    Investigation,
    InvestigationAlert,
    InvestigationEvent,
    InvestigationNote,
    LogEvent,
    SecurityAlert,
)

NOT_CONFIRMED = "not a confirmed compromise"
SECTIONS = (
    "observations",
    "automated_hypotheses",
    "analyst_confirmed_findings",
)


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _observation(event: LogEvent) -> dict[str, object]:
    return {
        "id": str(event.id),
        "source_id": str(event.source_id),
        "line_number": event.line_number,
        "event_timestamp": _iso(event.event_timestamp),
        "hostname": event.hostname,
        "component": event.component,
        "event_id": event.event_id,
        "content": event.content,
        "raw_line": event.raw_line,
        "source_ip": event.source_ip,
        "username": event.username,
    }


def _rule_alert(alert: SecurityAlert, rule_name: str | None) -> dict[str, object]:
    return {
        "id": str(alert.id),
        "title": alert.title,
        "severity": alert.severity,
        "status": alert.status,
        "rule_id": str(alert.rule_id),
        "rule_name": rule_name,
        "rule_version": alert.rule_version,
        "threshold": alert.threshold,
        "window_seconds": alert.window_seconds,
        "window_type": alert.window_type,
        "window_start": _iso(alert.window_start),
        "window_end": _iso(alert.window_end),
        "source_address": alert.source_address,
        "explanation": alert.explanation,
        "event_ids": [str(item) for item in alert.event_ids],
        "line_numbers": [int(item) for item in alert.line_numbers],
        "first_event_at": _iso(alert.first_event_at),
        "last_event_at": _iso(alert.last_event_at),
        "confirmed_compromise": False,
        "label": NOT_CONFIRMED,
        "disclaimer": DISCLAIMER,
    }


def _anomaly_window(score: AnomalyScore, model_version: int) -> dict[str, object]:
    return {
        "id": str(score.id),
        "model_id": str(score.model_id),
        "model_version": model_version,
        "source_id": str(score.source_id),
        "window_start": _iso(score.window_start),
        "window_end": _iso(score.window_end),
        "event_count": score.event_count,
        "isolation_score": score.isolation_score,
        "baseline_score": score.baseline_score,
        "flagged_isolation": score.flagged_isolation,
        "flagged_baseline": score.flagged_baseline,
        "confirmed_compromise": False,
        "label": NOT_CONFIRMED,
        "disclaimer": NO_GROUND_TRUTH,
    }


def _note(note: InvestigationNote) -> dict[str, object]:
    return {
        "id": str(note.id),
        "actor": note.actor,
        "body": note.body,
        "created_at": _iso(note.created_at),
    }


def _span(
    events: list[LogEvent], alerts: list[SecurityAlert]
) -> tuple[datetime | None, datetime | None]:
    stamps: list[datetime] = []
    for event in events:
        if event.event_timestamp is not None:
            stamps.append(event.event_timestamp)
    for alert in alerts:
        stamps.append(alert.window_start)
        stamps.append(alert.window_end)
    if not stamps:
        return None, None
    return min(stamps), max(stamps)


def _linked_alerts(session: Session, investigation: Investigation) -> list[SecurityAlert]:
    return list(
        session.scalars(
            select(SecurityAlert)
            .join(InvestigationAlert, InvestigationAlert.alert_id == SecurityAlert.id)
            .where(InvestigationAlert.investigation_id == investigation.id)
            .order_by(SecurityAlert.window_start, SecurityAlert.id)
        ).all()
    )


def _linked_events(session: Session, investigation: Investigation) -> list[LogEvent]:
    return list(
        session.scalars(
            select(LogEvent)
            .join(InvestigationEvent, InvestigationEvent.log_event_id == LogEvent.id)
            .where(InvestigationEvent.investigation_id == investigation.id)
            .order_by(LogEvent.event_timestamp.asc().nulls_last(), LogEvent.line_number)
        ).all()
    )


def _overlapping_scores(
    session: Session,
    events: list[LogEvent],
    alerts: list[SecurityAlert],
) -> list[tuple[AnomalyScore, int]]:
    source_ids = {event.source_id for event in events}
    source_ids.update(alert.source_id for alert in alerts)
    start, end = _span(events, alerts)
    if not source_ids or start is None or end is None:
        return []
    rows = session.execute(
        select(AnomalyScore, AnomalyModel.version)
        .join(AnomalyModel, AnomalyModel.id == AnomalyScore.model_id)
        .where(
            AnomalyScore.source_id.in_(source_ids),
            AnomalyScore.window_start <= end,
            AnomalyScore.window_end > start,
        )
        .order_by(AnomalyScore.window_start, AnomalyScore.id)
    ).all()
    return [(score, int(version)) for score, version in rows]


def build_report(session: Session, investigation: Investigation) -> dict[str, object]:
    alerts = _linked_alerts(session, investigation)
    events = _linked_events(session, investigation)
    rule_ids = {alert.rule_id for alert in alerts}
    names: dict[object, str] = {}
    if rule_ids:
        names = {
            rule_id: name
            for rule_id, name in session.execute(
                select(DetectionRule.id, DetectionRule.name).where(DetectionRule.id.in_(rule_ids))
            ).all()
        }
    notes = session.scalars(
        select(InvestigationNote)
        .where(InvestigationNote.investigation_id == investigation.id)
        .order_by(InvestigationNote.created_at, InvestigationNote.id)
    ).all()
    timeline = [_observation(event) for event in events]
    rule_alerts = [_rule_alert(alert, names.get(alert.rule_id)) for alert in alerts]
    scores = _overlapping_scores(session, events, alerts)
    windows = [_anomaly_window(score, version) for score, version in scores]
    findings = [_note(note) for note in notes]
    return {
        "kind": "investigation_report",
        "pdf": True,
        "label": (
            "Observations are stored log lines and timestamps. "
            "Automated hypotheses are rule alerts and anomaly windows, and each one is "
            f"{NOT_CONFIRMED}. "
            "Analyst-confirmed findings are only notes the analyst wrote."
        ),
        "investigation": {
            "id": str(investigation.id),
            "title": investigation.title,
            "status": investigation.status,
            "summary": investigation.summary,
            "created_at": _iso(investigation.created_at),
            "updated_at": _iso(investigation.updated_at),
        },
        "observations": {
            "section": "observations",
            "label": "Observations",
            "description": "Stored log lines and timestamps.",
            "timeline": timeline,
        },
        "automated_hypotheses": {
            "section": "automated_hypotheses",
            "label": "Automated hypotheses",
            "description": (
                "Rule alerts and anomaly windows. Each item is not a confirmed compromise."
            ),
            "rule_alerts": rule_alerts,
            "anomaly_windows": windows,
        },
        "analyst_confirmed_findings": {
            "section": "analyst_confirmed_findings",
            "label": "Analyst-confirmed findings",
            "description": "Only notes the analyst wrote.",
            "notes": findings,
        },
    }


def _lines_for(report: dict[str, object]) -> list[str]:
    investigation = report["investigation"]
    assert isinstance(investigation, dict)
    lines = [
        "SentinelLog investigation report",
        f"Title: {investigation['title']}",
        f"Status: {investigation['status']}",
        f"Id: {investigation['id']}",
        str(report["label"]),
        "",
    ]
    observations = report["observations"]
    hypotheses = report["automated_hypotheses"]
    findings = report["analyst_confirmed_findings"]
    assert isinstance(observations, dict)
    assert isinstance(hypotheses, dict)
    assert isinstance(findings, dict)
    lines.extend(
        [
            observations["label"],
            observations["description"],
            "Timeline",
        ]
    )
    timeline = observations["timeline"]
    assert isinstance(timeline, list)
    if not timeline:
        lines.append("No linked log lines.")
    for item in timeline:
        assert isinstance(item, dict)
        lines.append(
            f"{item['event_timestamp'] or 'no timestamp'} "
            f"L{item['line_number']} {item['hostname']} {item['component']}"
        )
        lines.append(str(item["raw_line"]))
    lines.append("")
    lines.extend([hypotheses["label"], hypotheses["description"], "Rule alerts"])
    rule_alerts = hypotheses["rule_alerts"]
    assert isinstance(rule_alerts, list)
    if not rule_alerts:
        lines.append("No linked rule alerts.")
    for alert in rule_alerts:
        assert isinstance(alert, dict)
        lines.append(f"{alert['title']} [{alert['severity']}]")
        lines.append(
            f"rule_id {alert['rule_id']} version {alert['rule_version']} "
            f"threshold {alert['threshold']} {alert['window_type']} {alert['window_seconds']}s"
        )
        lines.append(str(alert["label"]))
        lines.append(str(alert["explanation"]))
    lines.append("Anomaly windows")
    windows = hypotheses["anomaly_windows"]
    assert isinstance(windows, list)
    if not windows:
        lines.append("No anomaly window overlaps the selected evidence.")
    for window in windows:
        assert isinstance(window, dict)
        lines.append(
            f"{window['window_start']} to {window['window_end']} "
            f"events {window['event_count']}"
        )
        lines.append(
            f"model {window['model_id']} version {window['model_version']} "
            f"isolation {window['isolation_score']} baseline {window['baseline_score']}"
        )
        lines.append(str(window["label"]))
    lines.append("")
    lines.extend([findings["label"], findings["description"]])
    notes = findings["notes"]
    assert isinstance(notes, list)
    if not notes:
        lines.append("No analyst notes.")
    for note in notes:
        assert isinstance(note, dict)
        lines.append(f"{note['created_at']} {note['actor']}")
        lines.append(str(note["body"]))
    wrapped: list[str] = []
    for line in lines:
        wrapped.extend(wrap_text(str(line)))
    return wrapped


def render_pdf(report: dict[str, object]) -> bytes:
    return render_lines(_lines_for(report))
