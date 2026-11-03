"""Investigation workspace over stored alerts and events, plus JSON and PDF export."""

from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from sentinellog.clock import utcnow
from sentinellog.investigations.report import SECTIONS, build_report, render_pdf
from sentinellog.models import (
    AuditLog,
    Investigation,
    InvestigationAlert,
    InvestigationEvent,
    InvestigationNote,
    LogEvent,
    SecurityAlert,
)

GRAPH_EVENT_LIMIT = 40
STATUSES = ("open", "closed")


class InvestigationNotFound(Exception):
    pass


class LinkedRecordMissing(Exception):
    pass


def _audit(session: Session, *, actor: str, action: str, entity_id: str, details: dict) -> None:
    session.add(
        AuditLog(
            actor=actor,
            action=action,
            entity_type="investigation",
            entity_id=entity_id,
            details=details,
        )
    )


def _require(session: Session, investigation_id: UUID) -> Investigation:
    row = session.get(Investigation, investigation_id)
    if row is None:
        raise InvestigationNotFound(str(investigation_id))
    return row


def _event_ids_for_alerts(session: Session, alert_ids: list[UUID]) -> list[UUID]:
    if not alert_ids:
        return []
    alerts = session.scalars(select(SecurityAlert).where(SecurityAlert.id.in_(alert_ids))).all()
    found = {alert.id for alert in alerts}
    missing = [str(alert_id) for alert_id in alert_ids if alert_id not in found]
    if missing:
        raise LinkedRecordMissing(f"alert not found: {', '.join(missing)}")
    collected: list[UUID] = []
    for alert in alerts:
        for raw in alert.event_ids:
            collected.append(UUID(str(raw)))
    return collected


def _attach(
    session: Session,
    investigation: Investigation,
    *,
    alert_ids: list[UUID],
    event_ids: list[UUID],
) -> None:
    wanted_events = list(event_ids)
    wanted_events.extend(_event_ids_for_alerts(session, alert_ids))
    if wanted_events:
        existing_events = set(
            session.scalars(select(LogEvent.id).where(LogEvent.id.in_(set(wanted_events)))).all()
        )
        missing = [
            str(event_id) for event_id in set(wanted_events) if event_id not in existing_events
        ]
        if missing:
            raise LinkedRecordMissing(f"event not found: {', '.join(missing)}")
    already_alerts = set(
        session.scalars(
            select(InvestigationAlert.alert_id).where(
                InvestigationAlert.investigation_id == investigation.id
            )
        ).all()
    )
    for alert_id in dict.fromkeys(alert_ids):
        if alert_id in already_alerts:
            continue
        session.add(InvestigationAlert(investigation_id=investigation.id, alert_id=alert_id))
    already_events = set(
        session.scalars(
            select(InvestigationEvent.log_event_id).where(
                InvestigationEvent.investigation_id == investigation.id
            )
        ).all()
    )
    for event_id in dict.fromkeys(wanted_events):
        if event_id in already_events:
            continue
        session.add(InvestigationEvent(investigation_id=investigation.id, log_event_id=event_id))


def create_investigation(
    session: Session,
    *,
    actor: str,
    title: str,
    summary: str | None,
    alert_ids: list[UUID],
    event_ids: list[UUID],
    note: str | None,
) -> Investigation:
    row = Investigation(title=title.strip(), summary=summary, status="open")
    session.add(row)
    session.flush()
    _attach(session, row, alert_ids=alert_ids, event_ids=event_ids)
    if note and note.strip():
        session.add(InvestigationNote(investigation_id=row.id, actor=actor, body=note.strip()))
    _audit(
        session,
        actor=actor,
        action="investigation.create",
        entity_id=str(row.id),
        details={
            "title": row.title,
            "alerts": len(alert_ids),
            "events": len(event_ids),
        },
    )
    session.commit()
    return row


def add_links(
    session: Session,
    investigation_id: UUID,
    *,
    actor: str,
    alert_ids: list[UUID],
    event_ids: list[UUID],
) -> Investigation:
    row = _require(session, investigation_id)
    _attach(session, row, alert_ids=alert_ids, event_ids=event_ids)
    row.updated_at = utcnow()
    _audit(
        session,
        actor=actor,
        action="investigation.link",
        entity_id=str(row.id),
        details={"alerts": len(alert_ids), "events": len(event_ids)},
    )
    session.commit()
    return row


def set_status(
    session: Session,
    investigation_id: UUID,
    *,
    actor: str,
    status: str,
    note: str,
) -> Investigation:
    if status not in STATUSES:
        raise ValueError("status must be open or closed")
    if not note.strip():
        raise ValueError("a note is required")
    row = _require(session, investigation_id)
    if row.status == status:
        raise ValueError("investigation already has that status")
    previous = row.status
    row.status = status
    row.updated_at = utcnow()
    session.add(InvestigationNote(investigation_id=row.id, actor=actor, body=note.strip()))
    _audit(
        session,
        actor=actor,
        action="investigation.status",
        entity_id=str(row.id),
        details={"from_status": previous, "to_status": status, "note": note.strip()},
    )
    session.commit()
    return row


def add_note(
    session: Session,
    investigation_id: UUID,
    *,
    actor: str,
    body: str,
) -> Investigation:
    if not body.strip():
        raise ValueError("note is required")
    row = _require(session, investigation_id)
    session.add(InvestigationNote(investigation_id=row.id, actor=actor, body=body.strip()))
    row.updated_at = utcnow()
    _audit(
        session,
        actor=actor,
        action="investigation.note",
        entity_id=str(row.id),
        details={"note": body.strip()},
    )
    session.commit()
    return row


def list_investigations(session: Session) -> list[dict[str, object]]:
    rows = session.scalars(
        select(Investigation).order_by(Investigation.updated_at.desc(), Investigation.id)
    ).all()
    payload = []
    for row in rows:
        alerts = int(
            session.scalar(
                select(func.count())
                .select_from(InvestigationAlert)
                .where(InvestigationAlert.investigation_id == row.id)
            )
            or 0
        )
        events = int(
            session.scalar(
                select(func.count())
                .select_from(InvestigationEvent)
                .where(InvestigationEvent.investigation_id == row.id)
            )
            or 0
        )
        payload.append(
            {
                "id": row.id,
                "title": row.title,
                "status": row.status,
                "summary": row.summary,
                "alerts": alerts,
                "events": events,
                "created_at": row.created_at,
                "updated_at": row.updated_at,
            }
        )
    return payload


def investigation_detail(session: Session, investigation_id: UUID) -> dict[str, object]:
    row = _require(session, investigation_id)
    report = build_report(session, row)
    hypotheses = report["automated_hypotheses"]
    observations = report["observations"]
    findings = report["analyst_confirmed_findings"]
    assert isinstance(hypotheses, dict)
    assert isinstance(observations, dict)
    assert isinstance(findings, dict)
    investigation = report["investigation"]
    assert isinstance(investigation, dict)
    return {
        "id": investigation["id"],
        "title": investigation["title"],
        "status": investigation["status"],
        "summary": investigation["summary"],
        "created_at": investigation["created_at"],
        "updated_at": investigation["updated_at"],
        "alerts": hypotheses["rule_alerts"],
        "anomaly_windows": hypotheses["anomaly_windows"],
        "events": observations["timeline"],
        "notes": findings["notes"],
    }


def evidence_bundle(
    session: Session,
    investigation_id: UUID,
    *,
    actor: str,
    record: bool,
) -> dict[str, object]:
    row = _require(session, investigation_id)
    report = build_report(session, row)
    if record:
        _record_export(session, row, actor=actor, fmt="json", report=report)
        session.commit()
    return report


def pdf_export(session: Session, investigation_id: UUID, *, actor: str) -> bytes:
    row = _require(session, investigation_id)
    report = build_report(session, row)
    payload = render_pdf(report)
    _record_export(session, row, actor=actor, fmt="pdf", report=report)
    session.commit()
    return payload


def _record_export(
    session: Session,
    row: Investigation,
    *,
    actor: str,
    fmt: str,
    report: dict[str, object],
) -> None:
    hypotheses = report["automated_hypotheses"]
    observations = report["observations"]
    findings = report["analyst_confirmed_findings"]
    assert isinstance(hypotheses, dict)
    assert isinstance(observations, dict)
    assert isinstance(findings, dict)
    _audit(
        session,
        actor=actor,
        action="investigation.export",
        entity_id=str(row.id),
        details={
            "format": fmt,
            "sections": list(SECTIONS),
            "observations": len(observations["timeline"]),  # type: ignore[arg-type]
            "rule_alerts": len(hypotheses["rule_alerts"]),  # type: ignore[arg-type]
            "anomaly_windows": len(hypotheses["anomaly_windows"]),  # type: ignore[arg-type]
            "analyst_notes": len(findings["notes"]),  # type: ignore[arg-type]
        },
    )


def correlation_graph(session: Session, investigation_id: UUID) -> dict[str, object]:
    detail = investigation_detail(session, investigation_id)
    nodes: list[dict[str, object]] = [
        {
            "id": f"investigation:{detail['id']}",
            "kind": "investigation",
            "label": str(detail["title"]),
        }
    ]
    edges: list[dict[str, str]] = []
    investigation_node = f"investigation:{detail['id']}"
    rule_ids: set[str] = set()
    addresses: set[str] = set()
    linked_event_ids = {str(event["id"]) for event in detail["events"]}  # type: ignore[index]
    shown_events = list(detail["events"])[:GRAPH_EVENT_LIMIT]  # type: ignore[index]
    hidden = len(detail["events"]) - len(shown_events)  # type: ignore[arg-type]
    shown_ids = {str(event["id"]) for event in shown_events}
    for alert in detail["alerts"]:  # type: ignore[union-attr]
        alert_node = f"alert:{alert['id']}"
        nodes.append(
            {
                "id": alert_node,
                "kind": "alert",
                "label": alert["title"],
                "severity": alert["severity"],
            }
        )
        edges.append(
            {
                "id": f"{investigation_node}->{alert_node}",
                "source": investigation_node,
                "target": alert_node,
                "kind": "includes_alert",
            }
        )
        rule_ids.add(str(alert["rule_id"]))
        if alert["source_address"]:
            addresses.add(str(alert["source_address"]))
            address_node = f"address:{alert['source_address']}"
            edges.append(
                {
                    "id": f"{alert_node}->{address_node}",
                    "source": alert_node,
                    "target": address_node,
                    "kind": "source_address",
                }
            )
        for raw_event_id in alert["event_ids"]:
            if raw_event_id in shown_ids and raw_event_id in linked_event_ids:
                event_node = f"event:{raw_event_id}"
                edges.append(
                    {
                        "id": f"{alert_node}->{event_node}",
                        "source": alert_node,
                        "target": event_node,
                        "kind": "evidence",
                    }
                )
    for rule_id in sorted(rule_ids):
        rule_node = f"rule:{rule_id}"
        nodes.append({"id": rule_node, "kind": "rule", "label": rule_id})
        edges.append(
            {
                "id": f"{investigation_node}->{rule_node}",
                "source": investigation_node,
                "target": rule_node,
                "kind": "rule",
            }
        )
        for alert in detail["alerts"]:  # type: ignore[union-attr]
            if str(alert["rule_id"]) == rule_id:
                edges.append(
                    {
                        "id": f"alert:{alert['id']}->{rule_node}",
                        "source": f"alert:{alert['id']}",
                        "target": rule_node,
                        "kind": "triggered_rule",
                    }
                )
    for address in sorted(addresses):
        nodes.append({"id": f"address:{address}", "kind": "address", "label": address})
    for event in shown_events:
        event_node = f"event:{event['id']}"
        label = f"L{event['line_number']} {event['event_id'] or event['component']}"
        nodes.append(
            {
                "id": event_node,
                "kind": "event",
                "label": label,
                "line_number": event["line_number"],
                "component": event["component"],
            }
        )
        edges.append(
            {
                "id": f"{investigation_node}->{event_node}",
                "source": investigation_node,
                "target": event_node,
                "kind": "includes_event",
            }
        )
    if hidden > 0:
        more_id = f"more:{detail['id']}"
        nodes.append(
            {
                "id": more_id,
                "kind": "more_events",
                "label": f"{hidden} additional linked events",
                "count": hidden,
            }
        )
        edges.append(
            {
                "id": f"{investigation_node}->{more_id}",
                "source": investigation_node,
                "target": more_id,
                "kind": "truncated_events",
            }
        )
    return {
        "investigation_id": str(detail["id"]),
        "event_limit": GRAPH_EVENT_LIMIT,
        "linked_events": len(detail["events"]),  # type: ignore[arg-type]
        "shown_events": len(shown_events),
        "nodes": nodes,
        "edges": edges,
    }
