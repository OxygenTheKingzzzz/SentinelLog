"""Rule catalog sync, analyst updates, and detection runs."""

from uuid import UUID

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from sentinellog.clock import utcnow
from sentinellog.detection.catalog import BUILTIN_RULES
from sentinellog.detection.engine import DetectionRunResult, run_detection
from sentinellog.models import AlertNote, AuditLog, DetectionRule, SecurityAlert

ALERT_STATUSES = ("open", "investigating", "resolved", "false_positive")
WINDOW_TYPES = ("sliding", "tumbling")
MAX_THRESHOLD = 1_000_000
MAX_WINDOW_SECONDS = 366 * 24 * 3600


class RuleNotFound(Exception):
    pass


class AlertNotFound(Exception):
    pass


class StatusUnchanged(Exception):
    pass


class NoteRequired(Exception):
    pass


def _audit(
    session: Session,
    *,
    actor: str,
    action: str,
    entity_type: str,
    entity_id: str | None,
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


def ensure_builtin_rules(session: Session, *, actor: str) -> list[DetectionRule]:
    """Insert catalog rules that are missing. Do not overwrite analyst edits."""
    existing = {row.name: row for row in session.scalars(select(DetectionRule)).all()}
    for spec in BUILTIN_RULES:
        if spec.name in existing:
            continue
        row = DetectionRule(
            name=spec.name,
            description=spec.description,
            enabled=True,
            severity=spec.severity,
            version=1,
            logic=spec.logic(),
        )
        session.add(row)
        session.flush()
        existing[spec.name] = row
        _audit(
            session,
            actor=actor,
            action="detection_rule.create",
            entity_type="detection_rule",
            entity_id=str(row.id),
            details={
                "name": spec.name,
                "version": 1,
                "severity": spec.severity,
                "threshold": spec.threshold,
                "window_seconds": spec.window_seconds,
                "window_type": spec.window_type,
                "enabled": True,
            },
        )
    return [existing[spec.name] for spec in BUILTIN_RULES]


def list_rules(session: Session, *, actor: str) -> list[DetectionRule]:
    return ensure_builtin_rules(session, actor=actor)


def get_rule(session: Session, rule_id: UUID) -> DetectionRule:
    rule = session.get(DetectionRule, rule_id)
    if rule is None:
        raise RuleNotFound(str(rule_id))
    return rule


def update_rule(
    session: Session,
    rule_id: UUID,
    *,
    actor: str,
    enabled: bool | None = None,
    threshold: int | None = None,
    window_seconds: int | None = None,
    window_type: str | None = None,
    fields_set: set[str],
) -> DetectionRule:
    """Update enablement, threshold, or window. Definition edits bump version."""
    rule = get_rule(session, rule_id)
    logic = dict(rule.logic)
    before = {
        "enabled": rule.enabled,
        "threshold": logic.get("threshold"),
        "window_seconds": logic.get("window_seconds"),
        "window_type": logic.get("window_type"),
        "version": rule.version,
        "severity": rule.severity,
    }
    definition_changed = False
    if "threshold" in fields_set:
        if threshold is None or not 1 <= threshold <= MAX_THRESHOLD:
            raise ValueError("threshold must be between 1 and 1000000")
        if logic.get("threshold") != threshold:
            logic["threshold"] = threshold
            definition_changed = True
    if "window_seconds" in fields_set:
        if window_seconds is None or not 1 <= window_seconds <= MAX_WINDOW_SECONDS:
            raise ValueError("window_seconds is out of range")
        if logic.get("window_seconds") != window_seconds:
            logic["window_seconds"] = window_seconds
            definition_changed = True
    if "window_type" in fields_set:
        if window_type not in WINDOW_TYPES:
            raise ValueError("window_type must be sliding or tumbling")
        if logic.get("window_type") != window_type:
            logic["window_type"] = window_type
            definition_changed = True
    enabled_changed = False
    if "enabled" in fields_set and enabled is not None and rule.enabled != enabled:
        rule.enabled = enabled
        enabled_changed = True
    if not definition_changed and not enabled_changed:
        return rule
    if definition_changed:
        rule.version += 1
        rule.logic = logic
        flag_modified(rule, "logic")
    rule.updated_at = utcnow()
    after = {
        "enabled": rule.enabled,
        "threshold": rule.logic.get("threshold"),
        "window_seconds": rule.logic.get("window_seconds"),
        "window_type": rule.logic.get("window_type"),
        "version": rule.version,
        "severity": rule.severity,
    }
    _audit(
        session,
        actor=actor,
        action="detection_rule.update",
        entity_type="detection_rule",
        entity_id=str(rule.id),
        details={"name": rule.name, "before": before, "after": after},
    )
    session.commit()
    return rule


def detect(
    session: Session,
    *,
    source_id: UUID | None,
    actor: str,
) -> DetectionRunResult:
    rules = ensure_builtin_rules(session, actor=actor)
    result = run_detection(session, source_id=source_id, rules=rules)
    session.commit()
    return result


def list_alerts(
    session: Session,
    *,
    severity: str | None = None,
    status: str | None = None,
    rule: str | None = None,
    source_id: UUID | None = None,
    limit: int = 100,
    offset: int = 0,
    sort: str = "window_start",
) -> tuple[list[SecurityAlert], int]:
    stmt = select(SecurityAlert)
    count_stmt = select(func.count()).select_from(SecurityAlert)
    if severity is not None:
        stmt = stmt.where(SecurityAlert.severity == severity)
        count_stmt = count_stmt.where(SecurityAlert.severity == severity)
    if status is not None:
        stmt = stmt.where(SecurityAlert.status == status)
        count_stmt = count_stmt.where(SecurityAlert.status == status)
    if source_id is not None:
        stmt = stmt.where(SecurityAlert.source_id == source_id)
        count_stmt = count_stmt.where(SecurityAlert.source_id == source_id)
    if rule is not None:
        rule_id = _rule_filter(session, rule)
        stmt = stmt.where(SecurityAlert.rule_id == rule_id)
        count_stmt = count_stmt.where(SecurityAlert.rule_id == rule_id)
    total = int(session.scalar(count_stmt) or 0)
    if sort == "window_start":
        order = (SecurityAlert.window_start, SecurityAlert.title, SecurityAlert.id)
    elif sort == "created_at":
        order = (SecurityAlert.created_at.desc(), SecurityAlert.id)
    elif sort == "severity":
        rank = case(
            (SecurityAlert.severity == "critical", 0),
            (SecurityAlert.severity == "high", 1),
            (SecurityAlert.severity == "medium", 2),
            (SecurityAlert.severity == "low", 3),
            else_=4,
        )
        order = (rank, SecurityAlert.window_start, SecurityAlert.id)
    else:
        raise ValueError("sort must be window_start, created_at, or severity")
    rows = session.scalars(stmt.order_by(*order).limit(limit).offset(offset)).all()
    return list(rows), total


def _rule_filter(session: Session, rule: str) -> UUID:
    try:
        parsed = UUID(rule)
    except ValueError:
        parsed = None
    if parsed is not None:
        found = session.get(DetectionRule, parsed)
        if found is None:
            raise RuleNotFound(rule)
        return found.id
    found = session.scalar(select(DetectionRule).where(DetectionRule.name == rule))
    if found is None:
        raise RuleNotFound(rule)
    return found.id


def get_alert(session: Session, alert_id: UUID) -> SecurityAlert:
    alert = session.get(SecurityAlert, alert_id)
    if alert is None:
        raise AlertNotFound(str(alert_id))
    return alert


def notes_for(session: Session, alert_ids: list[UUID]) -> dict[UUID, list[AlertNote]]:
    if not alert_ids:
        return {}
    rows = session.scalars(
        select(AlertNote)
        .where(AlertNote.alert_id.in_(alert_ids))
        .order_by(AlertNote.created_at, AlertNote.id)
    ).all()
    grouped: dict[UUID, list[AlertNote]] = {alert_id: [] for alert_id in alert_ids}
    for row in rows:
        grouped.setdefault(row.alert_id, []).append(row)
    return grouped


def transition_alert(
    session: Session,
    alert_id: UUID,
    *,
    actor: str,
    status: str,
    note: str,
) -> SecurityAlert:
    if status not in ALERT_STATUSES:
        raise ValueError("status is not a known lifecycle value")
    text = note.strip()
    if text == "":
        raise NoteRequired("a note is required when the status changes")
    alert = get_alert(session, alert_id)
    if alert.status == status:
        raise StatusUnchanged(status)
    previous = alert.status
    alert.status = status
    alert.updated_at = utcnow()
    session.add(
        AlertNote(
            alert_id=alert.id,
            actor=actor,
            note=text,
            from_status=previous,
            to_status=status,
        )
    )
    _audit(
        session,
        actor=actor,
        action="security_alert.status",
        entity_type="security_alert",
        entity_id=str(alert.id),
        details={
            "from_status": previous,
            "to_status": status,
            "note": text,
            "rule_id": str(alert.rule_id),
            "rule_version": alert.rule_version,
        },
    )
    session.commit()
    return alert
