from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from sentinellog.api.deps import get_db
from sentinellog.detection.schemas import (
    AlertOut,
    AlertPage,
    AlertStatusUpdate,
    DetectionRunOut,
    RuleOut,
    RuleUpdate,
    alert_out,
    rule_out,
)
from sentinellog.detection.service import (
    AlertNotFound,
    NoteRequired,
    RuleNotFound,
    StatusUnchanged,
    detect,
    get_alert,
    get_rule,
    list_alerts,
    list_rules,
    notes_for,
    transition_alert,
    update_rule,
)
from sentinellog.models import LogSource

detection_router = APIRouter(prefix="/detection", tags=["detection"])
rules_router = APIRouter(prefix="/rules", tags=["detection"])
alerts_router = APIRouter(prefix="/alerts", tags=["detection"])


@detection_router.get("/status")
def detection_status() -> dict[str, object]:
    return {
        "module": "detection",
        "implemented": True,
        "detail": (
            "Rule engine evaluates enabled detection_rules against log_events "
            "and writes security_alerts. Findings are not confirmed incidents."
        ),
    }


@detection_router.post("/run", response_model=DetectionRunOut)
def run_detection_route(
    source_id: UUID | None = None,
    db: Session = Depends(get_db),
) -> DetectionRunOut:
    if source_id is not None and db.get(LogSource, source_id) is None:
        raise HTTPException(status_code=404, detail="source not found")
    result = detect(db, source_id=source_id, actor="api")
    return DetectionRunOut(
        created=result.created,
        updated=result.updated,
        skipped=result.skipped,
        by_rule=dict(sorted(result.by_rule.items())),
        disabled=result.disabled,
    )


@rules_router.get("", response_model=list[RuleOut])
def get_rules(db: Session = Depends(get_db)) -> list[RuleOut]:
    rules = list_rules(db, actor="api")
    db.commit()
    return [rule_out(rule) for rule in rules]


@rules_router.get("/{rule_id}", response_model=RuleOut)
def get_one_rule(rule_id: UUID, db: Session = Depends(get_db)) -> RuleOut:
    try:
        rule = get_rule(db, rule_id)
    except RuleNotFound:
        raise HTTPException(status_code=404, detail="rule not found") from None
    return rule_out(rule)


@rules_router.patch("/{rule_id}", response_model=RuleOut)
def patch_rule(rule_id: UUID, payload: RuleUpdate, db: Session = Depends(get_db)) -> RuleOut:
    try:
        rule = update_rule(
            db,
            rule_id,
            actor="api",
            enabled=payload.enabled,
            threshold=payload.threshold,
            window_seconds=payload.window_seconds,
            window_type=payload.window_type,
            fields_set=set(payload.model_fields_set),
        )
    except RuleNotFound:
        raise HTTPException(status_code=404, detail="rule not found") from None
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    return rule_out(rule)


@alerts_router.get("", response_model=AlertPage)
def get_alerts(
    severity: str | None = None,
    status: str | None = None,
    rule: str | None = None,
    source_id: UUID | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    sort: str = "window_start",
    db: Session = Depends(get_db),
) -> AlertPage:
    try:
        rows, total = list_alerts(
            db,
            severity=severity,
            status=status,
            rule=rule,
            source_id=source_id,
            limit=limit,
            offset=offset,
            sort=sort,
        )
    except RuleNotFound:
        raise HTTPException(status_code=404, detail="rule not found") from None
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    notes = notes_for(db, [row.id for row in rows])
    return AlertPage(
        total=total,
        limit=limit,
        offset=offset,
        items=[alert_out(row, notes.get(row.id, [])) for row in rows],
    )


@alerts_router.get("/{alert_id}", response_model=AlertOut)
def get_one_alert(alert_id: UUID, db: Session = Depends(get_db)) -> AlertOut:
    try:
        alert = get_alert(db, alert_id)
    except AlertNotFound:
        raise HTTPException(status_code=404, detail="alert not found") from None
    notes = notes_for(db, [alert.id])
    return alert_out(alert, notes.get(alert.id, []))


@alerts_router.post("/{alert_id}/status", response_model=AlertOut)
def post_alert_status(
    alert_id: UUID,
    payload: AlertStatusUpdate,
    db: Session = Depends(get_db),
) -> AlertOut:
    try:
        alert = transition_alert(
            db,
            alert_id,
            actor="api",
            status=payload.status,
            note=payload.note,
        )
    except AlertNotFound:
        raise HTTPException(status_code=404, detail="alert not found") from None
    except StatusUnchanged:
        raise HTTPException(status_code=400, detail="alert already has that status") from None
    except NoteRequired as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    notes = notes_for(db, [alert.id])
    return alert_out(alert, notes.get(alert.id, []))
