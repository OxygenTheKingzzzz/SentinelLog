import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from sentinellog.models import AlertNote, DetectionRule, SecurityAlert

Severity = Literal["low", "medium", "high", "critical"]
AlertStatus = Literal["open", "investigating", "resolved", "false_positive"]
WindowType = Literal["sliding", "tumbling"]


class RuleOut(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None
    enabled: bool
    severity: str | None
    version: int
    logic: dict
    created_at: datetime
    updated_at: datetime


class RuleUpdate(BaseModel):
    enabled: bool | None = None
    threshold: int | None = Field(default=None, ge=1, le=1_000_000)
    window_seconds: int | None = Field(default=None, ge=1, le=366 * 24 * 3600)
    window_type: WindowType | None = None


class NoteOut(BaseModel):
    id: uuid.UUID
    actor: str
    note: str
    from_status: str
    to_status: str
    created_at: datetime


class AlertOut(BaseModel):
    id: uuid.UUID
    rule_id: uuid.UUID
    rule_version: int
    source_id: uuid.UUID
    title: str
    severity: str
    status: str
    source_address: str | None
    explanation: str
    threshold: int
    window_seconds: int
    window_type: str
    window_start: datetime
    window_end: datetime
    first_event_at: datetime
    last_event_at: datetime
    event_ids: list[str]
    line_numbers: list[int]
    group_value: str
    dedup_key: str
    details: dict
    created_at: datetime
    updated_at: datetime
    notes: list[NoteOut]


class AlertPage(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[AlertOut]


class AlertStatusUpdate(BaseModel):
    status: AlertStatus
    note: str = Field(min_length=1, max_length=4000)


class DetectionRunOut(BaseModel):
    created: int
    updated: int
    skipped: int
    by_rule: dict[str, int]
    disabled: list[str]


def rule_out(rule: DetectionRule) -> RuleOut:
    return RuleOut(
        id=rule.id,
        name=rule.name,
        description=rule.description,
        enabled=rule.enabled,
        severity=rule.severity,
        version=rule.version,
        logic=dict(rule.logic),
        created_at=rule.created_at,
        updated_at=rule.updated_at,
    )


def note_out(note: AlertNote) -> NoteOut:
    return NoteOut(
        id=note.id,
        actor=note.actor,
        note=note.note,
        from_status=note.from_status,
        to_status=note.to_status,
        created_at=note.created_at,
    )


def alert_out(alert: SecurityAlert, notes: list[AlertNote]) -> AlertOut:
    return AlertOut(
        id=alert.id,
        rule_id=alert.rule_id,
        rule_version=alert.rule_version,
        source_id=alert.source_id,
        title=alert.title,
        severity=alert.severity,
        status=alert.status,
        source_address=alert.source_address,
        explanation=alert.explanation,
        threshold=alert.threshold,
        window_seconds=alert.window_seconds,
        window_type=alert.window_type,
        window_start=alert.window_start,
        window_end=alert.window_end,
        first_event_at=alert.first_event_at,
        last_event_at=alert.last_event_at,
        event_ids=[str(item) for item in alert.event_ids],
        line_numbers=[int(item) for item in alert.line_numbers],
        group_value=alert.group_value,
        dedup_key=alert.dedup_key,
        details=dict(alert.details),
        created_at=alert.created_at,
        updated_at=alert.updated_at,
        notes=[note_out(note) for note in notes],
    )
