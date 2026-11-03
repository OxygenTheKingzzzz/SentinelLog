"""API shapes for risk labels, predictions, and published evaluations."""

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from sentinellog.models import LogEvent, RiskLabel, RiskModel, RiskPrediction
from sentinellog.risk.constants import NOT_EVALUATED


class LabelIn(BaseModel):
    log_event_id: uuid.UUID
    risk_level: str = Field(pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$")
    note: str | None = None


class LabelOut(BaseModel):
    id: uuid.UUID
    log_event_id: uuid.UUID
    risk_level: str
    provenance: str
    note: str | None
    created_at: datetime


class ModelOut(BaseModel):
    id: uuid.UUID
    version: int
    algorithm: str
    task: str
    dataset_name: str
    dataset_version: str
    label_provenance: str
    random_seed: int
    n_train: int
    n_test: int
    metrics: dict[str, Any] | None
    metrics_status: str
    metrics_note: str
    config: dict[str, Any]
    sklearn_version: str
    created_at: datetime
    real_world: bool


class PredictionOut(BaseModel):
    id: uuid.UUID
    model_id: uuid.UUID
    model_version: int
    algorithm: str
    log_event_id: uuid.UUID
    line_number: int
    event_timestamp: datetime | None
    content: str
    split_role: str
    predicted_risk: str
    class_confidence: float | None
    anomaly_score: float | None
    score_kind: str
    explanation: dict[str, Any]
    attached_label: str | None
    attached_provenance: str | None
    verified_label: str | None


class PredictionPage(BaseModel):
    total: int
    limit: int
    offset: int
    model_id: uuid.UUID | None
    metrics_status: str | None
    metrics_note: str
    items: list[PredictionOut]


def label_out(row: RiskLabel) -> LabelOut:
    return LabelOut(
        id=row.id,
        log_event_id=row.log_event_id,
        risk_level=row.risk_level,
        provenance=row.provenance,
        note=row.note,
        created_at=row.created_at,
    )


def model_out(row: RiskModel) -> ModelOut:
    real_world = row.metrics_status == "evaluated" and row.metrics is not None
    return ModelOut(
        id=row.id,
        version=row.version,
        algorithm=row.algorithm,
        task=row.task,
        dataset_name=row.dataset_name,
        dataset_version=row.dataset_version,
        label_provenance=row.label_provenance,
        random_seed=row.random_seed,
        n_train=row.n_train,
        n_test=row.n_test,
        metrics=row.metrics,
        metrics_status=row.metrics_status,
        metrics_note=row.metrics_note,
        config=row.config,
        sklearn_version=row.sklearn_version,
        created_at=row.created_at,
        real_world=real_world,
    )


def prediction_out(
    row: RiskPrediction,
    event: LogEvent,
    label: RiskLabel | None,
    model: RiskModel,
) -> PredictionOut:
    attached = label.risk_level if label is not None else None
    provenance = label.provenance if label is not None else None
    verified = attached if provenance in {"verified_manual", "verified_import"} else None
    return PredictionOut(
        id=row.id,
        model_id=row.model_id,
        model_version=model.version,
        algorithm=model.algorithm,
        log_event_id=row.log_event_id,
        line_number=event.line_number,
        event_timestamp=event.event_timestamp,
        content=event.content,
        split_role=row.split_role,
        predicted_risk=row.predicted_risk,
        class_confidence=row.class_confidence,
        anomaly_score=row.anomaly_score,
        score_kind=row.score_kind,
        explanation=row.explanation,
        attached_label=attached,
        attached_provenance=provenance,
        verified_label=verified,
    )


def empty_page(limit: int, offset: int) -> PredictionPage:
    return PredictionPage(
        total=0,
        limit=limit,
        offset=offset,
        model_id=None,
        metrics_status=None,
        metrics_note=NOT_EVALUATED,
        items=[],
    )
