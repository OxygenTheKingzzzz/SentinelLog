import uuid
from datetime import datetime

from pydantic import BaseModel

from sentinellog.ml.constants import NO_GROUND_TRUTH
from sentinellog.models import AnomalyModel, AnomalyScore


class ModelSummary(BaseModel):
    id: uuid.UUID
    version: int
    algorithm: str
    window_seconds: int
    window_type: str
    train_fraction: float
    n_train: int
    n_validation: int
    n_features: int
    baseline_z_threshold: float
    isolation_score_threshold: float
    sklearn_version: str
    dropped_features: list
    created_at: datetime
    ground_truth: bool = False
    metrics: None = None
    metrics_note: str = NO_GROUND_TRUTH


class ModelOut(ModelSummary):
    feature_names: list
    feature_medians: dict
    feature_mads: dict
    feature_scales: dict
    feature_scale_kinds: dict
    template_ids: list
    component_names: list
    hyperparameters: dict
    validation_summary: dict
    train_windows: list
    validation_windows: list
    artifact_sha256: str
    disclaimer: str


class ScoreOut(BaseModel):
    id: uuid.UUID
    model_id: uuid.UUID
    model_version: int
    source_id: uuid.UUID
    window_start: datetime
    window_end: datetime
    event_count: int
    split_role: str
    features: dict
    isolation_score: float
    baseline_score: float
    flagged_isolation: bool
    flagged_baseline: bool
    explanation: dict
    created_at: datetime
    ground_truth: bool = False
    metrics: None = None
    metrics_note: str = NO_GROUND_TRUTH


class ScorePage(BaseModel):
    total: int
    limit: int
    offset: int
    model_id: uuid.UUID | None
    model_version: int | None
    items: list[ScoreOut]
    ground_truth: bool = False
    metrics: None = None
    metrics_note: str = NO_GROUND_TRUTH


class TrainOut(ModelOut):
    pass


class ScoreRunOut(BaseModel):
    model_id: uuid.UUID
    model_version: int
    source_id: uuid.UUID
    windows: int
    ground_truth: bool = False
    metrics: None = None
    metrics_note: str = NO_GROUND_TRUTH


def model_summary(record: AnomalyModel) -> ModelSummary:
    return ModelSummary(
        id=record.id,
        version=record.version,
        algorithm=record.algorithm,
        window_seconds=record.window_seconds,
        window_type=record.window_type,
        train_fraction=record.train_fraction,
        n_train=record.n_train,
        n_validation=record.n_validation,
        n_features=len(record.feature_names),
        baseline_z_threshold=record.baseline_z_threshold,
        isolation_score_threshold=record.isolation_score_threshold,
        sklearn_version=record.sklearn_version,
        dropped_features=list(record.dropped_features),
        created_at=record.created_at,
    )


def model_out(record: AnomalyModel) -> ModelOut:
    summary = model_summary(record)
    return ModelOut(
        **summary.model_dump(),
        feature_names=list(record.feature_names),
        feature_medians=dict(record.feature_medians),
        feature_mads=dict(record.feature_mads),
        feature_scales=dict(record.feature_scales),
        feature_scale_kinds=dict(record.feature_scale_kinds),
        template_ids=list(record.template_ids),
        component_names=list(record.component_names),
        hyperparameters=dict(record.hyperparameters),
        validation_summary=dict(record.validation_summary),
        train_windows=list(record.train_windows),
        validation_windows=list(record.validation_windows),
        artifact_sha256=record.artifact_sha256,
        disclaimer=record.disclaimer,
    )


def score_out(row: AnomalyScore, version: int) -> ScoreOut:
    return ScoreOut(
        id=row.id,
        model_id=row.model_id,
        model_version=version,
        source_id=row.source_id,
        window_start=row.window_start,
        window_end=row.window_end,
        event_count=row.event_count,
        split_role=row.split_role,
        features=dict(row.features),
        isolation_score=row.isolation_score,
        baseline_score=row.baseline_score,
        flagged_isolation=row.flagged_isolation,
        flagged_baseline=row.flagged_baseline,
        explanation=dict(row.explanation),
        created_at=row.created_at,
    )
