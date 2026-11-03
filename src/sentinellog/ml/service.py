"""Train and score anomaly models. Does not write security_alerts."""

import hashlib
import json
import math
from pathlib import Path
from uuid import UUID, uuid4

import joblib
import sklearn
from sqlalchemy import delete, func, or_, select
from sqlalchemy.orm import Session

from sentinellog.clock import utcnow
from sentinellog.config import get_settings
from sentinellog.ml.constants import (
    ALGORITHM,
    BASELINE_Z_THRESHOLD,
    CONTAMINATION,
    ISOLATION_SCORE_THRESHOLD,
    MIN_SPLIT,
    N_ESTIMATORS,
    NO_GROUND_TRUTH,
    RANDOM_STATE,
    TRAIN_FRACTION,
    WINDOW_SECONDS,
    WINDOW_TYPE,
    Z_CAP,
    Z_CONSISTENCY,
)
from sentinellog.ml.features import (
    FeatureSchema,
    RawWindow,
    build_windows,
    dropped_for_columns,
    load_events,
    load_template_ids,
    log_event_columns,
    matrix_rows,
    schema_for,
)
from sentinellog.ml.scoring import (
    column_stats,
    feature_matrix,
    fit_forest,
    json_number,
    score_rows,
    stats_as_dicts,
    validation_summary,
)
from sentinellog.models import AnomalyModel, AnomalyScore, AuditLog, LogSource


class SourceNotFound(Exception):
    pass


class ModelNotFound(Exception):
    pass


class NoTimestampedEvents(Exception):
    pass


class NotEnoughWindows(Exception):
    pass


class ArtifactError(Exception):
    pass


def repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def artifact_root() -> Path:
    configured = Path(get_settings().anomaly_artifact_dir)
    if configured.is_absolute():
        return configured
    return repo_root() / configured


def _window_stamp(window: RawWindow) -> dict[str, str]:
    return {
        "source_id": str(window.source_id),
        "window_start": window.window_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def _audit(session: Session, *, actor: str, action: str, entity_id: str, details: dict) -> None:
    session.add(
        AuditLog(
            actor=actor,
            action=action,
            entity_type="anomaly_model",
            entity_id=entity_id,
            details=details,
        )
    )


def _require_source(session: Session, source_id: UUID) -> LogSource:
    source = session.get(LogSource, source_id)
    if source is None:
        raise SourceNotFound(str(source_id))
    return source


def train_model(session: Session, *, source_id: UUID | None, actor: str) -> AnomalyModel:
    if source_id is not None:
        _require_source(session, source_id)
    events = load_events(session, source_id)
    if not events:
        raise NoTimestampedEvents("no timestamped log events to train on")
    windows = build_windows(events)
    train_n = math.floor(len(windows) * TRAIN_FRACTION)
    validation_n = len(windows) - train_n
    if train_n < MIN_SPLIT or validation_n < MIN_SPLIT:
        raise NotEnoughWindows(
            f"need at least {MIN_SPLIT} train and {MIN_SPLIT} validation windows, "
            f"found {len(windows)}"
        )
    train_windows = windows[:train_n]
    validation_windows = windows[train_n:]
    dropped = dropped_for_columns(log_event_columns(session))
    template_ids = load_template_ids(session)
    schema = schema_for(train_windows, template_ids, dropped)
    if not schema.feature_names:
        raise NotEnoughWindows("every feature was dropped because its columns are missing")
    names = list(schema.feature_names)
    train_rows = matrix_rows(train_windows, schema)
    validation_rows = matrix_rows(validation_windows, schema)
    train_matrix = feature_matrix(train_rows, names)
    medians_a, mads_a, scales_a, kinds = column_stats(train_matrix)
    medians, mads, scales, kind_map = stats_as_dicts(names, medians_a, mads_a, scales_a, kinds)
    forest = fit_forest(train_matrix)
    scored_validation = score_rows(forest, validation_rows, names, medians, mads, scales, kind_map)
    model_id = uuid4()
    directory = artifact_root() / str(model_id)
    directory.mkdir(parents=True, exist_ok=True)
    artifact = directory / "model.joblib"
    bundle = {
        "feature_names": names,
        "medians": medians,
        "mads": mads,
        "scales": scales,
        "scale_kinds": kind_map,
        "template_ids": list(schema.template_ids),
        "component_names": list(schema.component_names),
        "model": forest,
        "baseline_z_threshold": BASELINE_Z_THRESHOLD,
        "isolation_score_threshold": ISOLATION_SCORE_THRESHOLD,
    }
    joblib.dump(bundle, artifact)
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    version = int(session.scalar(select(func.max(AnomalyModel.version))) or 0) + 1
    hyperparameters = {
        "n_estimators": N_ESTIMATORS,
        "contamination": CONTAMINATION,
        "random_state": RANDOM_STATE,
        "bootstrap": False,
        "n_jobs": 1,
        "train_fraction": TRAIN_FRACTION,
        "window_seconds": WINDOW_SECONDS,
        "window_type": WINDOW_TYPE,
        "baseline_z_threshold": BASELINE_Z_THRESHOLD,
        "isolation_score_threshold": ISOLATION_SCORE_THRESHOLD,
        "z_cap": Z_CAP,
        "z_consistency": Z_CONSISTENCY,
        "decision_function_offset": float(forest.offset_),
        "scale": "median; MAD, else mean absolute deviation, else constant cap",
        "features_exclude": "security_alerts and any label",
    }
    record = AnomalyModel(
        id=model_id,
        version=version,
        algorithm=ALGORITHM,
        window_seconds=WINDOW_SECONDS,
        window_type=WINDOW_TYPE,
        train_fraction=TRAIN_FRACTION,
        n_train=train_n,
        n_validation=validation_n,
        baseline_z_threshold=BASELINE_Z_THRESHOLD,
        isolation_score_threshold=ISOLATION_SCORE_THRESHOLD,
        feature_names=names,
        feature_medians={key: json_number(value) for key, value in medians.items()},
        feature_mads={key: json_number(value) for key, value in mads.items()},
        feature_scales={key: json_number(value) for key, value in scales.items()},
        feature_scale_kinds=kind_map,
        template_ids=list(schema.template_ids),
        component_names=list(schema.component_names),
        hyperparameters=hyperparameters,
        validation_summary=validation_summary(scored_validation),
        train_windows=[_window_stamp(window) for window in train_windows],
        validation_windows=[_window_stamp(window) for window in validation_windows],
        dropped_features=dropped,
        artifact_path=str(artifact),
        artifact_sha256=digest,
        sklearn_version=sklearn.__version__,
        disclaimer=NO_GROUND_TRUTH,
        created_at=utcnow(),
    )
    (directory / "metadata.json").write_text(
        json.dumps(
            {
                "id": str(model_id),
                "version": version,
                "algorithm": ALGORITHM,
                "ground_truth": False,
                "metrics": None,
                "metrics_note": NO_GROUND_TRUTH,
                "hyperparameters": hyperparameters,
                "dropped_features": dropped,
                "n_train": train_n,
                "n_validation": validation_n,
                "feature_names": names,
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    session.add(record)
    _audit(
        session,
        actor=actor,
        action="anomaly_model.train",
        entity_id=str(model_id),
        details={
            "version": version,
            "n_train": train_n,
            "n_validation": validation_n,
            "n_features": len(names),
            "dropped_features": [item["feature"] for item in dropped],
            "ground_truth": False,
            "metrics": None,
        },
    )
    session.commit()
    return record


def _load_bundle(record: AnomalyModel) -> dict:
    path = Path(record.artifact_path)
    if not path.is_file():
        raise ArtifactError(f"model artifact is missing: {path}")
    bundle = joblib.load(path)
    if list(bundle["feature_names"]) != list(record.feature_names):
        raise ArtifactError("artifact feature names do not match the stored model")
    return bundle


def _schema_from_record(record: AnomalyModel) -> FeatureSchema:
    return FeatureSchema(
        feature_names=tuple(record.feature_names),
        template_ids=tuple(record.template_ids),
        component_names=tuple(record.component_names),
        dropped_features=tuple(record.dropped_features),
    )


def score_source(
    session: Session,
    *,
    source_id: UUID,
    model_id: UUID | None,
    actor: str,
) -> tuple[AnomalyModel, int]:
    _require_source(session, source_id)
    record = get_model(session, model_id) if model_id is not None else latest_model(session)
    bundle = _load_bundle(record)
    events = load_events(session, source_id)
    if not events:
        raise NoTimestampedEvents("no timestamped log events to score")
    windows = build_windows(events)
    schema = _schema_from_record(record)
    names = list(schema.feature_names)
    rows = matrix_rows(windows, schema)
    medians = {key: float(value) for key, value in record.feature_medians.items()}
    mads = {key: float(value) for key, value in record.feature_mads.items()}
    scales = {key: float(value) for key, value in record.feature_scales.items()}
    kinds = {key: str(value) for key, value in record.feature_scale_kinds.items()}
    scored = score_rows(bundle["model"], rows, names, medians, mads, scales, kinds)
    train_keys = {f"{item['source_id']}|{item['window_start']}" for item in record.train_windows}
    validation_keys = {
        f"{item['source_id']}|{item['window_start']}" for item in record.validation_windows
    }
    session.execute(
        delete(AnomalyScore).where(
            AnomalyScore.model_id == record.id,
            AnomalyScore.source_id == source_id,
        )
    )
    for window, row, result in zip(windows, rows, scored, strict=True):
        stamp = _window_stamp(window)
        key = f"{stamp['source_id']}|{stamp['window_start']}"
        if key in train_keys:
            role = "train"
        elif key in validation_keys:
            role = "validation"
        else:
            role = "new"
        session.add(
            AnomalyScore(
                model_id=record.id,
                source_id=window.source_id,
                window_start=window.window_start,
                window_end=window.window_end,
                event_count=window.event_count,
                split_role=role,
                features={name: json_number(row[name]) for name in names},
                isolation_score=float(result["isolation_score"]),
                baseline_score=float(result["baseline_score"]),
                flagged_isolation=bool(result["flagged_isolation"]),
                flagged_baseline=bool(result["flagged_baseline"]),
                explanation=result["explanation"],
            )
        )
    _audit(
        session,
        actor=actor,
        action="anomaly_model.score",
        entity_id=str(record.id),
        details={
            "source_id": str(source_id),
            "windows": len(windows),
            "ground_truth": False,
            "metrics": None,
        },
    )
    session.commit()
    return record, len(windows)


def list_models(session: Session) -> list[AnomalyModel]:
    return list(session.scalars(select(AnomalyModel).order_by(AnomalyModel.version.desc())).all())


def latest_model(session: Session) -> AnomalyModel:
    record = session.scalar(select(AnomalyModel).order_by(AnomalyModel.version.desc()).limit(1))
    if record is None:
        raise ModelNotFound("no anomaly model has been trained")
    return record


def get_model(session: Session, model_id: UUID) -> AnomalyModel:
    record = session.get(AnomalyModel, model_id)
    if record is None:
        raise ModelNotFound(str(model_id))
    return record


def list_scores(
    session: Session,
    *,
    source_id: UUID | None,
    model_id: UUID | None,
    flagged: str | None,
    limit: int,
    offset: int,
) -> tuple[list[AnomalyScore], int, AnomalyModel | None]:
    record: AnomalyModel | None
    if model_id is not None:
        record = get_model(session, model_id)
    else:
        try:
            record = latest_model(session)
        except ModelNotFound:
            record = None
    if record is None:
        return [], 0, None
    stmt = select(AnomalyScore).where(AnomalyScore.model_id == record.id)
    count_stmt = (
        select(func.count()).select_from(AnomalyScore).where(AnomalyScore.model_id == record.id)
    )
    if source_id is not None:
        stmt = stmt.where(AnomalyScore.source_id == source_id)
        count_stmt = count_stmt.where(AnomalyScore.source_id == source_id)
    if flagged == "isolation":
        stmt = stmt.where(AnomalyScore.flagged_isolation.is_(True))
        count_stmt = count_stmt.where(AnomalyScore.flagged_isolation.is_(True))
    elif flagged == "baseline":
        stmt = stmt.where(AnomalyScore.flagged_baseline.is_(True))
        count_stmt = count_stmt.where(AnomalyScore.flagged_baseline.is_(True))
    elif flagged == "either":
        either = or_(
            AnomalyScore.flagged_isolation.is_(True),
            AnomalyScore.flagged_baseline.is_(True),
        )
        stmt = stmt.where(either)
        count_stmt = count_stmt.where(either)
    elif flagged is not None:
        raise ValueError("flagged must be isolation, baseline, or either")
    total = int(session.scalar(count_stmt) or 0)
    rows = list(
        session.scalars(
            stmt.order_by(AnomalyScore.window_start, AnomalyScore.source_id)
            .limit(limit)
            .offset(offset)
        ).all()
    )
    return rows, total, record
