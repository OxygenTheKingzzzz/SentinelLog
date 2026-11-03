"""Store risk labels, unsupervised bands, and verified-label evaluations.

Weak rule labels never occupy the metrics column. Linux_2k bands stay unlabeled.
"""

import csv
import hashlib
import io
from pathlib import Path
from uuid import UUID

import joblib
import sklearn
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from sentinellog.config import get_settings
from sentinellog.ml.service import repo_root
from sentinellog.models import (
    AuditLog,
    LogEvent,
    LogSource,
    RiskLabel,
    RiskModel,
    RiskPrediction,
    SecurityAlert,
)
from sentinellog.risk.compare import ModelRun, compare_models, fit_linux_bands
from sentinellog.risk.constants import (
    NOT_EVALUATED,
    RANDOM_SEED,
    RISK_LEVELS,
    RISK_RANK,
    SEVERITY_TO_RISK,
    VERIFIED_PROVENANCE,
    WEAK_PROVENANCE,
)
from sentinellog.risk.experiments import linux_experiment
from sentinellog.risk.records import Example
from sentinellog.risk.textnorm import group_key, keyword_severity

_PUBLISHED = Path(__file__).resolve().parent / "published_results.json"
_REALISTIC = Path(__file__).resolve().parent / "realistic_results.json"


class RiskError(Exception):
    pass


class SourceNotFound(RiskError):
    pass


class EventNotFound(RiskError):
    pass


def artifact_root() -> Path:
    configured = Path(get_settings().risk_artifact_dir)
    if configured.is_absolute():
        return configured
    return repo_root() / configured


def published_experiments() -> dict[str, object]:
    if not _PUBLISHED.is_file():
        return {"generated_at": None, "generator": None, "experiments": [linux_experiment()]}
    import json

    return json.loads(_PUBLISHED.read_text(encoding="utf-8"))


def realistic_experiments() -> dict[str, object]:
    if not _REALISTIC.is_file():
        return {
            "generated_at": None,
            "generator": None,
            "experiments": [],
            "detail": "Realistic prevalence results have not been generated.",
        }
    import json

    return json.loads(_REALISTIC.read_text(encoding="utf-8"))


def _audit(session: Session, *, actor: str, action: str, entity_id: str, details: dict) -> None:
    session.add(
        AuditLog(
            actor=actor,
            action=action,
            entity_type="risk",
            entity_id=entity_id,
            details=details,
        )
    )


def _source(session: Session, source_id: UUID) -> LogSource:
    source = session.get(LogSource, source_id)
    if source is None:
        raise SourceNotFound(str(source_id))
    return source


def _event_example(event: LogEvent, label: str | None) -> Example:
    template = event.event_template or event.content
    return Example(
        key=str(event.id),
        content=event.content,
        group_key=group_key(template),
        timestamp=event.event_timestamp,
        component=event.component,
        pid=event.pid,
        severity_rank=keyword_severity(event.content),
        label=label,
    )


def _events(session: Session, source_id: UUID) -> list[LogEvent]:
    return list(
        session.scalars(
            select(LogEvent).where(LogEvent.source_id == source_id).order_by(LogEvent.line_number)
        ).all()
    )


def set_label(
    session: Session,
    *,
    log_event_id: UUID,
    risk_level: str,
    provenance: str,
    actor: str,
    note: str | None,
    rule_id: UUID | None = None,
) -> RiskLabel:
    if risk_level not in RISK_LEVELS:
        raise RiskError("risk_level must be LOW, MEDIUM, HIGH, or CRITICAL")
    if provenance not in {"verified_manual", "verified_import", "weak_rule"}:
        raise RiskError("unsupported label provenance")
    event = session.get(LogEvent, log_event_id)
    if event is None:
        raise EventNotFound(str(log_event_id))
    existing = session.scalar(
        select(RiskLabel).where(
            RiskLabel.log_event_id == log_event_id,
            RiskLabel.provenance == provenance,
        )
    )
    if existing is None:
        existing = RiskLabel(
            log_event_id=log_event_id,
            risk_level=risk_level,
            provenance=provenance,
            reviewer=actor,
            note=note,
            rule_id=rule_id,
        )
        session.add(existing)
    else:
        existing.risk_level = risk_level
        existing.reviewer = actor
        existing.note = note
        existing.rule_id = rule_id
    _audit(
        session,
        actor=actor,
        action="risk_label.upsert",
        entity_id=str(log_event_id),
        details={"risk_level": risk_level, "provenance": provenance},
    )
    session.commit()
    return existing


def import_label_csv(
    session: Session,
    *,
    source_id: UUID,
    data: bytes,
    actor: str,
) -> dict[str, int]:
    _source(session, source_id)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RiskError("label file is not valid UTF-8") from exc
    reader = csv.DictReader(io.StringIO(text))
    if reader.fieldnames is None or "risk_level" not in reader.fieldnames:
        raise RiskError("label file needs a risk_level column")
    if "line_number" not in reader.fieldnames and "log_event_id" not in reader.fieldnames:
        raise RiskError("label file needs line_number or log_event_id")
    by_line = {event.line_number: event.id for event in _events(session, source_id)}
    written = 0
    for row in reader:
        level = (row.get("risk_level") or "").strip().upper()
        if level not in RISK_LEVELS:
            raise RiskError(f"unknown risk_level {level}")
        if row.get("log_event_id"):
            event_id = UUID(row["log_event_id"].strip())
            if event_id not in set(by_line.values()):
                raise RiskError("log_event_id is not in this source")
        else:
            line_number = int(row["line_number"])
            if line_number not in by_line:
                raise RiskError(f"line {line_number} is not in this source")
            event_id = by_line[line_number]
        set_label(
            session,
            log_event_id=event_id,
            risk_level=level,
            provenance="verified_import",
            actor=actor,
            note=(row.get("note") or "").strip() or None,
        )
        written += 1
    return {"labels": written}


def apply_weak_labels(session: Session, *, source_id: UUID, actor: str) -> dict[str, int]:
    """Copy alert severity onto events. These rows are weak labels, not ground truth."""
    _source(session, source_id)
    alerts = session.scalars(
        select(SecurityAlert).where(SecurityAlert.source_id == source_id)
    ).all()
    best: dict[UUID, tuple[int, str, UUID]] = {}
    for alert in alerts:
        level = SEVERITY_TO_RISK[alert.severity]
        rank = RISK_RANK[level]
        for raw_id in alert.event_ids:
            event_id = UUID(str(raw_id))
            current = best.get(event_id)
            if current is None or rank > current[0]:
                best[event_id] = (rank, level, alert.rule_id)
    for event_id, (_rank, level, rule_id) in best.items():
        set_label(
            session,
            log_event_id=event_id,
            risk_level=level,
            provenance=WEAK_PROVENANCE,
            actor=actor,
            note="Weak label copied from rule alert severity. Not verified ground truth.",
            rule_id=rule_id,
        )
    return {"weak_labels": len(best)}


def _labels_for(session: Session, source_id: UUID, provenance: str) -> dict[UUID, str]:
    rows = session.execute(
        select(RiskLabel.log_event_id, RiskLabel.risk_level)
        .join(LogEvent, LogEvent.id == RiskLabel.log_event_id)
        .where(LogEvent.source_id == source_id, RiskLabel.provenance == provenance)
    ).all()
    return {event_id: level for event_id, level in rows}


def train_bands(session: Session, *, source_id: UUID, actor: str) -> RiskModel:
    source = _source(session, source_id)
    events = _events(session, source_id)
    if len(events) < 8:
        raise RiskError("need at least 8 stored events to fit score bands")
    examples = [_event_example(event, None) for event in events]
    run = fit_linux_bands(examples, RANDOM_SEED)
    return _persist(
        session,
        run,
        source=source,
        provenance="none",
        actor=actor,
        weak_metrics=None,
    )


def train_labeled(
    session: Session,
    *,
    source_id: UUID,
    provenance: str,
    actor: str,
) -> list[RiskModel]:
    if provenance not in VERIFIED_PROVENANCE | {WEAK_PROVENANCE}:
        raise RiskError("label_provenance must be verified_manual, verified_import, or weak_rule")
    if provenance == "dataset_native":
        raise RiskError("dataset evaluations are loaded from published result files")
    source = _source(session, source_id)
    labels = _labels_for(session, source_id, provenance)
    if len(labels) < 8:
        raise RiskError(NOT_EVALUATED)
    events = {event.id: event for event in _events(session, source_id)}
    examples = [
        _event_example(events[event_id], label)
        for event_id, label in labels.items()
        if event_id in events
    ]
    runs = compare_models(examples, task="multiclass_risk", seed=RANDOM_SEED)
    stored: list[RiskModel] = []
    for run in runs:
        weak_metrics = run.metrics if provenance == WEAK_PROVENANCE else None
        stored.append(
            _persist(
                session,
                run,
                source=source,
                provenance=provenance,
                actor=actor,
                weak_metrics=weak_metrics,
            )
        )
    return stored


def _persist(
    session: Session,
    run: ModelRun,
    *,
    source: LogSource,
    provenance: str,
    actor: str,
    weak_metrics: dict | None,
) -> RiskModel:
    version = (session.scalar(select(func.max(RiskModel.version))) or 0) + 1
    directory = artifact_root()
    directory.mkdir(parents=True, exist_ok=True)
    artifact = directory / f"risk-{version}.joblib"
    joblib.dump(run.bundle or {"refused": run.detail}, artifact)
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    weak = provenance == WEAK_PROVENANCE
    if weak:
        status = "weak_agreement_only"
        note = NOT_EVALUATED
        metrics = None
    elif run.metrics_status == "evaluated":
        status = "evaluated"
        note = "Held-out test on verified labels. Cross-validation is not this score."
        metrics = run.metrics
    else:
        status = "not_evaluated"
        note = run.metrics_note or NOT_EVALUATED
        metrics = None
    record = RiskModel(
        version=version,
        algorithm=run.algorithm,
        task=run.task,
        dataset_name=source.name,
        dataset_version=str(source.id),
        label_provenance=provenance,
        random_seed=RANDOM_SEED,
        n_train=run.n_train,
        n_test=run.n_test,
        metrics=metrics,
        metrics_status=status,
        metrics_note=note,
        config={
            "cv": run.cv,
            "detail": run.detail,
            "fit_protocol": run.fit_protocol,
            "real_world": status == "evaluated",
            "weak_label_agreement": weak_metrics,
            "sklearn_version": sklearn.__version__,
        },
        artifact_path=str(artifact),
        artifact_sha256=digest,
        sklearn_version=sklearn.__version__,
    )
    session.add(record)
    session.flush()
    for item in run.predictions:
        session.add(
            RiskPrediction(
                model_id=record.id,
                log_event_id=UUID(item.example.key),
                source_id=source.id,
                split_role=item.split_role,
                predicted_risk=item.predicted_risk,
                class_confidence=item.class_confidence,
                anomaly_score=item.anomaly_score,
                score_kind=item.score_kind,
                explanation=item.explanation,
            )
        )
    _audit(
        session,
        actor=actor,
        action="risk_model.train",
        entity_id=str(record.id),
        details={
            "algorithm": run.algorithm,
            "metrics_status": status,
            "label_provenance": provenance,
            "n_train": run.n_train,
            "n_test": run.n_test,
        },
    )
    session.commit()
    return record


def latest_model(session: Session, source_id: UUID | None) -> RiskModel | None:
    query = select(RiskModel).order_by(RiskModel.version.desc())
    if source_id is not None:
        query = query.where(RiskModel.dataset_version == str(source_id))
    return session.scalars(query).first()


def list_models(session: Session) -> list[RiskModel]:
    return list(session.scalars(select(RiskModel).order_by(RiskModel.version.desc())).all())


def list_predictions(
    session: Session,
    *,
    source_id: UUID | None,
    model_id: UUID | None,
    limit: int,
    offset: int,
) -> tuple[list[tuple[RiskPrediction, LogEvent, RiskLabel | None]], int, RiskModel | None]:
    model = (
        session.get(RiskModel, model_id)
        if model_id is not None
        else latest_model(session, source_id)
    )
    if model is None:
        return [], 0, None
    filters = [RiskPrediction.model_id == model.id]
    if source_id is not None:
        filters.append(RiskPrediction.source_id == source_id)
    total = session.scalar(select(func.count()).select_from(RiskPrediction).where(*filters)) or 0
    rows = session.execute(
        select(RiskPrediction, LogEvent)
        .join(LogEvent, LogEvent.id == RiskPrediction.log_event_id)
        .where(*filters)
        .order_by(RiskPrediction.anomaly_score.desc().nulls_last(), LogEvent.line_number)
        .limit(limit)
        .offset(offset)
    ).all()
    event_ids = [event.id for _prediction, event in rows]
    labels = {}
    if event_ids:
        for label in session.scalars(
            select(RiskLabel).where(RiskLabel.log_event_id.in_(event_ids))
        ).all():
            current = labels.get(label.log_event_id)
            if current is None or _provenance_rank(label.provenance) > _provenance_rank(
                current.provenance
            ):
                labels[label.log_event_id] = label
    paired = [(prediction, event, labels.get(event.id)) for prediction, event in rows]
    return paired, int(total), model


def _provenance_rank(provenance: str) -> int:
    if provenance in {"verified_manual", "verified_import"}:
        return 2
    if provenance == WEAK_PROVENANCE:
        return 1
    return 0


def distribution(session: Session, source_id: UUID | None) -> dict[str, object]:
    model = latest_model(session, source_id)
    if model is None:
        return {"model_id": None, "counts": []}
    filters = [RiskPrediction.model_id == model.id]
    if source_id is not None:
        filters.append(RiskPrediction.source_id == source_id)
    rows = session.execute(
        select(RiskPrediction.predicted_risk, func.count())
        .where(*filters)
        .group_by(RiskPrediction.predicted_risk)
    ).all()
    counts = {risk: count for risk, count in rows}
    return {
        "model_id": str(model.id),
        "model_version": model.version,
        "algorithm": model.algorithm,
        "metrics_status": model.metrics_status,
        "metrics_note": model.metrics_note,
        "counts": [
            {"risk": risk, "count": counts.get(risk, 0)}
            for risk in RISK_LEVELS
            if risk in counts
        ],
    }
