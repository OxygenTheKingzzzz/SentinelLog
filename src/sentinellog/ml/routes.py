from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from sentinellog.api.deps import get_db
from sentinellog.ml.constants import NO_GROUND_TRUTH
from sentinellog.ml.schemas import (
    ModelOut,
    ModelSummary,
    ScorePage,
    ScoreRunOut,
    model_out,
    model_summary,
    score_out,
)
from sentinellog.ml.service import (
    ArtifactError,
    ModelNotFound,
    NotEnoughWindows,
    NoTimestampedEvents,
    SourceNotFound,
    get_model,
    latest_model,
    list_models,
    list_scores,
    score_source,
    train_model,
)

router = APIRouter(prefix="/ml", tags=["ml"])


@router.get("/status")
def ml_status() -> dict[str, object]:
    return {
        "module": "ml",
        "implemented": True,
        "ground_truth": False,
        "metrics": None,
        "metrics_note": NO_GROUND_TRUTH,
        "detail": (
            "Experimental anomaly detection: Isolation Forest and a robust-z baseline "
            "on stored log events. Findings are not security alerts and are not "
            "confirmed compromise."
        ),
    }


@router.post("/train", response_model=ModelOut)
def post_train(
    source_id: UUID | None = None,
    db: Session = Depends(get_db),
) -> ModelOut:
    try:
        record = train_model(db, source_id=source_id, actor="api")
    except SourceNotFound:
        raise HTTPException(status_code=404, detail="source not found") from None
    except (NoTimestampedEvents, NotEnoughWindows) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    return model_out(record)


@router.post("/score", response_model=ScoreRunOut)
def post_score(
    source_id: UUID,
    model_id: UUID | None = None,
    db: Session = Depends(get_db),
) -> ScoreRunOut:
    try:
        record, windows = score_source(db, source_id=source_id, model_id=model_id, actor="api")
    except SourceNotFound:
        raise HTTPException(status_code=404, detail="source not found") from None
    except ModelNotFound:
        raise HTTPException(status_code=404, detail="model not found") from None
    except NoTimestampedEvents as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    except ArtifactError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from None
    return ScoreRunOut(
        model_id=record.id,
        model_version=record.version,
        source_id=source_id,
        windows=windows,
    )


@router.get("/models", response_model=list[ModelSummary])
def get_models(db: Session = Depends(get_db)) -> list[ModelSummary]:
    return [model_summary(record) for record in list_models(db)]


@router.get("/models/latest", response_model=ModelOut)
def get_latest_model(db: Session = Depends(get_db)) -> ModelOut:
    try:
        record = latest_model(db)
    except ModelNotFound:
        raise HTTPException(status_code=404, detail="model not found") from None
    return model_out(record)


@router.get("/models/{model_id}", response_model=ModelOut)
def get_one_model(model_id: UUID, db: Session = Depends(get_db)) -> ModelOut:
    try:
        record = get_model(db, model_id)
    except ModelNotFound:
        raise HTTPException(status_code=404, detail="model not found") from None
    return model_out(record)


@router.get("/scores", response_model=ScorePage)
def get_scores(
    source_id: UUID | None = None,
    model_id: UUID | None = None,
    flagged: str | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> ScorePage:
    try:
        rows, total, record = list_scores(
            db,
            source_id=source_id,
            model_id=model_id,
            flagged=flagged,
            limit=limit,
            offset=offset,
        )
    except ModelNotFound:
        raise HTTPException(status_code=404, detail="model not found") from None
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    version = record.version if record is not None else None
    return ScorePage(
        total=total,
        limit=limit,
        offset=offset,
        model_id=record.id if record is not None else None,
        model_version=version,
        items=[score_out(row, record.version) for row in rows] if record is not None else [],
    )
