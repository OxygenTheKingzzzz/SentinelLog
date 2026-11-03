from uuid import UUID

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from sqlalchemy.orm import Session

from sentinellog.api.deps import get_db
from sentinellog.ingestion.validation import FileRejected, validate_filename
from sentinellog.risk.constants import NOT_EVALUATED
from sentinellog.risk.schemas import (
    LabelIn,
    LabelOut,
    ModelOut,
    PredictionPage,
    empty_page,
    label_out,
    model_out,
    prediction_out,
)
from sentinellog.risk.service import (
    EventNotFound,
    RiskError,
    SourceNotFound,
    apply_weak_labels,
    distribution,
    import_label_csv,
    list_models,
    list_predictions,
    published_experiments,
    realistic_experiments,
    set_label,
    train_bands,
    train_labeled,
)

router = APIRouter(prefix="/risk", tags=["risk"])


@router.get("/status")
def risk_status(db: Session = Depends(get_db)) -> dict[str, object]:
    published = published_experiments()
    return {
        "module": "risk",
        "linux_ground_truth": False,
        "metrics_note": NOT_EVALUATED,
        "detail": (
            "Four-level risk bands can be assigned without labels. "
            "Accuracy is reported only for a held-out test with verified labels."
        ),
        "experiments": published.get("experiments", []),
        "generated_at": published.get("generated_at"),
        "distribution": distribution(db, None),
    }


@router.get("/experiments")
def risk_experiments() -> dict[str, object]:
    return published_experiments()


@router.get("/realistic")
def risk_realistic() -> dict[str, object]:
    return realistic_experiments()


@router.get("/distribution")
def risk_distribution(
    source_id: UUID | None = None,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    return distribution(db, source_id)


@router.post("/labels", response_model=LabelOut)
def post_label(payload: LabelIn, db: Session = Depends(get_db)) -> LabelOut:
    try:
        row = set_label(
            db,
            log_event_id=payload.log_event_id,
            risk_level=payload.risk_level,
            provenance="verified_manual",
            actor="api",
            note=payload.note,
        )
    except EventNotFound:
        raise HTTPException(status_code=404, detail="event not found") from None
    except RiskError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    return label_out(row)


@router.post("/labels/import")
async def post_label_import(
    source_id: UUID,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
) -> dict[str, int]:
    try:
        validate_filename(file.filename, frozenset({".csv"}))
        data = await file.read()
        if len(data) > 8_000_000:
            raise FileRejected("label file is too large")
        return import_label_csv(db, source_id=source_id, data=data, actor="api")
    except (RiskError, FileRejected, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    except SourceNotFound:
        raise HTTPException(status_code=404, detail="source not found") from None


@router.post("/weak-labels")
def post_weak_labels(source_id: UUID, db: Session = Depends(get_db)) -> dict[str, int]:
    try:
        return apply_weak_labels(db, source_id=source_id, actor="api")
    except SourceNotFound:
        raise HTTPException(status_code=404, detail="source not found") from None


@router.post("/bands", response_model=ModelOut)
def post_bands(source_id: UUID, db: Session = Depends(get_db)) -> ModelOut:
    try:
        record = train_bands(db, source_id=source_id, actor="api")
    except SourceNotFound:
        raise HTTPException(status_code=404, detail="source not found") from None
    except RiskError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    return model_out(record)


@router.post("/train", response_model=list[ModelOut])
def post_train(
    source_id: UUID,
    label_provenance: str,
    db: Session = Depends(get_db),
) -> list[ModelOut]:
    try:
        records = train_labeled(
            db,
            source_id=source_id,
            provenance=label_provenance,
            actor="api",
        )
    except SourceNotFound:
        raise HTTPException(status_code=404, detail="source not found") from None
    except RiskError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    return [model_out(record) for record in records]


@router.get("/models", response_model=list[ModelOut])
def get_models(db: Session = Depends(get_db)) -> list[ModelOut]:
    return [model_out(record) for record in list_models(db)]


@router.get("/predictions", response_model=PredictionPage)
def get_predictions(
    source_id: UUID | None = None,
    model_id: UUID | None = None,
    limit: int = Query(default=100, ge=1, le=5000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> PredictionPage:
    rows, total, model = list_predictions(
        db,
        source_id=source_id,
        model_id=model_id,
        limit=limit,
        offset=offset,
    )
    if model is None:
        return empty_page(limit, offset)
    return PredictionPage(
        total=total,
        limit=limit,
        offset=offset,
        model_id=model.id,
        metrics_status=model.metrics_status,
        metrics_note=model.metrics_note,
        items=[
            prediction_out(prediction, event, label, model) for prediction, event, label in rows
        ],
    )
