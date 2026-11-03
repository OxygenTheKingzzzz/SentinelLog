from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from sqlalchemy import func, select
from sqlalchemy.engine.url import make_url
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from sentinellog import __version__
from sentinellog.api.deps import get_db
from sentinellog.api.overview import overview
from sentinellog.api.schemas import (
    ErrorOut,
    EventOut,
    EventPage,
    JobOut,
    SourceCreate,
    SourceOut,
    TemplateOut,
    event_out,
    source_out,
)
from sentinellog.config import get_settings
from sentinellog.ingestion.service import (
    FileRejected,
    SourceNotFound,
    create_source,
    import_raw_log,
    import_structured_csv,
    import_template_csv,
)
from sentinellog.ingestion.validation import CSV_SUFFIXES, RAW_SUFFIXES, validate_filename
from sentinellog.models import (
    AuditLog,
    EventTemplate,
    IngestionError,
    IngestionJob,
    LogEvent,
    LogSource,
)
from sentinellog.normalization.storage import event_facets, quality_report, search_events

router = APIRouter(prefix="/api/v1")
root_router = APIRouter()


async def _read_upload(upload: UploadFile, *, allowed: frozenset[str]) -> tuple[str, bytes]:
    filename = validate_filename(upload.filename, allowed)
    limit = get_settings().max_upload_bytes
    chunks: list[bytes] = []
    size = 0
    while True:
        chunk = await upload.read(1024 * 1024)
        if not chunk:
            break
        size += len(chunk)
        if size > limit:
            raise FileRejected(f"file exceeds limit of {limit} bytes")
        chunks.append(chunk)
    return filename, b"".join(chunks)


def _job_or_404(session: Session, job_id: UUID) -> IngestionJob:
    job = session.get(IngestionJob, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="ingestion job not found")
    return job


@root_router.get("/health")
@router.get("/health")
def health(db: Session = Depends(get_db)) -> dict[str, str]:
    db.execute(select(1))
    return {"status": "ok"}


@router.post("/sources", response_model=SourceOut, status_code=201)
def post_source(payload: SourceCreate, db: Session = Depends(get_db)) -> SourceOut:
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="name is required")
    if "source_year" in payload.model_fields_set:
        year = payload.source_year
    else:
        year = get_settings().source_year
    try:
        source = create_source(db, name=name, description=payload.description, source_year=year)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="source name already exists") from None
    return source_out(source)


@router.get("/sources", response_model=list[SourceOut])
def list_sources(db: Session = Depends(get_db)) -> list[SourceOut]:
    rows = db.scalars(select(LogSource).order_by(LogSource.name)).all()
    return [source_out(row) for row in rows]


@router.get("/sources/{source_id}", response_model=SourceOut)
def get_source(source_id: UUID, db: Session = Depends(get_db)) -> SourceOut:
    source = db.get(LogSource, source_id)
    if source is None:
        raise HTTPException(status_code=404, detail="source not found")
    return source_out(source)


@router.post("/sources/{source_id}/ingest/raw", response_model=JobOut)
async def ingest_raw(
    source_id: UUID,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
) -> JobOut:
    filename, data = await _read_upload(file, allowed=RAW_SUFFIXES)
    try:
        job = import_raw_log(db, source_id=source_id, filename=filename, data=data, actor="api")
    except SourceNotFound:
        raise HTTPException(status_code=404, detail="source not found") from None
    return JobOut.model_validate(job)


@router.post("/sources/{source_id}/ingest/templates", response_model=JobOut)
async def ingest_templates(
    source_id: UUID,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
) -> JobOut:
    filename, data = await _read_upload(file, allowed=CSV_SUFFIXES)
    try:
        job = import_template_csv(
            db, source_id=source_id, filename=filename, data=data, actor="api"
        )
    except SourceNotFound:
        raise HTTPException(status_code=404, detail="source not found") from None
    return JobOut.model_validate(job)


@router.post("/sources/{source_id}/ingest/structured", response_model=JobOut)
async def ingest_structured(
    source_id: UUID,
    file: UploadFile = File(...),
    mode: str = Query(default="validate"),
    db: Session = Depends(get_db),
) -> JobOut:
    filename, data = await _read_upload(file, allowed=CSV_SUFFIXES)
    try:
        job = import_structured_csv(
            db,
            source_id=source_id,
            filename=filename,
            data=data,
            actor="api",
            mode=mode,
        )
    except SourceNotFound:
        raise HTTPException(status_code=404, detail="source not found") from None
    return JobOut.model_validate(job)


@router.get("/jobs/{job_id}", response_model=JobOut)
def get_job(job_id: UUID, db: Session = Depends(get_db)) -> JobOut:
    return JobOut.model_validate(_job_or_404(db, job_id))


@router.get("/jobs", response_model=list[JobOut])
def list_jobs(
    source_id: UUID | None = None,
    db: Session = Depends(get_db),
) -> list[JobOut]:
    stmt = select(IngestionJob).order_by(IngestionJob.created_at)
    if source_id is not None:
        stmt = stmt.where(IngestionJob.source_id == source_id)
    return [JobOut.model_validate(job) for job in db.scalars(stmt).all()]


@router.get("/jobs/{job_id}/errors", response_model=list[ErrorOut])
def job_errors(
    job_id: UUID,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> list[ErrorOut]:
    _job_or_404(db, job_id)
    rows = db.scalars(
        select(IngestionError)
        .where(IngestionError.job_id == job_id)
        .order_by(IngestionError.line_number)
        .limit(limit)
        .offset(offset)
    ).all()
    return [
        ErrorOut(
            line_number=row.line_number,
            error_kind=row.error_kind,
            message=row.message,
            raw_line=row.raw_line,
        )
        for row in rows
    ]


@router.get("/events", response_model=EventPage)
def list_events(
    source_id: UUID | None = None,
    component: str | None = None,
    event_id: str | None = None,
    hostname: str | None = None,
    q: str | None = Query(default=None, max_length=500),
    month: str | None = None,
    day: int | None = Query(default=None, ge=1, le=31),
    occurred_from: datetime | None = None,
    occurred_to: datetime | None = None,
    line_number: int | None = Query(default=None, ge=1),
    limit: int = Query(default=50, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> EventPage:
    rows, total = search_events(
        db,
        source_id=source_id,
        component=component,
        event_id=event_id,
        hostname=hostname,
        q=q,
        month=month,
        day=day,
        occurred_from=occurred_from,
        occurred_to=occurred_to,
        line_number=line_number,
        limit=limit,
        offset=offset,
    )
    return EventPage(
        total=total,
        limit=limit,
        offset=offset,
        items=[event_out(row) for row in rows],
    )


@router.get("/events/facets")
def get_event_facets(
    source_id: UUID | None = None,
    component: str | None = None,
    event_id: str | None = None,
    hostname: str | None = None,
    q: str | None = Query(default=None, max_length=500),
    month: str | None = None,
    day: int | None = Query(default=None, ge=1, le=31),
    occurred_from: datetime | None = None,
    occurred_to: datetime | None = None,
    line_number: int | None = Query(default=None, ge=1),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    return event_facets(
        db,
        source_id=source_id,
        component=component,
        event_id=event_id,
        hostname=hostname,
        q=q,
        month=month,
        day=day,
        occurred_from=occurred_from,
        occurred_to=occurred_to,
        line_number=line_number,
    )


@router.get("/overview")
def get_overview(
    source_id: UUID | None = None,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    body = overview(db, source_id)
    if body is None:
        raise HTTPException(status_code=404, detail="source not found")
    return body


@router.get("/audit")
def list_audit(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    total = int(db.scalar(select(func.count()).select_from(AuditLog)) or 0)
    rows = db.scalars(
        select(AuditLog)
        .order_by(AuditLog.created_at.desc(), AuditLog.id)
        .limit(limit)
        .offset(offset)
    ).all()
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": [
            {
                "id": str(row.id),
                "actor": row.actor,
                "action": row.action,
                "entity_type": row.entity_type,
                "entity_id": row.entity_id,
                "details": row.details,
                "created_at": row.created_at,
            }
            for row in rows
        ],
    }


@router.get("/settings")
def public_settings(db: Session = Depends(get_db)) -> dict[str, object]:
    db.execute(select(1))
    settings = get_settings()
    url = make_url(settings.database_url)
    return {
        "version": __version__,
        "log_level": settings.log_level,
        "max_upload_bytes": settings.max_upload_bytes,
        "source_year": settings.source_year,
        "anomaly_artifact_dir": settings.anomaly_artifact_dir,
        "live_collection": False,
        "pdf_export": False,
        "database": {
            "driver": url.drivername,
            "host": url.host,
            "port": url.port,
            "name": url.database,
        },
    }


@router.get("/events/{event_id}", response_model=EventOut)
def get_event(event_id: UUID, db: Session = Depends(get_db)) -> EventOut:
    event = db.get(LogEvent, event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="event not found")
    return event_out(event)


@router.get("/sources/{source_id}/quality")
def get_quality(source_id: UUID, db: Session = Depends(get_db)) -> dict[str, object]:
    report = quality_report(db, source_id)
    if report is None:
        raise HTTPException(status_code=404, detail="source not found")
    return report


@router.get("/templates", response_model=list[TemplateOut])
def list_templates(
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> list[TemplateOut]:
    rows = db.scalars(
        select(EventTemplate)
        .order_by(func.length(EventTemplate.event_id), EventTemplate.event_id)
        .limit(limit)
        .offset(offset)
    ).all()
    return [TemplateOut(event_id=row.event_id, template=row.template) for row in rows]
