from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from sentinellog.api.deps import get_db
from sentinellog.investigations.service import (
    InvestigationNotFound,
    LinkedRecordMissing,
    add_links,
    add_note,
    correlation_graph,
    create_investigation,
    evidence_bundle,
    investigation_detail,
    list_investigations,
    set_status,
)

router = APIRouter(prefix="/investigations", tags=["investigations"])


class InvestigationCreate(BaseModel):
    title: str = Field(min_length=1, max_length=300)
    summary: str | None = Field(default=None, max_length=4000)
    alert_ids: list[UUID] = Field(default_factory=list)
    event_ids: list[UUID] = Field(default_factory=list)
    note: str | None = Field(default=None, max_length=4000)
    actor: str = Field(default="dashboard", min_length=1, max_length=200)


class InvestigationLinks(BaseModel):
    alert_ids: list[UUID] = Field(default_factory=list)
    event_ids: list[UUID] = Field(default_factory=list)
    actor: str = Field(default="dashboard", min_length=1, max_length=200)


class InvestigationStatusBody(BaseModel):
    status: str
    note: str = Field(min_length=1, max_length=4000)
    actor: str = Field(default="dashboard", min_length=1, max_length=200)


class InvestigationNoteBody(BaseModel):
    body: str = Field(min_length=1, max_length=4000)
    actor: str = Field(default="dashboard", min_length=1, max_length=200)


def _missing(exc: LinkedRecordMissing) -> HTTPException:
    return HTTPException(status_code=400, detail=str(exc))


@router.get("")
def get_investigations(db: Session = Depends(get_db)) -> list[dict[str, object]]:
    return list_investigations(db)


@router.post("", status_code=201)
def post_investigation(
    payload: InvestigationCreate,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    title = payload.title.strip()
    if not title:
        raise HTTPException(status_code=400, detail="title is required")
    try:
        row = create_investigation(
            db,
            actor=payload.actor.strip(),
            title=title,
            summary=payload.summary,
            alert_ids=payload.alert_ids,
            event_ids=payload.event_ids,
            note=payload.note,
        )
    except LinkedRecordMissing as exc:
        raise _missing(exc) from None
    return investigation_detail(db, row.id)


@router.get("/{investigation_id}")
def get_investigation(
    investigation_id: UUID,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    try:
        return investigation_detail(db, investigation_id)
    except InvestigationNotFound:
        raise HTTPException(status_code=404, detail="investigation not found") from None


@router.post("/{investigation_id}/links")
def post_links(
    investigation_id: UUID,
    payload: InvestigationLinks,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    try:
        add_links(
            db,
            investigation_id,
            actor=payload.actor.strip(),
            alert_ids=payload.alert_ids,
            event_ids=payload.event_ids,
        )
        return investigation_detail(db, investigation_id)
    except InvestigationNotFound:
        raise HTTPException(status_code=404, detail="investigation not found") from None
    except LinkedRecordMissing as exc:
        raise _missing(exc) from None


@router.patch("/{investigation_id}/status")
def patch_status(
    investigation_id: UUID,
    payload: InvestigationStatusBody,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    try:
        set_status(
            db,
            investigation_id,
            actor=payload.actor.strip(),
            status=payload.status,
            note=payload.note,
        )
        return investigation_detail(db, investigation_id)
    except InvestigationNotFound:
        raise HTTPException(status_code=404, detail="investigation not found") from None
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None


@router.post("/{investigation_id}/notes", status_code=201)
def post_note(
    investigation_id: UUID,
    payload: InvestigationNoteBody,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    try:
        add_note(db, investigation_id, actor=payload.actor.strip(), body=payload.body)
        return investigation_detail(db, investigation_id)
    except InvestigationNotFound:
        raise HTTPException(status_code=404, detail="investigation not found") from None
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None


@router.get("/{investigation_id}/graph")
def get_graph(investigation_id: UUID, db: Session = Depends(get_db)) -> dict[str, object]:
    try:
        return correlation_graph(db, investigation_id)
    except InvestigationNotFound:
        raise HTTPException(status_code=404, detail="investigation not found") from None


@router.get("/{investigation_id}/evidence")
def get_evidence(investigation_id: UUID, db: Session = Depends(get_db)) -> dict[str, object]:
    try:
        return evidence_bundle(db, investigation_id)
    except InvestigationNotFound:
        raise HTTPException(status_code=404, detail="investigation not found") from None
