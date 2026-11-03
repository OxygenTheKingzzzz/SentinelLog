import asyncio
import json
import queue
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from sentinellog.api.deps import get_db
from sentinellog.live.hub import hub
from sentinellog.live.journald import journald_availability
from sentinellog.live.paths import PathRejected, allow_roots
from sentinellog.live.service import (
    CollectorNotFound,
    SourceNameTaken,
    authorize_file,
    collector_health,
    set_enabled,
)

router = APIRouter(prefix="/live", tags=["live"])


class AuthorizeFile(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    path: str = Field(min_length=1, max_length=1024)
    description: str | None = Field(default=None, max_length=2000)
    source_year: int | None = Field(default=None, ge=1970, le=2100)


@router.get("/status")
def live_status() -> dict[str, object]:
    available, detail = journald_availability()
    return {
        "module": "live",
        "implemented": True,
        "journald_available": available,
        "journald_detail": detail,
        "allow_roots": [str(path) for path in allow_roots()],
        "detail": (
            "Read-only tail of an explicitly authorized local file. "
            "The process does not run as root and does not pass log text to a shell. "
            "Journald collection is omitted when this VM has no readable journal."
        ),
    }


@router.get("/collectors")
def get_collectors(db: Session = Depends(get_db)) -> list[dict[str, object]]:
    return collector_health(db)


@router.post("/files", status_code=201)
def post_file(payload: AuthorizeFile, db: Session = Depends(get_db)) -> dict[str, object]:
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="name is required")
    try:
        collector = authorize_file(
            db,
            actor="api",
            name=name,
            path=payload.path,
            description=payload.description,
            source_year=payload.source_year,
        )
    except PathRejected as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    except SourceNameTaken:
        raise HTTPException(status_code=409, detail="source name already exists") from None
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="source name already exists") from None
    row = next(item for item in collector_health(db) if item["id"] == str(collector.id))
    return row


@router.post("/collectors/{collector_id}/start")
def start_collector(collector_id: UUID, db: Session = Depends(get_db)) -> dict[str, object]:
    try:
        set_enabled(db, collector_id, actor="api", enabled=True)
    except CollectorNotFound:
        raise HTTPException(status_code=404, detail="collector not found") from None
    row = next(item for item in collector_health(db) if item["id"] == str(collector_id))
    return row


@router.post("/collectors/{collector_id}/stop")
def stop_collector(collector_id: UUID, db: Session = Depends(get_db)) -> dict[str, object]:
    try:
        set_enabled(db, collector_id, actor="api", enabled=False)
    except CollectorNotFound:
        raise HTTPException(status_code=404, detail="collector not found") from None
    row = next(item for item in collector_health(db) if item["id"] == str(collector_id))
    return row


@router.get("/stream")
async def stream_live() -> StreamingResponse:
    async def events():
        subscriber = hub.subscribe()
        try:
            yield ": connected\n\n"
            while True:
                try:
                    item = await asyncio.to_thread(subscriber.get, True, 15)
                except queue.Empty:
                    yield ": keepalive\n\n"
                    continue
                yield f"data: {json.dumps(item)}\n\n"
        finally:
            hub.unsubscribe(subscriber)

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
