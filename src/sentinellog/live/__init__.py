"""Live collection is deferred. Milestone 1 imports historical files only."""

from fastapi import APIRouter

router = APIRouter(prefix="/live", tags=["live"])


@router.get("/status")
def live_status() -> dict[str, object]:
    return {
        "module": "live",
        "implemented": False,
        "detail": (
            "Live log collection is deferred. Ingestion is file upload and the bundled dataset."
        ),
    }
