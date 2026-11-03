"""Investigations are deferred. The investigations tables are intentionally empty."""

from fastapi import APIRouter

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.get("/status")
def incidents_status() -> dict[str, object]:
    return {
        "module": "incidents",
        "implemented": False,
        "detail": "Investigation workflow is deferred. No incidents are created from logs.",
    }
