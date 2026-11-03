"""Incident confirmation stays out of this build. Analyst workspaces are /investigations."""

from fastapi import APIRouter

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.get("/status")
def incidents_status() -> dict[str, object]:
    return {
        "module": "incidents",
        "implemented": False,
        "detail": (
            "Confirmed-incident workflow is not in this build. Analyst workspaces "
            "that group stored alerts and events are at /api/v1/investigations. "
            "PDF export is not included."
        ),
    }
