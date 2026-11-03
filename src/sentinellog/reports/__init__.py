"""Reporting is deferred. Milestone 1 does not render a dashboard or a report."""

from fastapi import APIRouter

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/status")
def reports_status() -> dict[str, object]:
    return {
        "module": "reports",
        "implemented": False,
        "detail": "Dashboards and reports are deferred.",
    }
