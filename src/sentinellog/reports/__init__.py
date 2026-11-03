"""Investigation reports are served from /api/v1/investigations. Incidents stay out."""

from fastapi import APIRouter

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/status")
def reports_status() -> dict[str, object]:
    return {
        "module": "reports",
        "implemented": True,
        "detail": (
            "An investigation exports JSON at /api/v1/investigations/{id}/evidence "
            "and a PDF at /api/v1/investigations/{id}/report.pdf. "
            "Both label observations, automated hypotheses, and analyst-confirmed findings. "
            "Hypotheses are not a confirmed compromise."
        ),
    }
