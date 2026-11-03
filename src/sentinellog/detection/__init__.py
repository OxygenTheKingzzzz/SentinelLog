"""Detection is deferred. The detection_rules table is intentionally unused in milestone 1."""

from fastapi import APIRouter

router = APIRouter(prefix="/detection", tags=["detection"])


@router.get("/status")
def detection_status() -> dict[str, object]:
    return {
        "module": "detection",
        "implemented": False,
        "detail": "Rule evaluation is deferred. detection_rules exists and is not seeded.",
    }
