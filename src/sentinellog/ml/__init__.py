"""ML scoring is deferred. Milestone 1 does not train or score models."""

from fastapi import APIRouter

router = APIRouter(prefix="/ml", tags=["ml"])


@router.get("/status")
def ml_status() -> dict[str, object]:
    return {
        "module": "ml",
        "implemented": False,
        "detail": "Model training and scoring are deferred.",
    }
