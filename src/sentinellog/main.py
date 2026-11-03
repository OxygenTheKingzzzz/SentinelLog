from fastapi import FastAPI
from fastapi.responses import JSONResponse

from sentinellog import __version__
from sentinellog.api.routes import root_router
from sentinellog.api.routes import router as api_router
from sentinellog.config import get_settings
from sentinellog.detection import router as detection_router
from sentinellog.incidents import router as incidents_router
from sentinellog.ingestion.validation import FileRejected
from sentinellog.jsonlog import configure_logging
from sentinellog.live import router as live_router
from sentinellog.ml import router as ml_router
from sentinellog.reports import router as reports_router


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level)
    app = FastAPI(
        title="SentinelLog",
        version=__version__,
        summary="Milestone 1: Linux syslog ingestion, storage, and search.",
    )
    app.include_router(root_router)
    app.include_router(api_router)
    app.include_router(detection_router, prefix="/api/v1")
    app.include_router(ml_router, prefix="/api/v1")
    app.include_router(incidents_router, prefix="/api/v1")
    app.include_router(reports_router, prefix="/api/v1")
    app.include_router(live_router, prefix="/api/v1")

    @app.exception_handler(FileRejected)
    async def file_rejected(_request, exc: FileRejected) -> JSONResponse:
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    return app


app = create_app()
