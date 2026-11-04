import os
import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from sentinellog import __version__
from sentinellog.api.routes import root_router
from sentinellog.api.routes import router as api_router
from sentinellog.config import get_settings
from sentinellog.detection import alerts_router, detection_router, rules_router
from sentinellog.incidents import router as incidents_router
from sentinellog.ingestion.validation import FileRejected
from sentinellog.investigations import router as investigations_router
from sentinellog.jsonlog import configure_logging
from sentinellog.live import router as live_router
from sentinellog.live.supervisor import supervisor_loop
from sentinellog.ml import router as ml_router
from sentinellog.ratelimit import WindowLimiter, bucket_for
from sentinellog.reports import router as reports_router
from sentinellog.risk import router as risk_router
from sentinellog.security import SecurityMiddleware


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        stop = threading.Event()
        thread: threading.Thread | None = None
        if os.environ.get("SENTINELLOG_LIVE_SUPERVISOR", "1") != "0":
            thread = threading.Thread(
                target=supervisor_loop,
                args=(stop,),
                name="live-supervisor",
                daemon=True,
            )
            thread.start()
        yield
        stop.set()
        if thread is not None:
            thread.join(timeout=2)

    app = FastAPI(
        title="SentinelLog",
        version=__version__,
        debug=settings.debug,
        summary="Risk classification, labeled evaluation, and the existing log workspace.",
        lifespan=lifespan,
    )
    limiter = WindowLimiter()

    @app.middleware("http")
    async def limit_expensive(request, call_next):
        bucket = bucket_for(request.method, request.url.path)
        if bucket is not None:
            current = get_settings()
            host = request.client.host if request.client else "unknown"
            allowed = limiter.allow(
                host,
                bucket,
                current.rate_limit_requests,
                current.rate_limit_window_seconds,
            )
            if not allowed:
                return JSONResponse(
                    status_code=429,
                    content={"detail": "rate limit exceeded"},
                    headers={"Retry-After": str(current.rate_limit_window_seconds)},
                )
        return await call_next(request)

    app.add_middleware(SecurityMiddleware, token=settings.api_admin_token,
                       max_bytes=settings.request_limit_bytes)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.origin_list(),
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(root_router)
    app.include_router(api_router)
    app.include_router(detection_router, prefix="/api/v1")
    app.include_router(rules_router, prefix="/api/v1")
    app.include_router(alerts_router, prefix="/api/v1")
    app.include_router(ml_router, prefix="/api/v1")
    app.include_router(risk_router, prefix="/api/v1")
    app.include_router(investigations_router, prefix="/api/v1")
    app.include_router(incidents_router, prefix="/api/v1")
    app.include_router(reports_router, prefix="/api/v1")
    app.include_router(live_router, prefix="/api/v1")

    @app.exception_handler(FileRejected)
    async def file_rejected(_request, exc: FileRejected) -> JSONResponse:
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    if not settings.debug:

        @app.exception_handler(Exception)
        async def unhandled(_request, _exc: Exception) -> JSONResponse:
            return JSONResponse(status_code=500, content={"detail": "internal server error"})

    return app


app = create_app()
