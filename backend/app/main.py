"""FastAPI application factory for APKGuard Industrial v3 Phase 2."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from time import perf_counter

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.router import router as v1_router
from app.core.config import get_settings
from app.core.context import normalize_request_id, reset_request_id, set_request_id
from app.core.errors import register_exception_handlers
from app.core.logging import configure_logging
from app.db.session import get_database

settings = get_settings()
configure_logging(settings.log_level, settings.log_format)
log = logging.getLogger("apkguard.application")


@asynccontextmanager
async def lifespan(_: FastAPI):
    database = get_database()
    database.initialize()
    log.info(
        "Starting %s version=%s environment=%s privacy_mode=%s database=%s queue=%s",
        settings.app_name,
        settings.app_version,
        settings.environment,
        settings.privacy_mode,
        settings.database_url.split(":", 1)[0],
        settings.queue_backend,
    )
    yield
    database.dispose()
    log.info("Stopping %s", settings.app_name)


def create_app() -> FastAPI:
    application = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description=(
            "Evidence-driven Android APK triage API. Phase 2 adds persistent scan jobs, "
            "content-addressed quarantine, immutable results, real progress, cancellation, "
            "timeouts, retries, stale-job recovery, PostgreSQL and Redis deployment adapters."
        ),
        lifespan=lifespan,
        openapi_tags=[
            {"name": "System", "description": "Health and capability metadata."},
            {"name": "Scan Jobs", "description": "Persistent asynchronous APK scan jobs."},
            {"name": "Scans", "description": "Synchronous compatibility analysis endpoint."},
            {"name": "History", "description": "Database-backed scan summaries."},
            {"name": "Integrations", "description": "Policy-controlled enrichment and exports."},
            {"name": "Reports", "description": "Immutable scan-ID and compatibility reports."},
        ],
    )
    application.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.cors_origins),
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "Authorization", "X-Request-ID"],
        expose_headers=["X-Request-ID", "X-Process-Time-Ms"],
    )

    @application.middleware("http")
    async def request_context(request: Request, call_next):
        request_id = normalize_request_id(request.headers.get("X-Request-ID"))
        token = set_request_id(request_id)
        request.state.request_id = request_id
        started = perf_counter()
        try:
            response = await call_next(request)
            response.headers["X-Request-ID"] = request_id
            response.headers["X-Process-Time-Ms"] = str(round((perf_counter() - started) * 1000, 2))
            return response
        finally:
            reset_request_id(token)

    register_exception_handlers(application)
    application.include_router(v1_router, prefix=settings.api_prefix)
    application.include_router(v1_router, include_in_schema=False)

    @application.get("/", include_in_schema=False)
    async def root() -> dict[str, str]:
        return {
            "service": settings.app_name,
            "version": settings.app_version,
            "api": settings.api_prefix,
            "documentation": "/docs",
        }

    return application


app = create_app()
