"""FastAPI application factory for APKGuard Industrial v3 Phase 1."""

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

settings = get_settings()
configure_logging(settings.log_level, settings.log_format)
log = logging.getLogger("apkguard.application")


@asynccontextmanager
async def lifespan(_: FastAPI):
    log.info(
        "Starting %s version=%s environment=%s privacy_mode=%s",
        settings.app_name,
        settings.app_version,
        settings.environment,
        settings.privacy_mode,
    )
    yield
    log.info("Stopping %s", settings.app_name)


def create_app() -> FastAPI:
    application = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description=(
            "Evidence-driven Android APK triage API. Phase 1 introduces typed contracts, "
            "versioned evidence, standard errors, request correlation, and compatibility routes."
        ),
        lifespan=lifespan,
        openapi_tags=[
            {"name": "System", "description": "Health and capability metadata."},
            {"name": "Scans", "description": "APK intake and evidence-backed analysis."},
            {"name": "History", "description": "Locally retained scan summaries."},
            {"name": "Integrations", "description": "Policy-controlled enrichment and exports."},
            {"name": "Reports", "description": "Compatibility reporting endpoint."},
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
    # Root routes remain temporarily available for the existing React frontend.
    # They are hidden from OpenAPI so new clients adopt /api/v1 immediately.
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
