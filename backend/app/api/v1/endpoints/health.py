from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter

from app.core.config import get_settings
from app.core.context import get_request_id
from app.db.session import get_database
from app.dependencies import get_dynamic_analysis_service, get_job_queue
from app.schemas.scan import HealthResponse
from app.services.capabilities import get_capabilities

router = APIRouter(tags=["System"])


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    settings = get_settings()
    queue = get_job_queue()
    sandbox = get_dynamic_analysis_service().capabilities()
    return HealthResponse(
        status="ok",
        timestamp=datetime.now(timezone.utc),
        service=settings.app_name,
        version=settings.app_version,
        api_version=settings.api_version,
        schema_version=settings.schema_version,
        request_id=get_request_id(),
        execution_mode=f"asynchronous_jobs_{settings.queue_backend}_phase4",
        modules={
            **get_capabilities().health(),
            "database": {
                "available": get_database().ping(),
                "backend": settings.database_url.split(":", 1)[0],
                "immutable_results": True,
            },
            "job_queue": {
                "available": queue.ping(),
                "backend": settings.queue_backend,
                "worker_required": settings.queue_backend == "redis",
            },
            "quarantine": {
                "available": settings.quarantine_dir.exists(),
                "content_addressed": True,
                "execution_permitted": False,
            },
            "advanced_static_analysis": {
                "available": True,
                "sbom_generation": True,
                "call_graph_foundation": True,
                "source_sink_candidates": True,
                "runtime_claims": False,
            },
            "isolated_dynamic_analysis": {
                "available": sandbox.enabled,
                "ready": sandbox.ready,
                "execution_permitted": sandbox.execution_permitted,
                "adapter_version": sandbox.adapter_version,
                "network_mode": sandbox.network_mode,
                "instrumentation_mode": sandbox.instrumentation_mode,
                "observed_runtime_only": True,
                "blockers": sandbox.blockers,
            },
        },
        privacy_mode={
            "mode": settings.privacy_mode,
            "cache_enabled": settings.cache_enabled,
            "history_enabled": settings.history_enabled,
            "virustotal_hash_lookup_permitted": settings.hash_reputation_allowed_by_policy,
            "virustotal_upload_enabled": False,
            "ai_enabled": bool(settings.groq_api_key and settings.ai_allowed_by_policy),
            "dynamic_mode": settings.dynamic_mode,
        },
    )
