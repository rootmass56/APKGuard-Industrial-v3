from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter

from app.core.config import get_settings
from app.core.context import get_request_id
from app.schemas.scan import HealthResponse
from app.services.capabilities import get_capabilities

router = APIRouter(tags=["System"])


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    settings = get_settings()
    return HealthResponse(
        status="ok",
        timestamp=datetime.now(timezone.utc),
        service=settings.app_name,
        version=settings.app_version,
        api_version=settings.api_version,
        schema_version=settings.schema_version,
        request_id=get_request_id(),
        execution_mode="synchronous_compatibility_phase1",
        modules=get_capabilities().health(),
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
