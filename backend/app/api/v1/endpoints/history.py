from __future__ import annotations

from fastapi import APIRouter, Depends

from app.core.config import Settings, get_settings
from app.dependencies import get_history_repository
from app.schemas.scan import HistoryResponse
from app.services.repositories import HistoryRepository

router = APIRouter(tags=["History"])


@router.get("/history", response_model=HistoryResponse)
async def history(
    settings: Settings = Depends(get_settings),
    repository: HistoryRepository = Depends(get_history_repository),
) -> HistoryResponse:
    scans = repository.list(limit=20)
    return HistoryResponse(
        scans=scans,
        total=repository.count(),
        retention_enabled=settings.history_enabled,
        schema_version=settings.schema_version,
    )
