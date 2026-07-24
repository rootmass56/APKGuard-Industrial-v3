from __future__ import annotations

from fastapi import APIRouter, Depends

from app.core.config import Settings, get_settings
from app.dependencies import get_scan_job_service
from app.schemas.scan import HistoryResponse
from app.services.job_service import ScanJobService

router = APIRouter(tags=["History"])


@router.get("/history", response_model=HistoryResponse)
async def history(
    settings: Settings = Depends(get_settings),
    service: ScanJobService = Depends(get_scan_job_service),
) -> HistoryResponse:
    scans = service.history_records(limit=20)
    return HistoryResponse(
        scans=scans,
        total=service.jobs.count(),
        retention_enabled=settings.history_enabled,
        schema_version=settings.schema_version,
    )
