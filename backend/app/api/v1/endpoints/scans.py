from __future__ import annotations

from fastapi import APIRouter, Depends, File, Request, UploadFile

from app.core.config import Settings, get_settings
from app.schemas.scan import ScanResponse
from app.services.scan_service import ScanService
from app.services.upload_service import persist_apk_upload
from app.dependencies import get_scan_service

router = APIRouter(tags=["Scans"])


@router.post("/analyze", response_model=ScanResponse, response_model_exclude_none=True)
async def analyze(
    request: Request,
    file: UploadFile = File(...),
    settings: Settings = Depends(get_settings),
    service: ScanService = Depends(get_scan_service),
) -> ScanResponse:
    artifact = await persist_apk_upload(file, settings)
    try:
        return service.analyze(artifact, request.state.request_id)
    finally:
        artifact.cleanup()
