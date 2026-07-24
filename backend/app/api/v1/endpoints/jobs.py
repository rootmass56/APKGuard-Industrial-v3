"""Phase 2 asynchronous scan-job API."""

from __future__ import annotations

from fastapi import APIRouter, Depends, File, Query, Request, UploadFile, status

from app.dependencies import get_scan_job_service
from app.schemas.jobs import (
    CancelScanResponse,
    ScanEventListResponse,
    ScanJobListResponse,
    ScanJobStatusResponse,
    ScanProgressResponse,
)
from app.schemas.scan import ScanResponse
from app.services.job_service import ScanJobService

router = APIRouter(prefix="/scans", tags=["Scan Jobs"])


@router.post("", response_model=ScanJobStatusResponse, status_code=status.HTTP_202_ACCEPTED)
async def submit_scan(
    request: Request,
    file: UploadFile = File(...),
    service: ScanJobService = Depends(get_scan_job_service),
) -> ScanJobStatusResponse:
    return await service.submit(file, request.state.request_id)


@router.get("", response_model=ScanJobListResponse)
async def list_scans(
    limit: int = Query(default=20, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    service: ScanJobService = Depends(get_scan_job_service),
) -> ScanJobListResponse:
    return service.list(limit=limit, offset=offset)


@router.get("/{scan_id}", response_model=ScanJobStatusResponse)
async def scan_status(
    scan_id: str,
    service: ScanJobService = Depends(get_scan_job_service),
) -> ScanJobStatusResponse:
    return service.status(scan_id)


@router.get("/{scan_id}/progress", response_model=ScanProgressResponse)
async def scan_progress(
    scan_id: str,
    service: ScanJobService = Depends(get_scan_job_service),
) -> ScanProgressResponse:
    return service.progress(scan_id)


@router.get("/{scan_id}/events", response_model=ScanEventListResponse)
async def scan_events(
    scan_id: str,
    service: ScanJobService = Depends(get_scan_job_service),
) -> ScanEventListResponse:
    return service.events(scan_id)


@router.get("/{scan_id}/result", response_model=ScanResponse, response_model_exclude_none=True)
async def scan_result(
    scan_id: str,
    service: ScanJobService = Depends(get_scan_job_service),
) -> ScanResponse:
    return service.result(scan_id)


@router.post("/{scan_id}/cancel", response_model=CancelScanResponse)
async def cancel_scan(
    scan_id: str,
    service: ScanJobService = Depends(get_scan_job_service),
) -> CancelScanResponse:
    return service.cancel(scan_id)
