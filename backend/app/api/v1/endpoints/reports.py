from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends
from fastapi.responses import FileResponse, JSONResponse

from app.dependencies import get_scan_job_service
from app.services.job_service import ScanJobService

log = logging.getLogger("apkguard.reports")
router = APIRouter(tags=["Reports"])


@router.get("/scans/{scan_id}/report")
async def immutable_scan_report(
    scan_id: str,
    service: ScanJobService = Depends(get_scan_job_service),
):
    data = service.result(scan_id).model_dump(mode="json")
    try:
        from report_generator import generate_pdf_report

        pdf = generate_pdf_report(data)
        return FileResponse(pdf, media_type="application/pdf", filename=f"apkguard_{scan_id}.pdf")
    except Exception as exc:
        log.warning("Immutable PDF generation failed scan_id=%s: %s", scan_id, exc)
        return JSONResponse(status_code=500, content={"scan_id": scan_id, "status": "report_generation_failed"})


@router.post("/report")
async def compatibility_report(data: dict[str, Any]):
    data.setdefault(
        "report_integrity_warning",
        "Compatibility endpoint accepts client-supplied data. Use GET /scans/{scan_id}/report for an immutable report.",
    )
    try:
        from report_generator import generate_pdf_report

        pdf = generate_pdf_report(data)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        return FileResponse(pdf, media_type="application/pdf", filename=f"apkguard_{timestamp}.pdf")
    except Exception as exc:
        log.warning("PDF generation failed: %s", exc)
        data["report_generation_status"] = "failed_json_fallback"
        return JSONResponse(content=data)
