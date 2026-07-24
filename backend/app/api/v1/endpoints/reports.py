from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter
from fastapi.responses import FileResponse, JSONResponse

log = logging.getLogger("apkguard.reports")
router = APIRouter(tags=["Reports"])


@router.post("/report")
async def report(data: dict[str, Any]):
    data.setdefault(
        "report_integrity_warning",
        "Phase 1 compatibility endpoint accepts client-supplied data. Immutable scan-ID reports arrive in Phase 2.",
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
