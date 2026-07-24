from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Query

from app.core.config import get_settings
from app.schemas.api import ScanUrlRequest
from app.services.capabilities import get_capabilities

router = APIRouter(tags=["Integrations"])


@router.get("/threat-feeds")
async def threat_feeds(refresh: bool = Query(default=False)) -> dict[str, Any]:
    settings = get_settings()
    if not settings.public_threat_feeds_allowed_by_policy:
        return {
            "status": "disabled_by_privacy_policy",
            "last_updated": None,
            "malwarebazaar_count": 0,
            "openphish_count": 0,
            "recent_malware": [],
        }
    capability = get_capabilities().threat_feeds
    if not capability.available or capability.function is None:
        raise HTTPException(503, "Threat feeds module is unavailable.")
    feeds = capability.function(force_refresh=refresh)
    return {
        "status": feeds.get("status", "unknown"),
        "last_updated": feeds.get("last_updated"),
        "malwarebazaar_count": len(feeds.get("malwarebazaar", [])),
        "openphish_count": len(feeds.get("openphish", [])),
        "recent_malware": feeds.get("malwarebazaar", [])[:5],
    }


@router.post("/siem-test")
async def siem_test() -> dict[str, Any]:
    settings = get_settings()
    capability = get_capabilities().siem_alert
    if not settings.siem_webhook_url:
        raise HTTPException(400, "SIEM_WEBHOOK_URL is not configured; refusing to send a test alert.")
    if not capability.available or capability.function is None:
        raise HTTPException(503, "SIEM module is unavailable.")
    payload = {
        "filename": "controlled-test.apk",
        "risk_score": 85,
        "severity": "CRITICAL",
        "app_info": {"package": "com.example.controlledtest"},
        "ai_analysis": {"threat_summary": "Controlled APKGuard SIEM connector test."},
        "mitre_mappings": [],
        "virustotal": {"sha256": "test", "status": "test"},
    }
    return {"test_result": capability.function(payload), "payload_sent": payload}


@router.post("/scan-url")
async def scan_url(payload: ScanUrlRequest) -> dict[str, Any]:
    from url_scanner import scan_message

    settings = get_settings()
    return scan_message(
        payload.message or payload.url or "",
        allow_external_lookup=settings.public_threat_feeds_allowed_by_policy,
    )


@router.get("/batch-results")
async def batch_results() -> dict[str, Any]:
    matrix_path = Path(__file__).resolve().parents[4] / "confusion_matrix.json"
    notice = "Synthetic feature-vector experiment only; not a real-world APK malware benchmark."
    if matrix_path.exists():
        with matrix_path.open(encoding="utf-8") as handle:
            return {"status": "cached", "validation_notice": notice, **json.load(handle)}

    from batch_tester import run_batch_test

    return {"status": "generated", "validation_notice": notice, **run_batch_test()}
