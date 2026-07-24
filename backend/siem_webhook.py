"""Policy-controlled SIEM webhook adapter."""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any

import requests

log = logging.getLogger("apkguard.siem")


def send_siem_alert(scan_result: dict[str, Any]) -> dict[str, Any]:
    webhook_url = os.getenv("SIEM_WEBHOOK_URL", "").strip() or os.getenv("BOI_SIEM_WEBHOOK", "").strip()
    threshold = int(os.getenv("SIEM_THRESHOLD", os.getenv("BOI_SIEM_THRESHOLD", "60")))

    if not webhook_url:
        return {"available": False, "status": "not_configured"}

    risk_score = int(scan_result.get("risk_score", 0))
    if risk_score < threshold:
        return {
            "available": True,
            "status": "skipped",
            "reason": f"score {risk_score} below threshold {threshold}",
        }

    severity = "CRITICAL" if risk_score >= 80 else "HIGH" if risk_score >= 60 else "MEDIUM"
    ai = scan_result.get("ai_analysis") or {}
    mitre = scan_result.get("mitre_mappings", [])
    vt = scan_result.get("virustotal") or {}
    payload = {
        "alert_source": "APKGuard Industrial v3",
        "alert_type": "SUSPICIOUS_APK_TRIAGE_RESULT",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "severity": severity,
        "risk_score": risk_score,
        "threat": {
            "filename": scan_result.get("filename", "unknown.apk"),
            "package": scan_result.get("app_info", {}).get("package", ""),
            "malware_family": ai.get("malware_family", "Unknown"),
            "confidence": ai.get("confidence", "Unknown"),
            "sha256": vt.get("sha256", ""),
            "vt_detected": vt.get("detected"),
        },
        "mitre_techniques": [
            {
                "id": item.get("technique_id", item.get("id", "")),
                "name": item.get("name", ""),
                "tactic": item.get("tactic", ""),
            }
            for item in mitre[:5]
        ],
        "summary": ai.get("threat_summary", ""),
        "recommendations": ai.get("recommendations", [])[:3],
    }
    try:
        response = requests.post(
            webhook_url,
            json=payload,
            headers={"Content-Type": "application/json", "X-APKGuard-Alert": severity},
            timeout=10,
        )
        response.raise_for_status()
        log.info("SIEM alert delivered with HTTP %s", response.status_code)
        return {
            "available": True,
            "status": "sent",
            "http_status": response.status_code,
            "severity": severity,
        }
    except requests.RequestException as exc:
        log.warning("SIEM webhook delivery failed: %s", exc)
        return {
            "available": True,
            "status": "failed",
            "reason": "SIEM webhook delivery failed.",
        }
