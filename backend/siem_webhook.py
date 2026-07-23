import os
import requests
import logging
from datetime import datetime

log = logging.getLogger("apkguard.siem")

def send_siem_alert(scan_result: dict) -> dict:
    SIEM_WEBHOOK_URL = os.getenv("BOI_SIEM_WEBHOOK", "")
    SIEM_THRESHOLD = int(os.getenv("BOI_SIEM_THRESHOLD", "60"))

    if not SIEM_WEBHOOK_URL:
        return {"status": "not_configured"}
    risk_score = scan_result.get("risk_score", 0)
    if risk_score < SIEM_THRESHOLD:
        return {"status": "skipped", "reason": f"score {risk_score} below threshold {SIEM_THRESHOLD}"}
    severity = "CRITICAL" if risk_score >= 80 else "HIGH" if risk_score >= 60 else "MEDIUM"
    ai = scan_result.get("ai_analysis") or {}
    mitre = scan_result.get("mitre_mappings", [])
    vt = scan_result.get("virustotal") or {}
    payload = {
        "alert_source": "APKGuard-AI",
        "alert_type": "MALICIOUS_APK_DETECTED",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "severity": severity,
        "risk_score": risk_score,
        "threat": {
            "filename": scan_result.get("filename", "unknown.apk"),
            "package": scan_result.get("app_info", {}).get("package", ""),
            "malware_family": ai.get("malware_family", "Unknown"),
            "confidence": ai.get("confidence", "Unknown"),
            "sha256": vt.get("sha256", ""),
            "vt_detected": vt.get("detected", 0),
        },
        "mitre_techniques": [{"id": m.get("technique_id", m.get("id","")), "name": m.get("name",""), "tactic": m.get("tactic","")} for m in mitre[:5]],
        "summary": ai.get("threat_summary", ""),
        "recommendations": ai.get("recommendations", [])[:3],
        "source_system": "APKGuard AI v2.0 - Bank of India CyberShield",
    }
    try:
        resp = requests.post(SIEM_WEBHOOK_URL, json=payload, headers={"Content-Type":"application/json","X-APKGuard-Alert":severity}, timeout=10)
        log.info(f"SIEM alert sent: {resp.status_code}")
        return {"status": "sent", "http_status": resp.status_code, "severity": severity}
    except Exception as e:
        log.error(f"SIEM webhook failed: {e}")
        return {"status": "failed", "error": str(e)}
