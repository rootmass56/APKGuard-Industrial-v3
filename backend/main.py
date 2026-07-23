from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse

from ai_engine import get_ai_analysis
from analyzer import analyze_apk
from behavioral import analyze_behavior
from scorer import calculate_final_score, calculate_score

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(message)s")
log = logging.getLogger("apkguard")

try:
    from smali_deobfuscator import run_smali_deobfuscation
    SMALI_AVAILABLE = True
except Exception:
    SMALI_AVAILABLE = False

try:
    from ml_classifier import kmeans_classify
    ML_AVAILABLE = True
except Exception:
    ML_AVAILABLE = False

try:
    from siem_webhook import send_siem_alert
    SIEM_AVAILABLE = True
except Exception:
    SIEM_AVAILABLE = False

try:
    from threat_feeds import get_threat_feeds, scan_apk_against_feeds
    THREAT_FEEDS_AVAILABLE = True
except Exception:
    THREAT_FEEDS_AVAILABLE = False

try:
    from dynamic_analyzer import run_dynamic_analysis
    DYNAMIC_AVAILABLE = True
except Exception:
    DYNAMIC_AVAILABLE = False

APP_VERSION = "2.1.0-sprint0-sec1"
MAX_UPLOAD_MB = int(os.getenv("APKGUARD_MAX_UPLOAD_MB", "100"))
MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024
RETENTION_ENABLED = os.getenv("APKGUARD_ENABLE_HISTORY", "true").lower() == "true"
CACHE_ENABLED = os.getenv("APKGUARD_ENABLE_CACHE", "true").lower() == "true"
VT_UPLOAD_ENABLED = os.getenv("APKGUARD_ALLOW_VT_UPLOAD", "false").lower() == "true"
CORS_ORIGINS = [o.strip() for o in os.getenv("APKGUARD_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",") if o.strip()]

app = FastAPI(title="APKGuard", version=APP_VERSION)
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

HISTORY_FILE = Path(os.path.expanduser("~/apkguard/scan_history.json"))
CACHE_DIR = Path("cache")
CACHE_DIR.mkdir(exist_ok=True)

SEVERITY_LEVELS = [
    (75, "CRITICAL"),
    (51, "HIGH"),
    (26, "MEDIUM"),
    (1, "LOW"),
    (0, "LOW"),
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_apk_sha256(file_bytes: bytes) -> str:
    return hashlib.sha256(file_bytes).hexdigest()


def severity_for_score(score: int) -> str:
    for threshold, severity in SEVERITY_LEVELS:
        if score >= threshold:
            return severity
    return "LOW"


def load_cached_result(sha256: str) -> dict[str, Any] | None:
    if not CACHE_ENABLED:
        return None
    cache_path = CACHE_DIR / f"{sha256}.json"
    if cache_path.exists():
        with open(cache_path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    return None


def save_result_to_cache(sha256: str, result: dict[str, Any]) -> None:
    if not CACHE_ENABLED:
        return
    cache_path = CACHE_DIR / f"{sha256}.json"
    with open(cache_path, "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)


def load_history() -> list[dict[str, Any]]:
    if not RETENTION_ENABLED:
        return []
    try:
        if HISTORY_FILE.exists():
            return json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        log.warning("Could not load scan history: %s", exc)
    return []


def save_history(history: list[dict[str, Any]]) -> None:
    if not RETENTION_ENABLED:
        return
    try:
        HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
        HISTORY_FILE.write_text(json.dumps(history[-50:], indent=2), encoding="utf-8")
    except Exception as exc:
        log.warning("Could not save history: %s", exc)


scan_history = load_history()


def validate_apk_upload(upload: UploadFile, file_bytes: bytes) -> None:
    """Compatibility validation helper for already-buffered uploads."""
    filename = upload.filename or ""
    if not filename.lower().endswith(".apk"):
        raise HTTPException(400, "Only .apk files are accepted.")
    if not file_bytes:
        raise HTTPException(400, "Uploaded APK is empty.")
    if len(file_bytes) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, f"APK exceeds configured {MAX_UPLOAD_MB} MB upload limit.")
    if not file_bytes.startswith(b"PK"):
        raise HTTPException(400, "File does not look like a valid APK/ZIP archive.")


async def persist_apk_upload(upload: UploadFile) -> tuple[str, str, int]:
    """Stream an APK to a private temporary file while hashing and enforcing limits."""
    filename = upload.filename or ""
    if not filename.lower().endswith(".apk"):
        raise HTTPException(400, "Only .apk files are accepted.")

    digest = hashlib.sha256()
    total_bytes = 0
    first_bytes = b""
    temporary_path: Path | None = None

    try:
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as temporary_file:
            temporary_path = Path(temporary_file.name)
            while True:
                chunk = await upload.read(1024 * 1024)
                if not chunk:
                    break
                if not first_bytes:
                    first_bytes = chunk[:4]
                total_bytes += len(chunk)
                if total_bytes > MAX_UPLOAD_BYTES:
                    raise HTTPException(
                        413,
                        f"APK exceeds configured {MAX_UPLOAD_MB} MB upload limit.",
                    )
                digest.update(chunk)
                temporary_file.write(chunk)

        if total_bytes == 0:
            raise HTTPException(400, "Uploaded APK is empty.")
        if not first_bytes.startswith(b"PK"):
            raise HTTPException(400, "File does not look like a valid APK/ZIP archive.")

        return str(temporary_path), digest.hexdigest(), total_bytes
    except Exception:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise


def get_virustotal_result(apk_path: str, sha256: str) -> dict[str, Any]:
    """Perform hash-only VirusTotal lookup by default.

    Sprint 0 privacy rule: unknown APK files are not uploaded to VirusTotal unless
    APKGUARD_ALLOW_VT_UPLOAD=true is explicitly configured.
    """
    import requests as req

    api_key = os.getenv("VT_API_KEY", "")
    base = {
        "sha256": sha256,
        "source": "virustotal",
        "upload_attempted": False,
        "upload_allowed": VT_UPLOAD_ENABLED,
    }
    if not api_key:
        return {**base, "available": False, "status": "disabled", "reason": "No VT_API_KEY configured."}

    headers = {"x-apikey": api_key}
    try:
        response = req.get(f"https://www.virustotal.com/api/v3/files/{sha256}", headers=headers, timeout=12)
        if response.status_code == 200:
            stats = response.json()["data"]["attributes"].get("last_analysis_stats", {})
            detected = stats.get("malicious", 0) + stats.get("suspicious", 0)
            return {
                **base,
                "available": True,
                "status": "completed",
                "detected": detected,
                "total": sum(stats.values()),
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
            }
        if response.status_code == 404:
            result = {
                **base,
                "available": True,
                "status": "not_found_hash_only",
                "detected": 0,
                "total": 0,
                "not_found": True,
                "reason": "Hash not found in VirusTotal. File upload is disabled by default.",
            }
            if VT_UPLOAD_ENABLED:
                # Intentionally not implemented in Sprint 0. Future cloud-enrichment mode must
                # require explicit user-facing consent and policy enforcement.
                result["reason"] = "Hash not found. Upload mode is enabled in config, but upload is blocked until the consent workflow is implemented."
            return result
        return {**base, "available": False, "status": "error", "reason": f"VT API returned HTTP {response.status_code}."}
    except Exception as exc:
        log.error("VT error: %s", exc)
        return {**base, "available": False, "status": "error", "reason": str(exc)[:120]}


def add_static_inference_labels(behavioral: dict[str, Any]) -> dict[str, Any]:
    for item in behavioral.get("dynamic_behaviors", []):
        item.setdefault("evidence_type", "INFERRED_STATIC")
        item.setdefault("confidence", "low_to_medium")
        item.setdefault("limitation", "This is inferred from static indicators; it is not observed runtime behaviour.")
    for item in behavioral.get("runtime_indicators", []):
        item.setdefault("evidence_type", "STATICALLY_DETECTED")
    for item in behavioral.get("anti_analysis_techniques", []):
        item.setdefault("evidence_type", "STATICALLY_DETECTED")
    return behavioral


def deterministic_findings(analysis: dict[str, Any], behavioral: dict[str, Any], vt: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for perm in analysis.get("permissions", {}).get("dangerous", []):
        findings.append({
            "title": f"Dangerous permission: {perm.get('permission', '').split('.')[-1]}",
            "description": perm.get("reason", "Dangerous Android permission requested."),
            "severity": "High" if perm.get("score", 0) >= 8 else "Medium",
            "evidence_type": "STATICALLY_DETECTED",
            "source": "AndroidManifest.xml",
            "value": perm.get("permission"),
        })
    for api in analysis.get("suspicious_apis", [])[:15]:
        findings.append({
            "title": f"Suspicious API reference: {api.get('api')}",
            "description": api.get("reason", "Suspicious API reference found in code."),
            "severity": "High" if api.get("score", 0) >= 8 else "Medium",
            "evidence_type": "STATICALLY_DETECTED",
            "source": api.get("class", "DEX code"),
            "value": api.get("api"),
        })
    if analysis.get("obfuscation", {}).get("detected"):
        findings.append({
            "title": "Code obfuscation indicators detected",
            "description": "; ".join(analysis.get("obfuscation", {}).get("indicators", [])),
            "severity": "Medium",
            "evidence_type": "STATICALLY_DETECTED",
            "source": "DEX class metadata",
        })
    if vt.get("available") and vt.get("detected", 0) > 0:
        findings.append({
            "title": "Threat-intelligence detections present",
            "description": f"VirusTotal reported {vt.get('detected')}/{vt.get('total')} malicious or suspicious detections.",
            "severity": "Critical" if vt.get("detected", 0) > 10 else "High",
            "evidence_type": "THREAT_INTEL_MATCH",
            "source": "VirusTotal hash lookup",
        })
    for inferred in behavioral.get("dynamic_behaviors", [])[:10]:
        findings.append({
            "title": f"Inferred behaviour: {inferred.get('behavior')}",
            "description": inferred.get("description"),
            "severity": inferred.get("severity", "Medium"),
            "evidence_type": "INFERRED_STATIC",
            "source": "Static behaviour inference",
            "limitation": inferred.get("limitation"),
        })
    return findings


def build_mitre(analysis: dict[str, Any], behavioral: dict[str, Any], score_mitre: list[dict[str, Any]]) -> list[dict[str, Any]]:
    mitre: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add(tid: str, name: str, tactic: str, evidence_type: str, reason: str) -> None:
        if tid in seen:
            return
        seen.add(tid)
        mitre.append({
            "technique_id": tid,
            "name": name,
            "tactic": tactic,
            "evidence_type": evidence_type,
            "mapping_confidence": "medium",
            "reason": reason,
        })

    perms = " ".join(analysis.get("permissions", {}).get("all", []))
    apis = " ".join(a.get("api", "") for a in analysis.get("suspicious_apis", []))
    if "READ_SMS" in perms or "RECEIVE_SMS" in perms:
        add("T1412", "Capture SMS Messages", "Collection", "STATICALLY_DETECTED", "SMS permissions were declared in the manifest.")
    if "READ_CONTACTS" in perms:
        add("T1432", "Access Contact List", "Collection", "STATICALLY_DETECTED", "Contacts permission was declared in the manifest.")
    if "ACCESS_FINE_LOCATION" in perms or "ACCESS_COARSE_LOCATION" in perms:
        add("T1430", "Location Tracking", "Collection", "STATICALLY_DETECTED", "Location permission was declared in the manifest.")
    if "DexClassLoader" in apis:
        add("T1407", "Download New Code at Runtime", "Defense Evasion", "STATICALLY_DETECTED", "Dynamic class loading API reference was found.")
    if "Runtime.exec" in apis:
        add("T1623", "Command and Scripting Interpreter", "Execution", "STATICALLY_DETECTED", "Runtime command execution API reference was found.")

    for sm in score_mitre:
        tid = sm.get("id") or sm.get("technique_id")
        if tid:
            add(tid, sm.get("name", "Unknown"), sm.get("tactic", "Unknown"), "STATICALLY_DETECTED", "Mapped by deterministic scoring rules.")
    return mitre


@app.get("/health")
async def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "timestamp": utc_now(),
        "version": APP_VERSION,
        "modules": {
            "dynamic_analysis_module": DYNAMIC_AVAILABLE,
            "dynamic_execution_status": "disabled_until_isolated_sandbox",
            "ml_classifier_module": ML_AVAILABLE,
            "smali_module": SMALI_AVAILABLE,
            "threat_feeds_module": THREAT_FEEDS_AVAILABLE,
            "siem_module": SIEM_AVAILABLE,
        },
        "privacy_mode": {
            "cache_enabled": CACHE_ENABLED,
            "history_enabled": RETENTION_ENABLED,
            "virustotal_upload_enabled": VT_UPLOAD_ENABLED,
            "ai_enabled": bool(os.getenv("GROQ_API_KEY")),
            "dynamic_mode": os.getenv("APKGUARD_DYNAMIC_MODE", "disabled"),
        },
    }


@app.get("/history")
async def history() -> dict[str, Any]:
    return {"scans": scan_history[-20:], "total": len(scan_history), "retention_enabled": RETENTION_ENABLED}


@app.post("/analyze")
async def analyze(file: UploadFile = File(...)) -> dict[str, Any]:
    log.info("Scan requested: %s", file.filename)
    tmp_path, sha256, upload_size_bytes = await persist_apk_upload(file)

    try:
        cached = load_cached_result(sha256)
        if cached:
            cached["cache_hit"] = True
            cached.setdefault("integrity_note", "Cached result from local APKGuard cache.")
            return cached

        log.info("Static analysis...")
        analysis = analyze_apk(tmp_path)
        app_info = analysis.setdefault("app_info", {})
        if app_info.get("package") and not app_info.get("package_name"):
            app_info["package_name"] = app_info["package"]

        log.info("Static behaviour inference...")
        behavioral = add_static_inference_labels(analyze_behavior(tmp_path, analysis=analysis))

        log.info("Dynamic analysis availability check...")
        package_name = app_info.get("package_name") or app_info.get("package")
        dynamic = {"status": "not_available", "dynamic_available": False, "summary": "Dynamic module unavailable."}
        if DYNAMIC_AVAILABLE:
            dynamic = run_dynamic_analysis(tmp_path, package_name, analysis=analysis)

        log.info("VirusTotal hash-only lookup...")
        vt = get_virustotal_result(tmp_path, sha256)

        log.info("Deterministic scoring...")
        score_result = calculate_score(analysis, behavioral, vt)
        final_score_data = calculate_final_score(score_result, dynamic)
        risk_score = int(final_score_data.get("final_score", score_result.get("score", 0)))
        severity = severity_for_score(risk_score)
        score_result["final_score"] = risk_score
        score_result["severity"] = severity

        ml_result: dict[str, Any] = {"available": False, "status": "disabled_or_unavailable"}
        if ML_AVAILABLE:
            try:
                raw_ml = kmeans_classify(analysis)
                raw_ml["advisory_only"] = True
                raw_ml["validation_status"] = "synthetic_baseline_not_real_world_benchmark"
                raw_ml["risk_contribution_applied"] = 0
                ml_result = raw_ml
            except Exception as exc:
                log.warning("ML error: %s", exc)
                ml_result = {"available": False, "status": "error", "reason": str(exc)[:120]}

        smali_result: dict[str, Any] = {"available": False, "status": "disabled_or_unavailable"}
        if SMALI_AVAILABLE:
            try:
                log.info("Smali explanation stage...")
                smali_result = run_smali_deobfuscation(tmp_path)
                smali_result.setdefault("advisory_only", True)
            except Exception as exc:
                log.warning("Smali error: %s", exc)
                smali_result = {"available": False, "status": "error", "reason": str(exc)[:120]}

        findings = deterministic_findings(analysis, behavioral, vt)
        analysis["findings"] = findings

        log.info("AI explanation stage...")
        ai_result = get_ai_analysis(analysis, score_result)

        mitre = build_mitre(analysis, behavioral, score_result.get("mitre", []))

        threat_intel: dict[str, Any] = {"available": False, "status": "disabled_or_unavailable"}
        if THREAT_FEEDS_AVAILABLE:
            try:
                urls_in_apk = analysis.get("urls_ips", {}).get("urls", [])
                threat_intel = scan_apk_against_feeds(sha256, urls_in_apk)
            except Exception as exc:
                log.warning("Threat feeds error: %s", exc)
                threat_intel = {"available": False, "status": "error", "reason": str(exc)[:120]}

        siem_result: dict[str, Any] = {"available": False, "status": "not_sent"}
        if SIEM_AVAILABLE and os.getenv("SIEM_WEBHOOK_URL"):
            try:
                alert_payload = {
                    "filename": file.filename,
                    "risk_score": risk_score,
                    "severity": severity,
                    "app_info": app_info,
                    "findings": findings,
                    "mitre_mappings": mitre,
                    "virustotal": vt,
                }
                siem_result = send_siem_alert(alert_payload)
            except Exception as exc:
                log.warning("SIEM error: %s", exc)
                siem_result = {"available": False, "status": "error", "reason": str(exc)[:120]}

        if RETENTION_ENABLED:
            scan_history.append({
                "filename": file.filename,
                "risk_score": risk_score,
                "severity": severity,
                "scan_time": utc_now(),
                "package": package_name or "",
                "sha256": sha256,
                "vt_status": vt.get("status"),
                "vt_detected": vt.get("detected"),
            })
            save_history(scan_history)

        full_result = {
            "filename": file.filename,
            "scan_time": utc_now(),
            "apk_sha256": sha256,
            "upload_size_bytes": upload_size_bytes,
            "risk_score": risk_score,
            "severity": severity,
            "app_info": app_info,
            "findings": findings,
            "permissions": analysis.get("permissions", {}).get("all", []),
            "behavioral": behavioral,
            "static_behavioral_inference": behavioral.get("dynamic_behaviors", []),
            "dynamic": dynamic,
            "virustotal": vt,
            "ai_analysis": ai_result,
            "mitre_mappings": mitre,
            "threat_intel": threat_intel,
            "siem_alert": siem_result,
            "ml_analysis": ml_result,
            "smali_analysis": smali_result,
            "score_breakdown": final_score_data.get("breakdown", []),
            "dynamic_breakdown": final_score_data.get("dynamic_breakdown", []),
            "static_score": final_score_data.get("static_score", risk_score),
            "dynamic_score": final_score_data.get("dynamic_score", 0),
            "scoring_mode": final_score_data.get("scoring_mode", "static_only"),
            "cache_hit": False,
            "integrity_note": "Sprint 0 result: dynamic evidence is included only when runtime instrumentation observes events.",
            "privacy_mode": {
                "vt_upload_attempted": vt.get("upload_attempted", False),
                "ai_enabled": ai_result.get("available", False),
                "cache_enabled": CACHE_ENABLED,
                "history_enabled": RETENTION_ENABLED,
            },
        }
        save_result_to_cache(sha256, full_result)
        return full_result
    except HTTPException:
        raise
    except Exception as exc:
        log.error("Analysis failed: %s", exc, exc_info=True)
        raise HTTPException(500, "APK analysis failed. Check backend logs for details.") from exc
    finally:
        try:
            Path(tmp_path).unlink(missing_ok=True)
        except OSError as exc:
            log.warning("Could not remove temporary APK %s: %s", tmp_path, exc)


@app.post("/report")
async def report(data: dict[str, Any]):
    try:
        from report_generator import generate_pdf_report
        data.setdefault("report_integrity_warning", "Sprint 0 endpoint accepts client-supplied data. Industrial target will generate reports only from immutable scan IDs.")
        pdf = generate_pdf_report(data)
        return FileResponse(pdf, media_type="application/pdf", filename=f"apkguard_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf")
    except Exception as exc:
        log.warning("PDF generation failed: %s", exc)
        data.setdefault("report_integrity_warning", "PDF generation failed; returning JSON fallback.")
        return JSONResponse(content=data)


@app.get("/threat-feeds")
async def threat_feeds_endpoint(refresh: bool = False):
    if not THREAT_FEEDS_AVAILABLE:
        raise HTTPException(503, "Threat feeds module not available")
    try:
        feeds = get_threat_feeds(force_refresh=refresh)
        return {
            "status": "ok",
            "last_updated": feeds.get("last_updated"),
            "malwarebazaar_count": len(feeds.get("malwarebazaar", [])),
            "openphish_count": len(feeds.get("openphish", [])),
            "recent_malware": feeds.get("malwarebazaar", [])[:5],
        }
    except Exception as exc:
        raise HTTPException(500, str(exc)) from exc


@app.post("/siem-test")
async def siem_test():
    if not SIEM_AVAILABLE:
        raise HTTPException(503, "SIEM module not available")
    if not os.getenv("SIEM_WEBHOOK_URL"):
        raise HTTPException(400, "SIEM_WEBHOOK_URL is not configured; refusing to send a test alert.")
    test_payload = {
        "filename": "test_malware.apk",
        "risk_score": 85,
        "severity": "CRITICAL",
        "app_info": {"package": "com.example.test"},
        "ai_analysis": {"threat_summary": "Controlled test alert from APKGuard."},
        "mitre_mappings": [{"technique_id": "T1417", "name": "Input Capture", "tactic": "Collection"}],
        "virustotal": {"sha256": "test", "status": "test"},
    }
    result = send_siem_alert(test_payload)
    return {"test_result": result, "payload_sent": test_payload}


@app.post("/scan-url")
async def scan_url(payload: dict[str, Any]):
    try:
        from url_scanner import scan_message
        message = payload.get("message", payload.get("url", ""))
        if not message:
            raise HTTPException(400, "Provide 'message' or 'url' in request body")
        return scan_message(message)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(500, str(exc)) from exc


@app.get("/batch-results")
async def get_batch_results():
    matrix_path = Path(__file__).with_name("confusion_matrix.json")
    if matrix_path.exists():
        with open(matrix_path, encoding="utf-8") as handle:
            data = json.load(handle)
        data["validation_notice"] = "Synthetic feature-vector experiment only; not a real-world APK malware benchmark."
        return {"status": "cached", **data}
    try:
        from batch_tester import run_batch_test
        result = run_batch_test()
        return {"status": "generated", "validation_notice": "Synthetic feature-vector experiment only; not a real-world APK malware benchmark.", **result}
    except Exception as exc:
        raise HTTPException(500, f"Batch test failed: {exc}") from exc
