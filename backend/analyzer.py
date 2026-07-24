"""Deterministic static APK analysis used by the Sprint 0 backend.

This module performs local, evidence-oriented triage only. External reputation
lookups are orchestrated elsewhere and unknown samples are never uploaded here.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import os
import re
import zipfile
from pathlib import Path
from typing import Any

import requests
from dotenv import load_dotenv

from behavioral import analyze_behavior

from app.static_analysis import ADVANCED_STATIC_ANALYZER_VERSION, run_advanced_static_analysis

load_dotenv(Path(__file__).with_name(".env"))
log = logging.getLogger("apkguard.analyzer")

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS": {"score": 10, "reason": "Can read SMS including OTPs"},
    "android.permission.RECEIVE_SMS": {"score": 10, "reason": "Can intercept incoming SMS"},
    "android.permission.SEND_SMS": {"score": 8, "reason": "Can send SMS"},
    "android.permission.READ_CALL_LOG": {"score": 7, "reason": "Can access call history"},
    "android.permission.PROCESS_OUTGOING_CALLS": {"score": 7, "reason": "Can observe outgoing calls"},
    "android.permission.BIND_ACCESSIBILITY_SERVICE": {
        "score": 15,
        "reason": "Accessibility services can observe or control interface content",
    },
    "android.permission.SYSTEM_ALERT_WINDOW": {"score": 12, "reason": "Can draw overlays over other apps"},
    "android.permission.REQUEST_INSTALL_PACKAGES": {"score": 9, "reason": "Can request installation of APKs"},
    "android.permission.READ_CONTACTS": {"score": 5, "reason": "Can read contacts"},
    "android.permission.RECORD_AUDIO": {"score": 8, "reason": "Can access the microphone"},
    "android.permission.CAMERA": {"score": 6, "reason": "Can access the camera"},
    "android.permission.READ_PHONE_STATE": {"score": 6, "reason": "Can access phone-state identifiers"},
    "android.permission.WRITE_EXTERNAL_STORAGE": {"score": 4, "reason": "Can write external storage"},
    "android.permission.GET_ACCOUNTS": {"score": 6, "reason": "Can enumerate device accounts"},
    "android.permission.DISABLE_KEYGUARD": {"score": 8, "reason": "Can interact with keyguard state"},
    "android.permission.RECEIVE_BOOT_COMPLETED": {"score": 5, "reason": "Can start after device boot"},
}

SUSPICIOUS_APIS = {
    "sendTextMessage": {"score": 8, "reason": "SMS sending API reference"},
    "getDeviceId": {"score": 6, "reason": "Device identifier API reference"},
    "getSubscriberId": {"score": 6, "reason": "Subscriber identifier API reference"},
    "getLine1Number": {"score": 6, "reason": "Phone-number API reference"},
    "DexClassLoader": {"score": 10, "reason": "Dynamic DEX loading reference"},
    "PathClassLoader": {"score": 7, "reason": "Dynamic class-loading reference"},
    "Runtime.exec": {"score": 9, "reason": "Runtime command-execution reference"},
    "execShellCommand": {"score": 9, "reason": "Shell-command API reference"},
    "setOnAccessibilityEventListener": {"score": 10, "reason": "Accessibility event listener reference"},
    "onAccessibilityEvent": {"score": 10, "reason": "Accessibility event handling reference"},
    "getPassword": {"score": 8, "reason": "Password-related API reference"},
    "HttpURLConnection": {"score": 3, "reason": "Network communication reference"},
    "Cipher.getInstance": {"score": 4, "reason": "Cryptographic API reference"},
    "Base64.decode": {"score": 3, "reason": "Base64 decoding reference"},
    "Class.forName": {"score": 6, "reason": "Reflection class-loading reference"},
    "Method.invoke": {"score": 6, "reason": "Reflection invocation reference"},
    "TelephonyManager": {"score": 5, "reason": "Telephony API reference"},
}

BANKING_INDICATORS = [
    "overlay",
    "inject",
    "keylog",
    "bankbot",
    "credential",
    "phish",
    "intercept",
    "hidden",
    "invisible",
    "stealth",
    "hook",
    "capture_screen",
]

READABLE_ARCHIVE_SUFFIXES = (".dex", ".xml", ".json", ".js", ".html", ".txt")
URL_WHITELIST = (
    "google.com",
    "gstatic.com",
    "googleapis.com",
    "android.com",
    "w3.org",
    "apache.org",
    "firebase.com",
)


def compute_hashes(apk_path: str | os.PathLike[str]) -> dict[str, Any]:
    """Calculate sample identifiers.

    SHA-256 is the authoritative integrity identifier. MD5 and SHA-1 are kept
    only for compatibility with historical malware-intelligence records.
    """
    md5_digest = hashlib.md5(usedforsecurity=False)
    sha1_digest = hashlib.sha1(usedforsecurity=False)
    sha256_digest = hashlib.sha256()

    path = Path(apk_path)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            md5_digest.update(chunk)
            sha1_digest.update(chunk)
            sha256_digest.update(chunk)

    return {
        "md5": md5_digest.hexdigest(),
        "sha1": sha1_digest.hexdigest(),
        "sha256": sha256_digest.hexdigest(),
        "authoritative_hash": "sha256",
        "legacy_hashes_for_compatibility_only": ["md5", "sha1"],
        "size_kb": round(path.stat().st_size / 1024, 2),
    }


def check_virustotal(sha256: str) -> dict[str, Any]:
    """Perform a hash-only VirusTotal lookup.

    This compatibility function never uploads the APK.
    """
    api_key = os.getenv("VT_API_KEY", "")
    base = {"sha256": sha256, "upload_attempted": False, "source": "virustotal"}
    if not api_key:
        return {**base, "available": False, "status": "disabled", "reason": "No VT API key configured"}

    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={"x-apikey": api_key},
            timeout=10,
        )
        if response.status_code == 200:
            attributes = response.json()["data"]["attributes"]
            stats = attributes.get("last_analysis_stats", {})
            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            return {
                **base,
                "available": True,
                "status": "completed",
                "detected": malicious + suspicious,
                "malicious": malicious,
                "suspicious": suspicious,
                "undetected": int(stats.get("undetected", 0)),
                "total": sum(int(value) for value in stats.values()),
                "permalink": f"https://www.virustotal.com/gui/file/{sha256}",
            }
        if response.status_code == 404:
            return {
                **base,
                "available": True,
                "status": "not_found_hash_only",
                "not_found": True,
                "detected": 0,
                "total": 0,
                "reason": "Hash not found; this is not a clean verdict.",
            }
        return {
            **base,
            "available": False,
            "status": "error",
            "reason": f"VirusTotal returned HTTP {response.status_code}",
        }
    except (requests.RequestException, KeyError, TypeError, ValueError) as exc:
        log.warning("VirusTotal hash lookup failed: %s", exc)
        return {**base, "available": False, "status": "error", "reason": str(exc)[:120]}


def _is_public_ip(candidate: str) -> bool:
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def extract_urls_and_ips(apk_path: str | os.PathLike[str]) -> dict[str, list[str]]:
    """Extract a bounded set of URL and public-IP string indicators."""
    urls: set[str] = set()
    ips: set[str] = set()
    url_pattern = re.compile(r"https?://[^\s'\"<>]{4,}")
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    try:
        with zipfile.ZipFile(apk_path, "r") as archive:
            for entry in archive.infolist():
                if entry.is_dir() or not entry.filename.lower().endswith(READABLE_ARCHIVE_SUFFIXES):
                    continue
                # Avoid reading unexpectedly large entries in the API process.
                if entry.file_size > 8 * 1024 * 1024:
                    log.debug("Skipping large archive entry during IOC extraction: %s", entry.filename)
                    continue
                try:
                    content = archive.read(entry).decode("utf-8", errors="ignore")
                except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
                    log.debug("Unable to read archive entry %s: %s", entry.filename, exc)
                    continue

                for url in url_pattern.findall(content):
                    if not any(allowed in url.lower() for allowed in URL_WHITELIST):
                        urls.add(url[:240])
                for candidate in ip_pattern.findall(content):
                    if _is_public_ip(candidate):
                        ips.add(candidate)
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        log.warning("URL/IP extraction could not inspect APK: %s", exc)

    return {"urls": sorted(urls)[:20], "ips": sorted(ips)[:10]}


def detect_obfuscation(dx: Any) -> dict[str, Any]:
    indicators: list[str] = []
    score = 0
    try:
        classes = [analysis_class.name for analysis_class in dx.get_classes()]
        short_names = [
            class_name
            for class_name in classes
            if len(class_name.split("/")[-1].replace(";", "")) <= 2
        ]
        ratio = len(short_names) / max(len(classes), 1)
        if ratio > 0.3:
            indicators.append(f"Heavy short-name obfuscation indicator ({int(ratio * 100)}%)")
            score = 10
        elif ratio > 0.1:
            indicators.append("Moderate short-name obfuscation indicator")
            score = 5
    except (AttributeError, TypeError, ValueError) as exc:
        log.warning("Obfuscation analysis was partial: %s", exc)
        indicators.append("Obfuscation analysis was incomplete")

    return {
        "detected": bool(indicators),
        "score": score,
        "indicators": indicators,
        "method": "short_class_name_ratio",
        "limitation": "This heuristic alone does not prove malicious obfuscation.",
    }


def detect_native_libs(apk_path: str | os.PathLike[str]) -> list[str]:
    try:
        with zipfile.ZipFile(apk_path, "r") as archive:
            return sorted(
                entry.filename
                for entry in archive.infolist()
                if not entry.is_dir()
                and entry.filename.startswith("lib/")
                and entry.filename.endswith(".so")
            )
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        log.warning("Native library inventory failed: %s", exc)
        return []


def _call_identity(call: Any) -> str:
    class_name = str(getattr(call, "class_name", "") or getattr(call, "get_class_name", lambda: "")())
    method_name = str(getattr(call, "name", "") or getattr(call, "get_name", lambda: "")())
    return f"{class_name}.{method_name}"


def analyze_apk(apk_path: str | os.PathLike[str]) -> dict[str, Any]:
    """Analyze one APK and return deterministic local evidence."""
    path = Path(apk_path)
    results: dict[str, Any] = {
        "status": "success",
        "analyzer": {"name": "apkguard_static", "version": "3.2.0-phase3"},
        "file_info": {},
        "app_info": {},
        "permissions": {"dangerous": [], "all": []},
        "suspicious_apis": [],
        "urls_ips": {"urls": [], "ips": []},
        "obfuscation": {},
        "native_libs": [],
        "banking_indicators": [],
        "virustotal": {"available": False, "status": "handled_by_orchestrator"},
        "errors": [],
    }

    try:
        results["file_info"] = compute_hashes(path)
        results["file_info"]["filename"] = path.name
    except (OSError, ValueError) as exc:
        results["errors"].append(f"Hash calculation failed: {exc}")
        results["status"] = "partial"

    apk = None
    analysis = None
    try:
        from androguard.misc import AnalyzeAPK

        apk, _, analysis = AnalyzeAPK(str(path))
        package_name = apk.get_package()
        results["app_info"] = {
            "package": package_name,
            "package_name": package_name,
            "app_name": str(apk.get_app_name()),
            "version_name": str(apk.get_androidversion_name()),
            "version_code": str(apk.get_androidversion_code()),
            "min_sdk": str(apk.get_min_sdk_version()),
            "target_sdk": str(apk.get_target_sdk_version()),
            "main_activity": str(apk.get_main_activity()),
        }

        all_permissions = list(apk.get_permissions() or [])
        results["permissions"]["all"] = all_permissions
        for permission in all_permissions:
            permission_info = DANGEROUS_PERMISSIONS.get(permission)
            if permission_info:
                results["permissions"]["dangerous"].append(
                    {
                        "permission": permission,
                        "score": permission_info["score"],
                        "reason": permission_info["reason"],
                        "evidence_type": "STATICALLY_DETECTED",
                        "source": "AndroidManifest.xml",
                    }
                )

        found_apis: set[str] = set()
        for analysis_class in analysis.get_classes():
            for method in analysis_class.get_methods():
                try:
                    references = method.get_xref_to()
                except (AttributeError, TypeError, ValueError) as exc:
                    log.debug("Unable to inspect method cross-references: %s", exc)
                    continue
                for _, call, _ in references:
                    identity = _call_identity(call)
                    for api_name, api_info in SUSPICIOUS_APIS.items():
                        if api_name in identity and api_name not in found_apis:
                            found_apis.add(api_name)
                            results["suspicious_apis"].append(
                                {
                                    "api": api_name,
                                    "matched_reference": identity,
                                    "score": api_info["score"],
                                    "reason": api_info["reason"],
                                    "evidence_type": "STATICALLY_DETECTED",
                                }
                            )

        results["obfuscation"] = detect_obfuscation(analysis)
        class_names = [str(item.name).lower() for item in analysis.get_classes()]
        results["banking_indicators"] = sorted(
            {
                indicator
                for class_name in class_names
                for indicator in BANKING_INDICATORS
                if indicator in class_name
            }
        )
    except Exception as exc:  # Androguard exposes several parser-specific exception types.
        log.warning("Androguard analysis failed or was partial: %s", exc)
        results["errors"].append(f"Androguard analysis failed: {str(exc)[:200]}")
        results["status"] = "partial"

    results["urls_ips"] = extract_urls_and_ips(path)
    results["native_libs"] = detect_native_libs(path)


    try:
        advanced = run_advanced_static_analysis(
            path,
            apk=apk,
            dx=analysis,
            apk_sha256=str(results.get("file_info", {}).get("sha256", "")),
        )
        results["advanced_static"] = advanced
        results["signing"] = advanced.get("signing", {})
        results["attack_surface"] = advanced.get("attack_surface", {})
        results["network_security"] = advanced.get("network_security", {})
        results["native_analysis"] = advanced.get("native_analysis", {})
        results["dependency_inventory"] = advanced.get("dependency_inventory", [])
        results["sbom"] = advanced.get("sbom", {})
        results["call_graph"] = advanced.get("call_graph", {})
        results["data_flows"] = advanced.get("data_flows", [])
        results["analyzer"]["advanced_static_version"] = ADVANCED_STATIC_ANALYZER_VERSION
        if advanced.get("status") != "completed":
            results["status"] = "partial"
    except (OSError, ValueError, TypeError, zipfile.BadZipFile) as exc:
        log.warning("Advanced static analysis failed: %s", exc)
        results["advanced_static"] = {
            "status": "failed",
            "evidence": [],
            "findings": [],
            "limitations": ["Advanced static analysis failed before completion."],
        }
        results["errors"].append(f"Advanced static analysis failed: {type(exc).__name__}")
        results["status"] = "partial"

    try:
        results["behavioral_analysis"] = analyze_behavior(str(path), analysis=results)
    except (OSError, ValueError, TypeError, zipfile.BadZipFile) as exc:
        log.warning("Static behavioural inference failed: %s", exc)
        results["behavioral_analysis"] = {
            "status": "failed",
            "error": str(exc)[:160],
            "runtime_indicators": [],
            "dynamic_behaviors": [],
            "anti_analysis_techniques": [],
        }
        results["status"] = "partial"

    return results
