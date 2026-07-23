"""Cautious static behavioural inference for APKGuard.

Despite legacy response field names retained for frontend compatibility, this
module does not execute the APK and never returns observed runtime evidence.
"""

from __future__ import annotations

import logging
import zipfile
from pathlib import Path
from typing import Any, Callable

log = logging.getLogger("apkguard.static_inference")
MAX_TEXT_BYTES = 12 * 1024 * 1024
READABLE_SUFFIXES = (".dex", ".xml", ".json", ".js", ".html", ".txt")


def _read_bounded_archive_text(apk_path: str | Path) -> tuple[str, list[str]]:
    """Read bounded text-like archive entries and report non-fatal warnings."""
    chunks: list[str] = []
    warnings: list[str] = []
    bytes_read = 0

    try:
        with zipfile.ZipFile(apk_path, "r") as archive:
            for entry in archive.infolist():
                if entry.is_dir() or not entry.filename.lower().endswith(READABLE_SUFFIXES):
                    continue
                if bytes_read >= MAX_TEXT_BYTES:
                    warnings.append("Static string scan reached its configured byte limit.")
                    break
                remaining = MAX_TEXT_BYTES - bytes_read
                try:
                    data = archive.read(entry)
                except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
                    log.debug("Could not read %s during static inference: %s", entry.filename, exc)
                    warnings.append(f"Skipped unreadable archive entry: {entry.filename}")
                    continue
                data = data[:remaining]
                bytes_read += len(data)
                chunks.append(data.decode("latin-1", errors="replace"))
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        log.warning("Static inference could not read APK archive: %s", exc)
        warnings.append("APK archive could not be fully inspected for static strings.")

    return "".join(chunks), warnings


def _build_indicator_set(analysis: dict[str, Any] | None) -> set[str]:
    if not analysis:
        return set()

    indicators: set[str] = set()
    permissions = analysis.get("permissions", {})
    for permission in permissions.get("all", []) or []:
        value = str(permission)
        indicators.add(value)
        indicators.add(value.replace("android.permission.", ""))

    for item in permissions.get("dangerous", []) or []:
        if isinstance(item, dict):
            value = str(item.get("permission", ""))
            indicators.add(value)
            indicators.add(value.replace("android.permission.", ""))

    for item in analysis.get("suspicious_apis", []) or []:
        if isinstance(item, dict):
            indicators.add(str(item.get("api") or item.get("name") or ""))
            indicators.add(str(item.get("matched_reference") or ""))
        else:
            indicators.add(str(item))

    return {value for value in indicators if value}


def analyze_behavior(
    apk_path: str,
    androguard_dx: Any = None,
    analysis: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Infer possible behaviour from static evidence only.

    ``androguard_dx`` is retained for API compatibility and is not used in this
    Sprint 0 implementation.
    """
    del androguard_dx

    static_indicators = _build_indicator_set(analysis)
    raw_content, warnings = _read_bounded_archive_text(apk_path)

    def found(pattern: str) -> bool:
        return any(pattern in indicator for indicator in static_indicators) or pattern in raw_content

    runtime_indicators: list[dict[str, Any]] = []
    inferred_behaviors: list[dict[str, Any]] = []
    anti_analysis: list[dict[str, Any]] = []

    indicator_checks = [
        ("RECEIVE_BOOT_COMPLETED", "Boot-completed capability is declared or referenced", "Persistence"),
        ("READ_SMS", "SMS-reading capability is declared or referenced", "Sensitive Data Access"),
        ("SEND_SMS", "SMS-sending capability is declared or referenced", "Communication"),
        ("RECEIVE_SMS", "Incoming-SMS capability is declared or referenced", "Sensitive Data Access"),
        ("READ_CALL_LOG", "Call-log capability is declared or referenced", "Sensitive Data Access"),
        ("RECORD_AUDIO", "Audio-recording capability is declared or referenced", "Surveillance Capability"),
        ("CAMERA", "Camera capability is declared or referenced", "Surveillance Capability"),
        ("READ_CONTACTS", "Contact-reading capability is declared or referenced", "Sensitive Data Access"),
        ("READ_PHONE_STATE", "Phone-state capability is declared or referenced", "Sensitive Data Access"),
        ("AccessibilityService", "Accessibility service code or declaration is referenced", "High-Risk Capability"),
        ("DeviceAdminReceiver", "Device-administrator code or declaration is referenced", "Privilege Capability"),
        ("DexClassLoader", "Dynamic DEX loading API is referenced", "Dynamic Loading"),
        ("SYSTEM_ALERT_WINDOW", "Overlay capability is declared or referenced", "High-Risk Capability"),
        ("REQUEST_INSTALL_PACKAGES", "Package-installation capability is declared or referenced", "Installer Capability"),
        ("INTERNET", "Network access permission is declared", "Network Capability"),
    ]

    for pattern, description, category in indicator_checks:
        if found(pattern):
            runtime_indicators.append(
                {
                    "indicator": pattern,
                    "description": description,
                    "category": category,
                    "evidence_type": "STATICALLY_DETECTED",
                    "observed_at_runtime": False,
                }
            )

    evasion_checks = [
        ("isEmulator", "Possible emulator-detection logic"),
        ("FINGERPRINT", "Build fingerprint inspection"),
        ("isDebugger", "Possible debugger-detection logic"),
        ("ro.secure", "System security property inspection"),
        ("Xposed", "Xposed framework detection reference"),
        ("frida", "Frida detection reference"),
        ("isRooted", "Possible root-detection logic"),
    ]
    for pattern, description in evasion_checks:
        if found(pattern):
            anti_analysis.append(
                {
                    "technique": pattern,
                    "description": description,
                    "evidence_type": "STATICALLY_DETECTED",
                    "observed_at_runtime": False,
                }
            )

    combinations: list[tuple[Callable[[], bool], str, str, str, list[str]]] = [
        (
            lambda: found("SYSTEM_ALERT_WINDOW") and found("AccessibilityService"),
            "Overlay and Accessibility Combination",
            "The static combination may support deceptive overlays or extensive interface control.",
            "Critical",
            ["SYSTEM_ALERT_WINDOW", "AccessibilityService"],
        ),
        (
            lambda: found("READ_SMS") and found("RECEIVE_SMS"),
            "SMS Interception Capability Combination",
            "The static combination may permit reading and receiving SMS messages, including OTPs.",
            "Critical",
            ["READ_SMS", "RECEIVE_SMS"],
        ),
        (
            lambda: found("DexClassLoader"),
            "Dynamic Code Loading Capability",
            "A dynamic class-loading API is referenced. Runtime use was not observed.",
            "High",
            ["DexClassLoader"],
        ),
        (
            lambda: found("READ_CONTACTS") and found("INTERNET"),
            "Contacts and Network Capability Combination",
            "The application can potentially read contacts and communicate over the network; data flow is not proven.",
            "High",
            ["READ_CONTACTS", "INTERNET"],
        ),
        (
            lambda: found("RECEIVE_BOOT_COMPLETED"),
            "Boot Persistence Capability",
            "The application may start work after device boot if its receiver and code path are active.",
            "Medium",
            ["RECEIVE_BOOT_COMPLETED"],
        ),
        (
            lambda: found("REQUEST_INSTALL_PACKAGES") or found("PackageInstaller"),
            "Package Installation Capability",
            "The application references package-installation capability. Installation behavior was not observed.",
            "High",
            ["REQUEST_INSTALL_PACKAGES", "PackageInstaller"],
        ),
    ]

    for predicate, behavior, description, severity, basis in combinations:
        if predicate():
            inferred_behaviors.append(
                {
                    "behavior": behavior,
                    "description": description,
                    "severity": severity,
                    "basis": [item for item in basis if found(item)],
                    "evidence_type": "INFERRED_STATIC",
                    "confidence": "low_to_medium",
                    "observed_at_runtime": False,
                    "limitation": "Static capability or API presence does not prove runtime execution or malicious intent.",
                }
            )

    return {
        "status": "completed_with_warnings" if warnings else "completed",
        "analysis_method": "static_behavioral_inference",
        "runtime_indicators": runtime_indicators,
        "anti_analysis_techniques": anti_analysis,
        # Legacy key retained for frontend compatibility; every entry is clearly labelled inferred.
        "dynamic_behaviors": inferred_behaviors,
        "static_behavioral_inference": inferred_behaviors,
        "total_runtime_indicators": len(runtime_indicators),
        "evasion_detected": bool(anti_analysis),
        "warnings": warnings,
        "limitations": [
            "The APK was not executed by this module.",
            "No item returned by this module is observed runtime evidence.",
        ],
    }
