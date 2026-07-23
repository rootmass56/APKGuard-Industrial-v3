"""Observed-only dynamic-analysis boundary for APKGuard Sprint 0.

Direct ADB/Frida execution from the API host has been intentionally disabled.
The industrial target will use a separately isolated Android sandbox worker with
controlled egress, immutable event capture, and explicit authorization.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

DYNAMIC_ADAPTER_VERSION = "2.1.0-sprint0-sec1"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def check_frida_available() -> bool:
    """Compatibility function: direct host instrumentation is disabled."""
    return False


def run_frida_capture(package_name: str, duration: int = 15) -> None:
    """Compatibility function retained until an isolated sandbox adapter exists."""
    del package_name, duration
    return None


def not_executed_result(reason: str, package_name: str | None = None) -> dict[str, Any]:
    return {
        "status": "not_executed",
        "stage_status": "UNAVAILABLE",
        "dynamic_available": False,
        "analysis_method": "isolated_sandbox_required",
        "adapter_version": DYNAMIC_ADAPTER_VERSION,
        "package_name": package_name,
        "observed_events": [],
        "api_calls_intercepted": [],
        "network_calls": [],
        "file_operations": [],
        "crypto_operations": [],
        "total_events": 0,
        "dynamic_risk_score": 0,
        "started_at": None,
        "completed_at": _utc_now(),
        "summary": reason,
        "limitations": [
            "No runtime behaviour was observed for this scan.",
            "Direct ADB/Frida access from the API process is disabled for safety.",
            "Static indicators and inferences are reported separately and never treated as runtime evidence.",
        ],
    }


def run_dynamic_analysis(
    apk_path: str,
    package_name: str | None = None,
    analysis: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return an honest unavailable result until the isolated sandbox is deployed."""
    del apk_path, analysis

    configured_mode = os.getenv("APKGUARD_DYNAMIC_MODE", "disabled").strip().lower()
    if not package_name:
        return not_executed_result(
            "Package name unavailable; isolated runtime analysis was not scheduled.",
            package_name,
        )

    if configured_mode not in {"disabled", "isolated_sandbox"}:
        return not_executed_result(
            "Unsupported dynamic-analysis mode. Only the future isolated_sandbox adapter is permitted.",
            package_name,
        )

    if configured_mode == "isolated_sandbox":
        return not_executed_result(
            "Isolated sandbox mode is selected, but no sandbox worker is connected in Sprint 0.",
            package_name,
        )

    return not_executed_result(
        "Dynamic analysis is disabled until the isolated Android sandbox worker is implemented.",
        package_name,
    )
