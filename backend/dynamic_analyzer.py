"""Compatibility boundary for APKGuard dynamic analysis.

Phase 4 routes runtime execution through ``app.dynamic_analysis`` on a dedicated
Redis-backed worker. This legacy module remains importable for older callers but
never starts ADB, the Android Emulator, or Frida directly.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

DYNAMIC_ADAPTER_VERSION = "apkguard-isolated-android/4.0.0-phase4"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def check_frida_available() -> bool:
    """Compatibility function; use the Phase 4 capabilities endpoint instead."""
    return False


def run_frida_capture(package_name: str, duration: int = 15) -> None:
    """Direct host instrumentation is intentionally prohibited."""
    del package_name, duration
    return None


def not_executed_result(reason: str, package_name: str | None = None) -> dict[str, Any]:
    return {
        "status": "not_executed",
        "stage_status": "NOT_EXECUTED",
        "dynamic_available": False,
        "analysis_method": "phase4_dedicated_worker_required",
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
            "No runtime behaviour was observed for this compatibility call.",
            "Direct ADB, emulator, and Frida execution from the API process is disabled.",
            "Use the Phase 4 Redis-backed dedicated sandbox worker and policy gate.",
        ],
        "cleanup_confirmed": True,
    }


def run_dynamic_analysis(
    apk_path: str,
    package_name: str | None = None,
    analysis: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return an honest unavailable result for legacy direct callers."""
    del apk_path, analysis
    return not_executed_result(
        "Legacy direct dynamic-analysis calls are disabled; use the Phase 4 sandbox service.",
        package_name,
    )
