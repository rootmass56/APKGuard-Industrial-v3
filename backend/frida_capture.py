"""Deprecated direct Frida capture compatibility module.

Production/API-host instrumentation is disabled. The future implementation will
live inside an isolated sandbox worker rather than invoking ADB from FastAPI.
"""

from __future__ import annotations

from typing import Any

from dynamic_analyzer import not_executed_result


def capture_dynamic(package_name: str, duration: int = 20) -> dict[str, Any]:
    """Return an explicit unavailable result without touching a local device."""
    del duration
    return not_executed_result(
        "Legacy direct Frida capture is disabled; use the future isolated sandbox worker.",
        package_name,
    )


if __name__ == "__main__":
    raise SystemExit(
        "Direct Frida capture is disabled. Configure the isolated APKGuard sandbox instead."
    )
