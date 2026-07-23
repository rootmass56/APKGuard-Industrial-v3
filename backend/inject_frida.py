"""Disabled legacy Frida-gadget injection utility.

The original prototype modified and re-signed APKs from the API-host filesystem,
used shell commands, a shared temporary directory, and a hard-coded keystore
password. That workflow is intentionally removed from the production path.

A future research-only implementation must run in an isolated workspace with
explicit authorization, ephemeral signing material, audited tool versions, and
no access to production samples or credentials.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


class FridaInjectionDisabledError(RuntimeError):
    """Raised when legacy APK modification is requested."""


def injection_status() -> dict[str, Any]:
    return {
        "available": False,
        "status": "disabled",
        "reason": "Legacy Frida-gadget APK injection is not part of the production analysis path.",
        "required_replacement": "isolated_sandbox_worker",
        "security_controls_required": [
            "explicit analyst authorization",
            "ephemeral workspace",
            "ephemeral signing credentials",
            "tool allowlist and version pinning",
            "no shell command execution",
            "audit logging",
        ],
    }


def inject_frida(apk_path: str | Path) -> tuple[str, str]:
    """Reject legacy injection instead of executing unsafe host commands."""
    del apk_path
    raise FridaInjectionDisabledError(injection_status()["reason"])


if __name__ == "__main__":
    raise SystemExit(
        "Frida-gadget injection is disabled in APKGuard Sprint 0. "
        "Use the future isolated sandbox workflow."
    )
