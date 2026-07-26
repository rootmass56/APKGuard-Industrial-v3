"""Fail-closed policy gate for Phase 4 runtime execution."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from app.core.config import Settings
from app.schemas.dynamic import SandboxPolicyResponse

SANDBOX_POLICY_VERSION = "apkguard-sandbox-policy/1.0.0-phase4"


@dataclass(frozen=True, slots=True)
class SandboxPolicy:
    settings: Settings

    def blockers(self) -> list[str]:
        blockers: list[str] = []
        if self.settings.dynamic_mode != "isolated_sandbox":
            blockers.append("APKGUARD_DYNAMIC_MODE must be isolated_sandbox.")
        if not self.settings.sandbox_enabled:
            blockers.append("APKGUARD_SANDBOX_ENABLED must be true.")
        if not self.settings.sandbox_risk_acknowledged:
            blockers.append("APKGUARD_SANDBOX_ACKNOWLEDGE_ISOLATION_RISK must be true.")
        if not self.settings.sandbox_dedicated_host:
            blockers.append("APKGUARD_SANDBOX_DEDICATED_HOST must confirm a dedicated worker host or VM.")
        if not self.settings.sandbox_host_egress_blocked:
            blockers.append("APKGUARD_SANDBOX_HOST_EGRESS_BLOCKED must confirm host-level egress blocking.")
        if self.settings.queue_backend != "redis":
            blockers.append("Dynamic execution requires the Redis-backed dedicated worker deployment.")
        if self.settings.analysis_isolation_mode != "subprocess":
            blockers.append("Dynamic execution requires APKGUARD_ANALYSIS_ISOLATION=subprocess.")
        if not self.settings.sandbox_avd_name:
            blockers.append("A dedicated Android Virtual Device name must be configured.")
        if not self.settings.sandbox_snapshot_name:
            blockers.append("A clean emulator snapshot name must be configured.")
        if self.settings.sandbox_network_mode != "offline":
            blockers.append("Phase 4 permits only the offline network policy.")
        if self.settings.sandbox_allow_adb_root:
            blockers.append("ADB root is not permitted by the Phase 4 baseline policy.")
        return blockers

    @property
    def execution_permitted(self) -> bool:
        return not self.blockers()

    def validate_artifact_path(self, artifact_path: Path) -> bool:
        try:
            resolved = artifact_path.resolve(strict=True)
            quarantine = self.settings.quarantine_dir.resolve(strict=True)
        except (FileNotFoundError, OSError):
            return False
        return resolved.is_file() and quarantine in resolved.parents and resolved.suffix.lower() == ".apk"

    def digest(self) -> str:
        payload = {
            "version": SANDBOX_POLICY_VERSION,
            "dynamic_mode": self.settings.dynamic_mode,
            "enabled": self.settings.sandbox_enabled,
            "risk_acknowledged": self.settings.sandbox_risk_acknowledged,
            "dedicated_host": self.settings.sandbox_dedicated_host,
            "host_egress_blocked": self.settings.sandbox_host_egress_blocked,
            "queue_backend": self.settings.queue_backend,
            "analysis_isolation_mode": self.settings.analysis_isolation_mode,
            "network_mode": self.settings.sandbox_network_mode,
            "instrumentation_mode": self.settings.sandbox_instrumentation_mode,
            "avd_name": self.settings.sandbox_avd_name,
            "snapshot_name": self.settings.sandbox_snapshot_name,
            "allow_adb_root": self.settings.sandbox_allow_adb_root,
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def response(self) -> SandboxPolicyResponse:
        return SandboxPolicyResponse(
            policy_version=SANDBOX_POLICY_VERSION,
            dynamic_mode=self.settings.dynamic_mode,
            enabled=self.settings.sandbox_enabled,
            risk_acknowledged=self.settings.sandbox_risk_acknowledged,
            dedicated_host=self.settings.sandbox_dedicated_host,
            host_egress_blocked=self.settings.sandbox_host_egress_blocked,
            queue_backend=self.settings.queue_backend,
            analysis_isolation_mode=self.settings.analysis_isolation_mode,
            network_mode=self.settings.sandbox_network_mode,
            execution_permitted=self.execution_permitted,
            requires_dedicated_worker=True,
            requires_content_addressed_quarantine=True,
            requires_snapshot_restore=True,
            allows_adb_root=False,
            allows_host_shell=False,
            allows_unrestricted_egress=False,
            blockers=self.blockers(),
            limitations=[
                "The Phase 4 baseline permits offline execution only; unrestricted internet egress is not supported.",
                "Frida instrumentation is optional and requires a separately prepared compatible emulator image.",
                "A host or VM security boundary remains responsible for containing emulator and worker processes.",
            ],
        )
