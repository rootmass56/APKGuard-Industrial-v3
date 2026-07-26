"""Non-executing Android sandbox preflight and capability discovery."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from app.core.config import Settings
from app.dynamic_analysis.command import CommandExecutionError, CommandPolicyError, CommandRunner
from app.dynamic_analysis.policy import SandboxPolicy
from app.schemas.dynamic import SandboxCapabilityResponse, ToolCapability

DYNAMIC_ADAPTER_VERSION = "apkguard-isolated-android/4.0.0-phase4"


class SandboxCapabilityProbe:
    def __init__(self, settings: Settings, runner: CommandRunner | None = None) -> None:
        self.settings = settings
        self.runner = runner or CommandRunner(
            [settings.sandbox_adb_path, settings.sandbox_emulator_path, settings.sandbox_frida_path],
            max_output_bytes=settings.sandbox_max_command_output_bytes,
        )

    def _tool(self, name: str, configured: str, version_args: list[str]) -> ToolCapability:
        executable = CommandRunner.resolve_executable(configured)
        if not executable:
            return ToolCapability(name=name, available=False, reason="Executable was not found on PATH or configured path.")
        try:
            result = self.runner.run([configured, *version_args], timeout_seconds=10, check=False)
            version = (result.stdout or result.stderr).strip().splitlines()
            return ToolCapability(
                name=name,
                available=result.returncode == 0,
                executable=str(Path(executable)),
                version=version[0][:300] if version else None,
                reason=None if result.returncode == 0 else f"Version probe exited with {result.returncode}.",
            )
        except (CommandExecutionError, CommandPolicyError, OSError) as exc:
            return ToolCapability(name=name, available=False, executable=str(Path(executable)), reason=str(exc))

    def report(self) -> SandboxCapabilityResponse:
        policy = SandboxPolicy(self.settings)
        adb = self._tool("adb", self.settings.sandbox_adb_path, ["version"])
        emulator = self._tool("emulator", self.settings.sandbox_emulator_path, ["-version"])
        frida = self._tool("frida", self.settings.sandbox_frida_path, ["--version"])

        avd_available = False
        avd_reason: str | None = None
        if emulator.available:
            try:
                result = self.runner.run(
                    [self.settings.sandbox_emulator_path, "-list-avds"],
                    timeout_seconds=15,
                    check=False,
                )
                avds = {line.strip() for line in result.stdout.splitlines() if line.strip()}
                avd_available = bool(self.settings.sandbox_avd_name and self.settings.sandbox_avd_name in avds)
                if not self.settings.sandbox_avd_name:
                    avd_reason = "No AVD name is configured."
                elif not avd_available:
                    avd_reason = f"Configured AVD '{self.settings.sandbox_avd_name}' was not listed."
            except (CommandExecutionError, CommandPolicyError, OSError) as exc:
                avd_reason = str(exc)
        else:
            avd_reason = "Android Emulator is unavailable."

        avd = ToolCapability(
            name="avd",
            available=avd_available,
            executable=self.settings.sandbox_avd_name or None,
            version=None,
            reason=avd_reason,
        )
        tools = {"adb": adb, "emulator": emulator, "frida": frida, "avd": avd}
        blockers = list(policy.blockers())
        if not adb.available:
            blockers.append("ADB is unavailable.")
        if not emulator.available:
            blockers.append("Android Emulator is unavailable.")
        if not avd.available:
            blockers.append(avd.reason or "The configured AVD is unavailable.")
        if self.settings.sandbox_instrumentation_mode == "frida_required" and not frida.available:
            blockers.append("Frida CLI is required by policy but unavailable.")

        warnings: list[str] = [
            "Snapshot existence is verified when the emulator starts; the preflight probe does not boot an AVD.",
            "Offline guest configuration supplements, but does not replace, host or VM containment controls.",
        ]
        if self.settings.sandbox_instrumentation_mode == "frida_optional" and not frida.available:
            warnings.append("Frida is unavailable; runtime collection will fall back to logcat and lifecycle evidence.")

        return SandboxCapabilityResponse(
            adapter_version=DYNAMIC_ADAPTER_VERSION,
            checked_at=datetime.now(timezone.utc),
            enabled=self.settings.sandbox_enabled,
            execution_permitted=policy.execution_permitted,
            ready=not blockers,
            avd_name=self.settings.sandbox_avd_name or None,
            snapshot_name=self.settings.sandbox_snapshot_name or None,
            network_mode=self.settings.sandbox_network_mode,
            instrumentation_mode=self.settings.sandbox_instrumentation_mode,
            tools=tools,
            blockers=blockers,
            warnings=warnings,
        )
