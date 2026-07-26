"""Disposable Android Emulator lifecycle and runtime evidence collection."""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from time import sleep
from typing import Callable
from uuid import uuid4

from app.core.config import Settings
from app.dynamic_analysis.android import AndroidSandboxTools
from app.dynamic_analysis.capabilities import DYNAMIC_ADAPTER_VERSION, SandboxCapabilityProbe
from app.dynamic_analysis.command import CommandRunner, ManagedProcess
from app.dynamic_analysis.events import (
    dynamic_views,
    make_observation,
    merge_observations,
    parse_frida_events,
    parse_granted_permissions,
    parse_logcat_events,
    parse_process_presence,
    risk_score,
)
from app.dynamic_analysis.frida import FridaController
from app.dynamic_analysis.policy import SANDBOX_POLICY_VERSION, SandboxPolicy
from app.schemas.common import SandboxEventCategory, SandboxState, Severity
from app.schemas.dynamic import RuntimeObservation, SandboxArtifact, SandboxExecutionResult
from app.services.sandbox_repository import SandboxRepository

log = logging.getLogger("apkguard.dynamic_sandbox")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class AndroidSandboxOrchestrator:
    def __init__(
        self,
        *,
        settings: Settings,
        repository: SandboxRepository | None = None,
        runner: CommandRunner | None = None,
        capability_probe: SandboxCapabilityProbe | None = None,
        sleeper: Callable[[float], None] = sleep,
    ) -> None:
        self.settings = settings
        self.repository = repository
        self.runner = runner or CommandRunner(
            [settings.sandbox_adb_path, settings.sandbox_emulator_path, settings.sandbox_frida_path],
            max_output_bytes=settings.sandbox_max_command_output_bytes,
        )
        self.capability_probe = capability_probe or SandboxCapabilityProbe(settings, self.runner)
        self.sleeper = sleeper

    def run(self, *, apk_path: Path, package_name: str, scan_id: str) -> SandboxExecutionResult:
        policy = SandboxPolicy(self.settings)
        capabilities = self.capability_probe.report()
        if not policy.execution_permitted or not capabilities.ready:
            return self.not_executed(
                package_name=package_name,
                blockers=list(dict.fromkeys([*policy.blockers(), *capabilities.blockers])),
            )
        if not policy.validate_artifact_path(apk_path):
            return self.not_executed(
                package_name=package_name,
                blockers=["The APK is not a verified content-addressed quarantine artifact."],
            )

        session_id = str(uuid4())
        workspace = self._create_workspace(session_id)
        tools = AndroidSandboxTools(self.settings, self.runner)
        frida = FridaController(self.settings, self.runner)
        started_at = utc_now()
        observations: list[RuntimeObservation] = []
        artifacts: list[SandboxArtifact] = []
        limitations: list[str] = []
        emulator_process: ManagedProcess | None = None
        frida_process: ManagedProcess | None = None
        installed = False
        emulator_started = False
        cleanup_confirmed = False
        state = SandboxState.CREATED

        self._create_session(session_id, scan_id, workspace, policy)
        try:
            state = SandboxState.PREFLIGHT
            self._transition(session_id, state)
            state = SandboxState.STARTING
            self._transition(session_id, state, emulator_serial=tools.serial)
            emulator_process = tools.start_emulator(workspace)
            emulator_started = True

            state = SandboxState.BOOTING
            self._transition(session_id, state, emulator_serial=tools.serial)
            tools.wait_for_boot()

            state = SandboxState.ISOLATING
            self._transition(session_id, state)
            network_policy = tools.apply_offline_network_policy()
            if not network_policy.get("policy_applied"):
                raise RuntimeError("Offline network policy could not be verified inside the emulator.")
            self._write_json(workspace / "network-policy.json", network_policy)

            tools.clear_logcat()
            state = SandboxState.INSTALLING
            self._transition(session_id, state)
            tools.install(apk_path)
            installed = True
            observations.append(
                make_observation(
                    session_id=session_id,
                    sequence=len(observations) + 1,
                    package_name=package_name,
                    category=SandboxEventCategory.LIFECYCLE,
                    event_type="apk_installed",
                    title="APK installed in disposable emulator",
                    description="ADB reported successful installation into the isolated emulator session.",
                    source="sandbox-orchestrator",
                    observed_at=utc_now(),
                    severity=Severity.INFO,
                    payload={"emulator_serial": tools.serial, "network_mode": self.settings.sandbox_network_mode},
                )
            )

            baseline_files, baseline_error = tools.collect_file_inventory(package_name)
            if baseline_error:
                limitations.append(baseline_error)

            state = SandboxState.INSTRUMENTING
            self._transition(session_id, state)
            tools.launch(package_name)
            observations.append(
                make_observation(
                    session_id=session_id,
                    sequence=len(observations) + 1,
                    package_name=package_name,
                    category=SandboxEventCategory.LIFECYCLE,
                    event_type="application_launched",
                    title="Application launch requested",
                    description="The sandbox invoked the package launcher activity through Android Monkey.",
                    source="sandbox-orchestrator",
                    observed_at=utc_now(),
                    severity=Severity.INFO,
                    payload={"emulator_serial": tools.serial},
                )
            )

            frida_available = capabilities.tools["frida"].available
            if self.settings.sandbox_instrumentation_mode != "logcat_only" and frida_available:
                try:
                    frida_process = frida.start(package_name, workspace)
                except Exception as exc:
                    if self.settings.sandbox_instrumentation_mode == "frida_required":
                        raise RuntimeError("Required Frida instrumentation could not attach.") from exc
                    limitations.append(f"Optional Frida instrumentation was unavailable: {type(exc).__name__}.")
            elif self.settings.sandbox_instrumentation_mode == "frida_required":
                raise RuntimeError("Required Frida CLI capability is unavailable.")
            elif self.settings.sandbox_instrumentation_mode == "frida_optional" and not frida_available:
                limitations.append("Frida was unavailable; only logcat and lifecycle evidence were collected.")

            state = SandboxState.INTERACTING
            self._transition(session_id, state)
            monkey = tools.exercise_ui(package_name)
            (workspace / "monkey.log").write_text(monkey.stdout + monkey.stderr, encoding="utf-8")
            observations.append(
                make_observation(
                    session_id=session_id,
                    sequence=len(observations) + 1,
                    package_name=package_name,
                    category=SandboxEventCategory.UI,
                    event_type="ui_exerciser_completed",
                    title="Bounded UI exercise completed",
                    description="Android Monkey delivered a bounded package-scoped event sequence.",
                    source="android-monkey",
                    observed_at=utc_now(),
                    severity=Severity.INFO,
                    payload={
                        "configured_events": self.settings.sandbox_monkey_events,
                        "returncode": monkey.returncode,
                    },
                )
            )
            self.sleeper(float(self.settings.sandbox_interaction_seconds))

            state = SandboxState.COLLECTING
            self._transition(session_id, state)
            if frida_process:
                frida_process.terminate()
                frida_process = None

            logcat_text = tools.collect_logcat() if self.settings.sandbox_capture_logcat else ""
            if logcat_text:
                (workspace / "logcat.txt").write_text(logcat_text, encoding="utf-8", errors="replace")
            package_dump = tools.collect_package_dump(package_name)
            (workspace / "package-dump.txt").write_text(package_dump, encoding="utf-8", errors="replace")
            process_text = tools.collect_process_list() if self.settings.sandbox_capture_processes else ""
            if process_text:
                (workspace / "process-list.txt").write_text(process_text, encoding="utf-8", errors="replace")

            after_files: list[str] = []
            if self.settings.sandbox_capture_filesystem_diff:
                after_files, after_error = tools.collect_file_inventory(package_name)
                if after_error:
                    limitations.append(after_error)
                self._write_json(
                    workspace / "filesystem-diff.json",
                    {
                        "baseline": baseline_files,
                        "after": after_files,
                        "created": sorted(set(after_files) - set(baseline_files)),
                        "removed": sorted(set(baseline_files) - set(after_files)),
                    },
                )
                for path in sorted(set(after_files) - set(baseline_files))[:500]:
                    observations.append(
                        make_observation(
                            session_id=session_id,
                            sequence=len(observations) + 1,
                            package_name=package_name,
                            category=SandboxEventCategory.FILE,
                            event_type="file_created",
                            title="Application-private file created",
                            description="A new file appeared in the package-private inventory during execution.",
                            source="adb-run-as-filesystem-diff",
                            observed_at=utc_now(),
                            severity=Severity.INFO,
                            payload={"operation": "create", "path": path, "size_bytes": 0},
                        )
                    )

            if self.settings.sandbox_capture_screenshot:
                screenshot = tools.capture_screenshot(workspace)
                if screenshot is None:
                    limitations.append("Runtime screenshot capture was unavailable.")

            frida_text = self._read_optional(workspace / "frida-events.log")
            parsed_frida = parse_frida_events(
                frida_text,
                session_id=session_id,
                package_name=package_name,
                start_sequence=len(observations) + 1,
            )
            parsed_logcat = parse_logcat_events(
                logcat_text,
                session_id=session_id,
                package_name=package_name,
                start_sequence=len(observations) + len(parsed_frida) + 1,
            )
            parsed_permissions = parse_granted_permissions(
                package_dump,
                session_id=session_id,
                package_name=package_name,
                start_sequence=len(observations) + len(parsed_frida) + len(parsed_logcat) + 1,
            )
            parsed_processes = parse_process_presence(
                process_text,
                session_id=session_id,
                package_name=package_name,
                start_sequence=(
                    len(observations)
                    + len(parsed_frida)
                    + len(parsed_logcat)
                    + len(parsed_permissions)
                    + 1
                ),
            )
            observations = merge_observations(
                observations,
                parsed_frida,
                parsed_logcat,
                parsed_permissions,
                parsed_processes,
            )
            artifacts = self._artifact_manifest(workspace)
            self._append_observations(session_id, observations)

            state = SandboxState.TEARDOWN
            self._transition(session_id, state)
            cleanup_confirmed = self._cleanup(tools, package_name, installed, emulator_started, emulator_process)
            installed = False
            emulator_started = False
            emulator_process = None

            state = SandboxState.COMPLETED
            self._transition(session_id, state)
            views = dynamic_views(observations)
            return SandboxExecutionResult(
                status="completed",
                stage_status="SUCCEEDED",
                dynamic_available=True,
                analysis_method=(
                    "isolated_android_emulator_frida"
                    if parsed_frida
                    else "isolated_android_emulator_logcat"
                ),
                adapter_version=DYNAMIC_ADAPTER_VERSION,
                policy_version=SANDBOX_POLICY_VERSION,
                session_id=session_id,
                package_name=package_name,
                sandbox_state=state,
                emulator_serial=tools.serial,
                avd_name=self.settings.sandbox_avd_name,
                snapshot_name=self.settings.sandbox_snapshot_name,
                network_mode=self.settings.sandbox_network_mode,
                instrumentation_mode=self.settings.sandbox_instrumentation_mode,
                observed_events=observations,
                total_events=len(observations),
                dynamic_risk_score=risk_score(observations),
                started_at=started_at,
                completed_at=utc_now(),
                summary=(
                    f"Observed {len(observations)} runtime events in a disposable offline Android emulator session."
                ),
                artifacts=artifacts,
                limitations=list(dict.fromkeys(limitations)),
                blockers=[],
                cleanup_confirmed=cleanup_confirmed,
                **views,
            )
        except Exception as exc:
            log.exception("Isolated sandbox execution failed scan_id=%s session_id=%s", scan_id, session_id)
            if frida_process:
                frida_process.terminate()
                frida_process = None
            try:
                if emulator_started:
                    logcat_text = tools.collect_logcat() if self.settings.sandbox_capture_logcat else ""
                    if logcat_text:
                        (workspace / "logcat.txt").write_text(logcat_text, encoding="utf-8", errors="replace")
                    observations = merge_observations(
                        observations,
                        parse_logcat_events(
                            logcat_text,
                            session_id=session_id,
                            package_name=package_name,
                            start_sequence=len(observations) + 1,
                        ),
                    )
                    self._append_observations(session_id, observations)
            except Exception:
                log.warning("Failed to collect partial sandbox evidence during error handling.", exc_info=True)
            cleanup_confirmed = self._cleanup(tools, package_name, installed, emulator_started, emulator_process)
            state = SandboxState.FAILED
            self._transition(
                session_id,
                state,
                error_code=type(exc).__name__,
                error_message="Sandbox execution failed; see worker logs and session artifacts.",
            )
            views = dynamic_views(observations)
            artifacts = self._artifact_manifest(workspace)
            return SandboxExecutionResult(
                status="partial" if observations else "failed",
                stage_status="PARTIAL" if observations else "FAILED",
                dynamic_available=bool(observations),
                analysis_method="isolated_android_emulator_failed",
                adapter_version=DYNAMIC_ADAPTER_VERSION,
                policy_version=SANDBOX_POLICY_VERSION,
                session_id=session_id,
                package_name=package_name,
                sandbox_state=state,
                emulator_serial=tools.serial,
                avd_name=self.settings.sandbox_avd_name,
                snapshot_name=self.settings.sandbox_snapshot_name,
                network_mode=self.settings.sandbox_network_mode,
                instrumentation_mode=self.settings.sandbox_instrumentation_mode,
                observed_events=observations,
                total_events=len(observations),
                dynamic_risk_score=risk_score(observations),
                started_at=started_at,
                completed_at=utc_now(),
                summary="The isolated sandbox did not complete successfully.",
                artifacts=artifacts,
                limitations=[
                    *list(dict.fromkeys(limitations)),
                    "Runtime coverage is incomplete because the sandbox session failed.",
                ],
                blockers=[type(exc).__name__],
                cleanup_confirmed=cleanup_confirmed,
                **views,
            )

    def not_executed(self, *, package_name: str | None, blockers: list[str]) -> SandboxExecutionResult:
        return SandboxExecutionResult(
            status="not_executed",
            stage_status="NOT_EXECUTED",
            dynamic_available=False,
            analysis_method="isolated_sandbox_policy_gate",
            adapter_version=DYNAMIC_ADAPTER_VERSION,
            policy_version=SANDBOX_POLICY_VERSION,
            package_name=package_name,
            sandbox_state=None,
            network_mode=self.settings.sandbox_network_mode,
            instrumentation_mode=self.settings.sandbox_instrumentation_mode,
            completed_at=utc_now(),
            summary="Dynamic execution was not permitted by the fail-closed sandbox gate.",
            limitations=[
                "No runtime behaviour was observed for this scan.",
                "Static indicators and inferred behaviours remain separate from runtime evidence.",
            ],
            blockers=blockers,
            cleanup_confirmed=True,
        )

    def _create_workspace(self, session_id: str) -> Path:
        root = self.settings.sandbox_workspace_dir.resolve()
        root.mkdir(parents=True, exist_ok=True)
        workspace = (root / session_id).resolve()
        if root not in workspace.parents:
            raise RuntimeError("Sandbox workspace escaped the configured root.")
        workspace.mkdir(mode=0o700, parents=False, exist_ok=False)
        try:
            os.chmod(workspace, 0o700)
        except OSError as exc:
            log.debug("Could not apply POSIX workspace permissions: %s", exc)
        return workspace

    def _create_session(self, session_id: str, scan_id: str, workspace: Path, policy: SandboxPolicy) -> None:
        if self.repository:
            self.repository.create_session(
                session_id=session_id,
                scan_id=scan_id,
                worker_id=self.settings.sandbox_worker_id,
                avd_name=self.settings.sandbox_avd_name,
                network_mode=self.settings.sandbox_network_mode,
                instrumentation_mode=self.settings.sandbox_instrumentation_mode,
                policy_digest=policy.digest(),
                artifact_directory=str(workspace),
            )

    def _transition(
        self,
        session_id: str,
        state: SandboxState,
        *,
        emulator_serial: str | None = None,
        error_code: str | None = None,
        error_message: str | None = None,
    ) -> None:
        if self.repository:
            self.repository.transition(
                session_id,
                state,
                emulator_serial=emulator_serial,
                error_code=error_code,
                error_message=error_message,
            )

    def _append_observations(self, session_id: str, observations: list[RuntimeObservation]) -> None:
        if self.repository:
            self.repository.append_observations(session_id, observations)

    def _cleanup(
        self,
        tools: AndroidSandboxTools,
        package_name: str,
        installed: bool,
        emulator_started: bool,
        emulator_process: ManagedProcess | None,
    ) -> bool:
        confirmed = True
        if installed:
            try:
                tools.force_stop(package_name)
                tools.uninstall(package_name)
            except Exception:
                confirmed = False
                log.warning("APK cleanup failed for package=%s", package_name, exc_info=True)
        if emulator_started:
            try:
                tools.stop_emulator()
            except Exception:
                confirmed = False
                log.warning("Emulator console shutdown failed.", exc_info=True)
        if emulator_process:
            try:
                emulator_process.terminate()
            except Exception:
                confirmed = False
                log.warning("Emulator process termination failed.", exc_info=True)
        return confirmed

    def _artifact_manifest(self, workspace: Path) -> list[SandboxArtifact]:
        artifacts: list[SandboxArtifact] = []
        descriptions = {
            "logcat.txt": ("logcat", "Timestamped Android system and application log capture."),
            "runtime-screenshot.png": ("screenshot", "Final emulator screenshot captured after UI exercise."),
            "filesystem-diff.json": ("filesystem_diff", "Package-private file inventory comparison when available."),
            "package-dump.txt": ("package_dump", "Android package-manager state captured after execution."),
            "process-list.txt": ("process_list", "Android process table captured after UI exercise."),
            "runtime-network.pcap": ("network_capture", "Android Emulator virtual-network packet capture under offline policy."),
            "frida-events.log": ("frida_events", "Observation-only Frida agent output."),
            "monkey.log": ("ui_exercise", "Bounded Android Monkey execution transcript."),
            "network-policy.json": ("network_policy", "Verified guest offline-policy state."),
            "emulator.stdout.log": ("emulator_log", "Android Emulator process standard output."),
            "emulator.stderr.log": ("emulator_log", "Android Emulator process standard error."),
        }
        for filename, (artifact_type, description) in descriptions.items():
            path = workspace / filename
            if not path.is_file():
                continue
            data = path.read_bytes()
            artifacts.append(
                SandboxArtifact(
                    artifact_type=artifact_type,
                    filename=filename,
                    sha256=hashlib.sha256(data).hexdigest(),
                    size_bytes=len(data),
                    description=description,
                )
            )
        return artifacts

    @staticmethod
    def _write_json(path: Path, payload: dict) -> None:
        path.write_text(json.dumps(payload, sort_keys=True, indent=2), encoding="utf-8")

    @staticmethod
    def _read_optional(path: Path) -> str:
        if not path.is_file():
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
