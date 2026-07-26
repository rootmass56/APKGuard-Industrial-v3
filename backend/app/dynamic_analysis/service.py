"""Application service exposing the Phase 4 sandbox control plane."""

from __future__ import annotations

import logging
from pathlib import Path
from time import monotonic
from typing import Any

from app.core.config import Settings
from app.core.errors import AppError, ErrorCode
from app.dynamic_analysis.android import AndroidSandboxTools
from app.dynamic_analysis.capabilities import DYNAMIC_ADAPTER_VERSION, SandboxCapabilityProbe
from app.dynamic_analysis.command import CommandRunner
from app.dynamic_analysis.orchestrator import AndroidSandboxOrchestrator
from app.dynamic_analysis.policy import SandboxPolicy
from app.schemas.common import SandboxState
from app.schemas.dynamic import (
    SandboxCapabilityResponse,
    SandboxEventListResponse,
    SandboxEventResponse,
    SandboxPolicyResponse,
    SandboxSessionResponse,
)
from app.services.sandbox_repository import SandboxRepository

log = logging.getLogger("apkguard.dynamic_service")


class DynamicAnalysisService:
    def __init__(
        self,
        *,
        settings: Settings,
        repository: SandboxRepository,
        capability_probe: SandboxCapabilityProbe | None = None,
        orchestrator: AndroidSandboxOrchestrator | None = None,
    ) -> None:
        self.settings = settings
        self.repository = repository
        self.capability_probe = capability_probe or SandboxCapabilityProbe(settings)
        self.orchestrator = orchestrator or AndroidSandboxOrchestrator(
            settings=settings,
            repository=repository,
            capability_probe=self.capability_probe,
        )
        self._capability_cache: SandboxCapabilityResponse | None = None
        self._capability_checked_at = 0.0

    def run(
        self,
        apk_path: str,
        package_name: str | None = None,
        *,
        scan_id: str,
        analysis: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        del analysis
        if not package_name:
            return self.orchestrator.not_executed(
                package_name=None,
                blockers=["Package name is unavailable; the sandbox cannot launch the application."],
            ).model_dump(mode="json")
        result = self.orchestrator.run(
            apk_path=Path(apk_path),
            package_name=package_name,
            scan_id=scan_id,
        )
        return result.model_dump(mode="json")

    def capabilities(self, *, refresh: bool = False) -> SandboxCapabilityResponse:
        now = monotonic()
        if refresh or self._capability_cache is None or now - self._capability_checked_at > 30:
            self._capability_cache = self.capability_probe.report()
            self._capability_checked_at = now
        return self._capability_cache

    def policy(self) -> SandboxPolicyResponse:
        return SandboxPolicy(self.settings).response()


    def recover_scan_session(self, scan_id: str) -> bool:
        session = self.repository.get_by_scan(scan_id)
        if session is None:
            return False
        if session.state in {
            SandboxState.COMPLETED.value,
            SandboxState.FAILED.value,
            SandboxState.CANCELLED.value,
            SandboxState.TIMED_OUT.value,
        }:
            return False
        runner = CommandRunner(
            [self.settings.sandbox_adb_path],
            max_output_bytes=self.settings.sandbox_max_command_output_bytes,
        )
        try:
            AndroidSandboxTools(self.settings, runner).stop_emulator()
        except Exception as exc:
            log.warning("Forced sandbox cleanup failed scan_id=%s: %s", scan_id, exc)
        self.repository.transition(
            session.session_id,
            SandboxState.FAILED,
            error_code="FORCED_ANALYSIS_TERMINATION",
            error_message="Sandbox session was finalized after cancellation or timeout.",
        )
        return True

    def recover_stale_sessions(self) -> int:
        recovered = 0
        runner = CommandRunner(
            [self.settings.sandbox_adb_path],
            max_output_bytes=self.settings.sandbox_max_command_output_bytes,
        )
        tools = AndroidSandboxTools(self.settings, runner)
        for session in self.repository.stale_sessions(self.settings.stale_job_seconds):
            try:
                if session.emulator_serial == self.settings.sandbox_serial:
                    tools.stop_emulator()
            except Exception as exc:
                log.warning("Stale sandbox cleanup failed session_id=%s: %s", session.session_id, exc)
            self.repository.transition(
                session.session_id,
                SandboxState.FAILED,
                error_code="STALE_SANDBOX_SESSION",
                error_message="Stale sandbox session was finalized during worker recovery.",
            )
            recovered += 1
        return recovered

    def session_for_scan(self, scan_id: str) -> SandboxSessionResponse:
        model = self.repository.get_by_scan(scan_id)
        if model is None:
            raise AppError(
                "No sandbox session exists for this scan.",
                code=ErrorCode.NOT_FOUND,
                status_code=404,
                details={"scan_id": scan_id},
            )
        return self._session_response(model)

    def events_for_scan(self, scan_id: str) -> SandboxEventListResponse:
        session = self.repository.get_by_scan(scan_id)
        if session is None:
            raise AppError(
                "No sandbox session exists for this scan.",
                code=ErrorCode.NOT_FOUND,
                status_code=404,
                details={"scan_id": scan_id},
            )
        records = self.repository.events(session.session_id)
        events = [
            SandboxEventResponse(
                event_id=record.event_id,
                session_id=record.session_id,
                sequence=record.sequence,
                category=record.category,
                event_type=record.event_type,
                severity=record.severity,
                observed_at=record.observed_at,
                source=record.source,
                payload=record.payload,
                evidence_digest=record.evidence_digest,
                created_at=record.created_at,
            )
            for record in records
        ]
        return SandboxEventListResponse(session_id=session.session_id, events=events, total=len(events))

    def _session_response(self, model) -> SandboxSessionResponse:
        return SandboxSessionResponse(
            session_id=model.session_id,
            scan_id=model.scan_id,
            state=model.state,
            worker_id=model.worker_id,
            avd_name=model.avd_name,
            emulator_serial=model.emulator_serial,
            network_mode=model.network_mode,
            instrumentation_mode=model.instrumentation_mode,
            policy_digest=model.policy_digest,
            artifact_directory=Path(model.artifact_directory).name,
            error_code=model.error_code,
            error_message=model.error_message,
            created_at=model.created_at,
            updated_at=model.updated_at,
            started_at=model.started_at,
            completed_at=model.completed_at,
            event_count=len(self.repository.events(model.session_id)),
        )


__all__ = ["DYNAMIC_ADAPTER_VERSION", "DynamicAnalysisService"]
