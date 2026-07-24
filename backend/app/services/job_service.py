"""Persistent scan submission, orchestration, progress, cancellation, and recovery."""

from __future__ import annotations

import logging
from pathlib import Path
from time import sleep
from uuid import uuid4

from fastapi import UploadFile

from app.core.config import Settings
from app.core.errors import AppError, ErrorCode, InvalidUploadError
from app.schemas.common import JobEventType, JobState, ResultStatus
from app.schemas.jobs import (
    CancelScanResponse,
    ScanEventListResponse,
    ScanEventResponse,
    ScanJobListResponse,
    ScanJobStatusResponse,
    ScanProgressResponse,
)
from app.schemas.scan import ScanResponse
from app.services.analysis_runner import (
    AnalysisCancelledError,
    AnalysisRequest,
    AnalysisTimedOutError,
)
from app.services.job_queue import JobQueue
from app.services.job_repository import ArtifactRepository, ImmutableResultRepository, PersistentJobRepository
from app.services.job_state import STATE_PROGRESS, is_terminal, validate_transition
from app.services.quarantine import QuarantineStorage
from app.services.upload_service import persist_apk_upload

log = logging.getLogger("apkguard.jobs")


class ScanJobService:
    def __init__(
        self,
        *,
        settings: Settings,
        jobs: PersistentJobRepository,
        artifacts: ArtifactRepository,
        results: ImmutableResultRepository,
        quarantine: QuarantineStorage,
        queue: JobQueue,
    ) -> None:
        self.settings = settings
        self.jobs = jobs
        self.artifacts = artifacts
        self.results = results
        self.quarantine = quarantine
        self.queue = queue

    async def submit(self, upload: UploadFile, request_id: str) -> ScanJobStatusResponse:
        scan_id = str(uuid4())
        correlation_id = request_id
        original_filename = Path(upload.filename or "unknown.apk").name or "unknown.apk"
        self.jobs.create_job(
            scan_id=scan_id,
            original_filename=original_filename,
            request_id=request_id,
            correlation_id=correlation_id,
            max_attempts=self.settings.job_max_attempts,
            queue_backend=self.queue.backend_name,
            execution_mode=self.settings.analysis_isolation_mode,
        )
        self._transition(scan_id, JobState.VALIDATING, "Validating streamed APK upload.", "validating_upload")
        artifact = None
        try:
            artifact = await persist_apk_upload(upload, self.settings)
            quarantined = self.quarantine.store(artifact)
            artifact_model = self.artifacts.upsert(
                sha256=quarantined.sha256,
                storage_path=str(quarantined.quarantine_path),
                original_filename=quarantined.original_filename,
                size_bytes=quarantined.size_bytes,
                zip_entry_count=quarantined.zip_entry_count,
                total_uncompressed_bytes=quarantined.total_uncompressed_bytes,
            )
            self.jobs.attach_artifact(scan_id, artifact_model.artifact_id)
            self._transition(
                scan_id,
                JobState.QUARANTINED,
                "APK stored in content-addressed quarantine.",
                "quarantined",
                metadata={"deduplicated": quarantined.deduplicated, "sha256": quarantined.sha256},
            )
            self._transition(scan_id, JobState.QUEUED, "Scan job accepted by the configured queue.", "queued")
            self.queue.enqueue(scan_id)
            return self.status(scan_id)
        except InvalidUploadError as exc:
            self._fail_nonterminal(scan_id, exc.code.value, exc.message)
            raise
        except Exception as exc:
            self._fail_nonterminal(scan_id, type(exc).__name__, "Scan submission failed.")
            raise AppError(
                "Scan submission failed before queueing.",
                code=ErrorCode.INTERNAL_ERROR,
                status_code=500,
            ) from exc
        finally:
            if artifact is not None:
                artifact.cleanup()

    def status(self, scan_id: str) -> ScanJobStatusResponse:
        job = self._required(scan_id)
        artifact = self.jobs.artifact_for_job(scan_id)
        return self._status_model(job, artifact)

    def list(self, limit: int = 20, offset: int = 0) -> ScanJobListResponse:
        jobs = self.jobs.list(limit=limit, offset=offset)
        statuses = [self._status_model(job, self.jobs.artifact_for_job(job.scan_id)) for job in jobs]
        return ScanJobListResponse(scans=statuses, total=self.jobs.count())

    def progress(self, scan_id: str) -> ScanProgressResponse:
        job = self._required(scan_id)
        state = JobState(job.state)
        return ScanProgressResponse(
            scan_id=job.scan_id,
            state=state,
            progress=job.progress,
            current_stage=job.current_stage,
            attempt_count=job.attempt_count,
            cancel_requested=job.cancel_requested,
            updated_at=job.updated_at,
            terminal=is_terminal(state),
            result_available=self.results.exists(scan_id),
            message=job.error_message,
        )

    def events(self, scan_id: str) -> ScanEventListResponse:
        self._required(scan_id)
        records = self.jobs.events(scan_id)
        events = [
            ScanEventResponse(
                event_id=record.event_id,
                sequence=record.sequence,
                scan_id=record.scan_id,
                event_type=record.event_type,
                previous_state=record.previous_state,
                new_state=record.new_state,
                message=record.message,
                metadata=record.event_metadata,
                created_at=record.created_at,
            )
            for record in records
        ]
        return ScanEventListResponse(scan_id=scan_id, events=events, total=len(events))

    def result(self, scan_id: str) -> ScanResponse:
        job = self._required(scan_id)
        state = JobState(job.state)
        if state not in {JobState.COMPLETED, JobState.PARTIAL}:
            raise AppError(
                "Scan result is not available yet.",
                code=ErrorCode.INVALID_REQUEST,
                status_code=409,
                details={"scan_id": scan_id, "state": state.value},
            )
        result = self.results.get(scan_id)
        if result is None:
            raise AppError(
                "Scan result metadata exists but the immutable payload is unavailable.",
                code=ErrorCode.INTERNAL_ERROR,
                status_code=500,
            )
        return ScanResponse.model_validate(result)

    def cancel(self, scan_id: str) -> CancelScanResponse:
        job = self._required(scan_id)
        state = JobState(job.state)
        if is_terminal(state):
            return CancelScanResponse(
                scan_id=scan_id,
                state=state,
                cancel_requested=job.cancel_requested,
                message="Scan is already in a terminal state.",
            )
        self.jobs.request_cancel(scan_id)
        if state in {JobState.CREATED, JobState.VALIDATING, JobState.QUARANTINED, JobState.QUEUED}:
            self._transition(scan_id, JobState.CANCELLED, "Scan cancelled before worker execution.", "cancelled")
        elif state == JobState.RUNNING:
            self._transition(
                scan_id,
                JobState.CANCEL_REQUESTED,
                "Cancellation will be enforced at the next worker checkpoint.",
                "cancel_requested",
                event_type=JobEventType.CANCELLATION,
            )
        updated = self._required(scan_id)
        return CancelScanResponse(
            scan_id=scan_id,
            state=JobState(updated.state),
            cancel_requested=updated.cancel_requested,
            message="Cancellation request recorded.",
        )

    def recover_stale_jobs(self) -> int:
        recovered = 0
        for job in self.jobs.stale_jobs(self.settings.stale_job_seconds):
            if job.cancel_requested:
                self._transition(
                    job.scan_id,
                    JobState.CANCELLED,
                    "Stale cancelled job finalized during worker recovery.",
                    "cancelled",
                    event_type=JobEventType.RECOVERY,
                )
            else:
                self._transition(
                    job.scan_id,
                    JobState.QUEUED,
                    "Stale worker lease recovered and scan requeued.",
                    "recovered_queued",
                    event_type=JobEventType.RECOVERY,
                )
                self.queue.enqueue(job.scan_id)
            recovered += 1
        return recovered

    def history_records(self, limit: int = 20) -> list[dict]:
        records = []
        for job in self.jobs.list(limit=limit):
            artifact = self.jobs.artifact_for_job(job.scan_id)
            records.append(
                {
                    "scan_id": job.scan_id,
                    "schema_version": self.settings.schema_version,
                    "filename": job.original_filename,
                    "risk_score": self._risk_score(job.scan_id),
                    "severity": self._severity(job.scan_id),
                    "scan_time": job.created_at.isoformat(),
                    "package": self._package(job.scan_id),
                    "sha256": artifact.sha256 if artifact else "",
                    "result_status": job.state,
                    "result_digest": job.result_digest,
                    "progress": job.progress,
                }
            )
        return records

    def _risk_score(self, scan_id: str) -> int:
        result = self.results.get(scan_id)
        return int(result.get("risk_score", 0)) if result else 0

    def _severity(self, scan_id: str) -> str:
        result = self.results.get(scan_id)
        return str(result.get("severity", "INFO")) if result else "INFO"

    def _package(self, scan_id: str) -> str:
        result = self.results.get(scan_id)
        return str((result.get("app_info") or {}).get("package_name", "")) if result else ""

    def _required(self, scan_id: str):
        job = self.jobs.get(scan_id)
        if job is None:
            raise AppError(
                "Scan job was not found.",
                code=ErrorCode.NOT_FOUND,
                status_code=404,
                details={"scan_id": scan_id},
            )
        return job

    def _transition(
        self,
        scan_id: str,
        target: JobState,
        message: str,
        stage: str,
        *,
        event_type: JobEventType = JobEventType.STATE_TRANSITION,
        error_code: str | None = None,
        error_message: str | None = None,
        metadata: dict | None = None,
    ):
        current = JobState(self._required(scan_id).state)
        validate_transition(current, target)
        return self.jobs.transition(
            scan_id,
            new_state=target,
            progress=STATE_PROGRESS[target],
            current_stage=stage,
            message=message,
            event_type=event_type,
            error_code=error_code,
            error_message=error_message,
            metadata=metadata,
        )

    def _fail_nonterminal(self, scan_id: str, error_code: str, error_message: str) -> None:
        job = self.jobs.get(scan_id)
        if job and not is_terminal(JobState(job.state)):
            self._transition(
                scan_id,
                JobState.FAILED,
                error_message,
                "failed",
                event_type=JobEventType.ERROR,
                error_code=error_code,
                error_message=error_message,
            )

    def _status_model(self, job, artifact) -> ScanJobStatusResponse:
        base = self.settings.api_prefix
        return ScanJobStatusResponse(
            scan_id=job.scan_id,
            request_id=job.request_id,
            correlation_id=job.correlation_id,
            state=job.state,
            progress=job.progress,
            current_stage=job.current_stage,
            original_filename=job.original_filename,
            apk_sha256=artifact.sha256 if artifact else None,
            size_bytes=artifact.size_bytes if artifact else None,
            attempt_count=job.attempt_count,
            max_attempts=job.max_attempts,
            cancel_requested=job.cancel_requested,
            result_available=self.results.exists(job.scan_id),
            result_digest=job.result_digest,
            error_code=job.error_code,
            error_message=job.error_message,
            created_at=job.created_at,
            updated_at=job.updated_at,
            started_at=job.started_at,
            completed_at=job.completed_at,
            heartbeat_at=job.heartbeat_at,
            queue_backend=job.queue_backend,
            execution_mode=job.execution_mode,
            links={
                "self": f"{base}/scans/{job.scan_id}",
                "progress": f"{base}/scans/{job.scan_id}/progress",
                "events": f"{base}/scans/{job.scan_id}/events",
                "result": f"{base}/scans/{job.scan_id}/result",
                "cancel": f"{base}/scans/{job.scan_id}/cancel",
                "report": f"{base}/scans/{job.scan_id}/report",
            },
        )


class ScanJobExecutor:
    def __init__(
        self,
        *,
        settings: Settings,
        jobs: PersistentJobRepository,
        results: ImmutableResultRepository,
        queue: JobQueue,
        runner,
    ) -> None:
        self.settings = settings
        self.jobs = jobs
        self.results = results
        self.queue = queue
        self.runner = runner

    def execute(self, scan_id: str) -> None:
        job = self.jobs.get(scan_id)
        if job is None or is_terminal(JobState(job.state)):
            return
        if self.results.exists(scan_id):
            self._finalize_existing_result(scan_id)
            return
        if job.cancel_requested:
            self._terminal(scan_id, JobState.CANCELLED, "Cancelled before worker execution.")
            return
        artifact = self.jobs.artifact_for_job(scan_id)
        if artifact is None:
            self._terminal(scan_id, JobState.FAILED, "Quarantined artifact metadata is missing.", "ARTIFACT_MISSING")
            return

        while True:
            job = self.jobs.get(scan_id)
            if job is None or is_terminal(JobState(job.state)):
                return
            if job.cancel_requested:
                self._terminal(scan_id, JobState.CANCELLED, "Cancellation enforced before attempt.")
                return
            if JobState(job.state) != JobState.RUNNING:
                self._transition(scan_id, JobState.RUNNING, "Worker started analysis.", "analysis_running")
            job = self.jobs.increment_attempt(scan_id)
            request = AnalysisRequest(
                scan_id=scan_id,
                request_id=job.request_id,
                filename=job.original_filename,
                artifact_path=Path(artifact.storage_path),
                sha256=artifact.sha256,
                size_bytes=artifact.size_bytes,
                zip_entry_count=artifact.zip_entry_count,
                total_uncompressed_bytes=artifact.total_uncompressed_bytes,
                execution_mode=f"asynchronous_{job.execution_mode}_phase3",
            )
            try:
                result = self.runner.run(
                    request,
                    timeout_seconds=self.settings.job_timeout_seconds,
                    cancel_check=lambda: bool((self.jobs.get(scan_id) or job).cancel_requested),
                    heartbeat=lambda: self.jobs.heartbeat(scan_id),
                )
                self.jobs.update_progress(scan_id, 95, "persisting_result", "Persisting immutable result.")
                payload = result.model_dump(mode="json")
                self.results.save(scan_id, payload, result.schema_version, result.result_digest)
                self.jobs.set_result_digest(scan_id, result.result_digest)
                terminal = JobState.PARTIAL if result.result_status == ResultStatus.PARTIAL else JobState.COMPLETED
                self._transition(
                    scan_id,
                    terminal,
                    "Immutable analysis result stored.",
                    "completed" if terminal == JobState.COMPLETED else "partial",
                    event_type=JobEventType.RESULT_STORED,
                    metadata={"result_digest": result.result_digest},
                )
                return
            except AnalysisCancelledError as exc:
                self._terminal(scan_id, JobState.CANCELLED, str(exc))
                return
            except AnalysisTimedOutError as exc:
                self._terminal(scan_id, JobState.TIMED_OUT, str(exc), "ANALYSIS_TIMEOUT")
                return
            except Exception as exc:
                log.exception("Scan attempt failed scan_id=%s attempt=%s", scan_id, job.attempt_count)
                latest = self.jobs.get(scan_id)
                if latest and latest.attempt_count < latest.max_attempts and not latest.cancel_requested:
                    self._transition(
                        scan_id,
                        JobState.QUEUED,
                        "Retryable analysis failure; retry scheduled.",
                        "retry_queued",
                        event_type=JobEventType.ERROR,
                        error_code=type(exc).__name__,
                        error_message="Analysis attempt failed; retry scheduled.",
                        metadata={"attempt": latest.attempt_count},
                    )
                    if self.settings.job_retry_delay_seconds:
                        sleep(self.settings.job_retry_delay_seconds)
                    if self.queue.backend_name == "redis":
                        self.queue.enqueue(scan_id)
                        return
                    continue
                self._terminal(scan_id, JobState.FAILED, "Analysis failed after all attempts.", type(exc).__name__)
                return

    def _finalize_existing_result(self, scan_id: str) -> None:
        payload = self.results.get(scan_id)
        job = self.jobs.get(scan_id)
        if payload is None or job is None:
            return
        if JobState(job.state) not in {JobState.RUNNING, JobState.CANCEL_REQUESTED}:
            self._transition(scan_id, JobState.RUNNING, "Recovering an already persisted immutable result.", "recovery")
        self.jobs.set_result_digest(scan_id, str(payload.get("result_digest", "")))
        result_status = str(payload.get("result_status", ResultStatus.COMPLETED.value))
        terminal = JobState.PARTIAL if result_status == ResultStatus.PARTIAL.value else JobState.COMPLETED
        self._transition(
            scan_id,
            terminal,
            "Recovered immutable result after an interrupted state update.",
            "completed" if terminal == JobState.COMPLETED else "partial",
            event_type=JobEventType.RECOVERY,
        )

    def _transition(
        self,
        scan_id: str,
        target: JobState,
        message: str,
        stage: str,
        *,
        event_type: JobEventType = JobEventType.STATE_TRANSITION,
        error_code: str | None = None,
        error_message: str | None = None,
        metadata: dict | None = None,
    ):
        current_job = self.jobs.get(scan_id)
        if current_job is None:
            return None
        current = JobState(current_job.state)
        validate_transition(current, target)
        return self.jobs.transition(
            scan_id,
            new_state=target,
            progress=STATE_PROGRESS[target],
            current_stage=stage,
            message=message,
            event_type=event_type,
            error_code=error_code,
            error_message=error_message,
            metadata=metadata,
        )

    def _terminal(self, scan_id: str, state: JobState, message: str, error_code: str | None = None) -> None:
        self._transition(
            scan_id,
            state,
            message,
            state.value.lower(),
            event_type=JobEventType.ERROR if state in {JobState.FAILED, JobState.TIMED_OUT} else JobEventType.CANCELLATION,
            error_code=error_code,
            error_message=message if error_code else None,
        )
