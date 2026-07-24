"""Transactional repositories for persistent scan jobs and immutable results."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from app.db.models import ArtifactModel, ScanEventModel, ScanJobModel, ScanResultModel
from app.db.session import Database
from app.schemas.common import JobEventType, JobState


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class PersistentJobRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def create_job(
        self,
        *,
        scan_id: str,
        original_filename: str,
        request_id: str,
        correlation_id: str,
        max_attempts: int,
        queue_backend: str,
        execution_mode: str,
    ) -> ScanJobModel:
        now = utc_now()
        with self.database.session() as session:
            job = ScanJobModel(
                scan_id=scan_id,
                request_id=request_id,
                correlation_id=correlation_id,
                original_filename=original_filename,
                state=JobState.CREATED.value,
                progress=0,
                current_stage="created",
                attempt_count=0,
                max_attempts=max_attempts,
                cancel_requested=False,
                queue_backend=queue_backend,
                execution_mode=execution_mode,
                created_at=now,
                updated_at=now,
            )
            session.add(job)
            session.flush()
            self._append_event_in_session(
                session,
                job,
                event_type=JobEventType.CREATED,
                message="Scan job created.",
                previous_state=None,
                new_state=JobState.CREATED,
            )
            session.refresh(job)
            return job

    def get(self, scan_id: str, *, for_update: bool = False) -> ScanJobModel | None:
        with self.database.session() as session:
            statement = select(ScanJobModel).where(ScanJobModel.scan_id == scan_id)
            if for_update:
                statement = statement.with_for_update()
            return session.scalar(statement)

    def list(self, *, limit: int = 20, offset: int = 0) -> list[ScanJobModel]:
        with self.database.session() as session:
            statement = (
                select(ScanJobModel)
                .order_by(ScanJobModel.created_at.desc())
                .offset(max(offset, 0))
                .limit(max(1, min(limit, 200)))
            )
            return list(session.scalars(statement))

    def count(self) -> int:
        with self.database.session() as session:
            return int(session.scalar(select(func.count()).select_from(ScanJobModel)) or 0)

    def attach_artifact(self, scan_id: str, artifact_id: str) -> ScanJobModel:
        with self.database.session() as session:
            job = self._required_job(session, scan_id)
            job.artifact_id = artifact_id
            job.updated_at = utc_now()
            session.flush()
            session.refresh(job)
            return job

    def transition(
        self,
        scan_id: str,
        *,
        new_state: JobState,
        progress: int,
        current_stage: str,
        message: str,
        event_type: JobEventType = JobEventType.STATE_TRANSITION,
        error_code: str | None = None,
        error_message: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ScanJobModel:
        now = utc_now()
        with self.database.session() as session:
            job = self._required_job(session, scan_id, for_update=True)
            previous_state = JobState(job.state)
            job.state = new_state.value
            job.progress = min(max(progress, 0), 100)
            job.current_stage = current_stage
            job.updated_at = now
            job.error_code = error_code
            job.error_message = error_message
            if new_state == JobState.RUNNING and job.started_at is None:
                job.started_at = now
            if new_state in {
                JobState.COMPLETED,
                JobState.PARTIAL,
                JobState.FAILED,
                JobState.CANCELLED,
                JobState.TIMED_OUT,
            }:
                job.completed_at = now
            self._append_event_in_session(
                session,
                job,
                event_type=event_type,
                message=message,
                previous_state=previous_state,
                new_state=new_state,
                metadata=metadata,
            )
            session.flush()
            session.refresh(job)
            return job

    def update_progress(self, scan_id: str, progress: int, current_stage: str, message: str) -> ScanJobModel:
        with self.database.session() as session:
            job = self._required_job(session, scan_id, for_update=True)
            job.progress = min(max(progress, 0), 100)
            job.current_stage = current_stage
            job.updated_at = utc_now()
            self._append_event_in_session(
                session,
                job,
                event_type=JobEventType.PROGRESS,
                message=message,
                previous_state=JobState(job.state),
                new_state=JobState(job.state),
                metadata={"progress": job.progress, "stage": current_stage},
            )
            session.flush()
            session.refresh(job)
            return job

    def increment_attempt(self, scan_id: str) -> ScanJobModel:
        with self.database.session() as session:
            job = self._required_job(session, scan_id, for_update=True)
            job.attempt_count += 1
            job.heartbeat_at = utc_now()
            job.updated_at = job.heartbeat_at
            self._append_event_in_session(
                session,
                job,
                event_type=JobEventType.ATTEMPT,
                message=f"Starting analysis attempt {job.attempt_count} of {job.max_attempts}.",
                previous_state=JobState(job.state),
                new_state=JobState(job.state),
                metadata={"attempt": job.attempt_count, "max_attempts": job.max_attempts},
            )
            session.flush()
            session.refresh(job)
            return job

    def heartbeat(self, scan_id: str) -> None:
        with self.database.session() as session:
            job = self._required_job(session, scan_id, for_update=True)
            job.heartbeat_at = utc_now()
            job.updated_at = job.heartbeat_at

    def request_cancel(self, scan_id: str) -> ScanJobModel:
        with self.database.session() as session:
            job = self._required_job(session, scan_id, for_update=True)
            job.cancel_requested = True
            job.updated_at = utc_now()
            self._append_event_in_session(
                session,
                job,
                event_type=JobEventType.CANCELLATION,
                message="Cancellation requested.",
                previous_state=JobState(job.state),
                new_state=JobState(job.state),
            )
            session.flush()
            session.refresh(job)
            return job

    def set_result_digest(self, scan_id: str, result_digest: str) -> None:
        with self.database.session() as session:
            job = self._required_job(session, scan_id, for_update=True)
            job.result_digest = result_digest
            job.updated_at = utc_now()

    def events(self, scan_id: str) -> list[ScanEventModel]:
        with self.database.session() as session:
            statement = (
                select(ScanEventModel)
                .where(ScanEventModel.scan_id == scan_id)
                .order_by(ScanEventModel.sequence.asc())
            )
            return list(session.scalars(statement))

    def stale_jobs(self, stale_seconds: int) -> list[ScanJobModel]:
        cutoff = utc_now() - timedelta(seconds=stale_seconds)
        with self.database.session() as session:
            statement = select(ScanJobModel).where(
                ScanJobModel.state.in_([JobState.RUNNING.value, JobState.CANCEL_REQUESTED.value]),
                func.coalesce(ScanJobModel.heartbeat_at, ScanJobModel.updated_at) < cutoff,
            )
            return list(session.scalars(statement))

    def artifact_for_job(self, scan_id: str) -> ArtifactModel | None:
        with self.database.session() as session:
            statement = (
                select(ArtifactModel)
                .join(ScanJobModel, ScanJobModel.artifact_id == ArtifactModel.artifact_id)
                .where(ScanJobModel.scan_id == scan_id)
            )
            return session.scalar(statement)

    @staticmethod
    def _required_job(session, scan_id: str, *, for_update: bool = False) -> ScanJobModel:
        statement = select(ScanJobModel).where(ScanJobModel.scan_id == scan_id)
        if for_update:
            statement = statement.with_for_update()
        job = session.scalar(statement)
        if job is None:
            raise KeyError(scan_id)
        return job

    @staticmethod
    def _append_event_in_session(
        session,
        job: ScanJobModel,
        *,
        event_type: JobEventType,
        message: str,
        previous_state: JobState | None,
        new_state: JobState | None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        max_sequence = session.scalar(
            select(func.max(ScanEventModel.sequence)).where(ScanEventModel.scan_id == job.scan_id)
        )
        session.add(
            ScanEventModel(
                scan_id=job.scan_id,
                sequence=int(max_sequence or 0) + 1,
                event_type=event_type.value,
                previous_state=previous_state.value if previous_state else None,
                new_state=new_state.value if new_state else None,
                message=message,
                event_metadata=metadata or {},
                created_at=utc_now(),
            )
        )


class ArtifactRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def upsert(
        self,
        *,
        sha256: str,
        storage_path: str,
        original_filename: str,
        size_bytes: int,
        zip_entry_count: int,
        total_uncompressed_bytes: int,
    ) -> ArtifactModel:
        now = utc_now()
        try:
            with self.database.session() as session:
                artifact = session.scalar(select(ArtifactModel).where(ArtifactModel.sha256 == sha256))
                if artifact is None:
                    artifact = ArtifactModel(
                        artifact_id=str(uuid4()),
                        sha256=sha256,
                        storage_path=storage_path,
                        original_filename=original_filename,
                        size_bytes=size_bytes,
                        zip_entry_count=zip_entry_count,
                        total_uncompressed_bytes=total_uncompressed_bytes,
                        created_at=now,
                        last_seen_at=now,
                    )
                    session.add(artifact)
                else:
                    artifact.last_seen_at = now
                    if artifact.storage_path != storage_path:
                        artifact.storage_path = storage_path
                session.flush()
                session.refresh(artifact)
                return artifact
        except IntegrityError:
            # Concurrent uploads can race on the unique SHA-256 constraint. The winner is authoritative.
            with self.database.session() as session:
                artifact = session.scalar(select(ArtifactModel).where(ArtifactModel.sha256 == sha256))
                if artifact is None:
                    raise
                return artifact

    def get_by_sha256(self, sha256: str) -> ArtifactModel | None:
        with self.database.session() as session:
            return session.scalar(select(ArtifactModel).where(ArtifactModel.sha256 == sha256))


class ImmutableResultRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def save(self, scan_id: str, result: dict[str, Any], schema_version: str, result_digest: str) -> ScanResultModel:
        if str(result.get("scan_id")) != scan_id:
            raise ValueError("Result scan_id does not match the persistent job identifier.")
        if str(result.get("result_digest")) != result_digest:
            raise ValueError("Result digest metadata is inconsistent.")
        serialized = json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        with self.database.session() as session:
            existing = session.get(ScanResultModel, scan_id)
            if existing is not None:
                raise ValueError(f"Immutable result already exists for scan {scan_id}.")
            model = ScanResultModel(
                scan_id=scan_id,
                schema_version=schema_version,
                result_digest=result_digest,
                result_json=serialized,
                immutable_version=1,
                created_at=utc_now(),
            )
            session.add(model)
            session.flush()
            session.refresh(model)
            return model

    def get(self, scan_id: str) -> dict[str, Any] | None:
        with self.database.session() as session:
            model = session.get(ScanResultModel, scan_id)
            if model is None:
                return None
            return json.loads(model.result_json)

    def exists(self, scan_id: str) -> bool:
        with self.database.session() as session:
            return session.get(ScanResultModel, scan_id) is not None
