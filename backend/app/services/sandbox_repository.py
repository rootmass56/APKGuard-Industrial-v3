"""Persistence for Phase 4 sandbox sessions and immutable runtime events."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import func, select

from app.db.models import SandboxEventModel, SandboxSessionModel
from app.db.session import Database
from app.schemas.common import SandboxState
from app.schemas.dynamic import RuntimeObservation


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class SandboxRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def create_session(
        self,
        *,
        session_id: str,
        scan_id: str,
        worker_id: str,
        avd_name: str,
        network_mode: str,
        instrumentation_mode: str,
        policy_digest: str,
        artifact_directory: str,
    ) -> SandboxSessionModel:
        with self.database.session() as session:
            model = SandboxSessionModel(
                session_id=session_id,
                scan_id=scan_id,
                state=SandboxState.CREATED.value,
                worker_id=worker_id,
                avd_name=avd_name,
                network_mode=network_mode,
                instrumentation_mode=instrumentation_mode,
                policy_digest=policy_digest,
                artifact_directory=artifact_directory,
            )
            session.add(model)
            session.flush()
            return model

    def transition(
        self,
        session_id: str,
        state: SandboxState,
        *,
        emulator_serial: str | None = None,
        error_code: str | None = None,
        error_message: str | None = None,
    ) -> SandboxSessionModel | None:
        now = utc_now()
        with self.database.session() as session:
            model = session.get(SandboxSessionModel, session_id)
            if model is None:
                return None
            model.state = state.value
            model.updated_at = now
            if emulator_serial:
                model.emulator_serial = emulator_serial
            if model.started_at is None and state not in {SandboxState.CREATED, SandboxState.PREFLIGHT}:
                model.started_at = now
            if state in {
                SandboxState.COMPLETED,
                SandboxState.FAILED,
                SandboxState.CANCELLED,
                SandboxState.TIMED_OUT,
            }:
                model.completed_at = now
            model.error_code = error_code
            model.error_message = error_message
            session.flush()
            return model

    def append_observations(self, session_id: str, observations: list[RuntimeObservation]) -> None:
        if not observations:
            return
        with self.database.session() as session:
            current = session.scalar(
                select(func.max(SandboxEventModel.sequence)).where(SandboxEventModel.session_id == session_id)
            )
            sequence = int(current or 0) + 1
            for observation in observations:
                session.add(
                    SandboxEventModel(
                        session_id=session_id,
                        sequence=sequence,
                        category=str(observation.category),
                        event_type=observation.event_type,
                        severity=str(observation.severity),
                        observed_at=observation.observed_at,
                        source=observation.source,
                        payload=observation.model_dump(mode="json"),
                        evidence_digest=observation.evidence_digest,
                    )
                )
                sequence += 1

    def get_by_scan(self, scan_id: str) -> SandboxSessionModel | None:
        with self.database.session() as session:
            return session.scalar(select(SandboxSessionModel).where(SandboxSessionModel.scan_id == scan_id))

    def get(self, session_id: str) -> SandboxSessionModel | None:
        with self.database.session() as session:
            return session.get(SandboxSessionModel, session_id)

    def events(self, session_id: str) -> list[SandboxEventModel]:
        with self.database.session() as session:
            return list(
                session.scalars(
                    select(SandboxEventModel)
                    .where(SandboxEventModel.session_id == session_id)
                    .order_by(SandboxEventModel.sequence)
                )
            )

    def stale_sessions(self, stale_seconds: int) -> list[SandboxSessionModel]:
        cutoff = utc_now().timestamp() - stale_seconds
        terminal = {
            SandboxState.COMPLETED.value,
            SandboxState.FAILED.value,
            SandboxState.CANCELLED.value,
            SandboxState.TIMED_OUT.value,
        }
        with self.database.session() as session:
            records = list(
                session.scalars(
                    select(SandboxSessionModel).where(SandboxSessionModel.state.not_in(terminal))
                )
            )
        return [record for record in records if record.updated_at.timestamp() < cutoff]
