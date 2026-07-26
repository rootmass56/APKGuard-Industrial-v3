from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.core.config import Settings
from app.db.models import SandboxEventModel, ScanJobModel
from app.db.session import Database
from app.schemas.common import JobState, SandboxEventCategory, Severity
from app.dynamic_analysis.events import make_observation
from app.services.sandbox_repository import SandboxRepository


def test_sandbox_sessions_and_events_are_persisted_immutably(tmp_path: Path):
    settings = Settings(
        database_url=f"sqlite:///{(tmp_path / 'phase4.db').as_posix()}",
        auto_create_database=True,
        quarantine_dir=tmp_path / "quarantine",
        sandbox_workspace_dir=tmp_path / "sessions",
    )
    database = Database(settings)
    database.initialize()
    with database.session() as session:
        session.add(
            ScanJobModel(
                scan_id="scan-1",
                request_id="request-1",
                correlation_id="request-1",
                original_filename="safe.apk",
                state=JobState.RUNNING.value,
                progress=50,
                current_stage="dynamic",
                attempt_count=1,
                max_attempts=2,
                cancel_requested=False,
                queue_backend="redis",
                execution_mode="subprocess",
            )
        )
    repository = SandboxRepository(database)
    repository.create_session(
        session_id="session-1",
        scan_id="scan-1",
        worker_id="worker-1",
        avd_name="APKGuard_API_35",
        network_mode="offline",
        instrumentation_mode="logcat_only",
        policy_digest="a" * 64,
        artifact_directory="session-1",
    )
    observation = make_observation(
        session_id="session-1",
        sequence=1,
        package_name="com.example.safe",
        category=SandboxEventCategory.LIFECYCLE,
        event_type="application_launch",
        title="Application launched",
        description="Launch observed",
        source="test",
        observed_at=datetime(2026, 7, 24, tzinfo=timezone.utc),
        severity=Severity.INFO,
    )
    repository.append_observations("session-1", [observation])
    records = repository.events("session-1")
    assert len(records) == 1
    assert records[0].evidence_digest == observation.evidence_digest
    with pytest.raises(RuntimeError, match="immutable observations"):
        with database.session() as session:
            record = session.get(SandboxEventModel, records[0].event_id)
            record.payload = {"tampered": True}
