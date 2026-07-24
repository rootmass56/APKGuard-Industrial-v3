from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from app.core.config import Settings
from app.db.session import Database
from app.schemas.common import JobState, ResultStatus, Severity
from app.schemas.scan import PrivacyContext, ScanResponse, VersionedScoreResult
from app.services.job_repository import ArtifactRepository, ImmutableResultRepository, PersistentJobRepository
from app.services.job_service import ScanJobExecutor


class FakeQueue:
    backend_name = "fake"

    def enqueue(self, scan_id: str) -> None:
        self.last_enqueued = scan_id

    def ping(self) -> bool:
        return True


class FakeRunner:
    def run(self, request, *, timeout_seconds, cancel_check, heartbeat):
        del timeout_seconds
        assert not cancel_check()
        heartbeat()
        now = datetime.now(timezone.utc)
        digest = "d" * 64
        return ScanResponse(
            schema_version="1.1",
            scan_id=request.scan_id,
            request_id=request.request_id,
            result_status=ResultStatus.COMPLETED,
            filename=request.filename,
            scan_time=now,
            completed_at=now,
            apk_sha256=request.sha256,
            upload_size_bytes=request.size_bytes,
            risk_score=0,
            severity=Severity.INFO,
            result_digest=digest,
            result_digest_scope="analysis_core_v1",
            execution_mode=request.execution_mode,
            analyzer_versions={"orchestrator": "test"},
            stages=[],
            evidence=[],
            findings=[],
            score=VersionedScoreResult(
                policy_version="test",
                final_score=0,
                severity=Severity.INFO,
                scoring_mode="static_only",
                static_score=0,
                dynamic_score=0,
            ),
            privacy=PrivacyContext(
                mode="local_only",
                cache_enabled=False,
                history_enabled=False,
                virustotal_hash_lookup_permitted=False,
                virustotal_file_upload_permitted=False,
                ai_permitted=False,
            ),
            integrity_note="Test immutable result.",
        )


def test_executor_persists_result_and_completes_job(tmp_path: Path):
    settings = Settings(
        database_url=f"sqlite:///{(tmp_path / 'executor.db').as_posix()}",
        auto_create_database=True,
        job_retry_delay_seconds=0,
    )
    database = Database(settings)
    database.initialize()
    jobs = PersistentJobRepository(database)
    artifacts = ArtifactRepository(database)
    results = ImmutableResultRepository(database)
    queue = FakeQueue()
    scan_id = str(uuid4())
    artifact_path = tmp_path / "artifact.apk"
    artifact_path.write_bytes(b"PK-test")
    artifact = artifacts.upsert(
        sha256="a" * 64,
        storage_path=str(artifact_path),
        original_filename="sample.apk",
        size_bytes=7,
        zip_entry_count=2,
        total_uncompressed_bytes=10,
    )
    jobs.create_job(
        scan_id=scan_id,
        original_filename="sample.apk",
        request_id="request",
        correlation_id="request",
        max_attempts=2,
        queue_backend="fake",
        execution_mode="inline",
    )
    jobs.attach_artifact(scan_id, artifact.artifact_id)
    jobs.transition(
        scan_id,
        new_state=JobState.VALIDATING,
        progress=10,
        current_stage="validating",
        message="Validating",
    )
    jobs.transition(
        scan_id,
        new_state=JobState.QUARANTINED,
        progress=20,
        current_stage="quarantined",
        message="Quarantined",
    )
    jobs.transition(
        scan_id,
        new_state=JobState.QUEUED,
        progress=30,
        current_stage="queued",
        message="Queued",
    )
    executor = ScanJobExecutor(
        settings=settings,
        jobs=jobs,
        results=results,
        queue=queue,
        runner=FakeRunner(),
    )
    executor.execute(scan_id)
    completed = jobs.get(scan_id)
    assert completed is not None
    assert completed.state == JobState.COMPLETED.value
    assert completed.progress == 100
    assert completed.attempt_count == 1
    assert results.exists(scan_id)
    assert results.get(scan_id)["scan_id"] == scan_id
    database.dispose()
