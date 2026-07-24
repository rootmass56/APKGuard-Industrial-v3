from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


from app.core.config import Settings
from app.db.session import Database
from app.schemas.common import JobState, ResultStatus, Severity
from app.schemas.scan import PrivacyContext, ScanResponse, VersionedScoreResult
from app.services.analysis_runner import AnalysisTimedOutError
from app.services.job_repository import ArtifactRepository, ImmutableResultRepository, PersistentJobRepository
from app.services.job_service import ScanJobExecutor


class FakeQueue:
    backend_name = "fake"

    def enqueue(self, scan_id: str) -> None:
        self.last_enqueued = scan_id

    def ping(self) -> bool:
        return True


def _result(request) -> ScanResponse:
    now = datetime.now(timezone.utc)
    digest = "e" * 64
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
        integrity_note="Test result.",
    )


class TimeoutRunner:
    def run(self, request, *, timeout_seconds, cancel_check, heartbeat):
        del request, timeout_seconds, cancel_check, heartbeat
        raise AnalysisTimedOutError("controlled timeout")


class FlakyRunner:
    def __init__(self):
        self.calls = 0

    def run(self, request, *, timeout_seconds, cancel_check, heartbeat):
        del timeout_seconds, cancel_check
        heartbeat()
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError("controlled first-attempt failure")
        return _result(request)


def _fixture(tmp_path: Path, runner, *, max_attempts: int = 2):
    settings = Settings(
        database_url=f"sqlite:///{(tmp_path / f'{uuid4()}.db').as_posix()}",
        auto_create_database=True,
        job_retry_delay_seconds=0,
        job_max_attempts=max_attempts,
    )
    database = Database(settings)
    database.initialize()
    jobs = PersistentJobRepository(database)
    artifacts = ArtifactRepository(database)
    results = ImmutableResultRepository(database)
    scan_id = str(uuid4())
    artifact_path = tmp_path / f"{scan_id}.apk"
    artifact_path.write_bytes(b"PK-test")
    artifact = artifacts.upsert(
        sha256=(scan_id.replace("-", "") * 2)[:64],
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
        max_attempts=max_attempts,
        queue_backend="fake",
        execution_mode="inline",
    )
    jobs.attach_artifact(scan_id, artifact.artifact_id)
    for state, progress, stage in [
        (JobState.VALIDATING, 10, "validating"),
        (JobState.QUARANTINED, 20, "quarantined"),
        (JobState.QUEUED, 30, "queued"),
    ]:
        jobs.transition(
            scan_id,
            new_state=state,
            progress=progress,
            current_stage=stage,
            message=stage,
        )
    executor = ScanJobExecutor(
        settings=settings,
        jobs=jobs,
        results=results,
        queue=FakeQueue(),
        runner=runner,
    )
    return database, jobs, results, executor, scan_id


def test_timeout_moves_job_to_terminal_state(tmp_path: Path):
    database, jobs, _, executor, scan_id = _fixture(tmp_path, TimeoutRunner())
    executor.execute(scan_id)
    job = jobs.get(scan_id)
    assert job is not None
    assert job.state == JobState.TIMED_OUT.value
    database.dispose()


def test_retry_succeeds_on_second_attempt(tmp_path: Path):
    runner = FlakyRunner()
    database, jobs, results, executor, scan_id = _fixture(tmp_path, runner)
    executor.execute(scan_id)
    job = jobs.get(scan_id)
    assert job is not None
    assert job.state == JobState.COMPLETED.value
    assert job.attempt_count == 2
    assert runner.calls == 2
    assert results.exists(scan_id)
    database.dispose()


def test_cancelled_queued_job_never_runs(tmp_path: Path):
    runner = FlakyRunner()
    database, jobs, results, executor, scan_id = _fixture(tmp_path, runner)
    jobs.request_cancel(scan_id)
    executor.execute(scan_id)
    job = jobs.get(scan_id)
    assert job is not None
    assert job.state == JobState.CANCELLED.value
    assert runner.calls == 0
    assert not results.exists(scan_id)
    database.dispose()
