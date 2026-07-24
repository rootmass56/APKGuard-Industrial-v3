from pathlib import Path
from uuid import uuid4

import pytest

from app.core.config import Settings
from app.db.session import Database
from app.schemas.common import JobState
from app.services.job_repository import ArtifactRepository, ImmutableResultRepository, PersistentJobRepository


@pytest.fixture()
def repositories(tmp_path: Path):
    settings = Settings(database_url=f"sqlite:///{(tmp_path / 'jobs.db').as_posix()}", auto_create_database=True)
    database = Database(settings)
    database.initialize()
    yield PersistentJobRepository(database), ArtifactRepository(database), ImmutableResultRepository(database)
    database.dispose()


def test_artifact_deduplication_and_immutable_result(repositories):
    jobs, artifacts, results = repositories
    artifact1 = artifacts.upsert(
        sha256="a" * 64,
        storage_path="/quarantine/a.apk",
        original_filename="one.apk",
        size_bytes=100,
        zip_entry_count=2,
        total_uncompressed_bytes=200,
    )
    artifact2 = artifacts.upsert(
        sha256="a" * 64,
        storage_path="/quarantine/a.apk",
        original_filename="two.apk",
        size_bytes=100,
        zip_entry_count=2,
        total_uncompressed_bytes=200,
    )
    assert artifact1.artifact_id == artifact2.artifact_id

    scan_id = str(uuid4())
    jobs.create_job(
        scan_id=scan_id,
        original_filename="one.apk",
        request_id="request",
        correlation_id="request",
        max_attempts=2,
        queue_backend="eager",
        execution_mode="inline",
    )
    jobs.attach_artifact(scan_id, artifact1.artifact_id)
    payload = {"scan_id": scan_id, "result_digest": "b" * 64}
    results.save(scan_id, payload, "1.1", "b" * 64)
    assert results.get(scan_id) == payload
    with pytest.raises(ValueError):
        results.save(scan_id, {"scan_id": scan_id, "result_digest": "c" * 64, "changed": True}, "1.1", "c" * 64)


def test_job_events_are_ordered(repositories):
    jobs, _, _ = repositories
    scan_id = str(uuid4())
    jobs.create_job(
        scan_id=scan_id,
        original_filename="one.apk",
        request_id="request",
        correlation_id="request",
        max_attempts=2,
        queue_backend="eager",
        execution_mode="inline",
    )
    jobs.transition(
        scan_id,
        new_state=JobState.VALIDATING,
        progress=10,
        current_stage="validating",
        message="Validating",
    )
    events = jobs.events(scan_id)
    assert [event.sequence for event in events] == [1, 2]


def test_database_model_rejects_result_updates(repositories):
    jobs, _, results = repositories
    scan_id = str(uuid4())
    jobs.create_job(
        scan_id=scan_id,
        original_filename="one.apk",
        request_id="request",
        correlation_id="request",
        max_attempts=2,
        queue_backend="eager",
        execution_mode="inline",
    )
    payload = {"scan_id": scan_id, "result_digest": "f" * 64}
    results.save(scan_id, payload, "1.1", "f" * 64)
    from app.db.models import ScanResultModel

    with pytest.raises(RuntimeError):
        with results.database.session() as session:
            model = session.get(ScanResultModel, scan_id)
            model.result_json = "{}"
            session.flush()
