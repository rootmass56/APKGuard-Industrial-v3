"""FastAPI dependency factories."""

from __future__ import annotations

from functools import lru_cache

from app.core.config import get_settings
from app.db.session import get_database
from app.dynamic_analysis.service import DynamicAnalysisService
from app.services.analysis_runner import InlineAnalysisRunner, SubprocessAnalysisRunner
from app.services.capabilities import get_capabilities
from app.services.job_queue import create_job_queue
from app.services.job_repository import ArtifactRepository, ImmutableResultRepository, PersistentJobRepository
from app.services.job_service import ScanJobExecutor, ScanJobService
from app.services.quarantine import QuarantineStorage
from app.services.repositories import CacheRepository, HistoryRepository
from app.services.sandbox_repository import SandboxRepository
from app.services.scan_service import ScanService


@lru_cache(maxsize=1)
def get_cache_repository() -> CacheRepository:
    settings = get_settings()
    return CacheRepository(settings.cache_dir, settings.cache_enabled, settings.schema_version)


@lru_cache(maxsize=1)
def get_history_repository() -> HistoryRepository:
    settings = get_settings()
    return HistoryRepository(settings.history_file, settings.history_enabled, settings.history_limit)


@lru_cache(maxsize=1)
def get_sandbox_repository() -> SandboxRepository:
    return SandboxRepository(get_database())


@lru_cache(maxsize=1)
def get_dynamic_analysis_service() -> DynamicAnalysisService:
    return DynamicAnalysisService(
        settings=get_settings(),
        repository=get_sandbox_repository(),
    )


@lru_cache(maxsize=1)
def get_scan_service() -> ScanService:
    return ScanService(
        settings=get_settings(),
        capabilities=get_capabilities(),
        cache=get_cache_repository(),
        history=get_history_repository(),
        dynamic_service=get_dynamic_analysis_service(),
    )


@lru_cache(maxsize=1)
def get_persistent_job_repository() -> PersistentJobRepository:
    return PersistentJobRepository(get_database())


@lru_cache(maxsize=1)
def get_artifact_repository() -> ArtifactRepository:
    return ArtifactRepository(get_database())


@lru_cache(maxsize=1)
def get_result_repository() -> ImmutableResultRepository:
    return ImmutableResultRepository(get_database())


@lru_cache(maxsize=1)
def get_quarantine_storage() -> QuarantineStorage:
    return QuarantineStorage(get_settings())


@lru_cache(maxsize=1)
def get_job_queue():
    return create_job_queue(get_settings())


@lru_cache(maxsize=1)
def get_analysis_runner():
    settings = get_settings()
    if settings.analysis_isolation_mode == "subprocess":
        return SubprocessAnalysisRunner()
    return InlineAnalysisRunner(get_scan_service())


@lru_cache(maxsize=1)
def get_job_executor() -> ScanJobExecutor:
    return ScanJobExecutor(
        settings=get_settings(),
        jobs=get_persistent_job_repository(),
        results=get_result_repository(),
        queue=get_job_queue(),
        runner=get_analysis_runner(),
    )


@lru_cache(maxsize=1)
def get_scan_job_service() -> ScanJobService:
    return ScanJobService(
        settings=get_settings(),
        jobs=get_persistent_job_repository(),
        artifacts=get_artifact_repository(),
        results=get_result_repository(),
        quarantine=get_quarantine_storage(),
        queue=get_job_queue(),
    )
