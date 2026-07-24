"""FastAPI dependency factories."""

from __future__ import annotations

from functools import lru_cache

from app.core.config import get_settings
from app.services.capabilities import get_capabilities
from app.services.repositories import CacheRepository, HistoryRepository
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
def get_scan_service() -> ScanService:
    return ScanService(
        settings=get_settings(),
        capabilities=get_capabilities(),
        cache=get_cache_repository(),
        history=get_history_repository(),
    )
