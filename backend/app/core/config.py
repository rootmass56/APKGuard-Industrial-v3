"""Central, typed environment configuration for APKGuard Industrial v3."""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv

BACKEND_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(BACKEND_ROOT / ".env")


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        parsed = int(raw)
    except ValueError:
        return default
    return min(max(parsed, minimum), maximum)


def _env_float(name: str, default: float, minimum: float, maximum: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        parsed = float(raw)
    except ValueError:
        return default
    return min(max(parsed, minimum), maximum)


def _env_csv(name: str, default: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in os.getenv(name, default).split(",") if item.strip())


def _privacy_mode() -> str:
    allowed = {"local_only", "hash_only", "cloud_enrichment", "private_enterprise"}
    configured = os.getenv("APKGUARD_PRIVACY_MODE", "local_only").strip().lower()
    return configured if configured in allowed else "local_only"


def _queue_backend() -> str:
    configured = os.getenv("APKGUARD_QUEUE_BACKEND", "eager").strip().lower()
    return configured if configured in {"eager", "redis"} else "eager"


def _analysis_isolation_mode() -> str:
    configured = os.getenv("APKGUARD_ANALYSIS_ISOLATION", "inline").strip().lower()
    return configured if configured in {"inline", "subprocess"} else "inline"


@dataclass(frozen=True, slots=True)
class Settings:
    """Immutable application settings resolved from environment variables."""

    app_name: str = "APKGuard Industrial v3"
    app_version: str = "3.2.0-phase3"
    api_version: str = "v1"
    api_prefix: str = "/api/v1"
    schema_version: str = "1.2"
    environment: str = os.getenv("APKGUARD_ENVIRONMENT", "development")
    log_level: str = os.getenv("APKGUARD_LOG_LEVEL", "INFO").upper()
    log_format: str = os.getenv("APKGUARD_LOG_FORMAT", "text").lower()

    max_upload_mb: int = _env_int("APKGUARD_MAX_UPLOAD_MB", 100, 1, 2048)
    max_zip_entries: int = _env_int("APKGUARD_MAX_ZIP_ENTRIES", 10000, 10, 100000)
    max_uncompressed_mb: int = _env_int("APKGUARD_MAX_UNCOMPRESSED_MB", 1024, 10, 8192)
    max_compression_ratio: int = _env_int("APKGUARD_MAX_COMPRESSION_RATIO", 250, 10, 10000)

    cache_enabled: bool = _env_bool("APKGUARD_ENABLE_CACHE", True)
    history_enabled: bool = _env_bool("APKGUARD_ENABLE_HISTORY", True)
    history_limit: int = _env_int("APKGUARD_HISTORY_LIMIT", 50, 1, 10000)
    virustotal_upload_enabled: bool = _env_bool("APKGUARD_ALLOW_VT_UPLOAD", False)
    privacy_mode: str = _privacy_mode()
    dynamic_mode: str = os.getenv("APKGUARD_DYNAMIC_MODE", "disabled").strip().lower()

    cors_origins: tuple[str, ...] = _env_csv(
        "APKGUARD_CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173",
    )

    cache_dir: Path = Path(os.getenv("APKGUARD_CACHE_DIR", str(BACKEND_ROOT / "cache"))).expanduser()
    history_file: Path = Path(
        os.getenv("APKGUARD_HISTORY_FILE", str(Path.home() / "apkguard" / "scan_history.json"))
    ).expanduser()

    database_url: str = os.getenv(
        "APKGUARD_DATABASE_URL",
        f"sqlite:///{(BACKEND_ROOT / 'data' / 'apkguard.db').as_posix()}",
    ).strip()
    database_echo: bool = _env_bool("APKGUARD_DATABASE_ECHO", False)
    auto_create_database: bool = _env_bool("APKGUARD_AUTO_CREATE_DATABASE", False)
    quarantine_dir: Path = Path(
        os.getenv("APKGUARD_QUARANTINE_DIR", str(BACKEND_ROOT / "data" / "quarantine"))
    ).expanduser()
    quarantine_retention_days: int = _env_int("APKGUARD_QUARANTINE_RETENTION_DAYS", 30, 1, 3650)

    queue_backend: str = _queue_backend()
    redis_url: str = os.getenv("APKGUARD_REDIS_URL", "redis://localhost:6379/0").strip()
    redis_queue_name: str = os.getenv("APKGUARD_REDIS_QUEUE", "apkguard:scan-jobs").strip()
    worker_poll_seconds: float = _env_float("APKGUARD_WORKER_POLL_SECONDS", 2.0, 0.1, 60.0)
    job_timeout_seconds: int = _env_int("APKGUARD_JOB_TIMEOUT_SECONDS", 900, 10, 86400)
    job_max_attempts: int = _env_int("APKGUARD_JOB_MAX_ATTEMPTS", 2, 1, 10)
    job_retry_delay_seconds: float = _env_float("APKGUARD_JOB_RETRY_DELAY_SECONDS", 1.0, 0.0, 300.0)
    stale_job_seconds: int = _env_int("APKGUARD_STALE_JOB_SECONDS", 1800, 30, 86400)
    analysis_isolation_mode: str = _analysis_isolation_mode()

    vt_api_key: str = os.getenv("VT_API_KEY", "").strip()
    groq_api_key: str = os.getenv("GROQ_API_KEY", "").strip()
    siem_webhook_url: str = (
        os.getenv("SIEM_WEBHOOK_URL", "").strip()
        or os.getenv("BOI_SIEM_WEBHOOK", "").strip()
    )
    siem_threshold: int = _env_int("SIEM_THRESHOLD", _env_int("BOI_SIEM_THRESHOLD", 60, 0, 100), 0, 100)

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_mb * 1024 * 1024

    @property
    def max_uncompressed_bytes(self) -> int:
        return self.max_uncompressed_mb * 1024 * 1024

    @property
    def ai_allowed_by_policy(self) -> bool:
        return self.privacy_mode in {"cloud_enrichment", "private_enterprise"}

    @property
    def hash_reputation_allowed_by_policy(self) -> bool:
        return self.privacy_mode in {"hash_only", "cloud_enrichment", "private_enterprise"}

    @property
    def public_threat_feeds_allowed_by_policy(self) -> bool:
        return self.privacy_mode in {"hash_only", "cloud_enrichment", "private_enterprise"}


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide immutable settings object."""
    settings = Settings()
    settings.cache_dir.mkdir(parents=True, exist_ok=True)
    settings.quarantine_dir.mkdir(parents=True, exist_ok=True)
    if settings.history_enabled:
        settings.history_file.parent.mkdir(parents=True, exist_ok=True)
    return settings
