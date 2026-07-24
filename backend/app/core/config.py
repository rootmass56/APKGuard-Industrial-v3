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


def _env_csv(name: str, default: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in os.getenv(name, default).split(",") if item.strip())


def _privacy_mode() -> str:
    allowed = {"local_only", "hash_only", "cloud_enrichment", "private_enterprise"}
    configured = os.getenv("APKGUARD_PRIVACY_MODE", "local_only").strip().lower()
    return configured if configured in allowed else "local_only"


@dataclass(frozen=True, slots=True)
class Settings:
    """Immutable application settings resolved from environment variables."""

    app_name: str = "APKGuard Industrial v3"
    app_version: str = "3.0.0-phase1"
    api_version: str = "v1"
    api_prefix: str = "/api/v1"
    schema_version: str = "1.0"
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
    if settings.history_enabled:
        settings.history_file.parent.mkdir(parents=True, exist_ok=True)
    return settings
