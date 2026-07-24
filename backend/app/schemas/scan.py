"""Versioned scan, stage, score, health, and history response contracts."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.common import ResultStatus, Severity, StageStatus
from app.schemas.evidence import EvidenceRecord, Finding


class ScanStageResult(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    stage: str
    status: StageStatus
    analyzer: str
    analyzer_version: str
    started_at: datetime
    completed_at: datetime
    duration_ms: int = Field(ge=0)
    evidence_count: int = Field(default=0, ge=0)
    finding_count: int = Field(default=0, ge=0)
    message: str | None = None
    error_code: str | None = None


class ScoreComponent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    category: str
    points: int
    max_points: int | None = None
    detail: str
    evidence_ids: list[str] = Field(default_factory=list)


class VersionedScoreResult(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    policy_version: str
    final_score: int = Field(ge=0, le=100)
    severity: Severity
    scoring_mode: str
    static_score: int = Field(ge=0, le=100)
    dynamic_score: int = Field(ge=0, le=100)
    components: list[ScoreComponent] = Field(default_factory=list)
    dynamic_components: list[ScoreComponent] = Field(default_factory=list)
    overrides: list[str] = Field(default_factory=list)
    model_advisory_applied: bool = False


class PrivacyContext(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: str
    cache_enabled: bool
    history_enabled: bool
    virustotal_hash_lookup_permitted: bool
    virustotal_file_upload_permitted: bool
    ai_permitted: bool
    external_services_used: list[str] = Field(default_factory=list)


class ScanResponse(BaseModel):
    model_config = ConfigDict(extra="allow", use_enum_values=True)

    schema_version: str
    scan_id: str
    request_id: str
    result_status: ResultStatus
    filename: str
    scan_time: datetime
    completed_at: datetime
    apk_sha256: str
    upload_size_bytes: int = Field(ge=0)
    risk_score: int = Field(ge=0, le=100)
    severity: Severity
    result_digest: str
    result_digest_scope: str
    execution_mode: str
    analyzer_versions: dict[str, str]
    stages: list[ScanStageResult]
    evidence: list[EvidenceRecord]
    findings: list[Finding]
    score: VersionedScoreResult
    privacy: PrivacyContext
    limitations: list[str] = Field(default_factory=list)

    app_info: dict[str, Any] = Field(default_factory=dict)
    permissions: list[Any] = Field(default_factory=list)
    behavioral: dict[str, Any] = Field(default_factory=dict)
    static_behavioral_inference: list[dict[str, Any]] = Field(default_factory=list)
    dynamic: dict[str, Any] = Field(default_factory=dict)
    virustotal: dict[str, Any] = Field(default_factory=dict)
    ai_analysis: dict[str, Any] = Field(default_factory=dict)
    mitre_mappings: list[dict[str, Any]] = Field(default_factory=list)
    threat_intel: dict[str, Any] = Field(default_factory=dict)
    siem_alert: dict[str, Any] = Field(default_factory=dict)
    ml_analysis: dict[str, Any] = Field(default_factory=dict)
    smali_analysis: dict[str, Any] = Field(default_factory=dict)
    score_breakdown: list[dict[str, Any]] = Field(default_factory=list)
    dynamic_breakdown: list[dict[str, Any]] = Field(default_factory=list)
    static_score: int = 0
    dynamic_score: int = 0
    scoring_mode: str = "static_only"
    cache_hit: bool = False
    integrity_note: str
    privacy_mode: dict[str, Any] = Field(default_factory=dict)


class HealthResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str
    timestamp: datetime
    service: str
    version: str
    api_version: str
    schema_version: str
    request_id: str
    execution_mode: str
    modules: dict[str, Any]
    privacy_mode: dict[str, Any]


class HistoryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scans: list[dict[str, Any]]
    total: int
    retention_enabled: bool
    schema_version: str
