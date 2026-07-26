"""Phase 4 isolated Android sandbox contracts."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.common import SandboxEventCategory, SandboxState, Severity


class ToolCapability(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    available: bool
    executable: str | None = None
    version: str | None = None
    reason: str | None = None


class SandboxCapabilityResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    adapter_version: str
    checked_at: datetime
    enabled: bool
    execution_permitted: bool
    ready: bool
    avd_name: str | None = None
    snapshot_name: str | None = None
    network_mode: str
    instrumentation_mode: str
    tools: dict[str, ToolCapability]
    blockers: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class SandboxPolicyResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy_version: str
    dynamic_mode: str
    enabled: bool
    risk_acknowledged: bool
    dedicated_host: bool
    host_egress_blocked: bool
    queue_backend: str
    analysis_isolation_mode: str
    network_mode: str
    execution_permitted: bool
    requires_dedicated_worker: bool
    requires_content_addressed_quarantine: bool
    requires_snapshot_restore: bool
    allows_adb_root: bool
    allows_host_shell: bool
    allows_unrestricted_egress: bool
    blockers: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class RuntimeObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    observation_id: str
    category: SandboxEventCategory
    event_type: str
    title: str
    description: str
    severity: Severity = Severity.INFO
    observed_at: datetime
    source: str
    package_name: str
    session_id: str
    process_id: int | None = None
    thread_id: int | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    evidence_digest: str


class SandboxArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid")

    artifact_type: str
    filename: str
    sha256: str
    size_bytes: int = Field(ge=0)
    description: str


class SandboxExecutionResult(BaseModel):
    model_config = ConfigDict(extra="allow", use_enum_values=True)

    status: str
    stage_status: str
    dynamic_available: bool
    analysis_method: str
    adapter_version: str
    policy_version: str
    session_id: str | None = None
    package_name: str | None = None
    sandbox_state: SandboxState | None = None
    emulator_serial: str | None = None
    avd_name: str | None = None
    snapshot_name: str | None = None
    network_mode: str
    instrumentation_mode: str
    observed_events: list[RuntimeObservation] = Field(default_factory=list)
    api_calls_intercepted: list[dict[str, Any]] = Field(default_factory=list)
    network_calls: list[dict[str, Any]] = Field(default_factory=list)
    file_operations: list[dict[str, Any]] = Field(default_factory=list)
    crypto_operations: list[dict[str, Any]] = Field(default_factory=list)
    total_events: int = Field(default=0, ge=0)
    dynamic_risk_score: int = Field(default=0, ge=0, le=100)
    started_at: datetime | None = None
    completed_at: datetime
    summary: str
    artifacts: list[SandboxArtifact] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    blockers: list[str] = Field(default_factory=list)
    cleanup_confirmed: bool = False


class SandboxSessionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    session_id: str
    scan_id: str
    state: SandboxState
    worker_id: str
    avd_name: str
    emulator_serial: str | None = None
    network_mode: str
    instrumentation_mode: str
    policy_digest: str
    artifact_directory: str
    error_code: str | None = None
    error_message: str | None = None
    created_at: datetime
    updated_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    event_count: int = Field(default=0, ge=0)


class SandboxEventResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    event_id: int
    session_id: str
    sequence: int
    category: SandboxEventCategory
    event_type: str
    severity: Severity
    observed_at: datetime
    source: str
    payload: dict[str, Any]
    evidence_digest: str
    created_at: datetime


class SandboxEventListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session_id: str
    events: list[SandboxEventResponse]
    total: int
