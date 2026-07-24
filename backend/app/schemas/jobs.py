"""Phase 2 asynchronous scan-job contracts."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.common import JobEventType, JobState


class ScanJobStatusResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    scan_id: str
    request_id: str
    correlation_id: str
    state: JobState
    progress: int = Field(ge=0, le=100)
    current_stage: str
    original_filename: str
    apk_sha256: str | None = None
    size_bytes: int | None = Field(default=None, ge=0)
    attempt_count: int = Field(ge=0)
    max_attempts: int = Field(ge=1)
    cancel_requested: bool
    result_available: bool
    result_digest: str | None = None
    error_code: str | None = None
    error_message: str | None = None
    created_at: datetime
    updated_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    heartbeat_at: datetime | None = None
    queue_backend: str
    execution_mode: str
    links: dict[str, str]


class ScanProgressResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    scan_id: str
    state: JobState
    progress: int = Field(ge=0, le=100)
    current_stage: str
    attempt_count: int = Field(ge=0)
    cancel_requested: bool
    updated_at: datetime
    terminal: bool
    result_available: bool
    message: str | None = None


class ScanEventResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    event_id: int
    sequence: int
    scan_id: str
    event_type: JobEventType
    previous_state: JobState | None = None
    new_state: JobState | None = None
    message: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class ScanEventListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scan_id: str
    events: list[ScanEventResponse]
    total: int


class ScanJobListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scans: list[ScanJobStatusResponse]
    total: int


class CancelScanResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    scan_id: str
    state: JobState
    cancel_requested: bool
    message: str
