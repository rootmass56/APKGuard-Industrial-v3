"""Canonical evidence and deterministic finding contracts."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.schemas.common import EvidenceType, Severity


class EvidenceLocation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str
    path: str | None = None
    class_name: str | None = None
    method_name: str | None = None
    instruction_offset: str | None = None
    line: int | None = None
    value: Any = None


class EvidenceRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    evidence_id: str
    evidence_type: EvidenceType
    title: str
    description: str
    location: EvidenceLocation
    analyzer: str
    analyzer_version: str
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    observed_at_runtime: bool = False
    limitations: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_runtime_provenance(self) -> "EvidenceRecord":
        if self.evidence_type == EvidenceType.OBSERVED_RUNTIME and not self.observed_at_runtime:
            raise ValueError("OBSERVED_RUNTIME evidence must set observed_at_runtime=true")
        if self.observed_at_runtime and self.evidence_type != EvidenceType.OBSERVED_RUNTIME:
            raise ValueError("Only OBSERVED_RUNTIME evidence may set observed_at_runtime=true")
        return self


class StandardMapping(BaseModel):
    model_config = ConfigDict(extra="forbid")

    framework: str
    identifier: str
    name: str | None = None
    version: str | None = None
    rationale: str | None = None


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    finding_id: str
    rule_id: str
    title: str
    description: str
    severity: Severity
    evidence_type: EvidenceType
    source: str
    value: Any = None
    evidence_ids: list[str] = Field(default_factory=list)
    standards: list[StandardMapping] = Field(default_factory=list)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    limitation: str | None = None
    remediation: list[str] = Field(default_factory=list)
    analyzer: str
    analyzer_version: str
    metadata: dict[str, Any] = Field(default_factory=dict)
