"""Shared enums and API primitives."""

from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class EvidenceType(str, Enum):
    STATICALLY_DETECTED = "STATICALLY_DETECTED"
    INFERRED_STATIC = "INFERRED_STATIC"
    OBSERVED_RUNTIME = "OBSERVED_RUNTIME"
    THREAT_INTEL_MATCH = "THREAT_INTEL_MATCH"
    MODEL_PREDICTION = "MODEL_PREDICTION"
    AI_GENERATED = "AI_GENERATED"
    ANALYST_VERDICT = "ANALYST_VERDICT"


class StageStatus(str, Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    UNAVAILABLE = "UNAVAILABLE"
    NOT_EXECUTED = "NOT_EXECUTED"
    CACHED = "CACHED"


class ResultStatus(str, Enum):
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"


class PrivacyMode(str, Enum):
    LOCAL_ONLY = "local_only"
    HASH_ONLY = "hash_only"
    CLOUD_ENRICHMENT = "cloud_enrichment"
    PRIVATE_ENTERPRISE = "private_enterprise"
