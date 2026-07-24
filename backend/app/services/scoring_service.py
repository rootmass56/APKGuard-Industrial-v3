"""Versioned wrapper around the deterministic Sprint 0 scoring policy."""

from __future__ import annotations

from typing import Any

from scorer import calculate_final_score, calculate_score

from app.schemas.common import Severity
from app.schemas.evidence import EvidenceRecord
from app.schemas.scan import ScoreComponent, VersionedScoreResult

SCORING_POLICY_VERSION = "apkguard-risk-policy/2.0.0-phase3"
_MAX_POINTS = {
    "Dangerous Permissions": 30,
    "Suspicious API Calls": 25,
    "Hardcoded URLs/IPs": 15,
    "Code Obfuscation": 15,
    "Banking Trojan Indicators": 10,
    "Native Libraries": 5,
    "Runtime API Intercepts": 40,
    "Covert File Operations": 20,
    "Runtime Crypto Operations": 20,
    "Network Calls": 20,
}


def _severity(score: int) -> Severity:
    if score >= 75:
        return Severity.CRITICAL
    if score >= 51:
        return Severity.HIGH
    if score >= 26:
        return Severity.MEDIUM
    return Severity.LOW


def _evidence_ids_for_category(category: str, evidence: list[EvidenceRecord]) -> list[str]:
    category_map = {
        "Dangerous Permissions": {"permission"},
        "Suspicious API Calls": {"api"},
        "Hardcoded URLs/IPs": {"network_indicator"},
        "Code Obfuscation": {"obfuscation"},
    }
    allowed = category_map.get(category, set())
    return [record.evidence_id for record in evidence if record.metadata.get("category") in allowed]


def calculate_versioned_score(
    analysis: dict[str, Any],
    behavioral: dict[str, Any],
    virustotal: dict[str, Any],
    dynamic: dict[str, Any],
    evidence: list[EvidenceRecord],
) -> tuple[VersionedScoreResult, dict[str, Any]]:
    legacy_static = calculate_score(analysis, behavioral, virustotal)
    legacy_final = calculate_final_score(legacy_static, dynamic)
    legacy_score = int(legacy_final.get("final_score", legacy_static.get("score", 0)))
    advanced_records = [record for record in evidence if record.analyzer == "apkguard-advanced-static"]
    advanced_points = sum(int(record.metadata.get("risk_points", 0)) for record in advanced_records)
    advanced_adjustment = min(20, advanced_points // 4)
    final_score = min(100, legacy_score + advanced_adjustment)

    components = [
        ScoreComponent(
            category=str(item.get("category", "Unknown")),
            points=int(item.get("points", 0)),
            max_points=_MAX_POINTS.get(str(item.get("category", ""))),
            detail=str(item.get("detail", "")),
            evidence_ids=_evidence_ids_for_category(str(item.get("category", "")), evidence),
        )
        for item in legacy_final.get("breakdown", [])
    ]
    dynamic_components = [
        ScoreComponent(
            category=str(item.get("category", "Unknown")),
            points=int(item.get("points", 0)),
            max_points=_MAX_POINTS.get(str(item.get("category", ""))),
            detail=str(item.get("detail", "")),
            evidence_ids=[
                record.evidence_id
                for record in evidence
                if record.evidence_type == "OBSERVED_RUNTIME"
            ],
        )
        for item in legacy_final.get("dynamic_breakdown", [])
    ]

    if advanced_adjustment:
        components.append(
            ScoreComponent(
                category="Advanced Static Analysis",
                points=advanced_adjustment,
                max_points=20,
                detail=(
                    f"Conservative Phase 3 adjustment derived from {len(advanced_records)} advanced deterministic "
                    "evidence records; duplicate legacy categories are bounded by a 20-point cap."
                ),
                evidence_ids=[record.evidence_id for record in advanced_records],
            )
        )

    result = VersionedScoreResult(
        policy_version=SCORING_POLICY_VERSION,
        final_score=final_score,
        severity=_severity(final_score),
        scoring_mode=str(legacy_final.get("scoring_mode", "static_only")),
        static_score=min(100, int(legacy_final.get("static_score", legacy_score)) + advanced_adjustment),
        dynamic_score=int(legacy_final.get("dynamic_score", 0)),
        components=components,
        dynamic_components=dynamic_components,
        overrides=[str(value) for value in legacy_static.get("overrides", [])],
        model_advisory_applied=False,
    )
    return result, legacy_static
