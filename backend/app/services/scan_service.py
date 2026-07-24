"""Synchronous compatibility orchestrator with typed Phase 1 contracts.

Phase 2 will move stage execution to background workers. This service already
normalizes stage states, evidence, scores, privacy, and immutable result metadata.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from time import perf_counter
from typing import Any
from uuid import uuid4

from ai_engine import get_ai_analysis
from analyzer import analyze_apk
from behavioral import analyze_behavior

from app.core.config import Settings
from app.core.errors import AnalysisFailedError
from app.schemas.common import ResultStatus, StageStatus
from app.schemas.scan import PrivacyContext, ScanResponse, ScanStageResult
from app.services.capabilities import CapabilityRegistry
from app.services.evidence_factory import (
    EVIDENCE_FACTORY_VERSION,
    add_static_inference_labels,
    build_evidence_and_findings,
    build_mitre_mappings,
)
from app.services.integrations import VirusTotalHashClient
from app.services.repositories import CacheRepository, HistoryRepository
from app.services.scoring_service import SCORING_POLICY_VERSION, calculate_versioned_score
from app.services.upload_service import UploadArtifact

log = logging.getLogger("apkguard.scan_service")
STATIC_ANALYZER_VERSION = "static-analyzer/1.0.0-phase1"
BEHAVIOUR_ANALYZER_VERSION = "static-behaviour-inference/1.0.0"
ORCHESTRATOR_VERSION = "scan-orchestrator/1.0.0"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _stage(
    stages: list[ScanStageResult],
    *,
    name: str,
    status: StageStatus,
    analyzer: str,
    version: str,
    started_at: datetime,
    started_perf: float,
    evidence_count: int = 0,
    finding_count: int = 0,
    message: str | None = None,
    error_code: str | None = None,
) -> None:
    completed = utc_now()
    stages.append(
        ScanStageResult(
            stage=name,
            status=status,
            analyzer=analyzer,
            analyzer_version=version,
            started_at=started_at,
            completed_at=completed,
            duration_ms=max(0, round((perf_counter() - started_perf) * 1000)),
            evidence_count=evidence_count,
            finding_count=finding_count,
            message=message,
            error_code=error_code,
        )
    )


def _canonical_digest(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


class ScanService:
    def __init__(
        self,
        settings: Settings,
        capabilities: CapabilityRegistry,
        cache: CacheRepository,
        history: HistoryRepository,
    ) -> None:
        self.settings = settings
        self.capabilities = capabilities
        self.cache = cache
        self.history = history
        self.virustotal = VirusTotalHashClient(settings)

    def analyze(
        self,
        artifact: UploadArtifact,
        request_id: str,
        *,
        scan_id: str | None = None,
        execution_mode: str = "synchronous_compatibility_phase2",
        allow_cache: bool = True,
        record_legacy_history: bool = True,
    ) -> ScanResponse:
        cached = self.cache.load(artifact.sha256) if allow_cache else None
        if cached:
            cached["cache_hit"] = True
            cached["request_id"] = request_id
            cached["integrity_note"] = "Phase 2 compatibility result retrieved from the versioned local cache."
            return ScanResponse.model_validate(cached)

        scan_id = scan_id or str(uuid4())
        scan_started = utc_now()
        stages: list[ScanStageResult] = []
        partial_failure = False
        external_services_used: list[str] = []

        started_at, timer = utc_now(), perf_counter()
        try:
            analysis = analyze_apk(str(artifact.temporary_path))
            app_info = analysis.setdefault("app_info", {})
            if app_info.get("package") and not app_info.get("package_name"):
                app_info["package_name"] = app_info["package"]
            _stage(
                stages,
                name="static_analysis",
                status=StageStatus.SUCCEEDED,
                analyzer="apkguard-static-analyzer",
                version=STATIC_ANALYZER_VERSION,
                started_at=started_at,
                started_perf=timer,
            )
        except Exception as exc:
            _stage(
                stages,
                name="static_analysis",
                status=StageStatus.FAILED,
                analyzer="apkguard-static-analyzer",
                version=STATIC_ANALYZER_VERSION,
                started_at=started_at,
                started_perf=timer,
                message="Static analysis failed.",
                error_code=type(exc).__name__,
            )
            log.exception("Static analysis failed")
            raise AnalysisFailedError("Static APK analysis failed.") from exc

        started_at, timer = utc_now(), perf_counter()
        try:
            behavioral = add_static_inference_labels(
                analyze_behavior(str(artifact.temporary_path), analysis=analysis)
            )
            inferred_count = len(behavioral.get("dynamic_behaviors", []))
            _stage(
                stages,
                name="static_behavior_inference",
                status=StageStatus.SUCCEEDED,
                analyzer="apkguard-static-behaviour-inference",
                version=BEHAVIOUR_ANALYZER_VERSION,
                started_at=started_at,
                started_perf=timer,
                evidence_count=inferred_count,
                message="Inference is explicitly separated from runtime evidence.",
            )
        except Exception as exc:
            partial_failure = True
            behavioral = {
                "status": "failed",
                "analysis_method": "static_behavioral_inference",
                "dynamic_behaviors": [],
                "runtime_indicators": [],
                "limitations": ["Static behaviour inference failed."],
            }
            _stage(
                stages,
                name="static_behavior_inference",
                status=StageStatus.FAILED,
                analyzer="apkguard-static-behaviour-inference",
                version=BEHAVIOUR_ANALYZER_VERSION,
                started_at=started_at,
                started_perf=timer,
                message="Static behaviour inference failed.",
                error_code=type(exc).__name__,
            )
            log.warning("Static behaviour inference failed: %s", exc)

        package_name = analysis.get("app_info", {}).get("package_name") or analysis.get("app_info", {}).get("package")
        started_at, timer = utc_now(), perf_counter()
        dynamic = {
            "status": "not_executed",
            "dynamic_available": False,
            "observed_events": [],
            "api_calls_intercepted": [],
            "network_calls": [],
            "file_operations": [],
            "crypto_operations": [],
            "dynamic_risk_score": 0,
            "summary": "Dynamic analysis is unavailable until an isolated sandbox worker is connected.",
        }
        if self.capabilities.dynamic_analysis.available and self.capabilities.dynamic_analysis.function:
            try:
                dynamic = self.capabilities.dynamic_analysis.function(
                    str(artifact.temporary_path),
                    package_name,
                    analysis=analysis,
                )
            except Exception as exc:
                partial_failure = True
                dynamic["status"] = "failed"
                dynamic["summary"] = "Dynamic adapter failed before execution."
                log.warning("Dynamic adapter failed: %s", exc)
        dynamic_status = (
            StageStatus.SUCCEEDED
            if dynamic.get("dynamic_available")
            else StageStatus.NOT_EXECUTED
        )
        _stage(
            stages,
            name="dynamic_analysis",
            status=dynamic_status,
            analyzer="apkguard-isolated-sandbox-adapter",
            version=str(dynamic.get("adapter_version", "not-connected")),
            started_at=started_at,
            started_perf=timer,
            evidence_count=len(dynamic.get("observed_events", [])),
            message=dynamic.get("summary"),
        )

        started_at, timer = utc_now(), perf_counter()
        virustotal = self.virustotal.lookup(artifact.sha256)
        vt_status = (
            StageStatus.SUCCEEDED
            if virustotal.get("status") in {"completed", "not_found_hash_only"}
            else StageStatus.UNAVAILABLE
        )
        if virustotal.get("status") in {"completed", "not_found_hash_only"}:
            external_services_used.append("VirusTotal hash lookup")
        _stage(
            stages,
            name="hash_reputation",
            status=vt_status,
            analyzer="virustotal-hash-client",
            version="virustotal-api-v3",
            started_at=started_at,
            started_perf=timer,
            message=virustotal.get("reason") or virustotal.get("status"),
        )

        started_at, timer = utc_now(), perf_counter()
        threat_intel: dict[str, Any] = {
            "available": False,
            "status": "disabled_by_privacy_policy",
            "threat_level": "unknown",
            "phishing_urls": [],
            "intel_source": [],
        }
        if self.settings.public_threat_feeds_allowed_by_policy and self.capabilities.threat_scan.available:
            try:
                threat_intel = self.capabilities.threat_scan.function(
                    artifact.sha256,
                    analysis.get("urls_ips", {}).get("urls", []),
                )
                if threat_intel.get("intel_source"):
                    external_services_used.extend(threat_intel.get("intel_source", []))
                threat_status = StageStatus.SUCCEEDED
            except Exception as exc:
                partial_failure = True
                threat_status = StageStatus.FAILED
                threat_intel = {
                    "available": False,
                    "status": "error",
                    "threat_level": "unknown",
                    "reason": "Threat-intelligence correlation failed.",
                }
                log.warning("Threat-intelligence correlation failed: %s", exc)
        else:
            threat_status = StageStatus.SKIPPED
        _stage(
            stages,
            name="threat_intelligence",
            status=threat_status,
            analyzer="apkguard-threat-intel-connectors",
            version="connectors/1.0.0-phase1",
            started_at=started_at,
            started_perf=timer,
            message=threat_intel.get("status"),
        )

        started_at, timer = utc_now(), perf_counter()
        evidence, findings = build_evidence_and_findings(
            analysis,
            behavioral,
            virustotal,
            threat_intel,
            dynamic,
            STATIC_ANALYZER_VERSION,
        )
        analysis["findings"] = [item.model_dump(mode="json") for item in findings]
        _stage(
            stages,
            name="evidence_normalization",
            status=StageStatus.SUCCEEDED,
            analyzer="apkguard-evidence-factory",
            version=EVIDENCE_FACTORY_VERSION,
            started_at=started_at,
            started_perf=timer,
            evidence_count=len(evidence),
            finding_count=len(findings),
        )

        started_at, timer = utc_now(), perf_counter()
        score, legacy_score = calculate_versioned_score(
            analysis,
            behavioral,
            virustotal,
            dynamic,
            evidence,
        )
        _stage(
            stages,
            name="risk_scoring",
            status=StageStatus.SUCCEEDED,
            analyzer="apkguard-risk-policy",
            version=SCORING_POLICY_VERSION,
            started_at=started_at,
            started_perf=timer,
            evidence_count=sum(len(component.evidence_ids) for component in score.components),
        )

        ml_result: dict[str, Any] = {"available": False, "status": "disabled_or_unavailable"}
        started_at, timer = utc_now(), perf_counter()
        if self.capabilities.ml_classifier.available and self.capabilities.ml_classifier.function:
            try:
                ml_result = self.capabilities.ml_classifier.function(analysis)
                ml_result["advisory_only"] = True
                ml_result["validation_status"] = "synthetic_baseline_not_real_world_benchmark"
                ml_result["risk_contribution_applied"] = 0
                ml_status = StageStatus.SUCCEEDED
            except Exception as exc:
                partial_failure = True
                ml_status = StageStatus.FAILED
                ml_result = {"available": False, "status": "error", "reason": "ML advisory failed."}
                log.warning("ML advisory failed: %s", exc)
        else:
            ml_status = StageStatus.UNAVAILABLE
        _stage(
            stages,
            name="ml_advisory",
            status=ml_status,
            analyzer="legacy-kmeans-advisory",
            version="synthetic-baseline/1.0",
            started_at=started_at,
            started_perf=timer,
            message="Advisory only; no contribution to the risk score.",
        )

        smali_result: dict[str, Any] = {"available": False, "status": "disabled_or_unavailable"}
        started_at, timer = utc_now(), perf_counter()
        if (
            self.settings.ai_allowed_by_policy
            and self.settings.groq_api_key
            and self.capabilities.smali_explanation.available
            and self.capabilities.smali_explanation.function
        ):
            try:
                smali_result = self.capabilities.smali_explanation.function(str(artifact.temporary_path))
                smali_result.setdefault("advisory_only", True)
                smali_status = StageStatus.SUCCEEDED
                external_services_used.append("Groq code explanation")
            except Exception as exc:
                partial_failure = True
                smali_status = StageStatus.FAILED
                smali_result = {"available": False, "status": "error", "reason": "Code explanation failed."}
                log.warning("Smali explanation failed: %s", exc)
        else:
            smali_status = StageStatus.SKIPPED
        _stage(
            stages,
            name="code_explanation",
            status=smali_status,
            analyzer="optional-code-explanation",
            version="1.0.0-phase1",
            started_at=started_at,
            started_perf=timer,
            message="Optional and privacy-policy controlled.",
        )

        started_at, timer = utc_now(), perf_counter()
        if self.settings.ai_allowed_by_policy and self.settings.groq_api_key:
            ai_result = get_ai_analysis(analysis, legacy_score)
            ai_status = StageStatus.SUCCEEDED if ai_result.get("available") else StageStatus.UNAVAILABLE
            if ai_result.get("available"):
                external_services_used.append("Groq analyst explanation")
        else:
            ai_result = {
                "available": False,
                "status": "disabled_by_privacy_policy",
                "analyst_note": "AI explanation is disabled unless cloud enrichment is explicitly permitted.",
            }
            ai_status = StageStatus.SKIPPED
        _stage(
            stages,
            name="ai_explanation",
            status=ai_status,
            analyzer="optional-ai-explanation",
            version="1.0.0-phase1",
            started_at=started_at,
            started_perf=timer,
            message=ai_result.get("analyst_note") or ai_result.get("status"),
        )

        mitre = build_mitre_mappings(analysis, legacy_score.get("mitre", []), evidence)

        siem_result: dict[str, Any] = {"available": False, "status": "not_sent"}
        started_at, timer = utc_now(), perf_counter()
        if self.settings.siem_webhook_url and self.capabilities.siem_alert.available:
            try:
                siem_payload = {
                    "filename": artifact.original_filename,
                    "risk_score": score.final_score,
                    "severity": str(score.severity),
                    "app_info": analysis.get("app_info", {}),
                    "findings": [item.model_dump(mode="json") for item in findings],
                    "mitre_mappings": mitre,
                    "virustotal": virustotal,
                    "ai_analysis": ai_result,
                }
                siem_result = self.capabilities.siem_alert.function(siem_payload)
                siem_status = StageStatus.SUCCEEDED if siem_result.get("status") == "sent" else StageStatus.SKIPPED
                if siem_result.get("status") == "sent":
                    external_services_used.append("Configured SIEM webhook")
            except Exception as exc:
                partial_failure = True
                siem_status = StageStatus.FAILED
                siem_result = {"available": False, "status": "error", "reason": "SIEM delivery failed."}
                log.warning("SIEM delivery failed: %s", exc)
        else:
            siem_status = StageStatus.SKIPPED
        _stage(
            stages,
            name="siem_delivery",
            status=siem_status,
            analyzer="siem-webhook-adapter",
            version="1.0.0-phase1",
            started_at=started_at,
            started_perf=timer,
            message=siem_result.get("status"),
        )

        completed_at = utc_now()
        privacy = PrivacyContext(
            mode=self.settings.privacy_mode,
            cache_enabled=self.settings.cache_enabled,
            history_enabled=self.settings.history_enabled,
            virustotal_hash_lookup_permitted=self.settings.hash_reputation_allowed_by_policy,
            virustotal_file_upload_permitted=False,
            ai_permitted=self.settings.ai_allowed_by_policy,
            external_services_used=sorted(set(external_services_used)),
        )
        analyzer_versions = {
            "orchestrator": ORCHESTRATOR_VERSION,
            "static": STATIC_ANALYZER_VERSION,
            "behaviour_inference": BEHAVIOUR_ANALYZER_VERSION,
            "evidence": EVIDENCE_FACTORY_VERSION,
            "scoring_policy": SCORING_POLICY_VERSION,
        }
        core_digest_payload = {
            "schema_version": self.settings.schema_version,
            "scan_id": scan_id,
            "apk_sha256": artifact.sha256,
            "findings": [item.model_dump(mode="json") for item in findings],
            "evidence": [item.model_dump(mode="json") for item in evidence],
            "score": score.model_dump(mode="json"),
            "analyzer_versions": analyzer_versions,
        }
        result_digest = _canonical_digest(core_digest_payload)
        result_status = ResultStatus.PARTIAL if partial_failure else ResultStatus.COMPLETED

        response = ScanResponse(
            schema_version=self.settings.schema_version,
            scan_id=scan_id,
            request_id=request_id,
            result_status=result_status,
            filename=artifact.original_filename,
            scan_time=scan_started,
            completed_at=completed_at,
            apk_sha256=artifact.sha256,
            upload_size_bytes=artifact.size_bytes,
            risk_score=score.final_score,
            severity=score.severity,
            result_digest=result_digest,
            result_digest_scope="analysis_core_v1",
            execution_mode=execution_mode,
            analyzer_versions=analyzer_versions,
            stages=stages,
            evidence=evidence,
            findings=findings,
            score=score,
            privacy=privacy,
            limitations=[
                "Dynamic analysis is not executed until the isolated Android sandbox is implemented.",
                "The ML output is a synthetic advisory baseline and does not affect the score.",
            ],
            app_info=analysis.get("app_info", {}),
            permissions=analysis.get("permissions", {}).get("all", []),
            behavioral=behavioral,
            static_behavioral_inference=behavioral.get("dynamic_behaviors", []),
            dynamic=dynamic,
            virustotal=virustotal,
            ai_analysis=ai_result,
            mitre_mappings=mitre,
            threat_intel=threat_intel,
            siem_alert=siem_result,
            ml_analysis=ml_result,
            smali_analysis=smali_result,
            score_breakdown=[component.model_dump(mode="json") for component in score.components],
            dynamic_breakdown=[
                component.model_dump(mode="json") for component in score.dynamic_components
            ],
            static_score=score.static_score,
            dynamic_score=score.dynamic_score,
            scoring_mode=score.scoring_mode,
            cache_hit=False,
            integrity_note=(
                "Phase 2 result is stored immutably when executed through the job API. Runtime evidence is included only "
                "when an isolated sandbox reports observed events."
            ),
            privacy_mode={
                "mode": privacy.mode,
                "vt_upload_attempted": virustotal.get("upload_attempted", False),
                "ai_enabled": bool(ai_result.get("available")),
                "cache_enabled": privacy.cache_enabled,
                "history_enabled": privacy.history_enabled,
            },
        )
        result_dict = response.model_dump(mode="json")
        if allow_cache:
            self.cache.save(artifact.sha256, result_dict)
        if record_legacy_history:
            self.history.append(
                {
                    "scan_id": scan_id,
                    "schema_version": self.settings.schema_version,
                    "filename": artifact.original_filename,
                    "risk_score": score.final_score,
                    "severity": str(score.severity),
                    "scan_time": scan_started.isoformat(),
                    "package": package_name or "",
                    "sha256": artifact.sha256,
                    "vt_status": virustotal.get("status"),
                    "vt_detected": virustotal.get("detected"),
                    "result_status": result_status.value,
                    "result_digest": result_digest,
                }
            )
        return response
