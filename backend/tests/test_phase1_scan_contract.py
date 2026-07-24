from __future__ import annotations

from pathlib import Path

from app.core.config import Settings
from app.services.capabilities import CapabilityRegistry, LoadedFunction
from app.services.repositories import CacheRepository, HistoryRepository
from app.services.scan_service import ScanService
from app.services.upload_service import UploadArtifact


def _capability(name: str, function=None) -> LoadedFunction:
    return LoadedFunction(name=name, function=function, available=function is not None)


def test_scan_service_builds_versioned_evidence_contract(monkeypatch, tmp_path: Path):
    analysis = {
        "app_info": {"package": "com.example.safe", "name": "Safe Example"},
        "permissions": {
            "all": ["android.permission.READ_SMS"],
            "dangerous": [
                {
                    "permission": "android.permission.READ_SMS",
                    "score": 10,
                    "reason": "Can read SMS including OTPs",
                }
            ],
        },
        "suspicious_apis": [],
        "urls_ips": {"urls": [], "ips": []},
        "obfuscation": {"detected": False, "score": 0, "indicators": []},
        "banking_indicators": [],
        "native_libs": [],
    }
    behavior = {
        "status": "completed",
        "analysis_method": "static_behavioral_inference",
        "runtime_indicators": [],
        "anti_analysis_techniques": [],
        "dynamic_behaviors": [
            {
                "behavior": "SMS access capability",
                "description": "SMS access is possible from declared permissions.",
                "severity": "High",
                "basis": ["READ_SMS"],
                "evidence_type": "INFERRED_STATIC",
                "observed_at_runtime": False,
            }
        ],
    }

    monkeypatch.setattr("app.services.scan_service.analyze_apk", lambda _: analysis)
    monkeypatch.setattr(
        "app.services.scan_service.analyze_behavior",
        lambda *_args, **_kwargs: behavior,
    )

    def dynamic_analysis_stub(*_args, **_kwargs):
        return {
            "status": "not_executed",
            "dynamic_available": False,
            "observed_events": [],
            "api_calls_intercepted": [],
            "network_calls": [],
            "file_operations": [],
            "crypto_operations": [],
            "dynamic_risk_score": 0,
            "summary": "No isolated sandbox connected.",
        }

    capabilities = CapabilityRegistry(
        dynamic_analysis=_capability("dynamic", dynamic_analysis_stub),
        ml_classifier=_capability("ml"),
        smali_explanation=_capability("smali"),
        threat_feeds=_capability("feeds"),
        threat_scan=_capability("threat_scan"),
        siem_alert=_capability("siem"),
    )
    settings = Settings(
        cache_enabled=False,
        history_enabled=False,
        cache_dir=tmp_path / "cache",
        history_file=tmp_path / "history.json",
        privacy_mode="local_only",
    )
    service = ScanService(
        settings=settings,
        capabilities=capabilities,
        cache=CacheRepository(settings.cache_dir, False, settings.schema_version),
        history=HistoryRepository(settings.history_file, False, 50),
    )
    apk_path = tmp_path / "sample.apk"
    apk_path.write_bytes(b"PK-test")
    artifact = UploadArtifact(
        original_filename="sample.apk",
        temporary_path=apk_path,
        sha256="a" * 64,
        size_bytes=7,
        zip_entry_count=2,
        total_uncompressed_bytes=10,
    )

    response = service.analyze(artifact, "request-phase1")

    assert response.schema_version == "1.2"
    assert response.request_id == "request-phase1"
    assert response.result_digest_scope == "analysis_core_v2_phase3"
    assert len(response.result_digest) == 64
    assert response.score.policy_version == "apkguard-risk-policy/2.0.0-phase3"
    assert response.dynamic["dynamic_available"] is False
    assert any(item.evidence_type == "STATICALLY_DETECTED" for item in response.evidence)
    assert any(item.evidence_type == "INFERRED_STATIC" for item in response.evidence)
    assert not any(item.observed_at_runtime for item in response.evidence)
    assert response.findings
    assert response.stages


def test_evidence_identifiers_are_stable():
    from app.services.evidence_factory import stable_id

    first = stable_id("EVD", "rule", "source", "value")
    second = stable_id("EVD", "rule", "source", "value")
    different = stable_id("EVD", "rule", "source", "different")

    assert first == second
    assert first != different
