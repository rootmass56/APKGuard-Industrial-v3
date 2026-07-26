from pathlib import Path

from app.core.config import Settings
from app.schemas.common import EvidenceType
from app.services.capabilities import CapabilityRegistry, LoadedFunction
from app.services.repositories import CacheRepository, HistoryRepository
from app.services.scan_service import ScanService
from app.services.upload_service import UploadArtifact


def _capability(name: str) -> LoadedFunction:
    return LoadedFunction(name=name, function=None, available=False)


class FakeDynamicService:
    def run(self, _apk_path, package_name, *, scan_id, analysis):
        del analysis
        return {
            "status": "completed",
            "stage_status": "SUCCEEDED",
            "dynamic_available": True,
            "analysis_method": "isolated_android_emulator_frida",
            "adapter_version": "apkguard-isolated-android/4.0.0-phase4",
            "policy_version": "apkguard-sandbox-policy/1.0.0-phase4",
            "session_id": "session-phase4",
            "package_name": package_name,
            "network_mode": "offline",
            "instrumentation_mode": "frida_optional",
            "observed_events": [
                {
                    "observation_id": "obs-phase4",
                    "category": "COMMAND",
                    "event_type": "runtime_exec",
                    "title": "Runtime command execution observed",
                    "description": "Runtime.exec was invoked.",
                    "severity": "HIGH",
                    "observed_at": "2026-07-24T00:00:00Z",
                    "source": "frida-java-agent",
                    "package_name": package_name,
                    "session_id": "session-phase4",
                    "process_id": 100,
                    "thread_id": 101,
                    "payload": {"api": "java.lang.Runtime.exec", "args": ["id"]},
                    "evidence_digest": "b" * 64,
                }
            ],
            "api_calls_intercepted": [
                {
                    "api": "java.lang.Runtime.exec",
                    "class": "java.lang.Runtime",
                    "args": ["id"],
                    "threat_level": "high",
                }
            ],
            "network_calls": [],
            "file_operations": [],
            "crypto_operations": [],
            "total_events": 1,
            "dynamic_risk_score": 18,
            "completed_at": "2026-07-24T00:00:01Z",
            "summary": "Observed one runtime event.",
            "artifacts": [],
            "limitations": [],
            "blockers": [],
            "cleanup_confirmed": True,
        }


def test_scan_contract_accepts_observed_runtime_evidence(monkeypatch, tmp_path: Path):
    analysis = {
        "app_info": {"package": "com.example.safe"},
        "permissions": {"all": [], "dangerous": []},
        "suspicious_apis": [],
        "urls_ips": {"urls": [], "ips": []},
        "obfuscation": {"detected": False, "score": 0},
        "banking_indicators": [],
        "native_libs": [],
        "advanced_static": {
            "status": "completed",
            "analyzer": {"version": "apkguard-advanced-static/3.2.0-phase3"},
            "metrics": {"evidence_count": 0, "finding_count": 0},
            "evidence": [],
            "findings": [],
        },
    }
    monkeypatch.setattr("app.services.scan_service.analyze_apk", lambda _: analysis)
    monkeypatch.setattr(
        "app.services.scan_service.analyze_behavior",
        lambda *_args, **_kwargs: {"dynamic_behaviors": [], "runtime_indicators": []},
    )
    settings = Settings(
        cache_enabled=False,
        history_enabled=False,
        cache_dir=tmp_path / "cache",
        history_file=tmp_path / "history.json",
        privacy_mode="local_only",
    )
    capabilities = CapabilityRegistry(
        dynamic_analysis=_capability("dynamic"),
        ml_classifier=_capability("ml"),
        smali_explanation=_capability("smali"),
        threat_feeds=_capability("feeds"),
        threat_scan=_capability("threat_scan"),
        siem_alert=_capability("siem"),
    )
    service = ScanService(
        settings=settings,
        capabilities=capabilities,
        cache=CacheRepository(settings.cache_dir, False, settings.schema_version),
        history=HistoryRepository(settings.history_file, False, 50),
        dynamic_service=FakeDynamicService(),
    )
    apk = tmp_path / "safe.apk"
    apk.write_bytes(b"PK-test")
    artifact = UploadArtifact(
        original_filename="safe.apk",
        temporary_path=apk,
        sha256="a" * 64,
        size_bytes=7,
        zip_entry_count=2,
        total_uncompressed_bytes=10,
    )
    response = service.analyze(artifact, "request-phase4", scan_id="scan-phase4")
    runtime = [item for item in response.evidence if item.evidence_type == EvidenceType.OBSERVED_RUNTIME]
    assert response.schema_version == "1.3"
    assert response.dynamic["dynamic_available"] is True
    assert response.score.scoring_mode == "static_dynamic_observed"
    assert len(runtime) == 1
    assert runtime[0].observed_at_runtime is True
