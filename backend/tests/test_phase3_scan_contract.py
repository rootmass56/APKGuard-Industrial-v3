from __future__ import annotations

from pathlib import Path

from app.core.config import Settings
from app.services.capabilities import CapabilityRegistry, LoadedFunction
from app.services.repositories import CacheRepository, HistoryRepository
from app.services.scan_service import ScanService
from app.services.upload_service import UploadArtifact


def _capability(name: str) -> LoadedFunction:
    return LoadedFunction(name=name, function=None, available=False)


def test_scan_response_exposes_phase3_contract(monkeypatch, tmp_path: Path):
    advanced = {
        "status": "completed",
        "analyzer": {"version": "apkguard-advanced-static/3.2.0-phase3"},
        "metrics": {"evidence_count": 0, "finding_count": 0},
        "evidence": [],
        "findings": [],
        "signing": {"detected_schemes": ["v2"]},
        "attack_surface": {"exported_components": []},
        "network_security": {},
        "native_analysis": {"libraries": []},
        "dependency_inventory": [],
        "sbom": {"bomFormat": "CycloneDX", "components": []},
        "call_graph": {"available": False},
        "data_flows": [],
    }
    analysis = {
        "app_info": {"package": "com.example"},
        "permissions": {"all": [], "dangerous": []},
        "suspicious_apis": [],
        "urls_ips": {"urls": [], "ips": []},
        "obfuscation": {"detected": False},
        "native_libs": [],
        "banking_indicators": [],
        "advanced_static": advanced,
        "signing": advanced["signing"],
        "attack_surface": advanced["attack_surface"],
        "network_security": {},
        "native_analysis": advanced["native_analysis"],
        "dependency_inventory": [],
        "sbom": advanced["sbom"],
        "call_graph": advanced["call_graph"],
        "data_flows": [],
    }
    monkeypatch.setattr("app.services.scan_service.analyze_apk", lambda _: analysis)
    monkeypatch.setattr(
        "app.services.scan_service.analyze_behavior",
        lambda *_args, **_kwargs: {"dynamic_behaviors": [], "runtime_indicators": [], "anti_analysis_techniques": []},
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
    )
    apk = tmp_path / "sample.apk"
    apk.write_bytes(b"PK-test")
    artifact = UploadArtifact(
        original_filename="sample.apk",
        temporary_path=apk,
        sha256="a" * 64,
        size_bytes=7,
        zip_entry_count=2,
        total_uncompressed_bytes=10,
    )
    response = service.analyze(artifact, "phase3-request")
    assert response.schema_version == "1.2"
    assert response.signing["detected_schemes"] == ["v2"]
    assert response.sbom["bomFormat"] == "CycloneDX"
    assert response.score.policy_version == "apkguard-risk-policy/2.0.0-phase3"
    assert any(stage.stage == "advanced_static_analysis" for stage in response.stages)
