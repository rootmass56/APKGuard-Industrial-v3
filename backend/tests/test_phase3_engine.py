from __future__ import annotations

import zipfile
from pathlib import Path

from app.schemas.evidence import EvidenceRecord, Finding
from app.static_analysis.engine import ADVANCED_STATIC_ANALYZER_VERSION, run_advanced_static_analysis


def test_advanced_engine_produces_canonical_evidence_and_sbom(tmp_path: Path):
    apk = tmp_path / "sample.apk"
    manifest = """<manifest xmlns:android='http://schemas.android.com/apk/res/android' package='com.example'>
    <application android:debuggable='true'>
      <service android:name='.S' android:exported='true'/>
    </application>
    </manifest>"""
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", manifest)
        archive.writestr(
            "classes.dex",
            b"dex DexClassLoader AES/ECB/PKCS5Padding okhttp3 getDeviceId HttpURLConnection",
        )
    report = run_advanced_static_analysis(apk, apk_sha256="a" * 64)
    assert report["status"] == "completed"
    assert report["analyzer"]["version"] == ADVANCED_STATIC_ANALYZER_VERSION
    assert report["findings"]
    assert report["evidence"]
    for raw in report["evidence"]:
        record = EvidenceRecord.model_validate(raw)
        assert record.observed_at_runtime is False
    for raw in report["findings"]:
        Finding.model_validate(raw)
    assert report["sbom"]["bomFormat"] == "CycloneDX"
    assert report["sbom"]["specVersion"] == "1.5"
    assert "timestamp" not in report["sbom"]["metadata"]
    assert report["data_flows"]
    mappings = {
        mapping["identifier"]
        for finding in report["findings"]
        for mapping in finding.get("standards", [])
    }
    assert "MASWE-0062" in mappings
    assert "MASWE-0001" not in mappings


def test_static_rule_metadata_endpoint():
    from fastapi.testclient import TestClient

    from app.main import create_app

    with TestClient(create_app()) as client:
        response = client.get("/api/v1/static-analysis/rules")
        assert response.status_code == 200
        body = response.json()
        assert body["ruleset_version"] == "apkguard-static-rules/3.0.0"
        assert len(body["rules"]) >= 10
