from __future__ import annotations

from pathlib import Path

import pytest


def test_hash_metadata_marks_sha256_authoritative(tmp_path: Path):
    from analyzer import compute_hashes

    sample = tmp_path / "sample.apk"
    sample.write_bytes(b"PK\x03\x04apkguard-test")

    result = compute_hashes(sample)

    assert result["authoritative_hash"] == "sha256"
    assert result["legacy_hashes_for_compatibility_only"] == ["md5", "sha1"]
    assert len(result["sha256"]) == 64


def test_legacy_frida_injection_is_disabled():
    from inject_frida import FridaInjectionDisabledError, inject_frida, injection_status

    assert injection_status()["available"] is False
    with pytest.raises(FridaInjectionDisabledError):
        inject_frida("sample.apk")


def test_direct_frida_capture_never_touches_host_device():
    from frida_capture import capture_dynamic

    result = capture_dynamic("com.example.sample", duration=1)

    assert result["status"] == "not_executed"
    assert result["dynamic_available"] is False
    assert result["observed_events"] == []


def test_static_inference_is_never_observed_runtime(tmp_path: Path):
    import zipfile

    from behavioral import analyze_behavior

    sample = tmp_path / "sample.apk"
    with zipfile.ZipFile(sample, "w") as archive:
        archive.writestr("classes.dex", "READ_SMS RECEIVE_SMS")

    result = analyze_behavior(str(sample))

    assert result["analysis_method"] == "static_behavioral_inference"
    assert all(item["evidence_type"] == "INFERRED_STATIC" for item in result["dynamic_behaviors"])
    assert all(item["observed_at_runtime"] is False for item in result["dynamic_behaviors"])
