from __future__ import annotations

from fastapi.testclient import TestClient
import pytest

from app.main import app
from app.schemas.common import EvidenceType
from app.schemas.evidence import EvidenceLocation, EvidenceRecord

client = TestClient(app)


def test_versioned_health_and_legacy_compatibility():
    versioned = client.get("/api/v1/health")
    legacy = client.get("/health")

    assert versioned.status_code == 200
    assert legacy.status_code == 200
    assert versioned.json()["version"] == "3.2.0-phase3"
    assert versioned.json()["schema_version"] == "1.2"
    assert legacy.json()["api_version"] == "v1"


def test_request_id_is_propagated():
    response = client.get("/api/v1/health", headers={"X-Request-ID": "phase1-test-123"})

    assert response.status_code == 200
    assert response.headers["X-Request-ID"] == "phase1-test-123"
    assert response.json()["request_id"] == "phase1-test-123"


def test_openapi_exposes_versioned_routes_only():
    schema = client.get("/openapi.json").json()

    assert "/api/v1/analyze" in schema["paths"]
    assert "/api/v1/health" in schema["paths"]
    assert "/analyze" not in schema["paths"]


def test_standard_validation_error_contract():
    response = client.post("/api/v1/scan-url", json={})

    assert response.status_code == 422
    payload = response.json()
    assert payload["error"]["code"] == "INVALID_REQUEST"
    assert payload["request_id"]
    assert payload["detail"] == "Request validation failed."


def test_runtime_evidence_contract_rejects_false_runtime_claim():
    with pytest.raises(ValueError):
        EvidenceRecord(
            evidence_id="EVD-TEST",
            evidence_type=EvidenceType.OBSERVED_RUNTIME,
            title="Runtime event",
            description="Invalid example",
            location=EvidenceLocation(source="sandbox"),
            analyzer="test",
            analyzer_version="1",
            observed_at_runtime=False,
        )


def test_invalid_request_id_is_replaced():
    response = client.get("/api/v1/health", headers={"X-Request-ID": "invalid request id with spaces"})

    assert response.status_code == 200
    assert response.headers["X-Request-ID"] != "invalid request id with spaces"
    assert response.json()["request_id"] == response.headers["X-Request-ID"]


def test_local_only_policy_blocks_external_ai_and_hash_lookup():
    from app.core.config import Settings

    settings = Settings(privacy_mode="local_only", vt_api_key="configured", groq_api_key="configured")

    assert settings.hash_reputation_allowed_by_policy is False
    assert settings.ai_allowed_by_policy is False


def test_local_only_url_scan_does_not_call_external_feed(monkeypatch):
    import url_scanner

    def unexpected_external_call():
        raise AssertionError("External feed must not be called in local-only mode")

    monkeypatch.setattr(url_scanner, "_load_openphish_feed", unexpected_external_call)
    result = url_scanner.scan_message(
        "Review https://example.com/login", allow_external_lookup=False
    )

    assert result["urls"][0]["openphish_status"] == "disabled_by_privacy_policy"
