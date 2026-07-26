from fastapi.testclient import TestClient

from app.main import create_app


def test_phase4_dynamic_control_plane_routes_are_published():
    client = TestClient(create_app())
    paths = client.get("/openapi.json").json()["paths"]
    assert "/api/v1/dynamic-analysis/capabilities" in paths
    assert "/api/v1/dynamic-analysis/policy" in paths
    assert "/api/v1/dynamic-analysis/sessions/{scan_id}" in paths
    assert "/api/v1/dynamic-analysis/sessions/{scan_id}/events" in paths


def test_health_reports_fail_closed_phase4_sandbox():
    with TestClient(create_app()) as client:
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        body = response.json()
        assert body["version"] == "4.0.0-phase4"
        sandbox = body["modules"]["isolated_dynamic_analysis"]
        assert sandbox["observed_runtime_only"] is True
        assert sandbox["network_mode"] == "offline"
