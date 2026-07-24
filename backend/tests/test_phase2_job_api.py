import io
import zipfile
from fastapi.testclient import TestClient

from app.main import create_app


def _apk_bytes() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
        archive.writestr("classes.dex", b"dex")
    return buffer.getvalue()


def test_phase2_routes_are_published():
    client = TestClient(create_app())
    schema = client.get("/openapi.json").json()
    paths = schema["paths"]
    assert "/api/v1/scans" in paths
    assert "/api/v1/scans/{scan_id}/progress" in paths
    assert "/api/v1/scans/{scan_id}/result" in paths
    assert "/api/v1/scans/{scan_id}/cancel" in paths
    assert "/api/v1/scans/{scan_id}/events" in paths


def test_health_reports_phase2_persistence():
    with TestClient(create_app()) as client:
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        body = response.json()
        assert body["version"] == "3.2.0-phase3"
        assert body["modules"]["database"]["immutable_results"] is True
        assert body["modules"]["quarantine"]["execution_permitted"] is False
