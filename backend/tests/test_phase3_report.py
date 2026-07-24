from pathlib import Path

from report_generator import generate_pdf_report


def test_phase3_report_accepts_advanced_static_sections():
    output = generate_pdf_report(
        {
            "scan_id": "phase3-report",
            "filename": "safe-fixture.apk",
            "risk_score": 20,
            "static_score": 20,
            "dynamic_score": 0,
            "findings": [],
            "advanced_static": {
                "metrics": {
                    "evidence_count": 3,
                    "finding_count": 2,
                    "exported_component_count": 1,
                    "deep_link_count": 1,
                    "native_library_count": 0,
                    "dependency_count": 1,
                    "candidate_flow_count": 1,
                }
            },
            "signing": {"detected_schemes": ["v2"]},
            "sbom": {"components": [{"name": "OkHttp"}]},
            "limitations": ["Static analysis only."],
        }
    )
    path = Path(output)
    try:
        assert path.exists()
        assert path.stat().st_size > 1000
    finally:
        path.unlink(missing_ok=True)
