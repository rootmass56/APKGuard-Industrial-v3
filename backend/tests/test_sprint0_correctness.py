import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def test_dynamic_analysis_does_not_simulate_without_package():
    from dynamic_analyzer import run_dynamic_analysis

    result = run_dynamic_analysis("/tmp/nonexistent.apk", package_name=None, analysis={"permissions": {"dangerous": []}})

    assert result["dynamic_available"] is False
    assert result["status"] == "not_executed"
    assert result["api_calls_intercepted"] == []
    assert result["dynamic_risk_score"] == 0


def test_ai_fallback_without_key(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    from ai_engine import get_ai_analysis

    result = get_ai_analysis({}, {"score": 10, "severity": "LOW"})

    assert result["available"] is False
    assert "disabled" in result["analyst_note"].lower()


def test_batch_tester_synthetic_notice():
    from batch_tester import run_batch_test

    result = run_batch_test()

    assert "Synthetic" in result["validation_notice"]
    assert result["total_samples"] > 0
