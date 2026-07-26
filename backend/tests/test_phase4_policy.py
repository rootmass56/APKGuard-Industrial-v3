from pathlib import Path

from app.core.config import Settings
from app.dynamic_analysis.policy import SandboxPolicy


def test_sandbox_policy_is_fail_closed_by_default(tmp_path: Path):
    settings = Settings(
        quarantine_dir=tmp_path / "quarantine",
        sandbox_workspace_dir=tmp_path / "sessions",
    )
    policy = SandboxPolicy(settings)
    assert policy.execution_permitted is False
    assert any("APKGUARD_DYNAMIC_MODE" in item for item in policy.blockers())
    assert any("Redis-backed" in item for item in policy.blockers())


def test_sandbox_policy_requires_dedicated_worker_and_offline_mode(tmp_path: Path):
    settings = Settings(
        dynamic_mode="isolated_sandbox",
        sandbox_enabled=True,
        sandbox_risk_acknowledged=True,
        sandbox_dedicated_host=True,
        sandbox_host_egress_blocked=True,
        queue_backend="redis",
        analysis_isolation_mode="subprocess",
        sandbox_avd_name="APKGuard_API_35",
        sandbox_snapshot_name="apkguard-clean",
        sandbox_network_mode="offline",
        sandbox_allow_adb_root=False,
        quarantine_dir=tmp_path / "quarantine",
        sandbox_workspace_dir=tmp_path / "sessions",
    )
    policy = SandboxPolicy(settings)
    assert policy.execution_permitted is True
    response = policy.response()
    assert response.allows_adb_root is False
    assert response.allows_host_shell is False
    assert response.allows_unrestricted_egress is False
    assert response.requires_dedicated_worker is True
