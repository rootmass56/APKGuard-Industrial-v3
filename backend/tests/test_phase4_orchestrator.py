from pathlib import Path

from app.core.config import Settings
from app.dynamic_analysis.command import CommandResult
from app.dynamic_analysis.orchestrator import AndroidSandboxOrchestrator
from app.schemas.dynamic import SandboxCapabilityResponse, ToolCapability


class FakeProcess:
    def __init__(self) -> None:
        self.terminated = False

    def terminate(self, timeout_seconds: float = 10.0) -> None:
        del timeout_seconds
        self.terminated = True


class FakeProbe:
    def __init__(self, response: SandboxCapabilityResponse) -> None:
        self.response = response

    def report(self) -> SandboxCapabilityResponse:
        return self.response


class FakeTools:
    inventory_calls = 0
    cleaned = []

    def __init__(self, settings, runner) -> None:
        del runner
        self.settings = settings
        self.serial = settings.sandbox_serial

    def start_emulator(self, workspace: Path):
        (workspace / "emulator.stdout.log").write_text("started", encoding="utf-8")
        return FakeProcess()

    def wait_for_boot(self) -> None:
        return None

    def apply_offline_network_policy(self):
        return {"airplane_mode": True, "policy_applied": True, "wifi_setting": "0"}

    def clear_logcat(self) -> None:
        return None

    def install(self, apk_path: Path):
        assert apk_path.is_file()
        return CommandResult(("adb", "install"), 0, "Success", "", 1)

    def collect_file_inventory(self, package_name: str):
        assert package_name == "com.example.safe"
        FakeTools.inventory_calls += 1
        if FakeTools.inventory_calls == 1:
            return [], None
        return ["./files/runtime.txt"], None

    def launch(self, package_name: str):
        return CommandResult(("adb", "monkey"), 0, "Events injected: 1", "", 1)

    def exercise_ui(self, package_name: str):
        return CommandResult(("adb", "monkey"), 0, "Events injected: 5", "", 1)

    def collect_logcat(self):
        return "1700000000.125 123 123 I ActivityTaskManager: START u0 cmp=com.example.safe/.MainActivity"

    def collect_package_dump(self, package_name: str):
        return f"Package [{package_name}]\nandroid.permission.CAMERA: granted=true"

    def collect_process_list(self):
        return "USER PID PPID NAME\nu0_a123 123 1 com.example.safe"

    def capture_screenshot(self, workspace: Path):
        path = workspace / "runtime-screenshot.png"
        path.write_bytes(b"png")
        return path

    def force_stop(self, package_name: str) -> None:
        FakeTools.cleaned.append(("force_stop", package_name))

    def uninstall(self, package_name: str) -> None:
        FakeTools.cleaned.append(("uninstall", package_name))

    def stop_emulator(self) -> None:
        FakeTools.cleaned.append(("stop_emulator", self.serial))


def test_orchestrator_produces_observed_runtime_evidence(monkeypatch, tmp_path: Path):
    quarantine = tmp_path / "quarantine"
    apk = quarantine / "aa" / "sample.apk"
    apk.parent.mkdir(parents=True)
    apk.write_bytes(b"PK-test")
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
        sandbox_instrumentation_mode="logcat_only",
        sandbox_interaction_seconds=1,
        sandbox_monkey_events=5,
        quarantine_dir=quarantine,
        sandbox_workspace_dir=tmp_path / "sessions",
    )
    tools = {
        "adb": ToolCapability(name="adb", available=True),
        "emulator": ToolCapability(name="emulator", available=True),
        "frida": ToolCapability(name="frida", available=False),
        "avd": ToolCapability(name="avd", available=True),
    }
    capability = SandboxCapabilityResponse(
        adapter_version="test-adapter",
        checked_at="2026-07-24T00:00:00Z",
        enabled=True,
        execution_permitted=True,
        ready=True,
        avd_name=settings.sandbox_avd_name,
        snapshot_name=settings.sandbox_snapshot_name,
        network_mode="offline",
        instrumentation_mode="logcat_only",
        tools=tools,
        blockers=[],
        warnings=[],
    )
    FakeTools.inventory_calls = 0
    FakeTools.cleaned = []
    monkeypatch.setattr("app.dynamic_analysis.orchestrator.AndroidSandboxTools", FakeTools)
    orchestrator = AndroidSandboxOrchestrator(
        settings=settings,
        repository=None,
        runner=object(),
        capability_probe=FakeProbe(capability),
        sleeper=lambda _seconds: None,
    )
    result = orchestrator.run(apk_path=apk, package_name="com.example.safe", scan_id="scan-phase4")
    assert result.dynamic_available is True
    assert result.status == "completed"
    assert result.cleanup_confirmed is True
    assert result.total_events >= 4
    assert all(event.evidence_digest for event in result.observed_events)
    assert any(event.event_type == "file_created" for event in result.observed_events)
    assert ("uninstall", "com.example.safe") in FakeTools.cleaned
