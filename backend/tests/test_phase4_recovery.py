from pathlib import Path
from types import SimpleNamespace

from app.core.config import Settings
from app.dynamic_analysis.service import DynamicAnalysisService
from app.schemas.common import SandboxState


class FakeRepository:
    def __init__(self):
        self.transitions = []
        self.model = SimpleNamespace(session_id="session-1", state=SandboxState.INTERACTING.value)

    def get_by_scan(self, scan_id):
        return self.model if scan_id == "scan-1" else None

    def transition(self, session_id, state, **kwargs):
        self.transitions.append((session_id, state, kwargs))


def test_forced_analysis_termination_finalizes_runtime_session(tmp_path: Path, monkeypatch):
    settings = Settings(
        quarantine_dir=tmp_path / "quarantine",
        sandbox_workspace_dir=tmp_path / "sessions",
    )
    repository = FakeRepository()
    service = DynamicAnalysisService(settings=settings, repository=repository)
    stopped = []
    monkeypatch.setattr(
        "app.dynamic_analysis.service.AndroidSandboxTools.stop_emulator",
        lambda _self: stopped.append(True),
    )

    assert service.recover_scan_session("scan-1") is True
    assert stopped == [True]
    assert repository.transitions[0][1] == SandboxState.FAILED
    assert repository.transitions[0][2]["error_code"] == "FORCED_ANALYSIS_TERMINATION"
