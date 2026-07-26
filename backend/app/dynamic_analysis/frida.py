"""Optional Frida CLI controller for the isolated emulator session."""

from __future__ import annotations

from pathlib import Path
from time import sleep

from app.core.config import Settings
from app.dynamic_analysis.command import CommandRunner, ManagedProcess


class FridaController:
    def __init__(self, settings: Settings, runner: CommandRunner) -> None:
        self.settings = settings
        self.runner = runner

    @property
    def agent_path(self) -> Path:
        return Path(__file__).with_name("frida_agent.js")

    def start(self, package_name: str, workspace: Path) -> ManagedProcess:
        process = self.runner.start(
            [
                self.settings.sandbox_frida_path,
                "-D",
                self.settings.sandbox_serial,
                "-n",
                package_name,
                "-l",
                str(self.agent_path),
                "-q",
            ],
            stdout_path=workspace / "frida-events.log",
            stderr_path=workspace / "frida-errors.log",
            cwd=workspace,
        )
        sleep(2.0)
        return process
