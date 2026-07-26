"""Android Emulator and ADB adapter used by the dedicated sandbox worker."""

from __future__ import annotations

import re
from pathlib import Path
from time import monotonic, sleep

from app.core.config import Settings
from app.dynamic_analysis.command import CommandExecutionError, CommandResult, CommandRunner, ManagedProcess

_PACKAGE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+$")


class SandboxBootError(RuntimeError):
    pass


class AndroidSandboxTools:
    def __init__(self, settings: Settings, runner: CommandRunner) -> None:
        self.settings = settings
        self.runner = runner
        self.serial = settings.sandbox_serial

    @staticmethod
    def validate_package_name(package_name: str) -> str:
        if not _PACKAGE_RE.fullmatch(package_name):
            raise ValueError("Package name is not safe for Android sandbox commands.")
        return package_name

    def start_emulator(self, workspace: Path) -> ManagedProcess:
        port = int(self.serial.rsplit("-", 1)[-1])
        argv = [
            self.settings.sandbox_emulator_path,
            "-avd",
            self.settings.sandbox_avd_name,
            "-port",
            str(port),
            "-snapshot",
            self.settings.sandbox_snapshot_name,
            "-no-snapshot-save",
            "-no-boot-anim",
            "-no-audio",
        ]
        if self.settings.sandbox_capture_network:
            argv.extend(["-tcpdump", str((workspace / "runtime-network.pcap").resolve())])
        if self.settings.sandbox_headless:
            argv.append("-no-window")
        return self.runner.start(
            argv,
            stdout_path=workspace / "emulator.stdout.log",
            stderr_path=workspace / "emulator.stderr.log",
            cwd=workspace,
        )

    def adb(
        self,
        *args: str,
        timeout_seconds: float = 30,
        check: bool = True,
    ) -> CommandResult:
        return self.runner.run(
            [self.settings.sandbox_adb_path, "-s", self.serial, *args],
            timeout_seconds=timeout_seconds,
            check=check,
        )

    def wait_for_boot(self) -> None:
        deadline = monotonic() + self.settings.sandbox_boot_timeout_seconds
        self.adb("wait-for-device", timeout_seconds=self.settings.sandbox_boot_timeout_seconds)
        last_error = ""
        while monotonic() < deadline:
            try:
                result = self.adb(
                    "shell",
                    "getprop",
                    "sys.boot_completed",
                    timeout_seconds=10,
                    check=False,
                )
                if result.stdout.strip() == "1":
                    self.adb("shell", "input", "keyevent", "82", timeout_seconds=10, check=False)
                    return
                last_error = result.stderr.strip()
            except (CommandExecutionError, OSError) as exc:
                last_error = str(exc)
            sleep(1.0)
        raise SandboxBootError(f"Emulator did not complete boot before timeout. {last_error}".strip())

    def apply_offline_network_policy(self) -> dict[str, str | bool]:
        commands = [
            ("shell", "settings", "put", "global", "airplane_mode_on", "1"),
            ("shell", "am", "broadcast", "-a", "android.intent.action.AIRPLANE_MODE", "--ez", "state", "true"),
            ("shell", "svc", "wifi", "disable"),
            ("shell", "svc", "data", "disable"),
            ("shell", "settings", "put", "global", "http_proxy", ":0"),
            ("shell", "settings", "put", "global", "private_dns_mode", "off"),
        ]
        for command in commands:
            self.adb(*command, timeout_seconds=15, check=False)
        airplane = self.adb(
            "shell",
            "settings",
            "get",
            "global",
            "airplane_mode_on",
            timeout_seconds=10,
            check=False,
        ).stdout.strip()
        wifi = self.adb("shell", "settings", "get", "global", "wifi_on", timeout_seconds=10, check=False)
        return {
            "airplane_mode": airplane == "1",
            "wifi_setting": wifi.stdout.strip(),
            "policy_applied": airplane == "1",
        }

    def clear_logcat(self) -> None:
        self.adb("logcat", "-c", timeout_seconds=15, check=False)

    def install(self, apk_path: Path) -> CommandResult:
        return self.adb(
            "install",
            "-r",
            "-t",
            str(apk_path.resolve()),
            timeout_seconds=self.settings.sandbox_execution_timeout_seconds,
        )

    def launch(self, package_name: str) -> CommandResult:
        package = self.validate_package_name(package_name)
        return self.adb(
            "shell",
            "monkey",
            "-p",
            package,
            "-c",
            "android.intent.category.LAUNCHER",
            "1",
            timeout_seconds=30,
            check=False,
        )

    def exercise_ui(self, package_name: str) -> CommandResult:
        package = self.validate_package_name(package_name)
        return self.adb(
            "shell",
            "monkey",
            "-p",
            package,
            "--throttle",
            "250",
            "--pct-syskeys",
            "0",
            "--pct-appswitch",
            "0",
            "-v",
            str(self.settings.sandbox_monkey_events),
            timeout_seconds=self.settings.sandbox_execution_timeout_seconds,
            check=False,
        )

    def collect_logcat(self) -> str:
        return self.adb(
            "logcat",
            "-d",
            "-v",
            "epoch",
            timeout_seconds=30,
            check=False,
        ).stdout


    def collect_process_list(self) -> str:
        return self.adb(
            "shell",
            "ps",
            "-A",
            timeout_seconds=30,
            check=False,
        ).stdout

    def collect_package_dump(self, package_name: str) -> str:
        package = self.validate_package_name(package_name)
        return self.adb(
            "shell",
            "dumpsys",
            "package",
            package,
            timeout_seconds=30,
            check=False,
        ).stdout

    def collect_file_inventory(self, package_name: str) -> tuple[list[str], str | None]:
        package = self.validate_package_name(package_name)
        result = self.adb(
            "shell",
            "run-as",
            package,
            "find",
            ".",
            "-type",
            "f",
            "-print",
            timeout_seconds=30,
            check=False,
        )
        if result.returncode != 0:
            return [], result.stderr.strip() or "run-as inventory unavailable for this application."
        files = sorted({line.strip() for line in result.stdout.splitlines() if line.strip()})
        return files[:10000], None

    def capture_screenshot(self, workspace: Path) -> Path | None:
        remote = "/sdcard/apkguard-runtime.png"
        self.adb("shell", "screencap", "-p", remote, timeout_seconds=20, check=False)
        local = workspace / "runtime-screenshot.png"
        pulled = self.adb("pull", remote, str(local), timeout_seconds=30, check=False)
        self.adb("shell", "rm", "-f", remote, timeout_seconds=10, check=False)
        return local if pulled.returncode == 0 and local.exists() else None

    def force_stop(self, package_name: str) -> None:
        package = self.validate_package_name(package_name)
        self.adb("shell", "am", "force-stop", package, timeout_seconds=15, check=False)

    def uninstall(self, package_name: str) -> None:
        package = self.validate_package_name(package_name)
        self.adb("uninstall", package, timeout_seconds=30, check=False)

    def stop_emulator(self) -> None:
        self.adb("emu", "kill", timeout_seconds=15, check=False)
