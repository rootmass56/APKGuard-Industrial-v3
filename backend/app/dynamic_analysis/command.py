"""Allowlisted process execution for the isolated sandbox worker.

Host commands are always passed as argv arrays with ``shell=False``. Android
shell subcommands are still interpreted by the guest device, so callers must
only provide validated package names and fixed command tokens.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from time import monotonic
from typing import IO, Sequence

import psutil

_CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0


class CommandPolicyError(ValueError):
    pass


class CommandExecutionError(RuntimeError):
    def __init__(self, message: str, result: "CommandResult | None" = None) -> None:
        super().__init__(message)
        self.result = result


@dataclass(frozen=True, slots=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    duration_ms: int


@dataclass(slots=True)
class ManagedProcess:
    argv: tuple[str, ...]
    process: psutil.Popen
    stdin_handle: IO[bytes] | None = None
    stdout_handle: IO[str] | None = None
    stderr_handle: IO[str] | None = None

    def terminate(self, timeout_seconds: float = 10.0) -> None:
        try:
            if self.process.is_running():
                self.process.terminate()
                try:
                    self.process.wait(timeout=timeout_seconds)
                except psutil.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=timeout_seconds)
        except psutil.NoSuchProcess:
            return
        finally:
            self._close_handles()

    def _close_handles(self) -> None:
        for handle in (self.stdin_handle, self.stdout_handle, self.stderr_handle):
            if handle is not None and not handle.closed:
                handle.close()


class CommandRunner:
    """Run a small allowlist of host executables without invoking a shell."""

    def __init__(self, allowed_executables: Sequence[str], max_output_bytes: int = 2_000_000) -> None:
        resolved: set[str] = set()
        for configured in allowed_executables:
            executable = self.resolve_executable(configured)
            if executable:
                resolved.add(os.path.normcase(str(Path(executable).resolve())))
        self.allowed_executables = frozenset(resolved)
        self.max_output_bytes = max_output_bytes

    @staticmethod
    def resolve_executable(configured: str) -> str | None:
        candidate = Path(configured).expanduser()
        if candidate.is_file():
            return str(candidate.resolve())
        return shutil.which(configured)

    def _validate_argv(self, argv: Sequence[str]) -> tuple[str, ...]:
        if not argv or not str(argv[0]).strip():
            raise CommandPolicyError("Command argv must include an executable.")
        executable = self.resolve_executable(str(argv[0]))
        if not executable:
            raise CommandPolicyError(f"Executable is unavailable: {argv[0]}")
        normalized = os.path.normcase(str(Path(executable).resolve()))
        if normalized not in self.allowed_executables:
            raise CommandPolicyError(f"Executable is not allowed by sandbox policy: {argv[0]}")
        return (executable, *(str(item) for item in argv[1:]))

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout_seconds: float,
        check: bool = True,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
    ) -> CommandResult:
        validated = self._validate_argv(argv)
        started = monotonic()
        with tempfile.TemporaryDirectory(prefix="apkguard-command-") as temporary:
            stdout_path = Path(temporary) / "stdout.txt"
            stderr_path = Path(temporary) / "stderr.txt"
            with (
                open(os.devnull, "rb") as stdin_handle,
                stdout_path.open("w", encoding="utf-8", errors="replace") as stdout_handle,
                stderr_path.open("w", encoding="utf-8", errors="replace") as stderr_handle,
            ):
                process = psutil.Popen(
                    validated,
                    shell=False,
                    stdin=stdin_handle,
                    stdout=stdout_handle,
                    stderr=stderr_handle,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    cwd=str(cwd) if cwd else None,
                    env=env,
                    creationflags=_CREATE_NO_WINDOW,
                )
                try:
                    returncode = int(process.wait(timeout=timeout_seconds))
                except psutil.TimeoutExpired as exc:
                    process.kill()
                    process.wait(timeout=10)
                    raise TimeoutError(f"Command exceeded {timeout_seconds} seconds.") from exc
            stdout = self._read_limited(stdout_path)
            stderr = self._read_limited(stderr_path)
        result = CommandResult(
            argv=tuple(validated),
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
            duration_ms=max(0, round((monotonic() - started) * 1000)),
        )
        if check and result.returncode != 0:
            raise CommandExecutionError(
                f"Command failed with exit code {result.returncode}: {Path(validated[0]).name}",
                result,
            )
        return result

    def start(
        self,
        argv: Sequence[str],
        *,
        stdout_path: Path | None = None,
        stderr_path: Path | None = None,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
    ) -> ManagedProcess:
        validated = self._validate_argv(argv)
        stdin_handle: IO[bytes] | None = None
        stdout_handle: IO[str] | None = None
        stderr_handle: IO[str] | None = None
        try:
            stdin_handle = open(os.devnull, "rb")
            if stdout_path:
                stdout_path.parent.mkdir(parents=True, exist_ok=True)
                stdout_handle = stdout_path.open("w", encoding="utf-8", errors="replace")
            if stderr_path:
                stderr_path.parent.mkdir(parents=True, exist_ok=True)
                stderr_handle = stderr_path.open("w", encoding="utf-8", errors="replace")
            process = psutil.Popen(
                validated,
                shell=False,
                stdin=stdin_handle,
                stdout=stdout_handle,
                stderr=stderr_handle,
                text=True,
                encoding="utf-8",
                errors="replace",
                cwd=str(cwd) if cwd else None,
                env=env,
                creationflags=_CREATE_NO_WINDOW,
            )
        except Exception:
            for handle in (stdin_handle, stdout_handle, stderr_handle):
                if handle is not None and not handle.closed:
                    handle.close()
            raise
        return ManagedProcess(tuple(validated), process, stdin_handle, stdout_handle, stderr_handle)

    def _read_limited(self, path: Path) -> str:
        data = path.read_bytes()
        if len(data) > self.max_output_bytes:
            data = data[: self.max_output_bytes]
            suffix = "\n[output truncated by APKGuard sandbox policy]"
        else:
            suffix = ""
        return data.decode("utf-8", errors="replace") + suffix
