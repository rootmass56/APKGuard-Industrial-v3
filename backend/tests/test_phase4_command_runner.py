import sys

import pytest

from app.dynamic_analysis.command import CommandPolicyError, CommandRunner


def test_command_runner_uses_allowlist_and_shell_free_argv():
    runner = CommandRunner([sys.executable], max_output_bytes=1024)
    result = runner.run([sys.executable, "-c", "print('sandbox-ok')"], timeout_seconds=10)
    assert result.returncode == 0
    assert result.stdout.strip() == "sandbox-ok"
    assert result.argv[0]


def test_command_runner_rejects_unavailable_or_unapproved_executable():
    runner = CommandRunner([sys.executable])
    with pytest.raises(CommandPolicyError):
        runner.run(["apkguard-command-that-does-not-exist", "--version"], timeout_seconds=1)
