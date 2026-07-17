"""Tests for the central bounded command runner."""

import sys

import pytest

from rescue.command import CommandResult, run, DEFAULT_TIMEOUT


def test_run_success_captures_output():
    result = run([sys.executable, "-c", "print('hello')"])
    assert isinstance(result, CommandResult)
    assert result.ok
    assert result.returncode == 0
    assert "hello" in result.stdout
    assert result.timed_out is False
    assert result.error is None


def test_run_nonzero_returncode_is_not_ok():
    result = run([sys.executable, "-c", "import sys; sys.exit(3)"])
    assert result.returncode == 3
    assert result.ok is False
    assert result.timed_out is False


def test_run_times_out_and_does_not_raise():
    result = run([sys.executable, "-c", "import time; time.sleep(30)"], timeout=0.5)
    assert result.timed_out is True
    assert result.ok is False
    assert result.error is not None


def test_run_missing_executable_returns_error_not_exception():
    result = run(["this_command_does_not_exist_xyz"])
    assert result.ok is False
    assert result.error is not None
    assert result.returncode is None


def test_run_truncates_oversized_output():
    # Emit ~200 KB but cap at 1 KB.
    code = "print('a' * 200000)"
    result = run([sys.executable, "-c", code], max_output=1024)
    assert result.truncated is True
    assert len(result.stdout) <= 1024 + 64  # small marker allowance


def test_run_rejects_string_command_to_prevent_shell_injection():
    with pytest.raises(TypeError):
        run("echo hello")  # must be a list, never a shell string


def test_default_timeout_is_bounded():
    assert 0 < DEFAULT_TIMEOUT <= 120
