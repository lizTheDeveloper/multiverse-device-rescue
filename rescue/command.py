"""Central bounded command runner.

Modules historically call :func:`subprocess.run` directly, frequently without a
timeout. That lets a single external command hang or flood memory and take down
an entire rescue session. This module provides one place where timeouts,
output-size limits, and error handling are enforced, and it always returns a
structured :class:`CommandResult` instead of raising.

Modules should migrate to :func:`run` instead of calling ``subprocess`` directly.
"""

from __future__ import annotations

import subprocess
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

# A read-only diagnostic scan should never wait minutes on one command.
DEFAULT_TIMEOUT = 20.0
# Cap captured output so a chatty command cannot exhaust memory.
DEFAULT_MAX_OUTPUT = 5 * 1024 * 1024  # 5 MiB
_TRUNCATION_MARKER = "\n...[output truncated]"


@dataclass
class CommandResult:
    """Outcome of a bounded command execution.

    ``returncode`` is ``None`` when the command never produced an exit status
    (it timed out, or the executable could not be launched).
    """

    args: list[str]
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool
    error: str | None
    duration_s: float
    truncated: bool

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and self.error is None


def _truncate(value: str | bytes, limit: int) -> tuple[str, bool]:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    if value is None:
        return "", False
    if len(value) <= limit:
        return value, False
    return value[:limit] + _TRUNCATION_MARKER, True


def run(
    args: Sequence[str],
    *,
    timeout: float = DEFAULT_TIMEOUT,
    max_output: int = DEFAULT_MAX_OUTPUT,
    text: bool = True,
    env: Mapping[str, str] | None = None,
    cwd: str | None = None,
    input: str | bytes | None = None,
) -> CommandResult:
    """Run ``args`` with a mandatory timeout and bounded output.

    Never raises for command failure, timeout, or a missing executable — the
    outcome is always reported on the returned :class:`CommandResult`. A
    ``str`` command is rejected so callers cannot accidentally invoke a shell.
    """
    if isinstance(args, (str, bytes)):
        raise TypeError(
            "command args must be a list/sequence of tokens, never a shell string"
        )
    arg_list = [str(a) for a in args]

    start = time.monotonic()
    try:
        completed = subprocess.run(
            arg_list,
            capture_output=True,
            text=text,
            timeout=timeout,
            env=dict(env) if env is not None else None,
            cwd=cwd,
            input=input,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        stdout, t1 = _truncate(exc.stdout or "", max_output)
        stderr, t2 = _truncate(exc.stderr or "", max_output)
        return CommandResult(
            args=arg_list,
            returncode=None,
            stdout=stdout,
            stderr=stderr,
            timed_out=True,
            error=f"timed out after {timeout}s",
            duration_s=time.monotonic() - start,
            truncated=t1 or t2,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return CommandResult(
            args=arg_list,
            returncode=None,
            stdout="",
            stderr="",
            timed_out=False,
            error=str(exc) or exc.__class__.__name__,
            duration_s=time.monotonic() - start,
            truncated=False,
        )

    stdout, t1 = _truncate(completed.stdout or "", max_output)
    stderr, t2 = _truncate(completed.stderr or "", max_output)
    return CommandResult(
        args=arg_list,
        returncode=completed.returncode,
        stdout=stdout,
        stderr=stderr,
        timed_out=False,
        error=None,
        duration_s=time.monotonic() - start,
        truncated=t1 or t2,
    )
