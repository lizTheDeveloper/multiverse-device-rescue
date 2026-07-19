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
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

# A read-only diagnostic scan should never wait minutes on one command.
DEFAULT_TIMEOUT = 20.0
# Cap captured output so a chatty command cannot exhaust memory.
DEFAULT_MAX_OUTPUT = 5 * 1024 * 1024  # 5 MiB
_TRUNCATION_MARKER = "\n...[output truncated]"
# How often the wait loop wakes to check for exit / overflow / timeout.
_POLL_INTERVAL = 0.02
# Pipe read chunk size.
_READ_CHUNK = 65536


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


def _drain(stream, cap: int, box: dict, overflow: threading.Event) -> None:
    """Read ``stream`` into ``box['data']`` keeping at most ``cap`` bytes.

    Once total bytes read exceed ``cap`` the stream is considered to be
    flooding: we set ``overflow`` and STOP reading (so peak memory stays bounded
    near ``cap`` instead of following the flood). The caller terminates the
    process on overflow, which unblocks any write the child is stuck on.
    """
    buf = bytearray()
    total = 0
    truncated = False
    try:
        while True:
            chunk = stream.read(_READ_CHUNK)
            if not chunk:
                break
            total += len(chunk)
            if len(buf) < cap:
                buf += chunk[: cap - len(buf)]
            if total > cap:
                truncated = True
                overflow.set()
                break
    except (OSError, ValueError):
        pass
    finally:
        try:
            stream.close()
        except OSError:
            pass
    box["data"] = bytes(buf)
    box["truncated"] = truncated


def _terminate(proc: subprocess.Popen) -> None:
    """Terminate then (if needed) hard-kill a process, and reap it."""
    for stop in (proc.terminate, proc.kill):
        try:
            stop()
            proc.wait(timeout=0.5)
            return
        except subprocess.TimeoutExpired:
            continue
        except (OSError, ValueError):
            return


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
    """Run ``args`` with a mandatory timeout and bounded PEAK output memory.

    Output is streamed and each of stdout/stderr is capped at ``max_output``
    bytes: as soon as a stream exceeds the cap the child is terminated, so a
    command that floods output cannot balloon this process's memory (unlike
    ``subprocess.run`` + ``communicate``, which buffers the whole stream before
    any truncation). Never raises for command failure, timeout, or a missing
    executable — the outcome is always reported on the returned
    :class:`CommandResult`. A ``str`` command is rejected so callers cannot
    accidentally invoke a shell.
    """
    if isinstance(args, (str, bytes)):
        raise TypeError(
            "command args must be a list/sequence of tokens, never a shell string"
        )
    arg_list = [str(a) for a in args]

    start = time.monotonic()
    try:
        proc = subprocess.Popen(
            arg_list,
            stdin=subprocess.PIPE if input is not None else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=dict(env) if env is not None else None,
            cwd=cwd,
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

    if input is not None:
        payload = input.encode("utf-8") if isinstance(input, str) else input

        def _feed() -> None:
            try:
                assert proc.stdin is not None
                proc.stdin.write(payload)
                proc.stdin.close()
            except (OSError, ValueError):
                pass

        threading.Thread(target=_feed, daemon=True).start()

    overflow = threading.Event()
    out_box: dict = {}
    err_box: dict = {}
    t_out = threading.Thread(
        target=_drain, args=(proc.stdout, max_output, out_box, overflow), daemon=True
    )
    t_err = threading.Thread(
        target=_drain, args=(proc.stderr, max_output, err_box, overflow), daemon=True
    )
    t_out.start()
    t_err.start()

    deadline = start + timeout
    timed_out = False
    while True:
        if proc.poll() is not None:
            break
        if overflow.is_set():
            # Give it a brief moment to finish on its own (a command that simply
            # printed a lot and is exiting), otherwise stop the flood.
            try:
                proc.wait(timeout=0.2)
            except subprocess.TimeoutExpired:
                _terminate(proc)
            break
        if time.monotonic() >= deadline:
            _terminate(proc)
            timed_out = True
            break
        time.sleep(_POLL_INTERVAL)

    try:
        proc.wait(timeout=1.0)
    except (subprocess.TimeoutExpired, OSError, ValueError):
        pass
    t_out.join(timeout=1.0)
    t_err.join(timeout=1.0)

    out_trunc = out_box.get("truncated", False)
    err_trunc = err_box.get("truncated", False)
    stdout = out_box.get("data", b"").decode("utf-8", errors="replace")
    stderr = err_box.get("data", b"").decode("utf-8", errors="replace")
    if out_trunc:
        stdout += _TRUNCATION_MARKER
    if err_trunc:
        stderr += _TRUNCATION_MARKER

    return CommandResult(
        args=arg_list,
        returncode=None if timed_out else proc.returncode,
        stdout=stdout,
        stderr=stderr,
        timed_out=timed_out,
        error=f"timed out after {timeout}s" if timed_out else None,
        duration_s=time.monotonic() - start,
        truncated=out_trunc or err_trunc,
    )
