"""Record every external command a scan runs.

Modules call ``subprocess`` directly in hundreds of places, so instead of
instrumenting each one this swaps ``subprocess.Popen`` (which ``run``,
``check_output`` and ``call`` all go through) for a subclass that reports each
command once it finishes. It is a context manager and restores the original on
exit, so tracing is opt-in (``rescue scan --trace``) and costs nothing otherwise.

Each event is a plain dict: ``module``, ``argv``, ``returncode`` (None if the
command never started) and ``seconds``; ``error`` is present when it failed to
start.
"""

from __future__ import annotations

import subprocess
import time
from contextlib import contextmanager


def _argv(args) -> list[str]:
    if isinstance(args, (str, bytes)):
        return [args.decode() if isinstance(args, bytes) else args]
    return [str(a) for a in args]


@contextmanager
def trace_commands(emit, current_module):
    original = subprocess.Popen

    class TracedPopen(original):
        def __init__(self, args, *a, **kw):
            self._trace_argv = _argv(args)
            self._trace_module = current_module()
            self._trace_start = time.monotonic()
            self._trace_sent = False
            try:
                super().__init__(args, *a, **kw)
            except OSError as exc:
                self._trace_send(None, error=str(exc))
                raise

        def _trace_send(self, returncode, **extra):
            if self._trace_sent:
                return
            self._trace_sent = True
            event = {
                "module": self._trace_module,
                "argv": self._trace_argv,
                "returncode": returncode,
                "seconds": round(time.monotonic() - self._trace_start, 3),
            }
            event.update(extra)
            try:
                emit(event)
            except Exception:
                pass  # tracing must never break a scan

        def poll(self):
            code = super().poll()
            if code is not None:
                self._trace_send(code)
            return code

        def wait(self, timeout=None):
            code = super().wait(timeout)
            self._trace_send(code)
            return code

    subprocess.Popen = TracedPopen
    try:
        yield
    finally:
        subprocess.Popen = original
