"""Tests for orchestrator-level execution bounds (timeout + budget)."""

import subprocess
import sys
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from rescue.models import (
    SystemProfile, Platform, CheckResult, Finding, Severity, RiskLevel,
)
from rescue.module_base import ModuleBase
from rescue.orchestrator import Orchestrator


FAKE_PROFILE = SystemProfile(
    platform=Platform.DARWIN, os_name="macOS", os_version="15.2",
    architecture="arm64", cpu_model="Apple M2", cpu_cores=8,
    ram_bytes=16 * 1024**3,
)


class HangingModule(ModuleBase):
    name = "hang_mod"
    category = "test"
    platforms = [Platform.DARWIN]
    depends_on = []

    def check(self, profile):
        time.sleep(30)
        return CheckResult(module_name=self.name)

    def fix(self, findings, mode):
        return None


class FastModule(ModuleBase):
    name = "fast_mod"
    category = "test"
    platforms = [Platform.DARWIN]
    depends_on = []

    def check(self, profile):
        return CheckResult(
            module_name=self.name,
            findings=[Finding("ok", "d", Severity.INFO, self.category)],
        )

    def fix(self, findings, mode):
        return None


def _patched(modules):
    return (
        patch("rescue.orchestrator.gather_profile", return_value=FAKE_PROFILE),
        patch("rescue.orchestrator.discover_modules", return_value=modules),
        patch("rescue.orchestrator.filter_by_platform", return_value=modules),
        patch("rescue.orchestrator.topological_sort", return_value=modules),
    )


def test_hanging_module_times_out_and_others_still_run():
    modules = [HangingModule(), FastModule()]
    patches = _patched(modules)
    for p in patches:
        p.start()
    try:
        orch = Orchestrator(modules_dir=Path("/fake"), module_timeout=0.5)
        start = time.monotonic()
        results = orch.run_checks()
        elapsed = time.monotonic() - start
    finally:
        for p in patches:
            p.stop()

    # The whole run must not block for the full 30s sleep.
    assert elapsed < 10
    by_name = {mod.name: check for mod, check in results}
    assert by_name["hang_mod"].error is not None
    assert "time" in by_name["hang_mod"].error.lower()
    assert by_name["fast_mod"].has_issues


def test_total_budget_skips_remaining_modules():
    # Two hanging modules; a tight budget means the second is skipped, not run.
    modules = [HangingModule(), FastModule()]
    patches = _patched(modules)
    for p in patches:
        p.start()
    try:
        orch = Orchestrator(
            modules_dir=Path("/fake"), module_timeout=0.5, total_budget=0.4
        )
        results = orch.run_checks()
    finally:
        for p in patches:
            p.stop()

    by_name = {mod.name: check for mod, check in results}
    # fast_mod should be reported as skipped due to exhausted budget.
    assert by_name["fast_mod"].error is not None
    assert "budget" in by_name["fast_mod"].error.lower()


def test_timeout_reason_is_plain_and_keeps_the_technical_detail():
    modules = [HangingModule()]
    patches = _patched(modules)
    for p in patches:
        p.start()
    try:
        results = Orchestrator(modules_dir=Path("/fake"), module_timeout=0.5).run_checks()
    finally:
        for p in patches:
            p.stop()
    error = results[0][1].error
    assert error.startswith(
        "This check took too long, so it was stopped before it could finish. "
        "Running the scan again may let it finish."
    )
    assert "next time" not in error
    assert "timed out after 0.5s" in error


# --- Regression: a timed-out check kept running commands in the background.
# Python cannot stop the abandoned worker thread, and on a real Mac one
# timed-out Wi-Fi check went on to run system_profiler 75 more times while
# later checks ran, slowing them until they timed out too.

_SLEEPER = [sys.executable, "-c", "import time; time.sleep(30)"]


class RunawayModule(ModuleBase):
    """Runs a command that never finishes, then (if it ever gets back) more."""

    name = "runaway_mod"
    category = "test"
    platforms = [Platform.DARWIN]
    depends_on = []

    def __init__(self):
        super().__init__()
        self.events = []
        self.done = threading.Event()

    def check(self, profile):
        try:
            started = time.monotonic()
            # No timeout of its own: the classic hang.
            subprocess.run(_SLEEPER, capture_output=True)
            self.events.append(("first-ended", round(time.monotonic() - started, 1)))
            for _ in range(5):
                try:
                    subprocess.run(_SLEEPER, capture_output=True)
                    self.events.append("another-ran")
                except OSError:
                    self.events.append("refused")
        finally:
            self.done.set()
        return CheckResult(module_name=self.name)

    def fix(self, findings, mode):
        return None


def test_abandoned_check_cannot_keep_running_commands():
    runaway = RunawayModule()
    modules = [runaway, FastModule()]
    patches = _patched(modules)
    for p in patches:
        p.start()
    original_popen = subprocess.Popen
    try:
        start = time.monotonic()
        results = Orchestrator(modules_dir=Path("/fake"), module_timeout=0.5).run_checks()
        elapsed = time.monotonic() - start
    finally:
        for p in patches:
            p.stop()

    assert elapsed < 5
    by_name = {mod.name: check for mod, check in results}
    assert "took too long" in by_name["runaway_mod"].error
    assert by_name["fast_mod"].has_issues  # the next check still ran

    # The hung command was stopped well before its 30 s sleep, and every
    # later command was refused rather than run.
    assert runaway.done.wait(5)
    first = runaway.events[0]
    assert first[0] == "first-ended" and first[1] < 5
    assert runaway.events[1:] == ["refused"] * 5
    # The guard wraps Popen rather than replacing it: still a Popen.
    assert issubclass(subprocess.Popen, original_popen)
    assert subprocess.run([sys.executable, "-c", "pass"]).returncode == 0


def test_commands_of_checks_that_finish_are_untouched():
    class Quick(ModuleBase):
        name = "quick_cmd"
        category = "test"
        platforms = [Platform.DARWIN]
        depends_on = []

        def check(self, profile):
            out = subprocess.run([sys.executable, "-c", "print('hi')"], capture_output=True, text=True)
            return CheckResult(
                module_name=self.name,
                findings=[Finding(out.stdout.strip(), "d", Severity.INFO, "test")],
            )

        def fix(self, findings, mode):
            return None

    modules = [HangingModule(), Quick()]
    patches = _patched(modules)
    for p in patches:
        p.start()
    try:
        results = Orchestrator(modules_dir=Path("/fake"), module_timeout=0.5).run_checks()
    finally:
        for p in patches:
            p.stop()
    by_name = {mod.name: check for mod, check in results}
    assert by_name["quick_cmd"].findings[0].title == "hi"


def _worker(guard, fn):
    """A thread the guard treats as a check's worker, like the orchestrator's."""
    thread = threading.Thread(target=fn, daemon=True)
    guard.register_worker(thread)
    thread.start()
    return thread


def _alive(pid):
    import os

    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    # A zombie still answers kill(0); treat it as gone if ps says so.
    out = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True)
    return bool(out.stdout.strip()) and not out.stdout.strip().startswith("Z")


@pytest.mark.skipif(sys.platform == "win32", reason="process groups are POSIX")
def test_stopping_a_check_kills_the_programs_its_command_started(tmp_path):
    """Review minor 5: killing only the direct child left grandchildren running."""
    from rescue.orchestrator import _AbandonGuard

    guard = _AbandonGuard()
    guard.ensure_installed()
    pid_file = tmp_path / "grandchild.pid"
    # The child starts a grandchild that sleeps, writes its pid, then waits on it.
    script = (
        "import subprocess, sys, time\n"
        "g = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])\n"
        f"open({str(pid_file)!r}, 'w').write(str(g.pid))\n"
        "g.wait()\n"
    )
    done = threading.Event()

    def check():
        subprocess.run([sys.executable, "-c", script], capture_output=True)
        done.set()

    worker = _worker(guard, check)
    deadline = time.monotonic() + 10
    while not pid_file.exists() or not pid_file.read_text():
        assert time.monotonic() < deadline
        time.sleep(0.05)
    grandchild = int(pid_file.read_text())
    assert _alive(grandchild)

    guard.abandon(worker)
    assert done.wait(5)
    deadline = time.monotonic() + 5
    while _alive(grandchild) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not _alive(grandchild)


def test_stopping_one_check_leaves_a_concurrent_checks_command_alone():
    """Review minor 11: two checks running commands at the same time; only the
    stopped one's command is killed."""
    from rescue.orchestrator import _AbandonGuard

    guard = _AbandonGuard()
    guard.ensure_installed()
    outcome = {}
    started = threading.Barrier(3)

    def survivor():
        started.wait()
        out = subprocess.run(
            [sys.executable, "-c", "import time; time.sleep(1.5); print('finished')"],
            capture_output=True, text=True,
        )
        outcome["survivor"] = (out.returncode, out.stdout.strip())

    def stopped():
        started.wait()
        t = time.monotonic()
        out = subprocess.run(_SLEEPER, capture_output=True)
        outcome["stopped"] = (out.returncode, time.monotonic() - t)

    a = _worker(guard, survivor)
    b = _worker(guard, stopped)
    started.wait()
    time.sleep(0.5)  # both commands are running now
    guard.abandon(b)
    a.join(10)
    b.join(10)

    assert outcome["survivor"] == (0, "finished")
    code, seconds = outcome["stopped"]
    assert code != 0 and seconds < 5


def test_a_command_started_as_its_check_is_stopped_is_reaped(monkeypatch):
    """Review minor 6: the child killed in the start path is waited on."""
    from rescue import orchestrator

    guard = orchestrator._AbandonGuard()
    guard.ensure_installed()
    waited = []
    popen_cls = subprocess.Popen
    real_wait = popen_cls.wait

    def spy_wait(self, timeout=None):
        waited.append(timeout)
        return real_wait(self, timeout)

    monkeypatch.setattr(popen_cls, "wait", spy_wait)
    calls = {"n": 0}
    real_admit = guard._admit

    def admit_then_abandon(proc):
        calls["n"] += 1
        if proc is not None:  # abandoned between the two admission checks
            guard.abandon(threading.current_thread())
        return real_admit(proc)

    monkeypatch.setattr(guard, "_admit", admit_then_abandon)
    errors = []

    def check():
        try:
            subprocess.Popen(_SLEEPER)
        except OSError as exc:
            errors.append(exc)

    _worker(guard, check).join(5)
    assert errors and "ran out of time" in str(errors[0])
    assert 1 in waited


# --- Windows: a check's command leads its own process group, and stopping
# it kills the whole tree with taskkill (falling back to the direct child).

def test_windows_command_gets_its_own_process_group():
    from rescue.orchestrator import _own_group_kwargs

    kwargs = {}
    assert _own_group_kwargs(kwargs, "nt") is True
    assert kwargs["creationflags"] & 0x00000200  # CREATE_NEW_PROCESS_GROUP
    kwargs = {"creationflags": 0x08000000}  # CREATE_NO_WINDOW kept
    _own_group_kwargs(kwargs, "nt")
    assert kwargs["creationflags"] == 0x08000000 | 0x00000200


def test_posix_respects_a_caller_chosen_session():
    from rescue.orchestrator import _own_group_kwargs

    kwargs = {"start_new_session": False}
    assert _own_group_kwargs(kwargs, "posix") is False
    assert kwargs == {"start_new_session": False}


class _FakeProc:
    def __init__(self, pid=4242):
        self.pid = pid
        self.killed = False
        self._rescue_own_group = True

    def poll(self):
        return None

    def kill(self):
        self.killed = True


def test_windows_stop_kills_the_tree_with_taskkill():
    from rescue import orchestrator

    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0)

    proc = _FakeProc()
    with patch.object(orchestrator.subprocess, "run", side_effect=fake_run):
        orchestrator._stop(proc, os_name="nt")
    assert calls == [["taskkill", "/T", "/F", "/PID", "4242"]]
    assert proc.killed is False


def test_windows_stop_falls_back_to_the_direct_child():
    from rescue import orchestrator

    proc = _FakeProc()
    with patch.object(orchestrator.subprocess, "run",
                      return_value=subprocess.CompletedProcess([], 128)):
        orchestrator._stop(proc, os_name="nt")
    assert proc.killed is True


# --- Cancel: the desktop cancels a scan by killing the engine (SIGTERM). The
# commands checks had started must not be left running.

_SIGNAL_CHILD = r"""
import subprocess, sys, threading, time
from rescue import orchestrator

orchestrator._GUARD.ensure_installed()
orchestrator.stop_commands_on_signals()

def check():
    p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    print(p.pid, flush=True)
    p.wait()

t = threading.Thread(target=check, daemon=True)
orchestrator._GUARD.register_worker(t)
t.start()
t.join()
"""


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")
@pytest.mark.parametrize("signame", ["SIGTERM", "SIGHUP"])
def test_signal_stops_check_commands_before_exit(signame):
    import os
    import signal

    root = str(Path(__file__).resolve().parent.parent)
    engine = subprocess.Popen(
        [sys.executable, "-c", _SIGNAL_CHILD],
        stdout=subprocess.PIPE, text=True, cwd=root,
        env={**os.environ, "PYTHONPATH": root},
    )
    try:
        command_pid = int(engine.stdout.readline())
        assert _alive(command_pid)
        engine.send_signal(getattr(signal, signame))
        assert engine.wait(10) == 128 + getattr(signal, signame)
        deadline = time.monotonic() + 5
        while _alive(command_pid) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert not _alive(command_pid)
    finally:
        if engine.poll() is None:
            engine.kill()


def test_scan_command_installs_the_signal_handler():
    import inspect

    from rescue import cli

    assert "stop_commands_on_signals()" in inspect.getsource(cli.scan.callback)
