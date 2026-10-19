"""Tests for orchestrator-level execution bounds (timeout + budget)."""

import subprocess
import sys
import threading
import time
from pathlib import Path
from unittest.mock import patch

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
