"""Tests for orchestrator-level execution bounds (timeout + budget)."""

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
