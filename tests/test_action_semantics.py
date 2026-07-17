"""Auto mode is read-only by default; guidance never counts as a system change."""

from pathlib import Path
from unittest.mock import patch

from rescue.models import (
    Action, ActionKind, CheckResult, Finding, FixResult, Mode, Platform,
    RiskLevel, Severity, SystemProfile,
)
from rescue.module_base import ModuleBase
from rescue.orchestrator import Orchestrator


FAKE_PROFILE = SystemProfile(
    platform=Platform.DARWIN, os_name="macOS", os_version="15.2",
    architecture="arm64", cpu_model="Apple M2", cpu_cores=8, ram_bytes=8 * 1024**3,
)


def _issue(cat="test"):
    return CheckResult(
        module_name="m",
        findings=[Finding("issue", "d", Severity.WARNING, cat)],
    )


class SafeNoAutoApply(ModuleBase):
    """SAFE, but has NOT opted into unattended mutation → read-only in auto."""
    name = "safe_no_auto"
    category = "test"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    depends_on = []

    def check(self, profile):
        return _issue()

    def fix(self, findings, mode):
        return FixResult(
            module_name=self.name,
            actions=[Action("did a thing", "d", RiskLevel.SAFE,
                            kind=ActionKind.MUTATION, executed=True, success=True)],
        )


class SafeAutoApply(SafeNoAutoApply):
    name = "safe_auto"
    auto_apply = True


def _patched(modules):
    return [
        patch("rescue.orchestrator.gather_profile", return_value=FAKE_PROFILE),
        patch("rescue.orchestrator.discover_modules", return_value=modules),
        patch("rescue.orchestrator.filter_by_platform", return_value=modules),
        patch("rescue.orchestrator.topological_sort", return_value=modules),
    ]


def test_auto_mode_is_readonly_for_modules_without_auto_apply():
    mod = SafeNoAutoApply()
    orch = Orchestrator.__new__(Orchestrator)
    results = orch.run_fixes([(mod, mod.check(FAKE_PROFILE))], Mode.AUTO)
    assert results == []  # nothing applied automatically


def test_auto_mode_applies_only_opted_in_modules():
    opted = SafeAutoApply()
    not_opted = SafeNoAutoApply()
    check_results = [
        (opted, opted.check(FAKE_PROFILE)),
        (not_opted, not_opted.check(FAKE_PROFILE)),
    ]
    orch = Orchestrator.__new__(Orchestrator)
    results = orch.run_fixes(check_results, Mode.AUTO)
    assert [m.name for m, _, _ in results] == ["safe_auto"]


def test_cli_mode_still_runs_all_regardless_of_auto_apply():
    not_opted = SafeNoAutoApply()
    orch = Orchestrator.__new__(Orchestrator)
    results = orch.run_fixes([(not_opted, not_opted.check(FAKE_PROFILE))], Mode.CLI)
    assert len(results) == 1


def test_guidance_actions_never_count_as_system_changes():
    fix = FixResult(
        module_name="m",
        actions=[
            Action("advice", "do this yourself", RiskLevel.SAFE,
                   kind=ActionKind.GUIDANCE, executed=True, success=True),
            Action("real change", "changed system", RiskLevel.SAFE,
                   kind=ActionKind.MUTATION, executed=True, success=True),
        ],
    )
    assert len(fix.executed_mutations) == 1
    assert fix.executed_mutations[0].title == "real change"
    assert len(fix.guidance_actions) == 1
