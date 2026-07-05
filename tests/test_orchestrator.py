from pathlib import Path
from unittest.mock import patch, MagicMock

from rescue.models import (
    SystemProfile, Platform, CheckResult, FixResult, Finding,
    Action, Severity, RiskLevel, Mode,
)
from rescue.module_base import ModuleBase
from rescue.orchestrator import Orchestrator


class SafeModule(ModuleBase):
    name = "safe_mod"
    category = "test"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    depends_on = []

    def check(self, profile):
        return CheckResult(
            module_name=self.name,
            findings=[
                Finding(
                    title="Safe issue",
                    description="Can be auto-fixed",
                    severity=Severity.WARNING,
                    category=self.category,
                )
            ],
        )

    def fix(self, findings, mode):
        return FixResult(
            module_name=self.name,
            actions=[
                Action(
                    title="Safe fix",
                    description="Applied safe fix",
                    risk_level=RiskLevel.SAFE,
                    success=True,
                )
            ],
        )


class DestructiveModule(ModuleBase):
    name = "destructive_mod"
    category = "test"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.DESTRUCTIVE
    depends_on = []

    def check(self, profile):
        return CheckResult(
            module_name=self.name,
            findings=[
                Finding(
                    title="Destructive issue",
                    description="Needs confirmation",
                    severity=Severity.CRITICAL,
                    category=self.category,
                )
            ],
        )

    def fix(self, findings, mode):
        return FixResult(
            module_name=self.name,
            actions=[
                Action(
                    title="Destructive fix",
                    description="Deleted something",
                    risk_level=RiskLevel.DESTRUCTIVE,
                    success=True,
                )
            ],
        )


class CleanModule(ModuleBase):
    name = "clean_mod"
    category = "test"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    depends_on = []

    def check(self, profile):
        return CheckResult(module_name=self.name)  # no findings

    def fix(self, findings, mode):
        return FixResult(module_name=self.name)


FAKE_PROFILE = SystemProfile(
    platform=Platform.DARWIN,
    os_name="macOS",
    os_version="15.2",
    architecture="arm64",
    cpu_model="Apple M2",
    cpu_cores=8,
    ram_bytes=16 * 1024**3,
)


def test_run_checks():
    fake_modules = [SafeModule(), CleanModule()]
    with patch("rescue.orchestrator.gather_profile", return_value=FAKE_PROFILE), \
         patch("rescue.orchestrator.discover_modules", return_value=fake_modules), \
         patch("rescue.orchestrator.filter_by_platform", return_value=fake_modules), \
         patch("rescue.orchestrator.topological_sort", return_value=fake_modules):
        orch = Orchestrator(modules_dir=Path("/fake"))
        results = orch.run_checks()

    assert len(results) == 2
    mod, check = results[0]
    assert mod.name == "safe_mod"
    assert check.has_issues

    mod, check = results[1]
    assert mod.name == "clean_mod"
    assert not check.has_issues


def test_run_fixes_auto_skips_destructive():
    safe = SafeModule()
    destructive = DestructiveModule()
    check_results = [
        (safe, safe.check(FAKE_PROFILE)),
        (destructive, destructive.check(FAKE_PROFILE)),
    ]

    orch = Orchestrator.__new__(Orchestrator)
    results = orch.run_fixes(check_results, Mode.AUTO)

    assert len(results) == 1  # only safe module gets fixed
    mod, check, fix = results[0]
    assert mod.name == "safe_mod"
    assert fix.all_succeeded


def test_run_fixes_cli_runs_all():
    safe = SafeModule()
    destructive = DestructiveModule()
    check_results = [
        (safe, safe.check(FAKE_PROFILE)),
        (destructive, destructive.check(FAKE_PROFILE)),
    ]

    orch = Orchestrator.__new__(Orchestrator)
    results = orch.run_fixes(check_results, Mode.CLI)

    assert len(results) == 2


def test_run_fixes_skips_clean_modules():
    clean = CleanModule()
    check_results = [
        (clean, clean.check(FAKE_PROFILE)),
    ]

    orch = Orchestrator.__new__(Orchestrator)
    results = orch.run_fixes(check_results, Mode.AUTO)
    assert len(results) == 0


def test_run_auto():
    fake_modules = [SafeModule(), DestructiveModule(), CleanModule()]
    with patch("rescue.orchestrator.gather_profile", return_value=FAKE_PROFILE), \
         patch("rescue.orchestrator.discover_modules", return_value=fake_modules), \
         patch("rescue.orchestrator.filter_by_platform", return_value=fake_modules), \
         patch("rescue.orchestrator.topological_sort", return_value=fake_modules):
        orch = Orchestrator(modules_dir=Path("/fake"))
        results = orch.run_auto()

    # 3 modules checked, but only safe_mod gets a fix in auto mode
    assert len(results) == 3
    names_with_fixes = [
        (mod.name, fix is not None) for mod, check, fix in results
    ]
    assert ("safe_mod", True) in names_with_fixes
    assert ("destructive_mod", False) in names_with_fixes
    assert ("clean_mod", False) in names_with_fixes
