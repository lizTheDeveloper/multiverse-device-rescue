from rescue.models import (
    SystemProfile, Platform, CheckResult, FixResult, Finding,
    Action, ActionKind, Severity, RiskLevel, Mode,
)
from rescue.module_base import ModuleBase


class FakeModule(ModuleBase):
    name = "fake_module"
    category = "test"
    platforms = [Platform.DARWIN, Platform.LINUX]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile):
        return CheckResult(
            module_name=self.name,
            findings=[
                Finding(
                    title="Test issue",
                    description="Something is wrong",
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
                    title="Fixed it",
                    description="Did the fix",
                    risk_level=RiskLevel.SAFE,
                    kind=ActionKind.MUTATION,
                    executed=True,
                    success=True,
                )
            ],
        )


def _make_profile():
    return SystemProfile(
        platform=Platform.DARWIN,
        os_name="macOS",
        os_version="15.2",
        architecture="arm64",
        cpu_model="Apple M2",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def test_module_check():
    mod = FakeModule()
    result = mod.check(_make_profile())
    assert result.has_issues
    assert len(result.findings) == 1
    assert result.findings[0].title == "Test issue"


def test_module_fix():
    mod = FakeModule()
    check = mod.check(_make_profile())
    fix = mod.fix(check, Mode.AUTO)
    assert fix.all_succeeded
    assert len(fix.actions) == 1


def test_module_report_with_issues():
    mod = FakeModule()
    check = mod.check(_make_profile())
    fix = mod.fix(check, Mode.AUTO)
    report = mod.report(check, fix)
    assert "fake_module" in report
    assert "Test issue" in report
    assert "Fixed it" in report
    assert "OK" in report


def test_module_report_no_issues():
    mod = FakeModule()
    check = CheckResult(module_name="fake_module")
    report = mod.report(check)
    assert "No issues found" in report
