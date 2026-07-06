from rescue.models import CheckResult, Finding, Platform, RiskLevel, Severity
from rescue.module_base import ModuleBase
from rescue.tui.formatting import (
    format_category_summary,
    format_finding_line,
    format_module_summary,
    group_by_category,
    risk_color,
    severity_color,
)


class PerfModule(ModuleBase):
    name = "disk_space"
    category = "performance"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE

    def check(self, profile):
        pass

    def fix(self, findings, mode):
        pass


class SecurityModule(ModuleBase):
    name = "firewall_audit"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.MODERATE

    def check(self, profile):
        pass

    def fix(self, findings, mode):
        pass


def test_group_by_category():
    modules = [SecurityModule(), PerfModule()]
    groups = group_by_category(modules)
    assert list(groups.keys()) == ["performance", "security"]
    assert groups["performance"] == [modules[1]]
    assert groups["security"] == [modules[0]]


def test_severity_color():
    assert severity_color(Severity.CRITICAL) == "red"
    assert severity_color(Severity.WARNING) == "yellow"
    assert severity_color(Severity.INFO) == "cyan"


def test_risk_color():
    assert risk_color(RiskLevel.SAFE) == "green"
    assert risk_color(RiskLevel.MODERATE) == "yellow"
    assert risk_color(RiskLevel.DESTRUCTIVE) == "red"


def test_format_finding_line_includes_severity_and_text():
    finding = Finding(
        title="Disk full",
        description="90% used",
        severity=Severity.CRITICAL,
        category="performance",
    )
    line = format_finding_line(finding)
    assert "CRITICAL" in line
    assert "Disk full" in line
    assert "90% used" in line
    assert "[red]" in line


def test_format_module_summary_no_issues():
    mod = PerfModule()
    check = CheckResult(module_name="disk_space")
    summary = format_module_summary(mod, check)
    assert "no issues found" in summary


def test_format_module_summary_with_issues():
    mod = PerfModule()
    check = CheckResult(
        module_name="disk_space",
        findings=[
            Finding(
                title="Disk full",
                description="d",
                severity=Severity.CRITICAL,
                category="performance",
            )
        ],
    )
    summary = format_module_summary(mod, check)
    assert "1 issue(s)" in summary
    assert "[red]" in summary


def test_format_category_summary_aggregates_across_modules():
    mods = [PerfModule()]
    results = {
        "disk_space": CheckResult(
            module_name="disk_space",
            findings=[
                Finding(
                    title="t", description="d", severity=Severity.WARNING, category="performance"
                )
            ],
        )
    }
    summary = format_category_summary("performance", mods, results)
    assert "1 issue(s)" in summary


def test_format_category_summary_no_issues():
    mods = [PerfModule()]
    results = {"disk_space": CheckResult(module_name="disk_space")}
    summary = format_category_summary("performance", mods, results)
    assert "no issues found" in summary
