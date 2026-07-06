"""Pure formatting/grouping helpers for the TUI. No Textual imports here —
kept dependency-free so it can be unit tested in isolation."""

from collections import defaultdict

from rescue.models import CheckResult, Finding, RiskLevel, Severity
from rescue.module_base import ModuleBase

SEVERITY_COLORS: dict[Severity, str] = {
    Severity.INFO: "cyan",
    Severity.WARNING: "yellow",
    Severity.CRITICAL: "red",
}

RISK_COLORS: dict[RiskLevel, str] = {
    RiskLevel.SAFE: "green",
    RiskLevel.MODERATE: "yellow",
    RiskLevel.DESTRUCTIVE: "red",
}


def group_by_category(modules: list[ModuleBase]) -> dict[str, list[ModuleBase]]:
    """Group modules by their `category` attribute, sorted by category name."""
    groups: dict[str, list[ModuleBase]] = defaultdict(list)
    for mod in modules:
        groups[mod.category].append(mod)
    return dict(sorted(groups.items()))


def severity_color(severity: Severity) -> str:
    return SEVERITY_COLORS.get(severity, "white")


def risk_color(risk_level: RiskLevel) -> str:
    return RISK_COLORS.get(risk_level, "white")


def format_finding_line(finding: Finding) -> str:
    """Rich-markup line for a single finding, color coded by severity."""
    color = severity_color(finding.severity)
    return f"[{color}]{finding.severity.value.upper()}[/{color}] {finding.title} — {finding.description}"


def format_module_summary(mod: ModuleBase, check: CheckResult) -> str:
    """One-line summary of a module's check result, for list rows."""
    if not check.has_issues:
        return f"{mod.name} — no issues found"
    color = "yellow"
    for f in check.findings:
        if f.severity == Severity.CRITICAL:
            color = "red"
            break
    return f"{mod.name} — [{color}]{len(check.findings)} issue(s)[/{color}]"


def format_category_summary(
    category: str, modules: list[ModuleBase], results: dict[str, CheckResult]
) -> str:
    """One-line summary of a category, showing total issue count across its modules."""
    total = sum(len(results[m.name].findings) for m in modules if m.name in results)
    if total == 0:
        return f"{category} — no issues found"
    return f"{category} — [yellow]{total} issue(s)[/yellow]"
