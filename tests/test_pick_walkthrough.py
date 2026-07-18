from rescue.guides import parse_guide_markdown
from rescue.models import CheckResult, Finding, Severity
from rescue.tui.screens._pick import highest_severity_walkthrough

WT = parse_guide_markdown(
    "---\ntitle: t\nestimated_time: \"5m\"\nremediates:\n  - c.crit\n"
    "automatable_steps: []\nhuman_only_steps: []\n---\n## Step 1: a\n\nb\n"
)


def test_picks_highest_severity_with_walkthrough():
    check = CheckResult(module_name="m", findings=[
        Finding(title="i", description="d", severity=Severity.INFO, category="s", code="c.info"),
        Finding(title="c", description="d", severity=Severity.CRITICAL, category="s", code="c.crit"),
    ])
    assert highest_severity_walkthrough({"c.crit": WT}, check) is WT


def test_none_when_no_coded_finding_has_walkthrough():
    check = CheckResult(module_name="m", findings=[
        Finding(title="i", description="d", severity=Severity.INFO, category="s"),
    ])
    assert highest_severity_walkthrough({"c.crit": WT}, check) is None
