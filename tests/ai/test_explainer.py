import asyncio
from unittest.mock import MagicMock

from rescue.ai.explainer import DiagnosticExplainer, Explanation, build_findings_summary
from rescue.models import CheckResult, Finding, Platform, RiskLevel, Severity
from rescue.module_base import ModuleBase


class FakeModule(ModuleBase):
    name = "disk_space"
    category = "performance"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE

    def check(self, profile):
        raise NotImplementedError

    def fix(self, findings, mode):
        raise NotImplementedError


def _finding(title="Low disk space", severity=Severity.WARNING):
    return Finding(
        title=title,
        description="Only 12 GB free on /",
        severity=severity,
        category="performance",
    )


def test_build_findings_summary_formats_lines():
    mod = FakeModule()
    check = CheckResult(module_name=mod.name, findings=[_finding()])
    summary = build_findings_summary([(mod, check)])
    assert summary == "[performance/disk_space] (warning) Low disk space: Only 12 GB free on /"


def test_build_findings_summary_empty_for_no_findings():
    mod = FakeModule()
    check = CheckResult(module_name=mod.name, findings=[])
    assert build_findings_summary([(mod, check)]) == ""


def test_explain_returns_no_issues_message_without_calling_provider():
    mod = FakeModule()
    check = CheckResult(module_name=mod.name, findings=[])
    fake_provider = MagicMock()
    fake_provider.provider_name = "anthropic"

    explainer = DiagnosticExplainer(fake_provider)
    result = explainer.explain([(mod, check)])

    assert isinstance(result, Explanation)
    assert "No issues found" in result.narrative
    fake_provider.complete.assert_not_called()


def test_explain_calls_provider_with_summary():
    mod = FakeModule()
    check = CheckResult(module_name=mod.name, findings=[_finding()])
    fake_provider = MagicMock()
    fake_provider.provider_name = "openai"
    fake_provider.complete.return_value = "Your disk is nearly full because of old backups."

    explainer = DiagnosticExplainer(fake_provider)
    result = explainer.explain([(mod, check)])

    assert result.narrative == "Your disk is nearly full because of old backups."
    assert result.provider_name == "openai"
    fake_provider.complete.assert_called_once()
    _, kwargs = fake_provider.complete.call_args
    assert "Low disk space" in kwargs["messages"][0].content


def test_explain_async_calls_provider_complete_async():
    mod = FakeModule()
    check = CheckResult(module_name=mod.name, findings=[_finding()])
    fake_provider = MagicMock()
    fake_provider.provider_name = "ollama"

    async def fake_complete_async(messages, system=None):
        return "Async explanation."

    fake_provider.complete_async = fake_complete_async

    explainer = DiagnosticExplainer(fake_provider)
    result = asyncio.run(explainer.explain_async([(mod, check)]))

    assert result.narrative == "Async explanation."
    assert result.provider_name == "ollama"
