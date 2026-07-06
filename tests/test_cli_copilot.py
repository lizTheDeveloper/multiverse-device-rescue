from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from rescue.ai.explainer import Explanation
from rescue.ai.providers.base import AIRequestError
from rescue.ai.recommender import RecommenderTurn
from rescue.cli import main
from rescue.models import (
    Action,
    CheckResult,
    Finding,
    FixResult,
    Mode,
    Platform,
    RiskLevel,
    Severity,
    SystemProfile,
)
from rescue.module_base import ModuleBase


class FakeMod(ModuleBase):
    name = "fake_mod"
    category = "test"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE

    def check(self, profile):
        return CheckResult(
            module_name=self.name,
            findings=[
                Finding(
                    title="Test issue",
                    description="Something wrong",
                    severity=Severity.WARNING,
                    category="test",
                )
            ],
        )

    def fix(self, findings, mode):
        return FixResult(
            module_name=self.name,
            actions=[
                Action(
                    title="Fixed",
                    description="Fixed it",
                    risk_level=RiskLevel.SAFE,
                    success=True,
                )
            ],
        )


def test_auto_copilot_without_provider_prints_message():
    fake = FakeMod()
    auto_results = [(fake, fake.check(None), fake.fix(None, Mode.AUTO))]

    with patch("rescue.cli.Orchestrator") as MockOrch, \
         patch("rescue.cli.get_provider", return_value=None):
        MockOrch.return_value.run_auto.return_value = auto_results
        runner = CliRunner()
        result = runner.invoke(main, ["--auto", "--copilot"])

    assert result.exit_code == 0
    assert "no AI provider is configured" in result.output


def test_auto_copilot_with_provider_prints_explanation():
    fake = FakeMod()
    auto_results = [(fake, fake.check(None), fake.fix(None, Mode.AUTO))]
    fake_provider = MagicMock()
    fake_provider.provider_name = "anthropic"

    with patch("rescue.cli.Orchestrator") as MockOrch, \
         patch("rescue.cli.get_provider", return_value=fake_provider), \
         patch("rescue.cli.DiagnosticExplainer") as MockExplainer:
        MockOrch.return_value.run_auto.return_value = auto_results
        MockExplainer.return_value.explain.return_value = Explanation(
            narrative="Your disk is fine, but a test issue was found.",
            provider_name="anthropic",
        )
        runner = CliRunner()
        result = runner.invoke(main, ["--auto", "--copilot"])

    assert result.exit_code == 0
    assert "Your disk is fine, but a test issue was found." in result.output
    assert "via anthropic" in result.output


def test_auto_without_copilot_never_mentions_ai():
    fake = FakeMod()
    auto_results = [(fake, fake.check(None), fake.fix(None, Mode.AUTO))]

    with patch("rescue.cli.Orchestrator") as MockOrch, \
         patch("rescue.cli.get_provider") as mock_get_provider:
        MockOrch.return_value.run_auto.return_value = auto_results
        runner = CliRunner()
        result = runner.invoke(main, ["--auto"])

    assert result.exit_code == 0
    mock_get_provider.assert_not_called()
    assert "AI" not in result.output
    assert "copilot" not in result.output.lower()


def test_auto_copilot_provider_error_does_not_crash():
    fake = FakeMod()
    auto_results = [(fake, fake.check(None), fake.fix(None, Mode.AUTO))]
    fake_provider = MagicMock()
    fake_provider.provider_name = "anthropic"

    with patch("rescue.cli.Orchestrator") as MockOrch, \
         patch("rescue.cli.get_provider", return_value=fake_provider), \
         patch("rescue.cli.DiagnosticExplainer") as MockExplainer:
        MockOrch.return_value.run_auto.return_value = auto_results
        MockExplainer.return_value.explain.side_effect = AIRequestError("connection reset")
        runner = CliRunner()
        result = runner.invoke(main, ["--auto", "--copilot"])

    # The AI failure must not crash the CLI or hide the scan results already printed.
    assert result.exit_code == 0
    assert result.exception is None
    assert "AI explanation unavailable" in result.output
    assert "connection reset" in result.output
    assert "Test issue" in result.output  # scan output still present


_FAKE_PROFILE = SystemProfile(
    platform=Platform.DARWIN, os_name="macOS", os_version="15.2",
    architecture="arm64", cpu_model="M2", cpu_cores=8,
    ram_bytes=16 * 1024**3,
)


def test_run_copilot_with_provider_prints_explanation():
    fake = FakeMod()
    fake_provider = MagicMock()
    fake_provider.provider_name = "anthropic"

    with patch("rescue.cli.discover_modules", return_value=[fake]), \
         patch("rescue.cli.gather_profile", return_value=_FAKE_PROFILE), \
         patch("rescue.cli.get_provider", return_value=fake_provider), \
         patch("rescue.cli.DiagnosticExplainer") as MockExplainer:
        MockExplainer.return_value.explain.return_value = Explanation(
            narrative="A single test issue was found.",
            provider_name="anthropic",
        )
        runner = CliRunner()
        result = runner.invoke(main, ["run", "fake_mod", "--yes", "--copilot"])

    assert result.exit_code == 0
    assert "A single test issue was found." in result.output
    assert "via anthropic" in result.output


def test_run_without_copilot_never_mentions_ai():
    fake = FakeMod()

    with patch("rescue.cli.discover_modules", return_value=[fake]), \
         patch("rescue.cli.gather_profile", return_value=_FAKE_PROFILE), \
         patch("rescue.cli.get_provider") as mock_get_provider:
        runner = CliRunner()
        result = runner.invoke(main, ["run", "fake_mod", "--yes"])

    assert result.exit_code == 0
    mock_get_provider.assert_not_called()


def test_recommend_without_provider():
    with patch("rescue.cli.get_provider", return_value=None):
        runner = CliRunner()
        result = runner.invoke(main, ["recommend"])

    assert result.exit_code == 0
    assert "requires an AI provider" in result.output


def test_recommend_provider_error_lets_user_retry():
    fake_provider = MagicMock()

    with patch("rescue.cli.get_provider", return_value=fake_provider), \
         patch("rescue.cli.ProfileRecommender") as MockRecommender:
        instance = MockRecommender.return_value
        instance.ask.side_effect = [
            AIRequestError("timed out"),
            RecommenderTurn(
                message="Got it.", is_recommendation=True, profile_slug="personal_lockdown"
            ),
        ]
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["recommend"],
            input="I want more privacy day to day.\nJust general caution.\n",
        )

    assert result.exit_code == 0
    assert result.exception is None
    assert "AI request failed: timed out" in result.output
    assert "Recommended profile: personal_lockdown" in result.output


def test_recommend_conversation_flow():
    fake_provider = MagicMock()

    with patch("rescue.cli.get_provider", return_value=fake_provider), \
         patch("rescue.cli.ProfileRecommender") as MockRecommender:
        instance = MockRecommender.return_value
        instance.ask.side_effect = [
            RecommenderTurn(
                message="Are you worried about a specific person?", is_recommendation=False
            ),
            RecommenderTurn(
                message="This sounds like Six Roses.",
                is_recommendation=True,
                profile_slug="six_roses",
            ),
        ]
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["recommend"],
            input="Someone I used to date might have access to my accounts.\nYes, my ex.\n",
        )

    assert result.exit_code == 0
    assert "Recommended profile: six_roses" in result.output


def test_explain_without_provider():
    with patch("rescue.cli.get_provider", return_value=None):
        runner = CliRunner()
        result = runner.invoke(main, ["explain"])

    assert result.exit_code == 0
    assert "requires an AI provider" in result.output


def test_explain_runs_checks_and_prints_narrative():
    fake = FakeMod()
    fake_provider = MagicMock()
    fake_provider.provider_name = "anthropic"

    with patch("rescue.cli.discover_modules", return_value=[fake]), \
         patch("rescue.cli.gather_profile", return_value=None), \
         patch("rescue.cli.get_provider", return_value=fake_provider), \
         patch("rescue.cli.DiagnosticExplainer") as MockExplainer:
        MockExplainer.return_value.explain.return_value = Explanation(
            narrative="Your test issue matters because it does.",
            provider_name="anthropic",
        )
        runner = CliRunner()
        result = runner.invoke(main, ["explain"])

    assert result.exit_code == 0
    assert "Your test issue matters because it does." in result.output
    assert "via anthropic" in result.output


def test_explain_provider_error_does_not_crash():
    fake = FakeMod()
    fake_provider = MagicMock()
    fake_provider.provider_name = "anthropic"

    with patch("rescue.cli.discover_modules", return_value=[fake]), \
         patch("rescue.cli.gather_profile", return_value=None), \
         patch("rescue.cli.get_provider", return_value=fake_provider), \
         patch("rescue.cli.DiagnosticExplainer") as MockExplainer:
        MockExplainer.return_value.explain.side_effect = AIRequestError("connection reset")
        runner = CliRunner()
        result = runner.invoke(main, ["explain"])

    assert result.exit_code == 0
    assert result.exception is None
    assert "AI explanation unavailable" in result.output
    assert "connection reset" in result.output
