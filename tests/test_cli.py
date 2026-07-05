from pathlib import Path
from unittest.mock import patch, MagicMock

from click.testing import CliRunner

from rescue.cli import main
from rescue.models import (
    CheckResult, FixResult, Finding, Action,
    Severity, RiskLevel, Platform, SystemProfile, Mode,
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


def test_version():
    runner = CliRunner()
    result = runner.invoke(main, ["version"])
    assert result.exit_code == 0
    assert "multiverse-device-rescue" in result.output


def test_auto_mode():
    fake = FakeMod()
    auto_results = [
        (fake, fake.check(None), fake.fix(None, Mode.AUTO)),
    ]

    with patch("rescue.cli.Orchestrator") as MockOrch:
        instance = MockOrch.return_value
        instance.run_auto.return_value = auto_results
        runner = CliRunner()
        result = runner.invoke(main, ["--auto"])

    assert result.exit_code == 0
    assert "Test issue" in result.output
    assert "Fixed" in result.output


def test_run_specific_modules():
    fake = FakeMod()
    profile = SystemProfile(
        platform=Platform.DARWIN, os_name="macOS", os_version="15.2",
        architecture="arm64", cpu_model="M2", cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )

    with patch("rescue.cli.Orchestrator") as MockOrch, \
         patch("rescue.cli.gather_profile", return_value=profile):
        instance = MockOrch.return_value
        instance.run_checks.return_value = [
            (fake, fake.check(None)),
        ]
        instance.run_fixes.return_value = [
            (fake, fake.check(None), fake.fix(None, Mode.CLI)),
        ]
        # Mock discover to return our fake module
        with patch("rescue.cli.discover_modules", return_value=[fake]):
            runner = CliRunner()
            result = runner.invoke(main, ["run", "fake_mod", "--yes"])

    assert result.exit_code == 0


def test_run_unknown_module():
    with patch("rescue.cli.discover_modules", return_value=[]):
        runner = CliRunner()
        result = runner.invoke(main, ["run", "nonexistent"])

    assert result.exit_code != 0 or "not found" in result.output.lower() or "unknown" in result.output.lower()
