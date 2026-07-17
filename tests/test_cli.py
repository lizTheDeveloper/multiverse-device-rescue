import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

from click.testing import CliRunner

import rescue.cli as cli
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


def test_bare_invocation_launches_tui():
    with patch("rescue.cli.run_tui") as mock_run_tui:
        runner = CliRunner()
        result = runner.invoke(main, [])

    assert result.exit_code == 0
    mock_run_tui.assert_called_once()


def test_project_root_unfrozen_matches_source_layout():
    """Not running from a PyInstaller bundle: root is the repo root two
    directories above rescue/cli.py, same as before frozen support existed."""
    assert not getattr(sys, "frozen", False)
    root = cli._project_root()
    assert root == Path(cli.__file__).parent.parent
    assert (root / "modules").is_dir()
    assert (root / "profiles").is_dir()
    assert (root / "guides").is_dir()


def test_startup_integrity_check_skipped_when_frozen(monkeypatch):
    """The integrity manifest is generated from loose .py files in a source
    checkout / pip install; a PyInstaller onefile bundle has no such files
    on disk (they're compiled into the archive), so comparing against it
    would always spuriously report everything as 'missing'. Skip it
    entirely when frozen rather than spamming a false-positive warning on
    every run."""
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    with patch("rescue.cli.IntegrityManifest") as MockManifest:
        cli._run_startup_integrity_check()
    MockManifest.from_json_bytes.assert_not_called()


def test_project_root_uses_meipass_when_frozen(monkeypatch, tmp_path):
    """Running from a PyInstaller onefile bundle: sys.frozen is set and the
    extracted-bundle temp dir sys._MEIPASS becomes the project root, instead
    of trusting __file__ (which PyInstaller does not reliably resolve for
    the entry script across platforms)."""
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)

    assert cli._project_root() == tmp_path
    assert cli._get_modules_dir() == tmp_path / "modules"
    assert cli._get_profiles_dir() == tmp_path / "profiles"
    assert cli._get_guides_dir() == tmp_path / "guides"
