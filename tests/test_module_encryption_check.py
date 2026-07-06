import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


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


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "encryption_check")


def _fake_run(output):
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.stdout = output
        result.returncode = 0
        return result
    return fake_run


def test_encryption_check_discovered():
    mod = _get_module()
    assert mod.name == "encryption_check"
    assert mod.risk_level == RiskLevel.SAFE


def test_encryption_check_healthy():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run("FileVault is On.\n")):
        result = mod.check(_make_profile())
    assert not result.has_issues


def test_encryption_check_off():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run("FileVault is Off.\n")):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert result.findings[0].severity == Severity.CRITICAL


def test_encryption_check_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run("FileVault is Off.\n")):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.AUTO)
    assert fix.all_succeeded
    assert "fdesetup enable" in fix.actions[0].description
