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
    return next(m for m in modules if m.name == "startup_optimizer")


def _fake_run(launchctl_output):
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.stdout = launchctl_output
        result.returncode = 0
        return result
    return fake_run


def test_startup_optimizer_discovered():
    mod = _get_module()
    assert mod.name == "startup_optimizer"
    assert mod.risk_level == RiskLevel.SAFE


def test_startup_optimizer_healthy():
    output = """PID\tStatus\tLabel
415\t0\tcom.apple.something
-\t0\tcom.apple.cfprefsd.agent
1234\t0\tcom.spotify.webhelper
"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(output)):
        result = mod.check(_make_profile())
    assert not result.has_issues


def test_startup_optimizer_warning():
    output = """PID\tStatus\tLabel
415\t0\tcom.apple.something
-\t0\tcom.adobe.acc.installer.v2
1234\t0\tcom.microsoft.autoupdate.helper
-\t0\tcom.spotify.webhelper
5678\t0\tcom.google.keystone.agent
-\t0\tcom.citrixonline.GoToMeeting.G2MUpdate
"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(output)):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert result.findings[0].severity == Severity.WARNING
    assert result.findings[0].data["count"] == 5


def test_startup_optimizer_critical():
    output = """PID\tStatus\tLabel
415\t0\tcom.apple.something
-\t0\tcom.adobe.acc.installer.v2
1234\t0\tcom.microsoft.autoupdate.helper
-\t0\tcom.spotify.webhelper
5678\t0\tcom.google.keystone.agent
-\t0\tcom.citrixonline.GoToMeeting.G2MUpdate
9999\t0\tcom.oracle.java.Java-Updater
-\t0\tcom.real.player.helper
1111\t0\tcom.example.bloat1
2222\t0\tcom.example.bloat2
"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(output)):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert result.findings[0].severity == Severity.CRITICAL
    assert result.findings[0].data["count"] == 9


def test_startup_optimizer_fix_is_informational():
    output = """PID\tStatus\tLabel
415\t0\tcom.apple.something
-\t0\tcom.adobe.acc.installer.v2
1234\t0\tcom.microsoft.autoupdate.helper
-\t0\tcom.spotify.webhelper
5678\t0\tcom.google.keystone.agent
"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(output)):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.AUTO)
    assert fix.all_succeeded
    assert "startup_auditor" in fix.actions[0].description
