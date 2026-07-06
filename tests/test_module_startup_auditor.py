import json
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, RiskLevel, Mode
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
    return next(m for m in modules if m.name == "startup_auditor")


def _fake_run_factory(launchctl_output, unload_returncode=0):
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        if cmd[0] == "launchctl" and cmd[1] == "list":
            result.stdout = launchctl_output
            result.returncode = 0
        elif cmd[0] == "launchctl" and cmd[1] == "unload":
            result.stdout = ""
            result.stderr = "" if unload_returncode == 0 else "operation not permitted"
            result.returncode = unload_returncode
        return result
    return fake_run


LAUNCHCTL_OUTPUT = """PID\tStatus\tLabel
415\t0\tcom.apple.something
-\t0\tcom.adobe.acc.installer.v2
1234\t0\tcom.microsoft.autoupdate.helper
-\t0\tcom.spotify.webhelper
5678\t0\tcom.random.unrelated.app
"""


def test_startup_auditor_discovered():
    mod = _get_module()
    assert mod.name == "startup_auditor"
    assert mod.risk_level == RiskLevel.MODERATE


def test_known_bloatware_data_file_valid():
    data_file = (
        Path(__file__).parent.parent
        / "modules" / "bloatware" / "startup_auditor" / "data" / "known_bloatware.json"
    )
    with open(data_file) as f:
        data = json.load(f)
    assert len(data) >= 5
    for entry in data:
        assert "label_pattern" in entry
        assert "name" in entry
        assert "description" in entry


def test_startup_auditor_finds_known_bloatware():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_factory(LAUNCHCTL_OUTPUT)):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert len(result.findings) == 3  # adobe, microsoft, spotify — not the random app
    titles = [f.title for f in result.findings]
    assert any("Adobe" in t for t in titles)


def test_startup_auditor_no_matches():
    output = """PID\tStatus\tLabel
415\t0\tcom.apple.something
5678\t0\tcom.random.unrelated.app
"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_factory(output)):
        result = mod.check(_make_profile())
    assert not result.has_issues


def test_startup_auditor_fix_unloads_job():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_factory(LAUNCHCTL_OUTPUT)):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert len(fix.actions) == 3


def test_startup_auditor_fix_handles_failure():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_factory(LAUNCHCTL_OUTPUT, unload_returncode=1)):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert not fix.all_succeeded
    assert fix.actions[0].error == "operation not permitted"
