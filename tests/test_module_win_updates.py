import json
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


def _make_profile():
    return SystemProfile(
        platform=Platform.WIN32,
        os_name="Windows 11",
        os_version="10.0.22621",
        architecture="AMD64",
        cpu_model="Intel(R) Core(TM) i7-9700K",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "win_updates")


def _fake_run(service_dict, start_returncode=0):
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        joined = " ".join(cmd)
        if "Get-Service" in joined:
            result.stdout = json.dumps(service_dict)
        elif "Start-Service" in joined:
            result.stdout = ""
            result.returncode = start_returncode
            if start_returncode != 0:
                result.stderr = "Access is denied."
        return result
    return fake_run


RUNNING_SERVICE = {"Name": "wuauserv", "DisplayName": "Windows Update", "Status": "Running"}
STOPPED_SERVICE = {"Name": "wuauserv", "DisplayName": "Windows Update", "Status": "Stopped"}


def test_win_updates_discovered():
    mod = _get_module()
    assert mod.name == "win_updates"
    assert mod.category == "integrity"
    assert Platform.WIN32 in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_win_updates_healthy_when_service_running():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(RUNNING_SERVICE)):
        result = mod.check(_make_profile())
    assert not result.has_issues


def test_win_updates_healthy_when_service_running_status_is_integer():
    # Windows PowerShell 5.1's ConvertTo-Json serializes the
    # ServiceControllerStatus enum as its raw integer (4 == Running)
    # rather than the string name emitted by PowerShell 7+.
    mod = _get_module()
    service = {"Name": "wuauserv", "DisplayName": "Windows Update", "Status": 4}
    with patch("subprocess.run", side_effect=_fake_run(service)):
        result = mod.check(_make_profile())
    assert not result.has_issues


def test_win_updates_warns_when_service_stopped():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(STOPPED_SERVICE)):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert result.findings[0].severity == Severity.WARNING
    assert result.findings[0].data["status"] == "Stopped"


def test_win_updates_handles_unparseable_output():
    def bad_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 1
        result.stdout = ""
        result.stderr = "Cannot find any service with service name 'wuauserv'."
        return result

    mod = _get_module()
    with patch("subprocess.run", side_effect=bad_run):
        result = mod.check(_make_profile())
    assert not result.has_issues


def test_win_updates_fix_starts_service():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(STOPPED_SERVICE)):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert len(fix.actions) == 1


def test_win_updates_fix_handles_permission_failure():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(STOPPED_SERVICE, start_returncode=1)):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert not fix.all_succeeded
    assert "Access is denied" in fix.actions[0].error
