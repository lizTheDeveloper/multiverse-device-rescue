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
    return next(m for m in modules if m.name == "win_services_security_audit")


def _make_services(services_list=None):
    """Create JSON output for PowerShell Get-WmiObject."""
    if services_list is None:
        return json.dumps([])
    return json.dumps(services_list)


def _make_run_result(services_json=None, expect_error=False):
    """Create a fake subprocess.run that returns service data."""

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        # PowerShell Get-WmiObject for services
        if "powershell" in cmd_str.lower() and "Get-WmiObject Win32_Service" in cmd_str:
            if expect_error:
                result.returncode = 1
                result.stderr = "Error getting services"
            elif services_json is not None:
                result.stdout = services_json
            else:
                result.stdout = json.dumps([])

        return result

    return fake_run


def test_win_services_security_audit_discovered():
    """Test that module is discovered correctly."""
    mod = _get_module()
    assert mod.name == "win_services_security_audit"
    assert mod.category == "security"
    assert Platform.WIN32 in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_win_services_empty_list():
    """Test with no services (edge case)."""
    mod = _get_module()
    fake_run = _make_run_result(services_json=json.dumps([]))
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    # Should have no findings when no services are returned
    assert not result.has_issues


def test_win_services_subprocess_error():
    """Test graceful handling of subprocess errors."""
    mod = _get_module()
    fake_run = _make_run_result(expect_error=True)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    # Should still complete without crashing
    assert isinstance(result.findings, list)


def test_win_services_unquoted_path_critical():
    """Test detection of unquoted paths with spaces (CRITICAL)."""
    mod = _get_module()
    services = [
        {
            "Name": "BadService",
            "DisplayName": "Bad Service With Unquoted Path",
            "PathName": "C:\\Program Files\\BadApp\\service.exe -start",
            "StartMode": "Automatic",
            "State": "Running",
            "StartName": "LocalSystem",
        }
    ]
    fake_run = _make_run_result(services_json=_make_services(services))
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    unquoted = [f for f in result.findings if f.data.get("check_type") == "unquoted_path"]
    assert len(unquoted) > 0
    assert unquoted[0].severity == Severity.CRITICAL
    assert "unquoted" in unquoted[0].title.lower()


def test_win_services_user_writable_directory():
    """Test detection of services in user-writable directories."""
    mod = _get_module()
    services = [
        {
            "Name": "AppDataService",
            "DisplayName": "AppData Service",
            "PathName": '"C:\\Users\\admin\\AppData\\Roaming\\Service\\svc.exe"',
            "StartMode": "Automatic",
            "State": "Running",
            "StartName": "LocalSystem",
        },
        {
            "Name": "TempService",
            "DisplayName": "Temp Service",
            "PathName": "C:\\Temp\\service.exe",
            "StartMode": "Manual",
            "State": "Stopped",
            "StartName": "NT AUTHORITY\\LOCAL SERVICE",
        },
    ]
    fake_run = _make_run_result(services_json=_make_services(services))
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    writable = [f for f in result.findings if f.data.get("check_type") == "user_writable_dir"]
    assert len(writable) >= 2
    assert all(f.severity == Severity.WARNING for f in writable)


def test_win_services_overprivileged_localsystem():
    """Test detection of third-party services running as LocalSystem."""
    mod = _get_module()
    services = [
        {
            "Name": "svchost",  # Expected to run as LocalSystem
            "DisplayName": "Service Host",
            "PathName": "C:\\Windows\\System32\\svchost.exe",
            "StartMode": "Automatic",
            "State": "Running",
            "StartName": "LocalSystem",
        },
        {
            "Name": "ThirdPartyService",  # Not in expected list
            "DisplayName": "Third Party Service",
            "PathName": '"C:\\Program Files\\ThirdParty\\service.exe"',
            "StartMode": "Automatic",
            "State": "Running",
            "StartName": "LocalSystem",
        },
    ]
    fake_run = _make_run_result(services_json=_make_services(services))
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    overprivileged = [
        f for f in result.findings if f.data.get("check_type") == "overprivileged"
    ]
    assert len(overprivileged) == 1  # Only ThirdPartyService
    assert overprivileged[0].severity == Severity.WARNING
    assert "Third" in overprivileged[0].description


def test_win_services_stopped_auto_start():
    """Test detection of auto-start services that are stopped."""
    mod = _get_module()
    services = [
        {
            "Name": "NormalService",
            "DisplayName": "Normal Service",
            "PathName": '"C:\\Program Files\\Normal\\service.exe"',
            "StartMode": "Automatic",
            "State": "Running",
            "StartName": "NT AUTHORITY\\NETWORK SERVICE",
        },
        {
            "Name": "StoppedAutoService",
            "DisplayName": "Stopped Auto Service",
            "PathName": '"C:\\Program Files\\App\\service.exe"',
            "StartMode": "Automatic",
            "State": "Stopped",
            "StartName": "NT AUTHORITY\\LOCAL SERVICE",
        },
        {
            "Name": "StoppedDelayedService",
            "DisplayName": "Stopped Delayed Service",
            "PathName": '"C:\\Program Files\\Delayed\\service.exe"',
            "StartMode": "Automatic (Delayed Start)",
            "State": "Stopped",
            "StartName": "LocalSystem",
        },
    ]
    fake_run = _make_run_result(services_json=_make_services(services))
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    stopped_auto = [
        f for f in result.findings if f.data.get("check_type") == "stopped_auto_start"
    ]
    assert len(stopped_auto) == 2  # StoppedAutoService and StoppedDelayedService
    assert all(f.severity == Severity.WARNING for f in stopped_auto)


def test_win_services_summary_info():
    """Test that service summary is generated."""
    mod = _get_module()
    services = [
        {
            "Name": "Service1",
            "DisplayName": "Service 1",
            "PathName": '"C:\\Windows\\System32\\service1.exe"',
            "StartMode": "Automatic",
            "State": "Running",
            "StartName": "NT AUTHORITY\\LOCAL SERVICE",
        },
        {
            "Name": "Service2",
            "DisplayName": "Service 2",
            "PathName": '"C:\\Windows\\System32\\service2.exe"',
            "StartMode": "Manual",
            "State": "Stopped",
            "StartName": "NT AUTHORITY\\NETWORK SERVICE",
        },
        {
            "Name": "Service3",
            "DisplayName": "Service 3",
            "PathName": '"C:\\Windows\\System32\\service3.exe"',
            "StartMode": "Disabled",
            "State": "Stopped",
            "StartName": "LocalSystem",
        },
    ]
    fake_run = _make_run_result(services_json=_make_services(services))
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    # Summary should always be present
    summary = [f for f in result.findings if f.data.get("check_type") == "summary"]
    assert len(summary) == 1
    assert summary[0].severity == Severity.INFO
    assert summary[0].data["total_services"] == 3
    assert summary[0].data["by_state"]["Running"] == 1
    assert summary[0].data["by_state"]["Stopped"] == 2
    assert summary[0].data["by_start_mode"]["Automatic"] == 1
    assert summary[0].data["by_start_mode"]["Manual"] == 1
    assert summary[0].data["by_start_mode"]["Disabled"] == 1


def test_win_services_multiple_issues():
    """Test detection of multiple security issues."""
    mod = _get_module()
    services = [
        {
            "Name": "UnquotedService",
            "DisplayName": "Unquoted Path Service",
            "PathName": "C:\\Program Files\\Bad\\service.exe -param",
            "StartMode": "Automatic",
            "State": "Running",
            "StartName": "LocalSystem",
        },
        {
            "Name": "AppDataService",
            "DisplayName": "AppData Service",
            "PathName": "C:\\Users\\user\\AppData\\Local\\service.exe",
            "StartMode": "Automatic",
            "State": "Running",
            "StartName": "LocalSystem",
        },
        {
            "Name": "StoppedService",
            "DisplayName": "Stopped Auto Service",
            "PathName": '"C:\\Program Files\\App\\service.exe"',
            "StartMode": "Automatic",
            "State": "Stopped",
            "StartName": "NT AUTHORITY\\LOCAL SERVICE",
        },
    ]
    fake_run = _make_run_result(services_json=_make_services(services))
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    check_types = [f.data.get("check_type") for f in result.findings]
    assert "unquoted_path" in check_types
    assert "user_writable_dir" in check_types
    assert "stopped_auto_start" in check_types
    assert "summary" in check_types


def test_win_services_fix_unquoted_path():
    """Test fix recommendation for unquoted paths."""
    mod = _get_module()
    services = [
        {
            "Name": "BadService",
            "DisplayName": "Bad Service",
            "PathName": "C:\\Program Files\\Bad\\service.exe",
            "StartMode": "Automatic",
            "State": "Running",
            "StartName": "LocalSystem",
        }
    ]
    fake_run = _make_run_result(services_json=_make_services(services))
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    unquoted_actions = [a for a in fix.actions if "unquoted" in a.title.lower()]
    assert len(unquoted_actions) > 0
    assert "BadService" in unquoted_actions[0].description
    # Fix actions are informational and should not auto-succeed
    assert not unquoted_actions[0].success


def test_win_services_fix_user_writable_dir():
    """Test fix recommendation for user-writable directories."""
    mod = _get_module()
    services = [
        {
            "Name": "AppDataService",
            "DisplayName": "AppData Service",
            "PathName": "C:\\Users\\user\\AppData\\Local\\service.exe",
            "StartMode": "Automatic",
            "State": "Running",
            "StartName": "LocalSystem",
        }
    ]
    fake_run = _make_run_result(services_json=_make_services(services))
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    writable_actions = [a for a in fix.actions if "user-writable" in a.title.lower()]
    assert len(writable_actions) > 0
    assert "AppDataService" in writable_actions[0].description
    assert not writable_actions[0].success


def test_win_services_fix_stopped_auto_start():
    """Test fix recommendation for stopped auto-start services."""
    mod = _get_module()
    services = [
        {
            "Name": "StoppedService",
            "DisplayName": "Stopped Auto Service",
            "PathName": '"C:\\Program Files\\App\\service.exe"',
            "StartMode": "Automatic",
            "State": "Stopped",
            "StartName": "NT AUTHORITY\\LOCAL SERVICE",
        }
    ]
    fake_run = _make_run_result(services_json=_make_services(services))
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    stopped_actions = [a for a in fix.actions if "auto-start" in a.title.lower()]
    assert len(stopped_actions) > 0
    assert "StoppedService" in stopped_actions[0].description
    assert not stopped_actions[0].success


def test_win_services_fix_overprivileged():
    """Test fix recommendation for overprivileged services."""
    mod = _get_module()
    services = [
        {
            "Name": "ThirdPartyService",
            "DisplayName": "Third Party Service",
            "PathName": '"C:\\Program Files\\ThirdParty\\service.exe"',
            "StartMode": "Automatic",
            "State": "Running",
            "StartName": "LocalSystem",
        }
    ]
    fake_run = _make_run_result(services_json=_make_services(services))
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    overprivileged_actions = [
        a for a in fix.actions if "service account" in a.title.lower()
    ]
    assert len(overprivileged_actions) > 0
    assert "ThirdPartyService" in overprivileged_actions[0].description
    assert not overprivileged_actions[0].success


def test_win_services_clean_system():
    """Test a clean system with no security issues."""
    mod = _get_module()
    services = [
        {
            "Name": "svchost",
            "DisplayName": "Service Host Process",
            "PathName": '"C:\\Windows\\System32\\svchost.exe"',
            "StartMode": "Automatic",
            "State": "Running",
            "StartName": "LocalSystem",
        },
        {
            "Name": "SearchIndexer",
            "DisplayName": "Windows Search",
            "PathName": '"C:\\Windows\\System32\\SearchIndexer.exe"',
            "StartMode": "Automatic",
            "State": "Running",
            "StartName": "LocalSystem",
        },
        {
            "Name": "GoodThirdPartyService",
            "DisplayName": "Good Third Party",
            "PathName": '"C:\\Program Files\\GoodApp\\service.exe"',
            "StartMode": "Automatic",
            "State": "Running",
            "StartName": "NT AUTHORITY\\LOCAL SERVICE",
        },
    ]
    fake_run = _make_run_result(services_json=_make_services(services))
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())

    # Should only have summary (INFO) finding
    non_summary = [f for f in result.findings if f.data.get("check_type") != "summary"]
    assert len(non_summary) == 0


def test_win_services_single_service_returned():
    """Test when PowerShell returns a single service object (not an array)."""
    mod = _get_module()
    # PowerShell sometimes returns a single object instead of an array
    single_service = {
        "Name": "OnlyService",
        "DisplayName": "Only Service",
        "PathName": '"C:\\Windows\\System32\\service.exe"',
        "StartMode": "Automatic",
        "State": "Running",
        "StartName": "LocalSystem",
    }
    fake_run = _make_run_result(services_json=json.dumps(single_service))
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    # Should handle single object gracefully
    summary = [f for f in result.findings if f.data.get("check_type") == "summary"]
    assert len(summary) == 1
    assert summary[0].data["total_services"] == 1


def test_win_services_malformed_json():
    """Test graceful handling of malformed JSON response."""
    mod = _get_module()

    def bad_json_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stdout = "not valid json {[ broken"
        result.stderr = ""
        return result

    with patch("subprocess.run", side_effect=bad_json_run):
        result = mod.check(_make_profile())
    # Should not crash, just return empty findings
    assert isinstance(result.findings, list)


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.win_services_security_audit.") for c in declared)
