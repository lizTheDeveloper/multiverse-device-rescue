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
    return next(m for m in modules if m.name == "win_startup_programs_audit")


def _make_run_result(
    cim_items=None,
    registry_user_items=None,
    registry_system_items=None,
    startup_folder_items=None,
    task_scheduler_items=None,
):
    """Create a fake subprocess.run that returns appropriate results."""

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        # PowerShell Get-CimInstance Win32_StartupCommand
        if "powershell" in cmd_str and "Get-CimInstance" in cmd_str:
            if cim_items is not None:
                result.stdout = json.dumps(cim_items)
            else:
                result.stdout = "[]"

        # PowerShell Get-ChildItem from startup folders
        elif "powershell" in cmd_str and "GetFolderPath" in cmd_str:
            if startup_folder_items is not None:
                result.stdout = json.dumps(startup_folder_items)
            else:
                result.stdout = "[]"

        # reg query commands
        elif cmd[0] == "reg" and "query" in cmd_str:
            if "HKCU" in cmd_str:
                if registry_user_items is not None:
                    result.stdout = registry_user_items
                else:
                    result.stdout = ""
            elif "HKLM" in cmd_str:
                if registry_system_items is not None:
                    result.stdout = registry_system_items
                else:
                    result.stdout = ""

        # schtasks query
        elif "schtasks" in cmd_str and "query" in cmd_str:
            if task_scheduler_items is not None:
                result.stdout = task_scheduler_items
            else:
                result.stdout = ""

        return result

    return fake_run


def test_win_startup_programs_audit_discovered():
    mod = _get_module()
    assert mod.name == "win_startup_programs_audit"
    assert mod.category == "performance"
    assert Platform.WIN32 in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_win_startup_programs_audit_no_items():
    """Test when no startup items are found."""
    mod = _get_module()
    fake_run = _make_run_result()
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "enumeration_failed" for f in result.findings)
    assert any(f.severity == Severity.INFO for f in result.findings)


def test_win_startup_programs_audit_normal_count():
    """Test with normal number of startup items (<15)."""
    mod = _get_module()
    cim_items = [
        {"name": "Chrome", "command": "C:\\Program Files\\Google\\Chrome\\chrome.exe", "location": "C:\\Program Files\\Google\\Chrome", "user": "USER"},
        {"name": "Firefox", "command": "C:\\Program Files\\Mozilla Firefox\\firefox.exe", "location": "C:\\Program Files\\Mozilla Firefox", "user": "USER"},
    ]
    fake_run = _make_run_result(cim_items=cim_items)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have INFO listing but no excessive count warning
    assert any(f.data.get("check") == "startup_programs_list" for f in result.findings)
    assert not any(f.data.get("check") == "excessive_count" for f in result.findings)


def test_win_startup_programs_audit_excessive_count():
    """Test when excessive startup items are detected (>15)."""
    mod = _get_module()
    cim_items = [
        {"name": f"Program{i}", "command": f"C:\\Program Files\\Program{i}\\app.exe", "location": f"C:\\Program Files\\Program{i}", "user": "USER"}
        for i in range(20)
    ]
    fake_run = _make_run_result(cim_items=cim_items)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "excessive_count" for f in result.findings)
    excessive = [f for f in result.findings if f.data.get("check") == "excessive_count"]
    assert excessive[0].severity == Severity.WARNING


def test_win_startup_programs_audit_bloatware_detection():
    """Test detection of known bloatware."""
    mod = _get_module()
    cim_items = [
        {"name": "Microsoft Teams", "command": "C:\\Program Files\\Microsoft\\Teams\\Teams.exe", "location": "C:\\Program Files\\Microsoft\\Teams", "user": "USER"},
        {"name": "OneDrive", "command": "C:\\Users\\USER\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe", "location": "C:\\Users\\USER\\AppData\\Local\\Microsoft\\OneDrive", "user": "USER"},
        {"name": "Skype", "command": "C:\\Program Files\\Skype\\Phone\\Skype.exe", "location": "C:\\Program Files\\Skype\\Phone", "user": "USER"},
    ]
    fake_run = _make_run_result(cim_items=cim_items)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "bloatware_detected" for f in result.findings)
    bloatware = [f for f in result.findings if f.data.get("check") == "bloatware_detected"]
    assert bloatware[0].severity == Severity.WARNING


def test_win_startup_programs_audit_suspicious_paths():
    """Test detection of startup items in suspicious paths."""
    mod = _get_module()
    cim_items = [
        {
            "name": "SuspiciousApp",
            "command": "C:\\Users\\USER\\AppData\\Local\\Temp\\malware.exe",
            "location": "C:\\Users\\USER\\AppData\\Local\\Temp",
            "user": "USER",
        },
        {
            "name": "AdwareApp",
            "command": "C:\\Users\\USER\\Downloads\\adware.exe",
            "location": "C:\\Users\\USER\\Downloads",
            "user": "USER",
        },
    ]
    fake_run = _make_run_result(cim_items=cim_items)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "suspicious_paths" for f in result.findings)
    suspicious = [f for f in result.findings if f.data.get("check") == "suspicious_paths"]
    assert suspicious[0].severity == Severity.WARNING


def test_win_startup_programs_audit_multiple_sources():
    """Test startup items from multiple sources."""
    mod = _get_module()
    cim_items = [
        {"name": "Chrome", "command": "C:\\Program Files\\Google\\Chrome\\chrome.exe", "location": "C:\\Program Files\\Google\\Chrome", "user": "USER"},
    ]
    registry_user = 'HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\n    OneNote    REG_SZ    C:\\Program Files\\Microsoft Office\\OneNote.exe\n'
    startup_folder = [
        {"name": "shortcut.lnk", "path": "C:\\Users\\USER\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\shortcut.lnk", "command": "C:\\Users\\USER\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\shortcut.lnk"},
    ]
    fake_run = _make_run_result(
        cim_items=cim_items,
        registry_user_items=registry_user,
        startup_folder_items=startup_folder,
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    info = [f for f in result.findings if f.data.get("check") == "startup_programs_list"]
    assert len(info) > 0
    # Should have items from multiple sources
    assert info[0].data.get("total_count") >= 2


def test_win_startup_programs_audit_deduplication():
    """Test that duplicate startup items are removed."""
    mod = _get_module()
    cim_items = [
        {"name": "Chrome", "command": "C:\\Program Files\\Google\\Chrome\\chrome.exe", "location": "C:\\Program Files\\Google\\Chrome", "user": "USER"},
        {"name": "Chrome", "command": "C:\\Program Files\\Google\\Chrome\\chrome.exe", "location": "C:\\Program Files\\Google\\Chrome", "user": "USER"},  # Duplicate
    ]
    fake_run = _make_run_result(cim_items=cim_items)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    info = [f for f in result.findings if f.data.get("check") == "startup_programs_list"]
    # Should count as 1, not 2
    assert info[0].data.get("total_count") == 1


def test_win_startup_programs_audit_fix_excessive_count():
    """Test fix recommendation for excessive startup items."""
    mod = _get_module()
    cim_items = [
        {"name": f"Program{i}", "command": f"C:\\Program Files\\Program{i}\\app.exe", "location": f"C:\\Program Files\\Program{i}", "user": "USER"}
        for i in range(20)
    ]
    fake_run = _make_run_result(cim_items=cim_items)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    assert any("reduce" in a.title.lower() or "excessive" in a.title.lower() for a in fix.actions)


def test_win_startup_programs_audit_fix_bloatware():
    """Test fix recommendation for bloatware."""
    mod = _get_module()
    cim_items = [
        {"name": "Microsoft Teams", "command": "C:\\Program Files\\Microsoft\\Teams\\Teams.exe", "location": "C:\\Program Files\\Microsoft\\Teams", "user": "USER"},
    ]
    fake_run = _make_run_result(cim_items=cim_items)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    assert any("disable" in a.title.lower() for a in fix.actions)


def test_win_startup_programs_audit_fix_suspicious_paths():
    """Test fix recommendation for suspicious paths."""
    mod = _get_module()
    cim_items = [
        {
            "name": "SuspiciousApp",
            "command": "C:\\Users\\USER\\AppData\\Local\\Temp\\malware.exe",
            "location": "C:\\Users\\USER\\AppData\\Local\\Temp",
            "user": "USER",
        },
    ]
    fake_run = _make_run_result(cim_items=cim_items)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    assert any("suspicious" in a.title.lower() or "malware" in a.description.lower() for a in fix.actions)


def test_win_startup_programs_audit_handles_subprocess_error():
    """Test graceful handling of subprocess errors."""
    mod = _get_module()

    def error_run(cmd, **kwargs):
        raise OSError("Command failed")

    with patch("subprocess.run", side_effect=error_run):
        result = mod.check(_make_profile())
    # Should still complete without crashing
    assert isinstance(result.findings, list)
    assert any(f.data.get("check") == "enumeration_failed" for f in result.findings)
