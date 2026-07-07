import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
import json

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


# Minimal healthy Windows services output
HEALTHY_SERVICES = [
    {
        "Name": "WinDefend",
        "DisplayName": "Windows Defender Antivirus Service",
        "Status": "Running",
        "StartType": "Automatic",
        "PathName": "C:\\Program Files\\Windows Defender\\MsMpEng.exe",
    },
    {
        "Name": "wuauserv",
        "DisplayName": "Windows Update",
        "Status": "Running",
        "StartType": "Automatic",
        "PathName": "C:\\Windows\\System32\\svchost.exe -k netsvcs",
    },
    {
        "Name": "AudioSrv",
        "DisplayName": "Windows Audio",
        "Status": "Running",
        "StartType": "Automatic",
        "PathName": "C:\\Windows\\System32\\svchost.exe -k netsvcs",
    },
]

# Services with bloatware
BLOATWARE_SERVICES = [
    {
        "Name": "WinDefend",
        "DisplayName": "Windows Defender Antivirus Service",
        "Status": "Running",
        "StartType": "Automatic",
        "PathName": "C:\\Program Files\\Windows Defender\\MsMpEng.exe",
    },
    {
        "Name": "hpqvfxs",
        "DisplayName": "HP Quick Functions Service",
        "Status": "Running",
        "StartType": "Automatic",
        "PathName": "C:\\Program Files\\HP\\HP OfficeJet\\Bin\\hpqvfxs.exe",
    },
    {
        "Name": "DellSystemDetect",
        "DisplayName": "Dell System Detect Service",
        "Status": "Running",
        "StartType": "Automatic",
        "PathName": "C:\\Program Files (x86)\\Dell\\DellSystemDetect\\bin\\DellSystemDetect.exe",
    },
]

# Services with suspicious paths
SUSPICIOUS_PATH_SERVICES = [
    {
        "Name": "WinDefend",
        "DisplayName": "Windows Defender Antivirus Service",
        "Status": "Running",
        "StartType": "Automatic",
        "PathName": "C:\\Program Files\\Windows Defender\\MsMpEng.exe",
    },
    {
        "Name": "MalwareService",
        "DisplayName": "Suspicious Service",
        "Status": "Running",
        "StartType": "Automatic",
        "PathName": "C:\\Windows\\Temp\\malware.exe",
    },
    {
        "Name": "UserFolderService",
        "DisplayName": "User Folder Service",
        "Status": "Running",
        "StartType": "Automatic",
        "PathName": "C:\\Users\\john\\AppData\\Local\\Temp\\service.exe",
    },
]

# Services that are stopped but set to auto-start
STOPPED_AUTOSTART_SERVICES = [
    {
        "Name": "WinDefend",
        "DisplayName": "Windows Defender Antivirus Service",
        "Status": "Running",
        "StartType": "Automatic",
        "PathName": "C:\\Program Files\\Windows Defender\\MsMpEng.exe",
    },
    {
        "Name": "ServiceA",
        "DisplayName": "Service A",
        "Status": "Stopped",
        "StartType": "Automatic",
        "PathName": "C:\\Program Files\\ServiceA\\service.exe",
    },
    {
        "Name": "ServiceB",
        "DisplayName": "Service B",
        "Status": "Stopped",
        "StartType": "Automatic",
        "PathName": "C:\\Program Files\\ServiceB\\service.exe",
    },
]

# Many auto-start services to exceed the 40 threshold
EXCESSIVE_AUTOSTART = [
    {
        "Name": f"Service{i}",
        "DisplayName": f"Service {i}",
        "Status": "Running",
        "StartType": "Automatic",
        "PathName": f"C:\\Program Files\\Service{i}\\service.exe",
    }
    for i in range(45)
]


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
    return next(m for m in modules if m.name == "win_services_audit")


def _fake_powershell_run(services_data):
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        # Mock the PowerShell call
        if len(cmd) > 0 and "powershell" in cmd[0].lower():
            result.stdout = json.dumps(services_data)
        return result
    return fake_run


def test_win_services_audit_discovered():
    mod = _get_module()
    assert mod.name == "win_services_audit"
    assert mod.category == "security"
    assert Platform.WIN32 in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_win_services_audit_healthy():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_powershell_run(HEALTHY_SERVICES)):
        result = mod.check(_make_profile())
    assert not result.has_issues


def test_win_services_audit_detects_bloatware():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_powershell_run(BLOATWARE_SERVICES)):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any("bloatware" in f.title.lower() for f in result.findings)
    assert any(f.severity == Severity.INFO for f in result.findings)


def test_win_services_audit_detects_suspicious_paths():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_powershell_run(SUSPICIOUS_PATH_SERVICES)):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any("suspicious path" in f.title.lower() for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_win_services_audit_detects_stopped_autostart():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_powershell_run(STOPPED_AUTOSTART_SERVICES)):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any("stopped" in f.title.lower() for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_win_services_audit_detects_excessive_autostart():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_powershell_run(EXCESSIVE_AUTOSTART)):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any("excessive" in f.title.lower() for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)
    excessive_finding = next(
        f for f in result.findings if "excessive" in f.title.lower()
    )
    assert excessive_finding.data["count"] == 45


def test_win_services_audit_fix_provides_bloatware_actions():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_powershell_run(BLOATWARE_SERVICES)):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    assert all("services.msc" in a.description for a in fix.actions)
    assert all(a.success for a in fix.actions)
