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
    return next(m for m in modules if m.name == "win_remote_access_audit")


def _make_run_result(
    teamviewer_installed=False,
    anydesk_installed=False,
    vnc_processes=None,
    logmein_installed=False,
    chrome_remote_desktop=False,
    rdp_enabled=None,
):
    """Create a fake subprocess.run that returns appropriate results."""

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        # Registry queries
        if "reg" in cmd_str and "query" in cmd_str:
            # TeamViewer registry
            if "TeamViewer" in cmd_str:
                if teamviewer_installed:
                    result.returncode = 0
                    result.stdout = "HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\TeamViewer\n    Version    REG_SZ    15.0\n"
                else:
                    result.returncode = 1
                    result.stderr = "ERROR: The system was unable to find the specified registry key or value."
            # AnyDesk registry
            elif "AnyDesk" in cmd_str:
                if anydesk_installed:
                    result.returncode = 0
                    result.stdout = "HKEY_LOCAL_MACHINE\\SOFTWARE\\AnyDesk\n    InstallPath    REG_SZ    C:\\Program Files\\AnyDesk\n"
                else:
                    result.returncode = 1
                    result.stderr = "ERROR: The system was unable to find the specified registry key or value."
            # LogMeIn registry (first location)
            elif "HKLM\\SOFTWARE\\LogMeIn" in cmd_str and "WOW6432Node" not in cmd_str:
                if logmein_installed:
                    result.returncode = 0
                    result.stdout = "HKEY_LOCAL_MACHINE\\SOFTWARE\\LogMeIn\n    Version    REG_SZ    1.0\n"
                else:
                    result.returncode = 1
                    result.stderr = "ERROR: The system was unable to find the specified registry key or value."
            # LogMeIn registry (second location)
            elif "WOW6432Node\\LogMeIn" in cmd_str:
                if logmein_installed:
                    result.returncode = 0
                    result.stdout = "HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\LogMeIn\n    Version    REG_SZ    1.0\n"
                else:
                    result.returncode = 1
                    result.stderr = "ERROR: The system was unable to find the specified registry key or value."
            # RDP registry query
            elif "Terminal Server" in cmd_str and "fDenyTSConnections" in cmd_str:
                if rdp_enabled is True:
                    # 0x0 means connections NOT denied, so RDP is enabled
                    result.returncode = 0
                    result.stdout = "fDenyTSConnections    REG_DWORD    0x0\n"
                elif rdp_enabled is False:
                    # 0x1 means connections denied, so RDP is disabled
                    result.returncode = 0
                    result.stdout = "fDenyTSConnections    REG_DWORD    0x1\n"
                else:
                    result.returncode = 1
                    result.stderr = "ERROR: The system was unable to find the specified registry key or value."

        # tasklist command
        elif "tasklist" in cmd_str:
            processes = []
            if teamviewer_installed:
                processes.append("TeamViewer.exe")
            if anydesk_installed:
                processes.append("AnyDesk.exe")
            if vnc_processes:
                processes.extend(vnc_processes)
            if logmein_installed:
                processes.append("LogMeIn.exe")
            if chrome_remote_desktop:
                processes.append("chrome_remote_desktop_host.exe")

            if processes:
                result.stdout = "Image Name                     PID Session Name        Session# Memory\n"
                result.stdout += "=============================== ==== ================ ====== ============\n"
                for proc in processes:
                    result.stdout += f"{proc:<30} 1234 Console                    1 50,000 K\n"
            else:
                result.stdout = "Image Name                     PID Session Name        Session# Memory\n"
                result.stdout += "=============================== ==== ================ ====== ============\n"

        return result

    return fake_run


def test_win_remote_access_audit_discovered():
    mod = _get_module()
    assert mod.name == "win_remote_access_audit"
    assert mod.category == "security"
    assert Platform.WIN32 in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_win_remote_access_audit_clean():
    """Test when no remote access tools are found."""
    mod = _get_module()
    fake_run = _make_run_result()
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have INFO finding about no tools found
    assert any(f.data.get("check") == "no_tools_found" for f in result.findings)
    assert any(f.severity == Severity.INFO for f in result.findings)


def test_win_remote_access_audit_teamviewer_detected():
    """Test detection of TeamViewer."""
    mod = _get_module()
    fake_run = _make_run_result(teamviewer_installed=True)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "teamviewer_installed" for f in result.findings)
    tv_finding = [f for f in result.findings if f.data.get("check") == "teamviewer_installed"]
    assert tv_finding[0].severity == Severity.WARNING


def test_win_remote_access_audit_anydesk_detected():
    """Test detection of AnyDesk."""
    mod = _get_module()
    fake_run = _make_run_result(anydesk_installed=True)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "anydesk_installed" for f in result.findings)
    ad_finding = [f for f in result.findings if f.data.get("check") == "anydesk_installed"]
    assert ad_finding[0].severity == Severity.WARNING


def test_win_remote_access_audit_vnc_detected():
    """Test detection of VNC servers."""
    mod = _get_module()
    vnc_procs = ["winvnc.exe", "uvnc.exe"]
    fake_run = _make_run_result(vnc_processes=vnc_procs)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "vnc_installed" for f in result.findings)
    vnc_finding = [f for f in result.findings if f.data.get("check") == "vnc_installed"]
    assert vnc_finding[0].severity == Severity.WARNING


def test_win_remote_access_audit_logmein_detected():
    """Test detection of LogMeIn."""
    mod = _get_module()
    fake_run = _make_run_result(logmein_installed=True)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "logmein_installed" for f in result.findings)
    lm_finding = [f for f in result.findings if f.data.get("check") == "logmein_installed"]
    assert lm_finding[0].severity == Severity.WARNING


def test_win_remote_access_audit_chrome_remote_desktop_detected():
    """Test detection of Chrome Remote Desktop."""
    mod = _get_module()
    fake_run = _make_run_result(chrome_remote_desktop=True)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "chrome_remote_desktop" for f in result.findings)
    crd_finding = [f for f in result.findings if f.data.get("check") == "chrome_remote_desktop"]
    assert crd_finding[0].severity == Severity.WARNING


def test_win_remote_access_audit_rdp_enabled():
    """Test detection of enabled RDP."""
    mod = _get_module()
    fake_run = _make_run_result(rdp_enabled=True)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "rdp_enabled" for f in result.findings)
    rdp_finding = [f for f in result.findings if f.data.get("check") == "rdp_enabled"]
    assert rdp_finding[0].severity == Severity.WARNING


def test_win_remote_access_audit_rdp_disabled():
    """Test when RDP is disabled."""
    mod = _get_module()
    fake_run = _make_run_result(rdp_enabled=False)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    # Should not have RDP finding if disabled
    assert not any(f.data.get("check") == "rdp_enabled" for f in result.findings)


def test_win_remote_access_audit_multiple_tools_critical():
    """Test CRITICAL finding when multiple tools are installed."""
    mod = _get_module()
    fake_run = _make_run_result(teamviewer_installed=True, anydesk_installed=True)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have CRITICAL finding for multiple tools
    assert any(f.data.get("check") == "multiple_tools" for f in result.findings)
    multi_finding = [f for f in result.findings if f.data.get("check") == "multiple_tools"]
    assert multi_finding[0].severity == Severity.CRITICAL
    assert multi_finding[0].data.get("count") == 2


def test_win_remote_access_audit_three_tools():
    """Test CRITICAL finding with three tools installed."""
    mod = _get_module()
    fake_run = _make_run_result(
        teamviewer_installed=True,
        anydesk_installed=True,
        logmein_installed=True
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    multi_finding = [f for f in result.findings if f.data.get("check") == "multiple_tools"]
    assert len(multi_finding) == 1
    assert multi_finding[0].severity == Severity.CRITICAL
    assert multi_finding[0].data.get("count") == 3


def test_win_remote_access_audit_tools_summary():
    """Test INFO summary of found tools."""
    mod = _get_module()
    fake_run = _make_run_result(teamviewer_installed=True, rdp_enabled=True)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have summary finding
    assert any(f.data.get("check") == "tools_summary" for f in result.findings)
    summary = [f for f in result.findings if f.data.get("check") == "tools_summary"]
    assert summary[0].severity == Severity.INFO
    assert summary[0].data.get("count") == 1


def test_win_remote_access_audit_fix_teamviewer():
    """Test fix action for TeamViewer."""
    mod = _get_module()
    fake_run = _make_run_result(teamviewer_installed=True)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    tv_actions = [a for a in fix.actions if "TeamViewer" in a.title]
    assert len(tv_actions) > 0
    # Fix actions should be informational (not success)
    assert not tv_actions[0].success
    assert "informational" in tv_actions[0].error.lower()


def test_win_remote_access_audit_fix_multiple_tools():
    """Test fix action for multiple tools."""
    mod = _get_module()
    fake_run = _make_run_result(teamviewer_installed=True, anydesk_installed=True)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    # Should have action for multiple tools
    multi_actions = [a for a in fix.actions if "multiple" in a.title.lower()]
    assert len(multi_actions) > 0


def test_win_remote_access_audit_fix_rdp():
    """Test fix action for RDP."""
    mod = _get_module()
    fake_run = _make_run_result(rdp_enabled=True)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    rdp_actions = [a for a in fix.actions if "RDP" in a.title]
    assert len(rdp_actions) > 0


def test_win_remote_access_audit_handles_subprocess_error():
    """Test graceful handling of subprocess errors."""
    mod = _get_module()

    def error_run(cmd, **kwargs):
        raise OSError("Command failed")

    with patch("subprocess.run", side_effect=error_run):
        result = mod.check(_make_profile())
    # Should still complete without crashing
    assert isinstance(result.findings, list)
