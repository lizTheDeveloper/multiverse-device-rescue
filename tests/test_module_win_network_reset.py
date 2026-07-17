import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


def _make_profile():
    return SystemProfile(
        platform=Platform.WIN32,
        os_name="Windows",
        os_version="10",
        architecture="x64",
        cpu_model="Intel i7",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "win_network_reset")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_healthy_stack():
    """System with healthy network stack"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "netsh" in cmd_str and "winsock" in cmd_str and "catalog" in cmd_str:
            # Return output with normal provider count (15)
            output = ""
            for i in range(15):
                output += f"Item : {i}\n"
                output += f"Entry Name : Protocol_{i}\n"
            return _make_subprocess_result(stdout=output)
        elif "reg" in cmd_str and "Tcpip" in cmd_str:
            # Return healthy TCP/IP parameters (no unusual mods)
            return _make_subprocess_result(
                stdout=r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" + "\n"
            )
        elif "reg" in cmd_str and "Protocol_Catalog9" in cmd_str:
            # Return normal entry count (8)
            output = ""
            for i in range(8):
                output += f"Entry_{i}\n"
            return _make_subprocess_result(stdout=output)
        elif "powershell" in cmd_str and "Dnscache" in cmd_str:
            return _make_subprocess_result(stdout="Running\n")
        elif "powershell" in cmd_str and "Dhcp" in cmd_str:
            return _make_subprocess_result(stdout="Running\n")
        return _make_subprocess_result()

    return fake_run


def _fake_run_winsock_contaminated():
    """System with Winsock catalog contamination (too many providers)"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "netsh" in cmd_str and "winsock" in cmd_str and "catalog" in cmd_str:
            # Return output with excessive provider count (35 - suggests LSP contamination)
            output = ""
            for i in range(35):
                output += f"Item : {i}\n"
                output += f"Entry Name : Protocol_{i}\n"
            return _make_subprocess_result(stdout=output)
        elif "reg" in cmd_str and "Tcpip" in cmd_str:
            return _make_subprocess_result(
                stdout=r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" + "\n"
            )
        elif "reg" in cmd_str and "Protocol_Catalog9" in cmd_str:
            output = ""
            for i in range(8):
                output += f"Entry_{i}\n"
            return _make_subprocess_result(stdout=output)
        elif "powershell" in cmd_str and "Dnscache" in cmd_str:
            return _make_subprocess_result(stdout="Running\n")
        elif "powershell" in cmd_str and "Dhcp" in cmd_str:
            return _make_subprocess_result(stdout="Running\n")
        return _make_subprocess_result()

    return fake_run


def _fake_run_dns_stopped():
    """System with DNS Client service stopped"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "netsh" in cmd_str and "winsock" in cmd_str and "catalog" in cmd_str:
            output = ""
            for i in range(15):
                output += f"Item : {i}\n"
            return _make_subprocess_result(stdout=output)
        elif "reg" in cmd_str and "Tcpip" in cmd_str:
            return _make_subprocess_result(
                stdout=r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" + "\n"
            )
        elif "reg" in cmd_str and "Protocol_Catalog9" in cmd_str:
            output = ""
            for i in range(8):
                output += f"Entry_{i}\n"
            return _make_subprocess_result(stdout=output)
        elif "powershell" in cmd_str and "Dnscache" in cmd_str:
            return _make_subprocess_result(stdout="Stopped\n")
        elif "powershell" in cmd_str and "Dhcp" in cmd_str:
            return _make_subprocess_result(stdout="Running\n")
        return _make_subprocess_result()

    return fake_run


def _fake_run_dhcp_stopped():
    """System with DHCP Client service stopped"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "netsh" in cmd_str and "winsock" in cmd_str and "catalog" in cmd_str:
            output = ""
            for i in range(15):
                output += f"Item : {i}\n"
            return _make_subprocess_result(stdout=output)
        elif "reg" in cmd_str and "Tcpip" in cmd_str:
            return _make_subprocess_result(
                stdout=r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" + "\n"
            )
        elif "reg" in cmd_str and "Protocol_Catalog9" in cmd_str:
            output = ""
            for i in range(8):
                output += f"Entry_{i}\n"
            return _make_subprocess_result(stdout=output)
        elif "powershell" in cmd_str and "Dnscache" in cmd_str:
            return _make_subprocess_result(stdout="Running\n")
        elif "powershell" in cmd_str and "Dhcp" in cmd_str:
            return _make_subprocess_result(stdout="Stopped\n")
        return _make_subprocess_result()

    return fake_run


def _fake_run_tcp_params_modified():
    """System with unusual TCP/IP parameters"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "netsh" in cmd_str and "winsock" in cmd_str and "catalog" in cmd_str:
            output = ""
            for i in range(15):
                output += f"Item : {i}\n"
            return _make_subprocess_result(stdout=output)
        elif "reg" in cmd_str and "Tcpip" in cmd_str:
            # Return output with unusual TCP/IP parameters
            return _make_subprocess_result(
                stdout=r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" + "\n"
                + "KeepAliveTime REG_DWORD 0x927c0\n"
                + "TcpMaxDataRetransmissions REG_DWORD 0x5\n"
            )
        elif "reg" in cmd_str and "Protocol_Catalog9" in cmd_str:
            output = ""
            for i in range(8):
                output += f"Entry_{i}\n"
            return _make_subprocess_result(stdout=output)
        elif "powershell" in cmd_str and "Dnscache" in cmd_str:
            return _make_subprocess_result(stdout="Running\n")
        elif "powershell" in cmd_str and "Dhcp" in cmd_str:
            return _make_subprocess_result(stdout="Running\n")
        return _make_subprocess_result()

    return fake_run


def test_win_network_reset_discovered():
    """Module is properly discovered and has correct metadata"""
    mod = _get_module()
    assert mod.name == "win_network_reset"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.WIN32 in mod.platforms


def test_win_network_reset_healthy_stack():
    """System with healthy network stack"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy_stack()):
        result = mod.check(_make_profile())

    # Should have findings (at minimum the summary)
    assert result.has_issues

    # Should report normal provider count
    assert any(
        f.data.get("check_type") == "winsock_catalog_info"
        for f in result.findings
    )

    # Should report normal TCP/IP parameters
    assert any(
        f.data.get("check_type") == "tcp_ip_params_info"
        for f in result.findings
    )

    # Should report DNS running
    assert any(
        f.data.get("check_type") == "dns_service_info"
        for f in result.findings
    )

    # Should report DHCP running
    assert any(
        f.data.get("check_type") == "dhcp_service_info"
        for f in result.findings
    )

    # No warnings should be present
    assert not any(f.severity == Severity.WARNING for f in result.findings)


def test_win_network_reset_winsock_contaminated():
    """System with Winsock catalog contamination"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_winsock_contaminated()):
        result = mod.check(_make_profile())

    # Should have issues
    assert result.has_issues

    # Should report excessive provider count warning
    winsock_warnings = [
        f
        for f in result.findings
        if f.data.get("check_type") == "winsock_catalog"
        and f.severity == Severity.WARNING
    ]
    assert len(winsock_warnings) > 0
    assert "unusual" in winsock_warnings[0].title.lower() or "35" in winsock_warnings[0].title


def test_win_network_reset_dns_stopped():
    """System with DNS Client service stopped"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_dns_stopped()):
        result = mod.check(_make_profile())

    # Should have issues
    assert result.has_issues

    # Should have warning about DNS service
    dns_warnings = [
        f
        for f in result.findings
        if f.data.get("check_type") == "dns_service"
        and f.severity == Severity.WARNING
    ]
    assert len(dns_warnings) > 0
    assert "not running" in dns_warnings[0].title.lower()


def test_win_network_reset_dhcp_stopped():
    """System with DHCP Client service stopped"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_dhcp_stopped()):
        result = mod.check(_make_profile())

    # Should have issues
    assert result.has_issues

    # Should have warning about DHCP service
    dhcp_warnings = [
        f
        for f in result.findings
        if f.data.get("check_type") == "dhcp_service"
        and f.severity == Severity.WARNING
    ]
    assert len(dhcp_warnings) > 0
    assert "not running" in dhcp_warnings[0].title.lower()


def test_win_network_reset_tcp_params_modified():
    """System with unusual TCP/IP parameters"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_tcp_params_modified()):
        result = mod.check(_make_profile())

    # Should have issues
    assert result.has_issues

    # Should have warning about TCP/IP parameters
    tcp_warnings = [
        f
        for f in result.findings
        if f.data.get("check_type") == "tcp_ip_params"
        and f.severity == Severity.WARNING
    ]
    assert len(tcp_warnings) > 0
    assert "unusual" in tcp_warnings[0].title.lower() or "modified" in tcp_warnings[0].title.lower()


def test_win_network_reset_fix_is_informational():
    """fix() should always succeed with informational messages"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_dns_stopped()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    # fix() should always succeed
    assert fix.all_succeeded

    # If there are warnings, there should be corresponding actions
    warnings = [f for f in check.findings if f.severity == Severity.WARNING]
    if warnings:
        assert len(fix.actions) > 0


def test_win_network_reset_fix_no_warnings():
    """fix() with no warnings should return empty actions list"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy_stack()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    # Should succeed
    assert fix.all_succeeded

    # Should have no actions for info-only findings
    assert len(fix.actions) == 0


def test_win_network_reset_fix_multiple_warnings():
    """fix() with multiple warnings should provide multiple actions"""
    mod = _get_module()

    def fake_run_all_broken(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "netsh" in cmd_str and "winsock" in cmd_str and "catalog" in cmd_str:
            output = ""
            for i in range(35):
                output += f"Item : {i}\n"
            return _make_subprocess_result(stdout=output)
        elif "reg" in cmd_str and "Tcpip" in cmd_str:
            return _make_subprocess_result(
                stdout=r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" + "\n"
                + "KeepAliveTime REG_DWORD 0x927c0\n"
            )
        elif "reg" in cmd_str and "Protocol_Catalog9" in cmd_str:
            output = ""
            for i in range(25):
                output += f"Entry_{i}\n"
            return _make_subprocess_result(stdout=output)
        elif "powershell" in cmd_str and "Dnscache" in cmd_str:
            return _make_subprocess_result(stdout="Stopped\n")
        elif "powershell" in cmd_str and "Dhcp" in cmd_str:
            return _make_subprocess_result(stdout="Stopped\n")
        return _make_subprocess_result()

    with patch("subprocess.run", side_effect=fake_run_all_broken):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    # Should have multiple warnings
    warnings = [f for f in check.findings if f.severity == Severity.WARNING]
    assert len(warnings) > 0

    # Should have actions for each warning
    assert len(fix.actions) >= len(warnings)

    # All actions should succeed
    assert fix.all_succeeded
