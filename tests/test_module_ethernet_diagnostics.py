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
        os_version="14.5",
        architecture="arm64",
        cpu_model="Apple M1 Pro",
        cpu_cores=12,
        ram_bytes=32 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "ethernet_diagnostics")


def test_ethernet_diagnostics_discovered():
    mod = _get_module()
    assert mod.name == "ethernet_diagnostics"
    assert mod.category == "network"
    assert Platform.DARWIN in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_ethernet_no_interfaces():
    """Test when no Ethernet interfaces are found."""
    mod = _get_module()

    def no_interfaces_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = (
            "SCTP:\n"
            "    Device: en3\n"
            "Wi-Fi:\n"
            "    Device: en0\n"
        )
        return result

    with patch("subprocess.run", side_effect=no_interfaces_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "no_ethernet" for f in result.findings)


def test_ethernet_single_active_interface():
    """Test single active Ethernet interface with good configuration."""
    mod = _get_module()

    def mock_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""

        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        # networksetup -listallhardwareports
        if "networksetup" in cmd_str and "listallhardwareports" in cmd_str:
            result.stdout = (
                "Hardware Ports:\n"
                "Ethernet:\n"
                "    Device: en5\n"
                "Wi-Fi:\n"
                "    Device: en0\n"
            )

        # ifconfig en5
        elif "ifconfig" in cmd_str and "en5" in cmd_str:
            result.stdout = (
                "en5: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n"
                "    inet 192.168.1.100 netmask 0xffffff00 broadcast 192.168.1.255\n"
                "    hwaddr 00:11:22:33:44:55\n"
                "    status: active\n"
                "    nd6 options=29<PERFORMNUD,IFDISABLED,AUTO_LINKLOCAL>\n"
            )

        # system_profiler SPEthernetDataType
        elif "system_profiler" in cmd_str and "SPEthernetDataType" in cmd_str:
            result.stdout = (
                "Ethernet Information:\n"
                "  Ethernet Connection:\n"
                "    Device: en5\n"
                "    Link Speed: 1000 Mbps\n"
            )

        # netstat -i
        elif "netstat" in cmd_str and "-i" in cmd_str:
            result.stdout = (
                "Name    Mtu Network        Address            Ipkts Ierrs Idrop Opkts Oerrs Coll\n"
                "en5     1500 <Link#20>      00:11:22:33:44:55  1000  0     0     1000  0     0\n"
            )

        return result

    with patch("subprocess.run", side_effect=mock_run):
        result = mod.check(_make_profile())
    # Should have summary but no issues
    assert result.has_issues
    assert any(f.data.get("check") == "ethernet_summary" for f in result.findings)
    assert not any(f.severity == Severity.CRITICAL for f in result.findings)


def test_ethernet_self_assigned_ip():
    """Test detection of self-assigned IP (DHCP failure)."""
    mod = _get_module()

    def mock_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""

        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        if "networksetup" in cmd_str:
            result.stdout = (
                "Hardware Ports:\n"
                "Ethernet:\n"
                "    Device: en5\n"
            )

        elif "ifconfig" in cmd_str and "en5" in cmd_str:
            result.stdout = (
                "en5: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n"
                "    inet 169.254.1.50 netmask 0xffff0000 broadcast 169.254.255.255\n"
                "    status: active\n"
            )

        elif "system_profiler" in cmd_str:
            result.stdout = "Ethernet Information:\n  Device: en5\n  Link Speed: 1000 Mbps\n"

        elif "netstat" in cmd_str:
            result.stdout = "Name    Mtu Network        Address Ipkts Ierrs Idrop Opkts Oerrs Coll\nen5     1500 <Link#20> 00:11:22 100 0 0 100 0 0\n"

        return result

    with patch("subprocess.run", side_effect=mock_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert len(critical) > 0
    assert any(f.data.get("check") == "self_assigned_ip" for f in critical)


def test_ethernet_inactive_interface():
    """Test detection of inactive Ethernet interface."""
    mod = _get_module()

    def mock_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""

        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        if "networksetup" in cmd_str:
            result.stdout = (
                "Hardware Ports:\n"
                "Ethernet:\n"
                "    Device: en5\n"
            )

        elif "ifconfig" in cmd_str and "en5" in cmd_str:
            result.stdout = (
                "en5: flags=8842<BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n"
                "    status: inactive\n"
            )

        else:
            result.returncode = 1
            result.stdout = ""

        return result

    with patch("subprocess.run", side_effect=mock_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    warnings = [f for f in result.findings if f.data.get("check") == "interface_inactive"]
    assert len(warnings) > 0


def test_ethernet_100mbps_speed_mismatch():
    """Test detection of 100 Mbps on gigabit adapter."""
    mod = _get_module()

    def mock_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""

        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        if "networksetup" in cmd_str:
            result.stdout = (
                "Hardware Ports:\n"
                "Ethernet:\n"
                "    Device: en5\n"
            )

        elif "ifconfig" in cmd_str and "en5" in cmd_str:
            result.stdout = (
                "en5: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n"
                "    inet 192.168.1.100 netmask 0xffffff00\n"
                "    status: active\n"
            )

        elif "system_profiler" in cmd_str:
            result.stdout = (
                "Ethernet Information:\n"
                "  Device: en5\n"
                "  Link Speed: 100 Mbps\n"
            )

        elif "netstat" in cmd_str:
            result.stdout = "Name    Mtu Network Address Ipkts Ierrs Idrop Opkts Oerrs Coll\nen5     1500 Link 00:11 100 0 0 100 0 0\n"

        return result

    with patch("subprocess.run", side_effect=mock_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    speed_warnings = [f for f in result.findings if f.data.get("check") == "link_speed_mismatch"]
    assert len(speed_warnings) > 0
    assert speed_warnings[0].severity == Severity.WARNING


def test_ethernet_non_standard_mtu():
    """Test detection of non-standard MTU."""
    mod = _get_module()

    def mock_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""

        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        if "networksetup" in cmd_str:
            result.stdout = (
                "Hardware Ports:\n"
                "Ethernet:\n"
                "    Device: en5\n"
            )

        elif "ifconfig" in cmd_str and "en5" in cmd_str:
            result.stdout = (
                "en5: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 9000\n"
                "    inet 192.168.1.100 netmask 0xffffff00\n"
                "    status: active\n"
            )

        elif "system_profiler" in cmd_str:
            result.stdout = "Ethernet Information:\n  Device: en5\n  Link Speed: 1000 Mbps\n"

        elif "netstat" in cmd_str:
            result.stdout = "Name    Mtu Network Address Ipkts Ierrs Idrop Opkts Oerrs Coll\nen5     9000 Link 00:11 100 0 0 100 0 0\n"

        return result

    with patch("subprocess.run", side_effect=mock_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    mtu_warnings = [f for f in result.findings if f.data.get("check") == "non_standard_mtu"]
    assert len(mtu_warnings) > 0
    assert mtu_warnings[0].severity == Severity.WARNING


def test_ethernet_high_packet_errors():
    """Test detection of high packet error rate."""
    mod = _get_module()

    def mock_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""

        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        if "networksetup" in cmd_str:
            result.stdout = (
                "Hardware Ports:\n"
                "Ethernet:\n"
                "    Device: en5\n"
            )

        elif "ifconfig" in cmd_str and "en5" in cmd_str:
            result.stdout = (
                "en5: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n"
                "    inet 192.168.1.100 netmask 0xffffff00\n"
                "    status: active\n"
            )

        elif "system_profiler" in cmd_str:
            result.stdout = "Ethernet Information:\n  Device: en5\n  Link Speed: 1000 Mbps\n"

        elif "netstat" in cmd_str:
            # 100 input packets, 3 errors = 3% error rate (>1%)
            result.stdout = "Name    Mtu Network Address Ipkts Ierrs Idrop Opkts Oerrs Coll\nen5     1500 Link 00:11 100 3 0 100 2 0\n"

        return result

    with patch("subprocess.run", side_effect=mock_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    error_warnings = [f for f in result.findings if f.data.get("check") == "high_packet_errors"]
    assert len(error_warnings) > 0
    assert error_warnings[0].severity == Severity.WARNING


def test_ethernet_multiple_issues():
    """Test detection of multiple issues on same interface."""
    mod = _get_module()

    def mock_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""

        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        if "networksetup" in cmd_str:
            result.stdout = (
                "Hardware Ports:\n"
                "Ethernet:\n"
                "    Device: en5\n"
            )

        elif "ifconfig" in cmd_str and "en5" in cmd_str:
            # Self-assigned IP + non-standard MTU
            result.stdout = (
                "en5: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 9000\n"
                "    inet 169.254.1.50 netmask 0xffff0000\n"
                "    status: active\n"
            )

        elif "system_profiler" in cmd_str:
            result.stdout = "Ethernet Information:\n  Device: en5\n  Link Speed: 1000 Mbps\n"

        elif "netstat" in cmd_str:
            result.stdout = "Name    Mtu Network Address Ipkts Ierrs Idrop Opkts Oerrs Coll\nen5     9000 Link 00:11 100 3 0 100 2 0\n"

        return result

    with patch("subprocess.run", side_effect=mock_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    checks = [f.data.get("check") for f in result.findings]
    # Should detect self-assigned IP (critical)
    assert "self_assigned_ip" in checks
    # Should also detect non-standard MTU and packet errors
    assert "non_standard_mtu" in checks
    assert "high_packet_errors" in checks


def test_ethernet_fix_self_assigned_ip():
    """Test fix recommendations for self-assigned IP."""
    mod = _get_module()

    def mock_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""

        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        if "networksetup" in cmd_str:
            result.stdout = "Hardware Ports:\nEthernet:\n    Device: en5\n"
        elif "ifconfig" in cmd_str:
            result.stdout = "en5: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n    inet 169.254.1.50\n    status: active\n"
        elif "system_profiler" in cmd_str:
            result.stdout = "Ethernet Information:\n  Device: en5\n  Link Speed: 1000 Mbps\n"
        elif "netstat" in cmd_str:
            result.stdout = "Name    Mtu Network Address Ipkts Ierrs Idrop Opkts Oerrs Coll\nen5     1500 Link 00:11 100 0 0 100 0 0\n"

        return result

    with patch("subprocess.run", side_effect=mock_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    actions = [a for a in fix.actions if "DHCP" in a.title or "DHCP" in a.description]
    assert len(actions) > 0


def test_ethernet_fix_link_speed_mismatch():
    """Test fix recommendations for link speed mismatch."""
    mod = _get_module()

    def mock_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""

        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        if "networksetup" in cmd_str:
            result.stdout = "Hardware Ports:\nEthernet:\n    Device: en5\n"
        elif "ifconfig" in cmd_str:
            result.stdout = "en5: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n    inet 192.168.1.100\n    status: active\n"
        elif "system_profiler" in cmd_str:
            result.stdout = "Ethernet Information:\n  Device: en5\n  Link Speed: 100 Mbps\n"
        elif "netstat" in cmd_str:
            result.stdout = "Name    Mtu Network Address Ipkts Ierrs Idrop Opkts Oerrs Coll\nen5     1500 Link 00:11 100 0 0 100 0 0\n"

        return result

    with patch("subprocess.run", side_effect=mock_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    actions = [a for a in fix.actions if "cable" in a.description.lower()]
    assert len(actions) > 0


def test_ethernet_subprocess_error():
    """Test graceful handling of subprocess errors."""
    mod = _get_module()

    def error_run(cmd, **kwargs):
        raise OSError("Command failed")

    with patch("subprocess.run", side_effect=error_run):
        result = mod.check(_make_profile())
    # Should complete without crashing
    assert isinstance(result.findings, list)


def test_ethernet_timeout():
    """Test graceful handling of subprocess timeout."""
    mod = _get_module()

    def timeout_run(cmd, **kwargs):
        raise Exception("Timeout")

    with patch("subprocess.run", side_effect=timeout_run):
        result = mod.check(_make_profile())
    # Should complete without crashing
    assert isinstance(result.findings, list)
