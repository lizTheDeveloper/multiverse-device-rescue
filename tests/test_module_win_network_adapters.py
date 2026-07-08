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
    return next(m for m in modules if m.name == "win_network_adapters")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_healthy_network():
    """System with healthy network configuration"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "Get-NetAdapter" in cmd_str:
            # Two healthy adapters
            output = """[
  {
    "Name": "Ethernet",
    "InterfaceDescription": "Intel(R) 82579LM Gigabit Network Connection",
    "Status": "Up",
    "LinkSpeed": "1000000000 bps",
    "MacAddress": "AA-BB-CC-DD-EE-FF"
  },
  {
    "Name": "WiFi",
    "InterfaceDescription": "Intel(R) Dual Band Wireless-AC 8265",
    "Status": "Disconnected",
    "LinkSpeed": "0 bps",
    "MacAddress": "11-22-33-44-55-66"
  }
]"""
            return _make_subprocess_result(stdout=output)
        elif "Get-NetIPConfiguration" in cmd_str:
            output = """[
  {
    "InterfaceAlias": "Ethernet",
    "IPv4Address": {
      "IPAddress": "192.168.1.100"
    },
    "IPv4DefaultGateway": {
      "NextHop": "192.168.1.1"
    },
    "IPv6Address": {
      "IPAddress": "fe80::1%5"
    }
  },
  {
    "InterfaceAlias": "WiFi",
    "IPv4Address": null,
    "IPv4DefaultGateway": null,
    "IPv6Address": null
  }
]"""
            return _make_subprocess_result(stdout=output)
        elif "Get-DnsClientServerAddress" in cmd_str:
            output = """[
  {
    "ServerAddresses": ["8.8.8.8", "8.8.4.4"]
  }
]"""
            return _make_subprocess_result(stdout=output)
        return _make_subprocess_result()

    return fake_run


def _fake_run_disconnected_adapter():
    """System with disconnected adapter"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "Get-NetAdapter" in cmd_str:
            output = """[
  {
    "Name": "Ethernet",
    "InterfaceDescription": "Intel(R) 82579LM Gigabit Network Connection",
    "Status": "Disconnected",
    "LinkSpeed": "0 bps",
    "MacAddress": "AA-BB-CC-DD-EE-FF"
  }
]"""
            return _make_subprocess_result(stdout=output)
        elif "Get-NetIPConfiguration" in cmd_str:
            return _make_subprocess_result(stdout="[]")
        elif "Get-DnsClientServerAddress" in cmd_str:
            return _make_subprocess_result(stdout="[]")
        return _make_subprocess_result()

    return fake_run


def _fake_run_self_assigned_ip():
    """System with self-assigned IP (DHCP failure)"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "Get-NetAdapter" in cmd_str:
            output = """[
  {
    "Name": "Ethernet",
    "InterfaceDescription": "Intel(R) 82579LM Gigabit Network Connection",
    "Status": "Up",
    "LinkSpeed": "1000000000 bps",
    "MacAddress": "AA-BB-CC-DD-EE-FF"
  }
]"""
            return _make_subprocess_result(stdout=output)
        elif "Get-NetIPConfiguration" in cmd_str:
            output = """[
  {
    "InterfaceAlias": "Ethernet",
    "IPv4Address": {
      "IPAddress": "169.254.1.100"
    },
    "IPv4DefaultGateway": null,
    "IPv6Address": {
      "IPAddress": "fe80::1%5"
    }
  }
]"""
            return _make_subprocess_result(stdout=output)
        elif "Get-DnsClientServerAddress" in cmd_str:
            return _make_subprocess_result(stdout="[]")
        return _make_subprocess_result()

    return fake_run


def _fake_run_multiple_gateways():
    """System with multiple default gateways (routing conflict)"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "Get-NetAdapter" in cmd_str:
            output = """[
  {
    "Name": "Ethernet",
    "InterfaceDescription": "Intel(R) 82579LM Gigabit Network Connection",
    "Status": "Up",
    "LinkSpeed": "1000000000 bps",
    "MacAddress": "AA-BB-CC-DD-EE-FF"
  },
  {
    "Name": "WiFi",
    "InterfaceDescription": "Intel(R) Dual Band Wireless-AC 8265",
    "Status": "Up",
    "LinkSpeed": "150000000 bps",
    "MacAddress": "11-22-33-44-55-66"
  }
]"""
            return _make_subprocess_result(stdout=output)
        elif "Get-NetIPConfiguration" in cmd_str:
            output = """[
  {
    "InterfaceAlias": "Ethernet",
    "IPv4Address": {
      "IPAddress": "192.168.1.100"
    },
    "IPv4DefaultGateway": {
      "NextHop": "192.168.1.1"
    },
    "IPv6Address": null
  },
  {
    "InterfaceAlias": "WiFi",
    "IPv4Address": {
      "IPAddress": "10.0.0.50"
    },
    "IPv4DefaultGateway": {
      "NextHop": "10.0.0.1"
    },
    "IPv6Address": null
  }
]"""
            return _make_subprocess_result(stdout=output)
        elif "Get-DnsClientServerAddress" in cmd_str:
            output = """[
  {
    "ServerAddresses": ["8.8.8.8"]
  }
]"""
            return _make_subprocess_result(stdout=output)
        return _make_subprocess_result()

    return fake_run


def _fake_run_no_dns():
    """System with no DNS configured"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "Get-NetAdapter" in cmd_str:
            output = """[
  {
    "Name": "Ethernet",
    "InterfaceDescription": "Intel(R) 82579LM Gigabit Network Connection",
    "Status": "Up",
    "LinkSpeed": "1000000000 bps",
    "MacAddress": "AA-BB-CC-DD-EE-FF"
  }
]"""
            return _make_subprocess_result(stdout=output)
        elif "Get-NetIPConfiguration" in cmd_str:
            output = """[
  {
    "InterfaceAlias": "Ethernet",
    "IPv4Address": {
      "IPAddress": "192.168.1.100"
    },
    "IPv4DefaultGateway": {
      "NextHop": "192.168.1.1"
    },
    "IPv6Address": null
  }
]"""
            return _make_subprocess_result(stdout=output)
        elif "Get-DnsClientServerAddress" in cmd_str:
            return _make_subprocess_result(stdout="[]")
        return _make_subprocess_result()

    return fake_run


def _fake_run_query_failed():
    """PowerShell query fails"""
    def fake_run(cmd, **kwargs):
        return _make_subprocess_result(returncode=1)

    return fake_run


def test_win_network_adapters_discovered():
    """Module is properly discovered and has correct metadata"""
    mod = _get_module()
    assert mod.name == "win_network_adapters"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.WIN32 in mod.platforms


def test_win_network_adapters_healthy():
    """System with healthy network configuration"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy_network()):
        result = mod.check(_make_profile())

    # Should have findings (adapter info, IP config, DNS config)
    assert result.has_issues

    # Should report adapters
    assert any(
        f.data.get("check") == "adapter_info"
        for f in result.findings
    )

    # Should report IP config
    assert any(
        f.data.get("check") == "ip_config_info"
        for f in result.findings
    )

    # Should report DNS config
    assert any(
        f.data.get("check") == "dns_config"
        for f in result.findings
    )

    # Should have no critical severity
    assert not any(f.severity == Severity.CRITICAL for f in result.findings)
    # WiFi adapter is disconnected, so there will be a warning for that
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warnings) > 0
    assert any("WiFi" in w.description or "disconnected" in w.description.lower() for w in warnings)


def test_win_network_adapters_disconnected():
    """System with disconnected adapter"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_disconnected_adapter()):
        result = mod.check(_make_profile())

    # Should have issues
    assert result.has_issues

    # Should have warning about disconnected adapter
    disconnected_warnings = [
        f
        for f in result.findings
        if f.data.get("check") == "adapter_disconnected"
        and f.severity == Severity.WARNING
    ]
    assert len(disconnected_warnings) > 0
    assert "Ethernet" in disconnected_warnings[0].title


def test_win_network_adapters_self_assigned_ip():
    """System with self-assigned IP (DHCP failure)"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_self_assigned_ip()):
        result = mod.check(_make_profile())

    # Should have issues
    assert result.has_issues

    # Should have critical finding for self-assigned IP
    self_assigned = [
        f
        for f in result.findings
        if f.data.get("check") == "self_assigned_ip"
        and f.severity == Severity.CRITICAL
    ]
    assert len(self_assigned) > 0
    assert "169.254" in self_assigned[0].description


def test_win_network_adapters_multiple_gateways():
    """System with multiple default gateways (routing conflict)"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_multiple_gateways()):
        result = mod.check(_make_profile())

    # Should have issues
    assert result.has_issues

    # Should have warning about multiple gateways
    multi_gw_warnings = [
        f
        for f in result.findings
        if f.data.get("check") == "multiple_gateways"
        and f.severity == Severity.WARNING
    ]
    assert len(multi_gw_warnings) > 0
    assert "multiple" in multi_gw_warnings[0].title.lower()


def test_win_network_adapters_no_dns():
    """System with no DNS configured"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_dns()):
        result = mod.check(_make_profile())

    # Should have issues
    assert result.has_issues

    # Should have warning about missing DNS
    no_dns_warnings = [
        f
        for f in result.findings
        if f.data.get("check") == "no_dns"
        and f.severity == Severity.WARNING
    ]
    assert len(no_dns_warnings) > 0
    assert "DNS" in no_dns_warnings[0].title


def test_win_network_adapters_query_failed():
    """PowerShell query fails"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_query_failed()):
        result = mod.check(_make_profile())

    # Should have issues
    assert result.has_issues

    # Should report query failure
    assert any(
        f.data.get("check") == "adapter_query_failed"
        for f in result.findings
    )


def test_win_network_adapters_fix_is_informational():
    """fix() should always succeed with informational messages"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_self_assigned_ip()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    # fix() should always succeed
    assert fix.all_succeeded

    # Should have actions for findings
    assert len(fix.actions) > 0


def test_win_network_adapters_fix_disconnected_adapter():
    """fix() provides action for disconnected adapter"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_disconnected_adapter()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    # Should have actions
    assert len(fix.actions) > 0

    # Should have action for disconnected adapter
    disconnected_actions = [
        a for a in fix.actions
        if "disconnected" in a.title.lower() or "enable" in a.title.lower()
    ]
    assert len(disconnected_actions) > 0
    assert disconnected_actions[0].success


def test_win_network_adapters_fix_self_assigned_ip():
    """fix() provides action for self-assigned IP"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_self_assigned_ip()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    # Should have actions
    assert len(fix.actions) > 0

    # Should have action for IP renewal
    renewal_actions = [
        a for a in fix.actions
        if "renew" in a.title.lower() or "release" in a.description.lower()
    ]
    assert len(renewal_actions) > 0
    assert renewal_actions[0].success


def test_win_network_adapters_fix_multiple_gateways():
    """fix() provides action for multiple gateways"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_multiple_gateways()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    # Should have actions
    assert len(fix.actions) > 0

    # Should have action for gateway conflict
    gateway_actions = [
        a for a in fix.actions
        if "gateway" in a.title.lower() or "route" in a.description.lower()
    ]
    assert len(gateway_actions) > 0
    assert gateway_actions[0].success


def test_win_network_adapters_fix_no_dns():
    """fix() provides action for missing DNS"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_dns()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    # Should have actions
    assert len(fix.actions) > 0

    # Should have action for DNS configuration
    dns_actions = [
        a for a in fix.actions
        if "dns" in a.title.lower() or "dns" in a.description.lower()
    ]
    assert len(dns_actions) > 0
    assert dns_actions[0].success


def test_win_network_adapters_fix_healthy():
    """fix() with healthy system returns appropriate actions"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy_network()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    # Should succeed
    assert fix.all_succeeded

    # Should have actions for informational findings
    assert len(fix.actions) > 0

    # All actions should succeed
    assert all(a.success for a in fix.actions)
