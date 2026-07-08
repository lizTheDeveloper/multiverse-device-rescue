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
    return next(m for m in modules if m.name == "network_proxy_check")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_no_proxies():
    """All networksetup commands return disabled proxies."""

    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "listallnetworkservices" in cmd_str:
            return _make_subprocess_result("Wi-Fi\nEthernet\n")
        elif "getwebproxy" in cmd_str or "getsecurewebproxy" in cmd_str or "getsocksfirewallproxy" in cmd_str:
            return _make_subprocess_result("Enabled: No\n")
        elif "getautoproxyurl" in cmd_str:
            return _make_subprocess_result("URL: (null)\n")
        elif "getproxybypassdomains" in cmd_str:
            return _make_subprocess_result("(null)\n")
        return _make_subprocess_result()

    return fake_run


def _fake_run_http_proxy_enabled():
    """HTTP proxy is enabled."""

    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "listallnetworkservices" in cmd_str:
            return _make_subprocess_result("Wi-Fi\nEthernet\n")
        elif "getwebproxy" in cmd_str:
            return _make_subprocess_result("Enabled: Yes\nServer: proxy.example.com\nPort: 8080\n")
        elif "getsecurewebproxy" in cmd_str:
            return _make_subprocess_result("Enabled: No\n")
        elif "getsocksfirewallproxy" in cmd_str:
            return _make_subprocess_result("Enabled: No\n")
        elif "getautoproxyurl" in cmd_str:
            return _make_subprocess_result("URL: (null)\n")
        elif "getproxybypassdomains" in cmd_str:
            return _make_subprocess_result("(null)\n")
        return _make_subprocess_result()

    return fake_run


def _fake_run_remote_pac_url():
    """Remote PAC URL configured - CRITICAL severity."""

    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "listallnetworkservices" in cmd_str:
            return _make_subprocess_result("Wi-Fi\nEthernet\n")
        elif "getwebproxy" in cmd_str:
            return _make_subprocess_result("Enabled: No\n")
        elif "getsecurewebproxy" in cmd_str:
            return _make_subprocess_result("Enabled: No\n")
        elif "getsocksfirewallproxy" in cmd_str:
            return _make_subprocess_result("Enabled: No\n")
        elif "getautoproxyurl" in cmd_str:
            return _make_subprocess_result("URL: http://malware.example.com/proxy.pac\n")
        elif "getproxybypassdomains" in cmd_str:
            return _make_subprocess_result("(null)\n")
        return _make_subprocess_result()

    return fake_run


def _fake_run_localhost_suspicious_proxy():
    """Proxy pointing to localhost with suspicious port."""

    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "listallnetworkservices" in cmd_str:
            return _make_subprocess_result("Wi-Fi\nEthernet\n")
        elif "getwebproxy" in cmd_str:
            return _make_subprocess_result("Enabled: Yes\nServer: localhost\nPort: 7777\n")
        elif "getsecurewebproxy" in cmd_str:
            return _make_subprocess_result("Enabled: No\n")
        elif "getsocksfirewallproxy" in cmd_str:
            return _make_subprocess_result("Enabled: No\n")
        elif "getautoproxyurl" in cmd_str:
            return _make_subprocess_result("URL: (null)\n")
        elif "getproxybypassdomains" in cmd_str:
            return _make_subprocess_result("(null)\n")
        return _make_subprocess_result()

    return fake_run


def _fake_run_localhost_standard_proxy():
    """Proxy pointing to localhost with standard port - not suspicious."""

    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "listallnetworkservices" in cmd_str:
            return _make_subprocess_result("Wi-Fi\nEthernet\n")
        elif "getwebproxy" in cmd_str:
            return _make_subprocess_result("Enabled: Yes\nServer: localhost\nPort: 8080\n")
        elif "getsecurewebproxy" in cmd_str:
            return _make_subprocess_result("Enabled: No\n")
        elif "getsocksfirewallproxy" in cmd_str:
            return _make_subprocess_result("Enabled: No\n")
        elif "getautoproxyurl" in cmd_str:
            return _make_subprocess_result("URL: (null)\n")
        elif "getproxybypassdomains" in cmd_str:
            return _make_subprocess_result("(null)\n")
        return _make_subprocess_result()

    return fake_run


def _fake_run_with_bypass_domains():
    """Proxy with bypass domains configured."""

    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "listallnetworkservices" in cmd_str:
            return _make_subprocess_result("Wi-Fi\nEthernet\n")
        elif "getwebproxy" in cmd_str:
            return _make_subprocess_result("Enabled: Yes\nServer: proxy.example.com\nPort: 8080\n")
        elif "getsecurewebproxy" in cmd_str:
            return _make_subprocess_result("Enabled: No\n")
        elif "getsocksfirewallproxy" in cmd_str:
            return _make_subprocess_result("Enabled: No\n")
        elif "getautoproxyurl" in cmd_str:
            return _make_subprocess_result("URL: (null)\n")
        elif "getproxybypassdomains" in cmd_str:
            return _make_subprocess_result("localhost\n127.0.0.1\n*.example.com\n")
        return _make_subprocess_result()

    return fake_run


def test_network_proxy_check_discovered():
    mod = _get_module()
    assert mod.name == "network_proxy_check"
    assert mod.category == "network"
    assert mod.risk_level == RiskLevel.SAFE


def test_network_proxy_check_no_proxies():
    """No proxies configured - should be INFO severity."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_proxies()):
        result = mod.check(_make_profile())

    assert result.has_issues
    no_proxy_findings = [f for f in result.findings if f.data.get("check") == "no_proxies"]
    assert len(no_proxy_findings) >= 1
    assert no_proxy_findings[0].severity == Severity.INFO


def test_network_proxy_check_http_proxy_enabled():
    """HTTP proxy enabled - should be WARNING."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_http_proxy_enabled()):
        result = mod.check(_make_profile())

    assert result.has_issues
    proxy_findings = [f for f in result.findings if f.data.get("check") == "proxy_enabled"]
    assert len(proxy_findings) >= 1
    assert proxy_findings[0].severity == Severity.WARNING
    assert "HTTP" in proxy_findings[0].data.get("enabled_proxies", [])


def test_network_proxy_check_remote_pac_url_critical():
    """Remote PAC URL configured - should be CRITICAL."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_remote_pac_url()):
        result = mod.check(_make_profile())

    assert result.has_issues
    pac_findings = [f for f in result.findings if f.data.get("check") == "remote_pac_url"]
    assert len(pac_findings) >= 1
    assert pac_findings[0].severity == Severity.CRITICAL
    assert "malware.example.com" in pac_findings[0].data.get("pac_url", "")


def test_network_proxy_check_localhost_suspicious():
    """Proxy with suspicious localhost port - should be WARNING."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_localhost_suspicious_proxy()):
        result = mod.check(_make_profile())

    assert result.has_issues
    localhost_findings = [f for f in result.findings if f.data.get("check") == "suspicious_localhost_proxy"]
    assert len(localhost_findings) >= 1
    assert localhost_findings[0].severity == Severity.WARNING


def test_network_proxy_check_localhost_standard_port():
    """Proxy with standard localhost port - should be WARNING as proxy_enabled."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_localhost_standard_proxy()):
        result = mod.check(_make_profile())

    assert result.has_issues
    # Should be flagged as proxy_enabled, not suspicious_localhost_proxy
    proxy_findings = [f for f in result.findings if f.data.get("check") == "proxy_enabled"]
    assert len(proxy_findings) >= 1
    assert proxy_findings[0].severity == Severity.WARNING


def test_network_proxy_check_bypass_domains():
    """Bypass domains are detected and reported."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_with_bypass_domains()):
        result = mod.check(_make_profile())

    assert result.has_issues
    bypass_findings = [f for f in result.findings if f.data.get("check") == "proxy_bypass_domains"]
    assert len(bypass_findings) >= 1
    assert bypass_findings[0].severity == Severity.INFO
    bypass_domains = bypass_findings[0].data.get("bypass_domains", [])
    assert "localhost" in bypass_domains or "*.example.com" in bypass_domains


def test_network_proxy_check_fix_is_informational():
    """fix() should be informational only, never modifies settings."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_http_proxy_enabled()):
        check = mod.check(_make_profile())

    # fix() should not call subprocess to modify anything
    with patch("subprocess.run") as mock_run:
        fix = mod.fix(check, Mode.MANUAL)

    # Verify no subprocess calls were made
    mock_run.assert_not_called()

    # Verify fix succeeded with informational actions
    assert fix.all_succeeded
    assert len(fix.actions) > 0
    assert all(a.success for a in fix.actions)


def test_network_proxy_check_fix_remote_pac_guidance():
    """fix() should provide guidance for removing remote PAC URL."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_remote_pac_url()):
        check = mod.check(_make_profile())

    fix = mod.fix(check, Mode.MANUAL)

    assert fix.all_succeeded
    pac_actions = [a for a in fix.actions if "PAC" in a.title or "PAC" in a.description]
    assert len(pac_actions) >= 1
    # Should mention System Settings or Network
    assert any("System Settings" in a.description or "Network" in a.description for a in pac_actions)


def test_network_proxy_check_fix_localhost_guidance():
    """fix() should provide guidance for removing suspicious localhost proxy."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_localhost_suspicious_proxy()):
        check = mod.check(_make_profile())

    fix = mod.fix(check, Mode.MANUAL)

    assert fix.all_succeeded
    localhost_actions = [a for a in fix.actions if "local proxy" in a.title or "local proxy" in a.description]
    assert len(localhost_actions) >= 1
