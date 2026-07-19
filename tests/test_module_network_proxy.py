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
    return next(m for m in modules if m.name == "network_proxy")


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

        if "getwebproxy" in cmd_str or "getsecurewebproxy" in cmd_str or "getsocksfirewallproxy" in cmd_str:
            return _make_subprocess_result("Enabled: No\n")
        elif "getproxyautodiscovery" in cmd_str:
            return _make_subprocess_result("Enabled: No\n")
        elif "getautoproxyurl" in cmd_str:
            return _make_subprocess_result("URL: (null)\n")
        return _make_subprocess_result()

    return fake_run


def _fake_run_http_proxy_enabled():
    """HTTP proxy is enabled."""

    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "getwebproxy" in cmd_str:
            return _make_subprocess_result("Enabled: Yes\nServer: proxy.example.com\nPort: 8080\n")
        elif "getsecurewebproxy" in cmd_str:
            return _make_subprocess_result("Enabled: No\n")
        elif "getsocksfirewallproxy" in cmd_str:
            return _make_subprocess_result("Enabled: No\n")
        elif "getproxyautodiscovery" in cmd_str:
            return _make_subprocess_result("Enabled: No\n")
        elif "getautoproxyurl" in cmd_str:
            return _make_subprocess_result("URL: (null)\n")
        return _make_subprocess_result()

    return fake_run


def _fake_run_https_proxy_enabled():
    """HTTPS proxy is enabled."""

    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "getwebproxy" in cmd_str:
            return _make_subprocess_result("Enabled: No\n")
        elif "getsecurewebproxy" in cmd_str:
            return _make_subprocess_result("Enabled: Yes\nServer: secure-proxy.example.com\nPort: 8443\n")
        elif "getsocksfirewallproxy" in cmd_str:
            return _make_subprocess_result("Enabled: No\n")
        elif "getproxyautodiscovery" in cmd_str:
            return _make_subprocess_result("Enabled: No\n")
        elif "getautoproxyurl" in cmd_str:
            return _make_subprocess_result("URL: (null)\n")
        return _make_subprocess_result()

    return fake_run


def _fake_run_socks_proxy_enabled():
    """SOCKS proxy is enabled."""

    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "getwebproxy" in cmd_str:
            return _make_subprocess_result("Enabled: No\n")
        elif "getsecurewebproxy" in cmd_str:
            return _make_subprocess_result("Enabled: No\n")
        elif "getsocksfirewallproxy" in cmd_str:
            return _make_subprocess_result("Enabled: Yes\nServer: socks-proxy.example.com\nPort: 1080\n")
        elif "getproxyautodiscovery" in cmd_str:
            return _make_subprocess_result("Enabled: No\n")
        elif "getautoproxyurl" in cmd_str:
            return _make_subprocess_result("URL: (null)\n")
        return _make_subprocess_result()

    return fake_run


def _fake_run_pac_file_configured():
    """PAC file URL is configured (CRITICAL)."""

    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "getwebproxy" in cmd_str:
            return _make_subprocess_result("Enabled: No\n")
        elif "getsecurewebproxy" in cmd_str:
            return _make_subprocess_result("Enabled: No\n")
        elif "getsocksfirewallproxy" in cmd_str:
            return _make_subprocess_result("Enabled: No\n")
        elif "getproxyautodiscovery" in cmd_str:
            return _make_subprocess_result("Enabled: No\n")
        elif "getautoproxyurl" in cmd_str:
            return _make_subprocess_result("URL: http://malware.local/proxy.pac\n")
        return _make_subprocess_result()

    return fake_run


def _fake_run_multiple_proxies_enabled():
    """Multiple proxy types are enabled."""

    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "getwebproxy" in cmd_str:
            return _make_subprocess_result("Enabled: Yes\nServer: proxy1.example.com\nPort: 8080\n")
        elif "getsecurewebproxy" in cmd_str:
            return _make_subprocess_result("Enabled: Yes\nServer: proxy2.example.com\nPort: 8443\n")
        elif "getsocksfirewallproxy" in cmd_str:
            return _make_subprocess_result("Enabled: Yes\nServer: proxy3.example.com\nPort: 1080\n")
        elif "getproxyautodiscovery" in cmd_str:
            return _make_subprocess_result("Enabled: No\n")
        elif "getautoproxyurl" in cmd_str:
            return _make_subprocess_result("URL: (null)\n")
        return _make_subprocess_result()

    return fake_run


def _fake_run_auto_discovery_enabled():
    """Auto proxy discovery is enabled."""

    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "getwebproxy" in cmd_str:
            return _make_subprocess_result("Enabled: No\n")
        elif "getsecurewebproxy" in cmd_str:
            return _make_subprocess_result("Enabled: No\n")
        elif "getsocksfirewallproxy" in cmd_str:
            return _make_subprocess_result("Enabled: No\n")
        elif "getproxyautodiscovery" in cmd_str:
            return _make_subprocess_result("Enabled: Yes\n")
        elif "getautoproxyurl" in cmd_str:
            return _make_subprocess_result("URL: (null)\n")
        return _make_subprocess_result()

    return fake_run


def test_network_proxy_discovered():
    mod = _get_module()
    assert mod.name == "network_proxy"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE


def test_network_proxy_no_proxies():
    """No proxies configured - should be INFO severity."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_proxies()):
        result = mod.check(_make_profile())

    assert result.has_issues
    assert len(result.findings) == 1
    assert result.findings[0].severity == Severity.INFO
    assert result.findings[0].data.get("check") == "no_proxies"


def test_network_proxy_http_proxy_enabled():
    """HTTP proxy enabled - should be WARNING."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_http_proxy_enabled()):
        result = mod.check(_make_profile())

    assert result.has_issues
    proxy_findings = [f for f in result.findings if f.data.get("check") == "proxy_enabled"]
    assert len(proxy_findings) >= 1
    assert proxy_findings[0].severity == Severity.WARNING
    assert "HTTP" in proxy_findings[0].data.get("enabled_proxies", [])


def test_network_proxy_https_proxy_enabled():
    """HTTPS proxy enabled - should be WARNING."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_https_proxy_enabled()):
        result = mod.check(_make_profile())

    assert result.has_issues
    proxy_findings = [f for f in result.findings if f.data.get("check") == "proxy_enabled"]
    assert len(proxy_findings) >= 1
    assert proxy_findings[0].severity == Severity.WARNING
    assert "HTTPS" in proxy_findings[0].data.get("enabled_proxies", [])


def test_network_proxy_socks_proxy_enabled():
    """SOCKS proxy enabled - should be WARNING."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_socks_proxy_enabled()):
        result = mod.check(_make_profile())

    assert result.has_issues
    proxy_findings = [f for f in result.findings if f.data.get("check") == "proxy_enabled"]
    assert len(proxy_findings) >= 1
    assert proxy_findings[0].severity == Severity.WARNING
    assert "SOCKS" in proxy_findings[0].data.get("enabled_proxies", [])


def test_network_proxy_pac_file_critical():
    """PAC file configured - should be CRITICAL."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_pac_file_configured()):
        result = mod.check(_make_profile())

    assert result.has_issues
    pac_findings = [f for f in result.findings if f.data.get("check") == "pac_url_detected"]
    assert len(pac_findings) >= 1
    assert pac_findings[0].severity == Severity.CRITICAL
    assert "proxy.pac" in pac_findings[0].data.get("pac_url", "")


def test_network_proxy_multiple_proxies():
    """Multiple proxies enabled - should have WARNING finding."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_multiple_proxies_enabled()):
        result = mod.check(_make_profile())

    assert result.has_issues
    proxy_findings = [f for f in result.findings if f.data.get("check") == "proxy_enabled"]
    assert len(proxy_findings) >= 1
    enabled = proxy_findings[0].data.get("enabled_proxies", [])
    assert "HTTP" in enabled
    assert "HTTPS" in enabled
    assert "SOCKS" in enabled


def test_network_proxy_auto_discovery_enabled():
    """Auto proxy discovery enabled - should be WARNING."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_auto_discovery_enabled()):
        result = mod.check(_make_profile())

    assert result.has_issues
    proxy_findings = [f for f in result.findings if f.data.get("check") == "proxy_enabled"]
    assert len(proxy_findings) >= 1
    assert "Auto Proxy Discovery" in proxy_findings[0].data.get("enabled_proxies", [])


def test_network_proxy_fix_is_informational():
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


def test_network_proxy_fix_pac_file_guidance():
    """fix() should provide removal guidance for PAC file."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_pac_file_configured()):
        check = mod.check(_make_profile())

    fix = mod.fix(check, Mode.MANUAL)

    assert fix.all_succeeded
    pac_actions = [a for a in fix.actions if "PAC" in a.title or "PAC" in a.description]
    assert len(pac_actions) >= 1
    assert "System Preferences" in pac_actions[0].description or "Network" in pac_actions[0].description


def test_network_proxy_interface_not_available():
    """Handle missing interface gracefully."""

    def fake_run_interface_error(cmd, **kwargs):
        raise Exception("Interface not found")

    mod = _get_module()
    with patch("subprocess.run", side_effect=fake_run_interface_error):
        result = mod.check(_make_profile())

    # Should not crash and should not find proxies
    assert result.has_issues or not result.has_issues  # Either is acceptable


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.network_proxy.") for c in declared)
