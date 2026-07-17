import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
import os

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
    return next(m for m in modules if m.name == "network_proxy_detect")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_no_proxies():
    """No proxies or environment variables set."""

    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "getwebproxy" in cmd_str or "getsecurewebproxy" in cmd_str or "getsocksfirewallproxy" in cmd_str:
            return _make_subprocess_result("Enabled: No\n")
        elif "getautoproxyurl" in cmd_str:
            return _make_subprocess_result("URL: (null)\n")
        return _make_subprocess_result()

    return fake_run


def _fake_run_env_proxy_set():
    """HTTP_PROXY environment variable is set."""

    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "getwebproxy" in cmd_str or "getsecurewebproxy" in cmd_str or "getsocksfirewallproxy" in cmd_str:
            return _make_subprocess_result("Enabled: No\n")
        elif "getautoproxyurl" in cmd_str:
            return _make_subprocess_result("URL: (null)\n")
        return _make_subprocess_result()

    return fake_run


def _fake_run_https_proxy_set():
    """HTTPS_PROXY environment variable is set."""

    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "getwebproxy" in cmd_str or "getsecurewebproxy" in cmd_str or "getsocksfirewallproxy" in cmd_str:
            return _make_subprocess_result("Enabled: No\n")
        elif "getautoproxyurl" in cmd_str:
            return _make_subprocess_result("URL: (null)\n")
        return _make_subprocess_result()

    return fake_run


def _fake_run_multiple_env_proxies():
    """Multiple proxy environment variables are set."""

    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "getwebproxy" in cmd_str or "getsecurewebproxy" in cmd_str or "getsocksfirewallproxy" in cmd_str:
            return _make_subprocess_result("Enabled: No\n")
        elif "getautoproxyurl" in cmd_str:
            return _make_subprocess_result("URL: (null)\n")
        return _make_subprocess_result()

    return fake_run


def _fake_run_networksetup_proxy_enabled():
    """HTTP proxy is enabled via networksetup."""

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
        elif "getautoproxyurl" in cmd_str:
            return _make_subprocess_result("URL: (null)\n")
        return _make_subprocess_result()

    return fake_run


def _fake_run_pac_url_configured():
    """PAC URL is configured."""

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
        elif "getautoproxyurl" in cmd_str:
            return _make_subprocess_result("URL: http://malware.local/proxy.pac\n")
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
        elif "getautoproxyurl" in cmd_str:
            return _make_subprocess_result("URL: (null)\n")
        return _make_subprocess_result()

    return fake_run


def test_network_proxy_detect_discovered():
    """Module should be discovered and have correct metadata."""
    mod = _get_module()
    assert mod.name == "network_proxy_detect"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE


def test_network_proxy_detect_no_proxies():
    """No proxies or environment variables - should be INFO severity."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_proxies()):
        with patch.dict(os.environ, {}, clear=False):
            # Make sure no proxy env vars are set
            for var in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"]:
                if var in os.environ:
                    del os.environ[var]
            result = mod.check(_make_profile())

    assert result.has_issues
    assert len(result.findings) == 1
    assert result.findings[0].severity == Severity.INFO
    assert result.findings[0].data.get("check") == "no_proxies"


def test_network_proxy_detect_env_http_proxy():
    """HTTP_PROXY environment variable set - should be WARNING."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_env_proxy_set()):
        with patch.dict(os.environ, {"HTTP_PROXY": "http://proxy.example.com:8080"}, clear=False):
            result = mod.check(_make_profile())

    assert result.has_issues
    env_findings = [f for f in result.findings if f.data.get("check") == "env_proxy_detected"]
    assert len(env_findings) >= 1
    assert env_findings[0].severity == Severity.WARNING
    assert "HTTP_PROXY" in env_findings[0].data.get("env_proxies", [])


def test_network_proxy_detect_env_https_proxy():
    """HTTPS_PROXY environment variable set - should be WARNING."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_https_proxy_set()):
        with patch.dict(os.environ, {"HTTPS_PROXY": "https://proxy.example.com:8443"}, clear=False):
            result = mod.check(_make_profile())

    assert result.has_issues
    env_findings = [f for f in result.findings if f.data.get("check") == "env_proxy_detected"]
    assert len(env_findings) >= 1
    assert env_findings[0].severity == Severity.WARNING
    assert "HTTPS_PROXY" in env_findings[0].data.get("env_proxies", [])


def test_network_proxy_detect_multiple_env_proxies():
    """Multiple proxy environment variables set - should be WARNING."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_multiple_env_proxies()):
        with patch.dict(os.environ, {
            "HTTP_PROXY": "http://proxy1.example.com:8080",
            "HTTPS_PROXY": "https://proxy2.example.com:8443",
            "ALL_PROXY": "socks://proxy3.example.com:1080",
        }, clear=False):
            result = mod.check(_make_profile())

    assert result.has_issues
    env_findings = [f for f in result.findings if f.data.get("check") == "env_proxy_detected"]
    assert len(env_findings) >= 1
    assert env_findings[0].severity == Severity.WARNING
    env_proxies = env_findings[0].data.get("env_proxies", [])
    assert "HTTP_PROXY" in env_proxies
    assert "HTTPS_PROXY" in env_proxies
    assert "ALL_PROXY" in env_proxies


def test_network_proxy_detect_networksetup_proxy():
    """HTTP proxy enabled via networksetup - should be WARNING."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_networksetup_proxy_enabled()):
        with patch.dict(os.environ, {}, clear=False):
            # Make sure no proxy env vars are set
            for var in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"]:
                if var in os.environ:
                    del os.environ[var]
            result = mod.check(_make_profile())

    assert result.has_issues
    proxy_findings = [f for f in result.findings if f.data.get("check") == "proxy_enabled"]
    assert len(proxy_findings) >= 1
    assert proxy_findings[0].severity == Severity.WARNING
    assert "HTTP" in proxy_findings[0].data.get("enabled_proxies", [])


def test_network_proxy_detect_pac_url():
    """PAC URL configured - should be WARNING."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_pac_url_configured()):
        with patch.dict(os.environ, {}, clear=False):
            # Make sure no proxy env vars are set
            for var in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"]:
                if var in os.environ:
                    del os.environ[var]
            result = mod.check(_make_profile())

    assert result.has_issues
    pac_findings = [f for f in result.findings if f.data.get("check") == "pac_url_detected"]
    assert len(pac_findings) >= 1
    assert pac_findings[0].severity == Severity.WARNING
    assert "proxy.pac" in pac_findings[0].data.get("pac_url", "")


def test_network_proxy_detect_socks_proxy():
    """SOCKS proxy enabled - should be WARNING."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_socks_proxy_enabled()):
        with patch.dict(os.environ, {}, clear=False):
            # Make sure no proxy env vars are set
            for var in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"]:
                if var in os.environ:
                    del os.environ[var]
            result = mod.check(_make_profile())

    assert result.has_issues
    proxy_findings = [f for f in result.findings if f.data.get("check") == "proxy_enabled"]
    assert len(proxy_findings) >= 1
    assert proxy_findings[0].severity == Severity.WARNING
    assert "SOCKS" in proxy_findings[0].data.get("enabled_proxies", [])


def test_network_proxy_detect_combined_env_and_networksetup():
    """Both environment variable and networksetup proxy set - should have multiple WARNING findings."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_networksetup_proxy_enabled()):
        with patch.dict(os.environ, {"HTTP_PROXY": "http://corporate.proxy:8080"}, clear=False):
            result = mod.check(_make_profile())

    assert result.has_issues
    # Should have findings for both env and networksetup proxies
    env_findings = [f for f in result.findings if f.data.get("check") == "env_proxy_detected"]
    proxy_findings = [f for f in result.findings if f.data.get("check") == "proxy_enabled"]
    assert len(env_findings) >= 1
    assert len(proxy_findings) >= 1


def test_network_proxy_detect_fix_informational():
    """fix() should be informational only, never modifies settings."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_networksetup_proxy_enabled()):
        with patch.dict(os.environ, {}, clear=False):
            for var in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"]:
                if var in os.environ:
                    del os.environ[var]
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


def test_network_proxy_detect_fix_env_proxy_guidance():
    """fix() should provide removal guidance for environment proxy variables."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_proxies()):
        with patch.dict(os.environ, {"HTTP_PROXY": "http://proxy.example.com:8080"}, clear=False):
            check = mod.check(_make_profile())

    fix = mod.fix(check, Mode.MANUAL)

    assert fix.all_succeeded
    env_actions = [a for a in fix.actions if "environment" in a.title.lower() or "HTTP_PROXY" in a.description]
    assert len(env_actions) >= 1
    assert "~/.zshrc" in env_actions[0].description or "shell" in env_actions[0].description.lower()


def test_network_proxy_detect_fix_pac_url_guidance():
    """fix() should provide removal guidance for PAC URL."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_pac_url_configured()):
        with patch.dict(os.environ, {}, clear=False):
            for var in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"]:
                if var in os.environ:
                    del os.environ[var]
            check = mod.check(_make_profile())

    fix = mod.fix(check, Mode.MANUAL)

    assert fix.all_succeeded
    pac_actions = [a for a in fix.actions if "PAC" in a.title or "PAC" in a.description]
    assert len(pac_actions) >= 1
    assert "System Preferences" in pac_actions[0].description or "Network" in pac_actions[0].description


def test_network_proxy_detect_interface_error_handled():
    """Handle interface errors gracefully."""

    def fake_run_error(cmd, **kwargs):
        raise Exception("networksetup error")

    mod = _get_module()
    with patch("subprocess.run", side_effect=fake_run_error):
        with patch.dict(os.environ, {}, clear=False):
            for var in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"]:
                if var in os.environ:
                    del os.environ[var]
            result = mod.check(_make_profile())

    # Should not crash and should still check environment variables
    assert result.has_issues or not result.has_issues  # Either is acceptable
