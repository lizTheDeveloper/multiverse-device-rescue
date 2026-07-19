import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules

# Registry query outputs
PROXY_DISABLED = r"""HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings
    ProxyEnable    REG_DWORD    0x0
"""

PROXY_ENABLED_WITH_SERVER = r"""HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings
    ProxyEnable    REG_DWORD    0x1
"""

PROXY_SERVER_VALUE = r"""HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings
    ProxyServer    REG_SZ    proxy.example.com:8080
"""

PROXY_SERVER_LOCALHOST_NORMAL = r"""HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings
    ProxyServer    REG_SZ    127.0.0.1:8080
"""

PROXY_SERVER_LOCALHOST_SUSPICIOUS = r"""HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings
    ProxyServer    REG_SZ    127.0.0.1:12345
"""

PAC_URL_VALUE = r"""HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings
    AutoConfigURL    REG_SZ    http://example.com/proxy.pac
"""

NO_PAC_URL = """Error: The system was unable to find the specified registry key or value."""

NETSH_NO_PROXY = """Current WinHTTP proxy settings:

    Direct access (no proxy server).
"""

NETSH_WITH_PROXY = """Current WinHTTP proxy settings:

    Proxy Server(s) :  proxy.example.com:8080
    Bypass List     :  local
"""


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
    return next(m for m in modules if m.name == "win_proxy_detect")


def _make_fake_run(
    proxy_enable_output=PROXY_DISABLED,
    proxy_server_output=NO_PAC_URL,
    pac_url_output=NO_PAC_URL,
    netsh_output=NETSH_NO_PROXY,
):
    """Create a fake subprocess.run for testing."""

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""

        # reg query HKCU\... /v ProxyEnable
        # cmd = ['reg', 'query', 'path', '/v', 'ProxyEnable']
        if len(cmd) >= 5 and cmd[0] == "reg" and cmd[1] == "query" and cmd[3] == "/v":
            value_name = cmd[4].upper()

            if value_name == "PROXYENABLE":
                result.stdout = proxy_enable_output
                result.returncode = 0 if "REG_DWORD" in proxy_enable_output else 1
            elif value_name == "PROXYSERVER":
                result.stdout = proxy_server_output
                result.returncode = 0 if "REG_SZ" in proxy_server_output else 1
            elif value_name == "AUTOCONFIGURL":
                result.stdout = pac_url_output
                result.returncode = 0 if "REG_SZ" in pac_url_output else 1
        elif len(cmd) >= 4 and cmd[0] == "netsh" and cmd[1] == "winhttp":
            result.stdout = netsh_output
            result.returncode = 0

        return result

    return fake_run


def test_win_proxy_detect_discovered():
    mod = _get_module()
    assert mod.name == "win_proxy_detect"
    assert mod.category == "security"
    assert Platform.WIN32 in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_win_proxy_detect_no_proxies():
    """Test when no proxies are configured (normal state)."""
    mod = _get_module()
    with patch(
        "subprocess.run",
        side_effect=_make_fake_run(
            proxy_enable_output=PROXY_DISABLED,
            proxy_server_output=NO_PAC_URL,
            pac_url_output=NO_PAC_URL,
            netsh_output=NETSH_NO_PROXY,
        ),
    ):
        result = mod.check(_make_profile())

    assert result.has_issues
    # Should have INFO about no proxies configured
    assert any(f.severity == Severity.INFO for f in result.findings)
    assert any("no proxies" in f.title.lower() for f in result.findings)


def test_win_proxy_detect_proxy_enabled_is_warning():
    """Test that enabled proxy without suspicious localhost is WARNING."""
    mod = _get_module()
    with patch(
        "subprocess.run",
        side_effect=_make_fake_run(
            proxy_enable_output=PROXY_ENABLED_WITH_SERVER,
            proxy_server_output=PROXY_SERVER_VALUE,
            pac_url_output=NO_PAC_URL,
            netsh_output=NETSH_NO_PROXY,
        ),
    ):
        result = mod.check(_make_profile())

    assert result.has_issues
    assert any(f.severity == Severity.WARNING for f in result.findings)
    assert any("proxy" in f.title.lower() for f in result.findings)


def test_win_proxy_detect_pac_url_is_warning():
    """Test that PAC URL configuration is WARNING."""
    mod = _get_module()
    with patch(
        "subprocess.run",
        side_effect=_make_fake_run(
            proxy_enable_output=PROXY_DISABLED,
            proxy_server_output=NO_PAC_URL,
            pac_url_output=PAC_URL_VALUE,
            netsh_output=NETSH_NO_PROXY,
        ),
    ):
        result = mod.check(_make_profile())

    assert result.has_issues
    assert any(f.severity == Severity.WARNING for f in result.findings)
    assert any("pac" in f.title.lower() or "auto-config" in f.title.lower() for f in result.findings)


def test_win_proxy_detect_localhost_normal_is_warning():
    """Test that normal localhost proxy on standard port is WARNING."""
    mod = _get_module()
    with patch(
        "subprocess.run",
        side_effect=_make_fake_run(
            proxy_enable_output=PROXY_ENABLED_WITH_SERVER,
            proxy_server_output=PROXY_SERVER_LOCALHOST_NORMAL,
            pac_url_output=NO_PAC_URL,
            netsh_output=NETSH_NO_PROXY,
        ),
    ):
        result = mod.check(_make_profile())

    assert result.has_issues
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warnings) > 0
    # Should NOT have CRITICAL (port 8080 is standard)
    assert not any(f.severity == Severity.CRITICAL for f in result.findings)


def test_win_proxy_detect_localhost_suspicious_is_critical():
    """Test that localhost proxy on suspicious port is CRITICAL."""
    mod = _get_module()
    with patch(
        "subprocess.run",
        side_effect=_make_fake_run(
            proxy_enable_output=PROXY_ENABLED_WITH_SERVER,
            proxy_server_output=PROXY_SERVER_LOCALHOST_SUSPICIOUS,
            pac_url_output=NO_PAC_URL,
            netsh_output=NETSH_NO_PROXY,
        ),
    ):
        result = mod.check(_make_profile())

    assert result.has_issues
    assert any(f.severity == Severity.CRITICAL for f in result.findings)
    critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert any("localhost" in f.title.lower() or "malware" in f.description.lower() for f in critical)


def test_win_proxy_detect_fix_localhost_suspicious():
    """Test fix action for suspicious localhost proxy."""
    mod = _get_module()
    with patch(
        "subprocess.run",
        side_effect=_make_fake_run(
            proxy_enable_output=PROXY_ENABLED_WITH_SERVER,
            proxy_server_output=PROXY_SERVER_LOCALHOST_SUSPICIOUS,
            pac_url_output=NO_PAC_URL,
            netsh_output=NETSH_NO_PROXY,
        ),
    ):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    assert len(fix.actions) > 0
    assert any("suspicious" in a.title.lower() or "malware" in a.description.lower() for a in fix.actions)


def test_win_proxy_detect_fix_pac_url():
    """Test fix action for PAC URL."""
    mod = _get_module()
    with patch(
        "subprocess.run",
        side_effect=_make_fake_run(
            proxy_enable_output=PROXY_DISABLED,
            proxy_server_output=NO_PAC_URL,
            pac_url_output=PAC_URL_VALUE,
            netsh_output=NETSH_NO_PROXY,
        ),
    ):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    assert len(fix.actions) > 0
    assert any("pac" in a.title.lower() or "auto-config" in a.description.lower() for a in fix.actions)


def test_win_proxy_detect_fix_all_succeed():
    """Test that all fix actions are marked as successful."""
    mod = _get_module()
    with patch(
        "subprocess.run",
        side_effect=_make_fake_run(
            proxy_enable_output=PROXY_ENABLED_WITH_SERVER,
            proxy_server_output=PROXY_SERVER_VALUE,
            pac_url_output=PAC_URL_VALUE,
            netsh_output=NETSH_WITH_PROXY,
        ),
    ):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    # All actions should succeed (they're informational, not actual changes)
    assert all(a.success for a in fix.actions)


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.win_proxy_detect.") for c in declared)
