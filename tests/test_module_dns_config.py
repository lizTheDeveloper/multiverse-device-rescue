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
    return next(m for m in modules if m.name == "dns_config")


def _fake_run_healthy_dns():
    """Mock subprocess for healthy DNS (Google DNS)."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        if "scutil" in cmd or (isinstance(cmd, list) and "scutil" in cmd[0]):
            result.stdout = """
DNS configuration:

resolver #0
  search domain[0] : local
  nameserver[0] : 8.8.8.8
  nameserver[1] : 8.8.4.4
"""
        elif "networksetup" in cmd or (isinstance(cmd, list) and "networksetup" in cmd[0]):
            if "Wi-Fi" in cmd or (isinstance(cmd, list) and "Wi-Fi" in str(cmd)):
                result.stdout = "8.8.8.8\n8.8.4.4\n"
            else:
                result.stdout = ""
        return result
    return fake_run


def _fake_run_cloudflare_dns():
    """Mock subprocess for Cloudflare DNS."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        if "scutil" in cmd or (isinstance(cmd, list) and "scutil" in cmd[0]):
            result.stdout = """
DNS configuration:

resolver #0
  search domain[0] : local
  nameserver[0] : 1.1.1.1
  nameserver[1] : 1.0.0.1
"""
        elif "networksetup" in cmd or (isinstance(cmd, list) and "networksetup" in cmd[0]):
            if "Wi-Fi" in cmd or (isinstance(cmd, list) and "Wi-Fi" in str(cmd)):
                result.stdout = "1.1.1.1\n1.0.0.1\n"
            else:
                result.stdout = ""
        return result
    return fake_run


def _fake_run_suspicious_dns():
    """Mock subprocess for suspicious/unknown DNS."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        if "scutil" in cmd or (isinstance(cmd, list) and "scutil" in cmd[0]):
            result.stdout = """
DNS configuration:

resolver #0
  search domain[0] : local
  nameserver[0] : 192.168.1.100
  nameserver[1] : 10.0.0.1
"""
        elif "networksetup" in cmd or (isinstance(cmd, list) and "networksetup" in cmd[0]):
            if "Wi-Fi" in cmd or (isinstance(cmd, list) and "Wi-Fi" in str(cmd)):
                result.stdout = "192.168.1.100\n10.0.0.1\n"
            else:
                result.stdout = ""
        return result
    return fake_run


def _fake_run_no_dns():
    """Mock subprocess for no DNS configuration."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        if "scutil" in cmd or (isinstance(cmd, list) and "scutil" in cmd[0]):
            result.stdout = """
DNS configuration:
"""
        elif "networksetup" in cmd or (isinstance(cmd, list) and "networksetup" in cmd[0]):
            result.stdout = ""
        return result
    return fake_run


def _fake_run_opendns():
    """Mock subprocess for OpenDNS."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        if "scutil" in cmd or (isinstance(cmd, list) and "scutil" in cmd[0]):
            result.stdout = """
DNS configuration:

resolver #0
  search domain[0] : local
  nameserver[0] : 208.67.222.222
  nameserver[1] : 208.67.220.220
"""
        elif "networksetup" in cmd or (isinstance(cmd, list) and "networksetup" in cmd[0]):
            if "Wi-Fi" in cmd or (isinstance(cmd, list) and "Wi-Fi" in str(cmd)):
                result.stdout = "208.67.222.222\n208.67.220.220\n"
            else:
                result.stdout = ""
        return result
    return fake_run


def test_dns_config_discovered():
    mod = _get_module()
    assert mod.name == "dns_config"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE


def test_dns_config_healthy_google():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy_dns()):
        with patch("socket.getaddrinfo"):
            result = mod.check(_make_profile())
    # Should have info finding about DNS, no warnings
    assert result.has_issues
    assert any(f.data.get("check_type") == "dns_info" for f in result.findings)
    assert not any(f.severity == Severity.CRITICAL for f in result.findings)


def test_dns_config_cloudflare():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_cloudflare_dns()):
        with patch("socket.getaddrinfo"):
            result = mod.check(_make_profile())
    # Should have info finding about DNS
    assert result.has_issues
    assert any(f.data.get("check_type") == "dns_info" for f in result.findings)
    assert not any(f.severity == Severity.WARNING for f in result.findings)


def test_dns_config_suspicious():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_suspicious_dns()):
        with patch("socket.getaddrinfo"):
            result = mod.check(_make_profile())
    # Should have warning about suspicious DNS
    assert result.has_issues
    assert any(f.data.get("check_type") == "suspicious_dns" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_dns_config_opendns():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_opendns()):
        with patch("socket.getaddrinfo"):
            result = mod.check(_make_profile())
    # Should have info finding, no warnings (OpenDNS is well-known)
    assert result.has_issues
    assert any(f.data.get("check_type") == "dns_info" for f in result.findings)
    assert not any(f.severity == Severity.WARNING for f in result.findings)


def test_dns_config_no_dns():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_dns()):
        with patch("socket.getaddrinfo"):
            result = mod.check(_make_profile())
    # Should have no findings if no DNS is configured
    assert not result.has_issues


def test_dns_config_unreachable():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy_dns()):
        with patch("socket.getaddrinfo", side_effect=OSError("DNS resolution failed")):
            result = mod.check(_make_profile())
    # Should have warning about unreachable DNS
    assert result.has_issues
    assert any(f.data.get("check_type") == "unreachable_dns" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_dns_config_fix_healthy():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy_dns()):
        with patch("socket.getaddrinfo"):
            check = mod.check(_make_profile())
            fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert len(fix.actions) > 0
    assert all(a.success for a in fix.actions)


def test_dns_config_fix_suspicious():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_suspicious_dns()):
        with patch("socket.getaddrinfo"):
            check = mod.check(_make_profile())
            fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert any("suspicious" in a.title.lower() for a in fix.actions)
    assert all(a.success for a in fix.actions)


def test_dns_config_fix_unreachable():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy_dns()):
        with patch("socket.getaddrinfo", side_effect=OSError("DNS resolution failed")):
            check = mod.check(_make_profile())
            fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert any("unreachable" in a.title.lower() for a in fix.actions)
    assert all(a.success for a in fix.actions)
