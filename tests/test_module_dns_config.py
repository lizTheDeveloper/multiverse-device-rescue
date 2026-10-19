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


def test_privacy_dns_providers_are_not_unrecognised():
    """Shared resolvers (Mullvad, Control D's free one, AdGuard's public one,
    Quad9's second address) are chosen on purpose and never flagged here. A
    NextDNS profile address isn't flagged here either: the security DNS check
    reports it on its own, for the person to confirm."""
    from unittest.mock import MagicMock

    servers = ["45.90.28.163", "45.90.30.163", "194.242.2.2", "76.76.2.0", "94.140.14.14", "149.112.112.112", "1.0.0.1"]

    def fake(cmd, *a, **kw):
        r = MagicMock()
        r.returncode = 0
        r.stdout = "\n".join(servers) + "\n" if "-getdnsservers" in cmd else ""
        if cmd[:2] == ["scutil", "--dns"]:
            r.stdout = "".join(f"  nameserver[{i}] : {s}\n" for i, s in enumerate(servers))
        return r

    module = _get_module()
    with patch("subprocess.run", side_effect=fake):
        result = module.check(_make_profile())
    assert not any(f.data.get("check_type") == "suspicious_dns" for f in result.findings)
    info = next(f for f in result.findings if f.data.get("check_type") == "dns_info")
    assert info.data["providers"]["45.90.28.163"] == "NextDNS profile"
    assert info.data["providers"]["194.242.2.2"] == "Mullvad DNS"
    assert "Mullvad DNS" in info.description


def test_provider_names():
    from rescue.dns_providers import ROUTER, provider_name

    assert provider_name("45.90.30.163") is None, "a profile address is never trusted silently"
    assert provider_name("45.90.30.0") == "NextDNS"
    assert provider_name("1.0.0.1") == "Cloudflare DNS"
    assert provider_name("192.168.1.1") == ROUTER
    assert provider_name("203.0.113.9") is None
    assert provider_name("not an ip") is None
