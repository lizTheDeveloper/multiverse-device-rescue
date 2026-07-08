import sys
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


def _make_profile():
    return SystemProfile(
        platform=Platform.DARWIN,
        os_name="macOS",
        os_version="14.0",
        architecture="arm64",
        cpu_model="Apple M2",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "dns_over_https_check")


def test_dns_over_https_check_discovered():
    """Test that module is discovered correctly."""
    mod = _get_module()
    assert mod.name == "dns_over_https_check"
    assert mod.category == "network"
    assert Platform.DARWIN in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_dns_over_https_check_cloudflare_dns():
    """Test detection of Cloudflare encrypted DNS."""
    mod = _get_module()

    def mock_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        if "scutil" in cmd_str and "--dns" in cmd_str:
            result.stdout = (
                "DNS configuration:\n"
                "resolver #1\n"
                "  nameserver[0]: 1.1.1.1\n"
                "  nameserver[1]: 1.0.0.1\n"
            )
        elif "profiles" in cmd_str:
            result.stdout = ""
            result.returncode = 1
        elif "ps" in cmd_str:
            result.stdout = "root 1234 ps aux\n"
        else:
            result.stdout = ""
        return result

    with patch("subprocess.run", side_effect=mock_run):
        result = mod.check(_make_profile())

    assert result.has_issues
    # Should have DNS configuration and encrypted provider info
    assert any(f.data.get("check") == "dns_configuration" for f in result.findings)
    assert any(f.data.get("check") == "encrypted_dns_provider" for f in result.findings)

    # Should NOT have unencrypted DNS warning
    assert not any(f.data.get("check") == "unencrypted_dns" for f in result.findings)


def test_dns_over_https_check_google_dns():
    """Test detection of Google encrypted DNS."""
    mod = _get_module()

    def mock_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        if "scutil" in cmd_str and "--dns" in cmd_str:
            result.stdout = (
                "DNS configuration:\n"
                "resolver #1\n"
                "  nameserver[0]: 8.8.8.8\n"
                "  nameserver[1]: 8.8.4.4\n"
            )
        elif "profiles" in cmd_str:
            result.returncode = 1
        elif "ps" in cmd_str:
            result.stdout = "root 1234 ps aux\n"
        else:
            result.stdout = ""
        return result

    with patch("subprocess.run", side_effect=mock_run):
        result = mod.check(_make_profile())

    assert result.has_issues
    assert any(f.data.get("check") == "dns_configuration" for f in result.findings)
    config = next(f for f in result.findings if f.data.get("check") == "dns_configuration")
    assert config.data.get("is_encrypted") is True
    assert config.data.get("provider") == "Google"


def test_dns_over_https_check_isp_dns_unencrypted():
    """Test detection of ISP DNS (unencrypted)."""
    mod = _get_module()

    def mock_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        if "scutil" in cmd_str and "--dns" in cmd_str:
            result.stdout = (
                "DNS configuration:\n"
                "resolver #1\n"
                "  nameserver[0]: 192.168.1.1\n"
                "  nameserver[1]: 10.0.0.1\n"
            )
        elif "profiles" in cmd_str:
            result.returncode = 1
        elif "ps" in cmd_str:
            result.stdout = "root 1234 ps aux\n"
        else:
            result.stdout = ""
        return result

    with patch("subprocess.run", side_effect=mock_run):
        result = mod.check(_make_profile())

    assert result.has_issues
    # Should warn about unencrypted DNS
    assert any(f.data.get("check") == "unencrypted_dns" for f in result.findings)
    warning = next(f for f in result.findings if f.data.get("check") == "unencrypted_dns")
    assert warning.severity == Severity.WARNING


def test_dns_over_https_check_no_encryption_no_profile():
    """Test when no encryption is configured."""
    mod = _get_module()

    def mock_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        if "scutil" in cmd_str and "--dns" in cmd_str:
            result.stdout = (
                "DNS configuration:\n"
                "resolver #1\n"
                "  nameserver[0]: 8.8.8.0\n"  # Unknown provider
            )
        elif "profiles" in cmd_str:
            result.returncode = 1  # No profiles
        elif "ps" in cmd_str:
            result.stdout = "root 1234 ps aux\nuser 5678 some other process\n"
        else:
            result.stdout = ""
        return result

    with patch("subprocess.run", side_effect=mock_run):
        result = mod.check(_make_profile())

    assert result.has_issues
    # Should warn about no encryption configured
    assert any(f.data.get("check") == "no_encryption_configured" for f in result.findings)


def test_dns_over_https_check_with_encrypted_profile():
    """Test when encrypted DNS profile is installed."""
    mod = _get_module()

    def mock_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        if "scutil" in cmd_str and "--dns" in cmd_str:
            result.stdout = (
                "DNS configuration:\n"
                "resolver #1\n"
                "  nameserver[0]: 1.1.1.1\n"
            )
        elif "profiles" in cmd_str:
            result.stdout = (
                "Configuration profiles:\n"
                "    Cloudflare DoH (com.cloudflare.dns)\n"
                "        DNSSettings enabled\n"
            )
        elif "ps" in cmd_str:
            result.stdout = "root 1234 ps aux\n"
        else:
            result.stdout = ""
        return result

    with patch("subprocess.run", side_effect=mock_run):
        result = mod.check(_make_profile())

    assert result.has_issues
    # Should have profile info
    assert any(f.data.get("check") == "encrypted_dns_profile" for f in result.findings)


def test_dns_over_https_check_with_local_resolver():
    """Test detection of local DNS resolver."""
    mod = _get_module()

    def mock_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        if "scutil" in cmd_str and "--dns" in cmd_str:
            result.stdout = (
                "DNS configuration:\n"
                "resolver #1\n"
                "  nameserver[0]: 127.0.0.1\n"
            )
        elif "profiles" in cmd_str:
            result.returncode = 1
        elif "ps" in cmd_str:
            result.stdout = (
                "root 1234 /usr/local/bin/dnscrypt-proxy -config /etc/dnscrypt-proxy.conf\n"
            )
        else:
            result.stdout = ""
        return result

    with patch("subprocess.run", side_effect=mock_run):
        result = mod.check(_make_profile())

    assert result.has_issues
    # Should detect local resolver
    assert any(f.data.get("check") == "local_dns_resolver" for f in result.findings)


def test_dns_over_https_check_quad9_dns():
    """Test detection of Quad9 encrypted DNS."""
    mod = _get_module()

    def mock_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        if "scutil" in cmd_str and "--dns" in cmd_str:
            result.stdout = (
                "DNS configuration:\n"
                "resolver #1\n"
                "  nameserver[0]: 9.9.9.9\n"
                "  nameserver[1]: 149.112.112.112\n"
            )
        elif "profiles" in cmd_str:
            result.returncode = 1
        elif "ps" in cmd_str:
            result.stdout = "root 1234 ps aux\n"
        else:
            result.stdout = ""
        return result

    with patch("subprocess.run", side_effect=mock_run):
        result = mod.check(_make_profile())

    assert result.has_issues
    config = next(f for f in result.findings if f.data.get("check") == "dns_configuration")
    assert config.data.get("is_encrypted") is True


def test_dns_over_https_check_subprocess_error():
    """Test graceful handling of subprocess errors."""
    mod = _get_module()

    def error_run(cmd, **kwargs):
        raise OSError("Command failed")

    with patch("subprocess.run", side_effect=error_run):
        result = mod.check(_make_profile())

    # Should complete without crashing
    assert isinstance(result.findings, list)


def test_dns_over_https_check_fix_unencrypted():
    """Test fix recommendations for unencrypted DNS."""
    mod = _get_module()

    def mock_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        if "scutil" in cmd_str and "--dns" in cmd_str:
            result.stdout = (
                "DNS configuration:\n"
                "resolver #1\n"
                "  nameserver[0]: 192.168.1.1\n"
            )
        elif "profiles" in cmd_str:
            result.returncode = 1
        elif "ps" in cmd_str:
            result.stdout = "root 1234 ps aux\n"
        else:
            result.stdout = ""
        return result

    with patch("subprocess.run", side_effect=mock_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    assert len(fix.actions) > 0
    # Should have action for unencrypted DNS
    unencrypted_actions = [a for a in fix.actions if "unencrypted" in a.title.lower() or "encrypt" in a.title.lower()]
    assert len(unencrypted_actions) > 0


def test_dns_over_https_check_fix_no_encryption():
    """Test fix recommendations for no encryption configuration."""
    mod = _get_module()

    def mock_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        if "scutil" in cmd_str and "--dns" in cmd_str:
            result.stdout = (
                "DNS configuration:\n"
                "resolver #1\n"
                "  nameserver[0]: 8.8.8.0\n"
            )
        elif "profiles" in cmd_str:
            result.returncode = 1
        elif "ps" in cmd_str:
            result.stdout = "root 1234 ps aux\n"
        else:
            result.stdout = ""
        return result

    with patch("subprocess.run", side_effect=mock_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    assert len(fix.actions) > 0


def test_dns_over_https_check_multiple_servers():
    """Test DNS configuration with multiple servers."""
    mod = _get_module()

    def mock_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        if "scutil" in cmd_str and "--dns" in cmd_str:
            result.stdout = (
                "DNS configuration:\n"
                "resolver #1\n"
                "  nameserver[0]: 1.1.1.1\n"
                "  nameserver[1]: 1.0.0.1\n"
                "  nameserver[2]: 8.8.8.8\n"
            )
        elif "profiles" in cmd_str:
            result.returncode = 1
        elif "ps" in cmd_str:
            result.stdout = "root 1234 ps aux\n"
        else:
            result.stdout = ""
        return result

    with patch("subprocess.run", side_effect=mock_run):
        result = mod.check(_make_profile())

    assert result.has_issues
    config = next(f for f in result.findings if f.data.get("check") == "dns_configuration")
    assert len(config.data.get("servers", [])) == 3


def test_dns_over_https_check_timeout():
    """Test graceful handling of timeout."""
    mod = _get_module()

    def timeout_run(cmd, **kwargs):
        raise Exception("Timeout")

    with patch("subprocess.run", side_effect=timeout_run):
        result = mod.check(_make_profile())

    # Should complete without crashing
    assert isinstance(result.findings, list)


def test_dns_over_https_check_no_dns_found():
    """Test when no DNS servers are found."""
    mod = _get_module()

    def mock_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 1  # Failed to get DNS
        result.stdout = ""
        return result

    with patch("subprocess.run", side_effect=mock_run):
        result = mod.check(_make_profile())

    assert result.has_issues
    assert any(f.data.get("check") == "no_dns_found" for f in result.findings)


def test_dns_over_https_check_all_findings():
    """Test with all detection mechanisms active."""
    mod = _get_module()

    def mock_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        if "scutil" in cmd_str and "--dns" in cmd_str:
            result.stdout = (
                "DNS configuration:\n"
                "resolver #1\n"
                "  nameserver[0]: 1.1.1.1\n"
            )
        elif "profiles" in cmd_str:
            result.stdout = "DNS Profile installed"
        elif "ps" in cmd_str:
            result.stdout = (
                "/usr/local/bin/stubby -g\n"
            )
        else:
            result.stdout = ""
        return result

    with patch("subprocess.run", side_effect=mock_run):
        result = mod.check(_make_profile())

    assert result.has_issues
    # Should have multiple positive findings
    check_types = {f.data.get("check") for f in result.findings}
    assert "dns_configuration" in check_types
    assert "encrypted_dns_profile" in check_types
    assert "local_dns_resolver" in check_types
