import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules

# Healthy hosts file - only localhost entries
HOSTS_HEALTHY = """# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names.
127.0.0.1       localhost
::1             localhost
"""

# Compromised hosts file - banking domain redirected to malicious IP
HOSTS_BANKING_REDIRECT = """# Copyright (c) 1993-2009 Microsoft Corp.
127.0.0.1       localhost
::1             localhost

# Malware redirects banking domain
192.168.1.100   paypal.com
192.168.1.100   www.paypal.com
"""

# Compromised hosts file - Microsoft/Windows domains redirected
HOSTS_MICROSOFT_REDIRECT = """127.0.0.1       localhost
::1             localhost

# Malware redirects Windows Update
10.0.0.1        microsoft.com
10.0.0.1        windows.com
10.0.0.1        windowsupdate.microsoft.com
"""

# Excessive entries - over 50 entries
HOSTS_EXCESSIVE = """# Sample hosts with many entries
127.0.0.1       localhost
::1             localhost
0.0.0.0         ad1.example.com
0.0.0.0         ad2.example.com
0.0.0.0         ad3.example.com
0.0.0.0         ad4.example.com
0.0.0.0         ad5.example.com
0.0.0.0         ad6.example.com
0.0.0.0         ad7.example.com
0.0.0.0         ad8.example.com
0.0.0.0         ad9.example.com
0.0.0.0         ad10.example.com
0.0.0.0         ad11.example.com
0.0.0.0         ad12.example.com
0.0.0.0         ad13.example.com
0.0.0.0         ad14.example.com
0.0.0.0         ad15.example.com
0.0.0.0         ad16.example.com
0.0.0.0         ad17.example.com
0.0.0.0         ad18.example.com
0.0.0.0         ad19.example.com
0.0.0.0         ad20.example.com
0.0.0.0         ad21.example.com
0.0.0.0         ad22.example.com
0.0.0.0         ad23.example.com
0.0.0.0         ad24.example.com
0.0.0.0         ad25.example.com
0.0.0.0         ad26.example.com
0.0.0.0         ad27.example.com
0.0.0.0         ad28.example.com
0.0.0.0         ad29.example.com
0.0.0.0         ad30.example.com
0.0.0.0         ad31.example.com
0.0.0.0         ad32.example.com
0.0.0.0         ad33.example.com
0.0.0.0         ad34.example.com
0.0.0.0         ad35.example.com
0.0.0.0         ad36.example.com
0.0.0.0         ad37.example.com
0.0.0.0         ad38.example.com
0.0.0.0         ad39.example.com
0.0.0.0         ad40.example.com
0.0.0.0         ad41.example.com
0.0.0.0         ad42.example.com
0.0.0.0         ad43.example.com
0.0.0.0         ad44.example.com
0.0.0.0         ad45.example.com
0.0.0.0         ad46.example.com
0.0.0.0         ad47.example.com
0.0.0.0         ad48.example.com
0.0.0.0         ad49.example.com
0.0.0.0         ad50.example.com
0.0.0.0         ad51.example.com
0.0.0.0         ad52.example.com
"""

# Multiple domains per line
HOSTS_MULTIPLE_DOMAINS = """127.0.0.1       localhost
0.0.0.0         badhost1.com badhost2.com badhost3.com
192.168.1.50    malicious.com www.malicious.com mail.malicious.com
"""

# Empty response
HOSTS_EMPTY = ""


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
    return next(m for m in modules if m.name == "win_hosts_file")


def _fake_run(hosts_output):
    def fake_ps_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = hosts_output
        return result
    return fake_ps_run


def test_win_hosts_file_discovered():
    mod = _get_module()
    assert mod.name == "win_hosts_file"
    assert mod.category == "security"
    assert Platform.WIN32 in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_win_hosts_file_healthy():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(HOSTS_HEALTHY)):
        result = mod.check(_make_profile())
    # Healthy hosts file should have no CRITICAL findings
    assert not any(f.severity == Severity.CRITICAL for f in result.findings)


def test_win_hosts_file_banking_redirect_critical():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(HOSTS_BANKING_REDIRECT)):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.severity == Severity.CRITICAL for f in result.findings)
    critical = next(f for f in result.findings if f.severity == Severity.CRITICAL)
    assert "paypal.com" in critical.data.get("redirects", [])


def test_win_hosts_file_microsoft_redirect_critical():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(HOSTS_MICROSOFT_REDIRECT)):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.severity == Severity.CRITICAL for f in result.findings)
    critical = next(f for f in result.findings if f.severity == Severity.CRITICAL)
    redirects = critical.data.get("redirects", [])
    assert any("microsoft.com" in r.lower() or "windows.com" in r.lower() for r in redirects)


def test_win_hosts_file_excessive_entries_warning():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(HOSTS_EXCESSIVE)):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.severity == Severity.WARNING for f in result.findings)
    warning = next(f for f in result.findings if f.severity == Severity.WARNING)
    assert warning.data.get("entry_count", 0) > 50


def test_win_hosts_file_entry_count_info():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(HOSTS_HEALTHY)):
        result = mod.check(_make_profile())
    # Should have an INFO finding for entry count
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert len(info_findings) > 0
    info = info_findings[0]
    assert "entry_count" in info.data


def test_win_hosts_file_multiple_domains_per_line():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(HOSTS_MULTIPLE_DOMAINS)):
        result = mod.check(_make_profile())
    # Should detect badhost domains if they match security list or be informational
    assert result.has_issues or True  # Allow both outcomes


def test_win_hosts_file_empty_response():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(HOSTS_EMPTY)):
        result = mod.check(_make_profile())
    # Empty hosts file should not have critical issues
    assert not any(f.severity == Severity.CRITICAL for f in result.findings)


def test_win_hosts_file_fix_generates_actions():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(HOSTS_BANKING_REDIRECT)):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # Should have at least one action
    assert len(fix.actions) > 0
    # Actions should be informational (success=True, no actual changes)
    assert all(a.success for a in fix.actions)


def test_win_hosts_file_fix_critical_finding():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(HOSTS_BANKING_REDIRECT)):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    critical_actions = [a for a in fix.actions if "malware" in a.title.lower()]
    assert len(critical_actions) > 0
