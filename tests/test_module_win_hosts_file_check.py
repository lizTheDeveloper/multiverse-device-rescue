import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


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
    return next(m for m in modules if m.name == "win_hosts_file_check")


def _make_run_result(
    hosts_content=None,
    file_size=None,
    permissions_output=None,
    expect_clean=False,
):
    """Create a fake subprocess.run that returns appropriate results.

    Args:
        hosts_content: Content of hosts file to return
        file_size: File size to return (in bytes)
        permissions_output: PowerShell permission check output
        expect_clean: If True, return clean results by default
    """

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        # PowerShell Get-Content for hosts file
        if "Get-Content" in cmd_str:
            if hosts_content is not None:
                result.stdout = hosts_content
            elif expect_clean:
                result.stdout = "# Loopback addresses\n127.0.0.1 localhost\n::1 localhost\n"
            else:
                result.stdout = ""

        # PowerShell file size check
        elif ".Length" in cmd_str:
            if file_size is not None:
                result.stdout = str(file_size)
            elif expect_clean:
                result.stdout = "1000"
            else:
                result.stdout = "0"

        # PowerShell permission check
        elif "GetAccessControl" in cmd_str:
            if permissions_output is not None:
                result.stdout = permissions_output
            elif expect_clean:
                result.stdout = "SYSTEM Administrators FullControl\n"
            else:
                result.stdout = ""

        return result

    return fake_run


def test_win_hosts_file_check_discovered():
    """Test that module is discovered correctly."""
    mod = _get_module()
    assert mod.name == "win_hosts_file_check"
    assert mod.category == "security"
    assert Platform.WIN32 in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_win_hosts_file_check_clean():
    """Test clean hosts file (no issues)."""
    mod = _get_module()
    hosts_content = "# Loopback addresses\n127.0.0.1 localhost\n::1 localhost\n"
    fake_run = _make_run_result(
        hosts_content=hosts_content,
        file_size=100,
        expect_clean=True,
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    # Should only have INFO about entry count
    assert result.has_issues
    assert any(f.data.get("check") == "entry_count_summary" for f in result.findings)
    assert all(f.severity == Severity.INFO for f in result.findings)


def test_win_hosts_file_check_blocked_security_domains():
    """Test detection of blocked antivirus update domains (CRITICAL)."""
    mod = _get_module()
    hosts_content = (
        "# Blocked by malware\n"
        "192.168.1.1 windowsupdate.com\n"
        "10.0.0.1 malwarebytes.com\n"
        "127.0.0.1 localhost\n"
    )
    fake_run = _make_run_result(
        hosts_content=hosts_content,
        file_size=200,
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    critical_findings = [
        f for f in result.findings
        if f.data.get("check") == "blocked_security_domains"
    ]
    assert len(critical_findings) > 0
    assert critical_findings[0].severity == Severity.CRITICAL
    assert "windowsupdate.com" in critical_findings[0].data.get("blocked_domains", [])
    assert "malwarebytes.com" in critical_findings[0].data.get("blocked_domains", [])


def test_win_hosts_file_check_blocked_subdomains():
    """Test detection of blocked antivirus subdomains (CRITICAL)."""
    mod = _get_module()
    hosts_content = (
        "192.168.1.1 update.microsoft.com\n"
        "10.0.0.1 av.kaspersky.com\n"
    )
    fake_run = _make_run_result(hosts_content=hosts_content, file_size=150)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert len(critical) > 0
    blocked = critical[0].data.get("blocked_domains", [])
    assert any("microsoft" in d.lower() for d in blocked)
    assert any("kaspersky" in d.lower() for d in blocked)


def test_win_hosts_file_check_redirected_legitimate_domains():
    """Test detection of legitimate domains redirected to suspicious IPs (WARNING)."""
    mod = _get_module()
    hosts_content = (
        "192.168.1.1 google.com\n"
        "10.0.0.1 facebook.com\n"
        "127.0.0.1 localhost\n"
    )
    fake_run = _make_run_result(hosts_content=hosts_content, file_size=150)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    redirected_findings = [
        f for f in result.findings
        if f.data.get("check") == "redirected_legitimate"
    ]
    assert len(redirected_findings) > 0
    assert redirected_findings[0].severity == Severity.WARNING


def test_win_hosts_file_check_large_file_size():
    """Test detection of unusually large hosts file (WARNING)."""
    mod = _get_module()
    hosts_content = "127.0.0.1 localhost\n"
    large_file_size = 2 * 1024 * 1024  # 2MB, exceeds 1MB threshold
    fake_run = _make_run_result(
        hosts_content=hosts_content,
        file_size=large_file_size,
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    size_findings = [
        f for f in result.findings if f.data.get("check") == "large_file_size"
    ]
    assert len(size_findings) > 0
    assert size_findings[0].severity == Severity.WARNING
    assert size_findings[0].data.get("file_size") == large_file_size


def test_win_hosts_file_check_file_permissions_issue():
    """Test detection of incorrect file permissions (WARNING)."""
    mod = _get_module()
    hosts_content = "127.0.0.1 localhost\n"
    # Simulating output showing Everyone has write access
    perms_output = "Everyone Modify, Write\n"
    fake_run = _make_run_result(
        hosts_content=hosts_content,
        file_size=500,
        permissions_output=perms_output,
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    perm_findings = [
        f for f in result.findings if f.data.get("check") == "file_permissions"
    ]
    assert len(perm_findings) > 0
    assert perm_findings[0].severity == Severity.WARNING


def test_win_hosts_file_check_multiple_issues():
    """Test detection of multiple issues simultaneously."""
    mod = _get_module()
    hosts_content = (
        "192.168.1.1 windowsupdate.com\n"
        "10.0.0.1 google.com\n"
    )
    fake_run = _make_run_result(
        hosts_content=hosts_content,
        file_size=2 * 1024 * 1024,  # 2MB
        permissions_output="Everyone Write\n",
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    checks = [f.data.get("check") for f in result.findings]
    assert "blocked_security_domains" in checks
    assert "redirected_legitimate" in checks
    assert "large_file_size" in checks
    assert "file_permissions" in checks


def test_win_hosts_file_check_entry_count_summary():
    """Test INFO finding with entry count summary."""
    mod = _get_module()
    hosts_content = (
        "127.0.0.1 localhost\n"
        "127.0.0.1 host1.local\n"
        "127.0.0.1 host2.local\n"
    )
    fake_run = _make_run_result(
        hosts_content=hosts_content,
        file_size=200,
        expect_clean=True,
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    info_findings = [
        f for f in result.findings if f.data.get("check") == "entry_count_summary"
    ]
    assert len(info_findings) > 0
    assert info_findings[0].severity == Severity.INFO
    assert info_findings[0].data.get("entry_count") == 3


def test_win_hosts_file_check_fix_blocked_security_domains():
    """Test fix recommendation for blocked security domains."""
    mod = _get_module()
    hosts_content = "192.168.1.1 windowsupdate.com\n"
    fake_run = _make_run_result(hosts_content=hosts_content, file_size=200)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    security_actions = [
        a for a in fix.actions
        if "security" in a.title.lower() or "antivirus" in a.title.lower()
    ]
    assert len(security_actions) > 0
    # Fix actions should not actually succeed (informational)
    assert not security_actions[0].success


def test_win_hosts_file_check_fix_redirected_domains():
    """Test fix recommendation for redirected legitimate domains."""
    mod = _get_module()
    hosts_content = "192.168.1.1 google.com\n"
    fake_run = _make_run_result(hosts_content=hosts_content, file_size=150)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    redirect_actions = [a for a in fix.actions if "suspicious" in a.title.lower()]
    assert len(redirect_actions) > 0


def test_win_hosts_file_check_fix_large_file():
    """Test fix recommendation for large hosts file."""
    mod = _get_module()
    hosts_content = "127.0.0.1 localhost\n"
    fake_run = _make_run_result(
        hosts_content=hosts_content,
        file_size=3 * 1024 * 1024,  # 3MB
    )
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    size_actions = [a for a in fix.actions if "large" in a.title.lower()]
    assert len(size_actions) > 0


def test_win_hosts_file_check_handles_read_error():
    """Test graceful handling when hosts file cannot be read."""
    mod = _get_module()

    def error_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 1
        result.stderr = "File not found"
        result.stdout = ""
        return result

    with patch("subprocess.run", side_effect=error_run):
        result = mod.check(_make_profile())
    # Should not crash, return empty findings list
    assert isinstance(result.findings, list)
    # With no content read, should return minimal findings
    assert not any(f.severity == Severity.CRITICAL for f in result.findings)


def test_win_hosts_file_check_handles_subprocess_error():
    """Test graceful handling of subprocess exceptions."""
    mod = _get_module()

    def error_run(cmd, **kwargs):
        raise OSError("Command execution failed")

    with patch("subprocess.run", side_effect=error_run):
        result = mod.check(_make_profile())
    # Should still complete without crashing
    assert isinstance(result.findings, list)


def test_win_hosts_file_check_ipv6_localhost():
    """Test that IPv6 localhost entries are properly recognized."""
    mod = _get_module()
    hosts_content = (
        "::1 localhost\n"
        "::1 host.local\n"
    )
    fake_run = _make_run_result(
        hosts_content=hosts_content,
        file_size=100,
        expect_clean=True,
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    # Should have no critical or warning findings, only INFO
    critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
    warning = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(critical) == 0
    assert len(warning) == 0


def test_win_hosts_file_check_comments_ignored():
    """Test that comment lines are properly ignored."""
    mod = _get_module()
    hosts_content = (
        "# This is a comment with 192.168.1.1 google.com\n"
        "# Another comment line\n"
        "127.0.0.1 localhost\n"
    )
    fake_run = _make_run_result(
        hosts_content=hosts_content,
        file_size=200,
        expect_clean=True,
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    # Comments should be ignored, so no redirected domains should be found
    redirected = [
        f for f in result.findings
        if f.data.get("check") == "redirected_legitimate"
    ]
    assert len(redirected) == 0
