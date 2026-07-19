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
    return next(m for m in modules if m.name == "screen_lock_check")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_secure_config():
    """Secure screen lock configuration"""
    def fake_run(cmd, **kwargs):
        # Ask for password: 1 (enabled)
        if cmd == ["defaults", "read", "com.apple.screensaver", "askForPassword"]:
            return _make_subprocess_result(stdout="1\n")
        # Ask for password delay: 0 seconds
        elif cmd == ["defaults", "read", "com.apple.screensaver", "askForPasswordDelay"]:
            return _make_subprocess_result(stdout="0\n")
        # Idle time: 5 minutes
        elif cmd == ["defaults", "-currentHost", "read", "com.apple.screensaver", "idleTime"]:
            return _make_subprocess_result(stdout="300\n")
        # Auto login: not enabled
        elif cmd == ["defaults", "read", "/Library/Preferences/com.apple.loginwindow", "autoLoginUser"]:
            return _make_subprocess_result(returncode=1, stderr="")
        # Password hint: not set
        elif cmd == ["defaults", "read", "/Library/Preferences/com.apple.loginwindow", "RetriesUntilHint"]:
            return _make_subprocess_result(returncode=1, stderr="")
        return _make_subprocess_result(returncode=1, stderr="")
    return fake_run


def _fake_run_insecure_config():
    """Insecure screen lock configuration"""
    def fake_run(cmd, **kwargs):
        # Ask for password: 0 (disabled)
        if cmd == ["defaults", "read", "com.apple.screensaver", "askForPassword"]:
            return _make_subprocess_result(stdout="0\n")
        # Ask for password delay: 30 seconds
        elif cmd == ["defaults", "read", "com.apple.screensaver", "askForPasswordDelay"]:
            return _make_subprocess_result(stdout="30\n")
        # Idle time: 30 minutes
        elif cmd == ["defaults", "-currentHost", "read", "com.apple.screensaver", "idleTime"]:
            return _make_subprocess_result(stdout="1800\n")
        # Auto login: enabled
        elif cmd == ["defaults", "read", "/Library/Preferences/com.apple.loginwindow", "autoLoginUser"]:
            return _make_subprocess_result(stdout="admin\n")
        # Password hint: 3 retries
        elif cmd == ["defaults", "read", "/Library/Preferences/com.apple.loginwindow", "RetriesUntilHint"]:
            return _make_subprocess_result(stdout="3\n")
        return _make_subprocess_result(returncode=1, stderr="")
    return fake_run


def _fake_run_no_screensaver():
    """Screensaver disabled (idle time 0)"""
    def fake_run(cmd, **kwargs):
        # Ask for password: 1 (enabled)
        if cmd == ["defaults", "read", "com.apple.screensaver", "askForPassword"]:
            return _make_subprocess_result(stdout="1\n")
        # Ask for password delay: 0 seconds
        elif cmd == ["defaults", "read", "com.apple.screensaver", "askForPasswordDelay"]:
            return _make_subprocess_result(stdout="0\n")
        # Idle time: 0 (disabled)
        elif cmd == ["defaults", "-currentHost", "read", "com.apple.screensaver", "idleTime"]:
            return _make_subprocess_result(stdout="0\n")
        # Auto login: not enabled
        elif cmd == ["defaults", "read", "/Library/Preferences/com.apple.loginwindow", "autoLoginUser"]:
            return _make_subprocess_result(returncode=1, stderr="")
        # Password hint: not set
        elif cmd == ["defaults", "read", "/Library/Preferences/com.apple.loginwindow", "RetriesUntilHint"]:
            return _make_subprocess_result(returncode=1, stderr="")
        return _make_subprocess_result(returncode=1, stderr="")
    return fake_run


def _fake_run_idle_time_not_set():
    """Screensaver idle time not set"""
    def fake_run(cmd, **kwargs):
        # Ask for password: 1 (enabled)
        if cmd == ["defaults", "read", "com.apple.screensaver", "askForPassword"]:
            return _make_subprocess_result(stdout="1\n")
        # Ask for password delay: 0 seconds
        elif cmd == ["defaults", "read", "com.apple.screensaver", "askForPasswordDelay"]:
            return _make_subprocess_result(stdout="0\n")
        # Idle time: not set (returncode 1)
        elif cmd == ["defaults", "-currentHost", "read", "com.apple.screensaver", "idleTime"]:
            return _make_subprocess_result(returncode=1, stderr="")
        # Auto login: not enabled
        elif cmd == ["defaults", "read", "/Library/Preferences/com.apple.loginwindow", "autoLoginUser"]:
            return _make_subprocess_result(returncode=1, stderr="")
        # Password hint: not set
        elif cmd == ["defaults", "read", "/Library/Preferences/com.apple.loginwindow", "RetriesUntilHint"]:
            return _make_subprocess_result(returncode=1, stderr="")
        return _make_subprocess_result(returncode=1, stderr="")
    return fake_run


def test_screen_lock_check_discovered():
    mod = _get_module()
    assert mod.name == "screen_lock_check"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.DARWIN in mod.platforms


def test_screen_lock_check_secure_config():
    """Test with secure configuration - should have only INFO findings"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_secure_config()):
        result = mod.check(_make_profile())
    # Should have findings for the positive cases
    assert result.has_issues
    # Should have INFO severity findings
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert len(info_findings) > 0
    # Should have no CRITICAL findings
    critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert len(critical_findings) == 0


def test_screen_lock_check_insecure_config():
    """Test with insecure configuration - should have CRITICAL and WARNING findings"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_insecure_config()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have CRITICAL for missing screen lock
    critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert any(f.data.get("check") == "screen_lock_required" for f in critical_findings)
    # Should have CRITICAL for auto login
    assert any(f.data.get("check") == "automatic_login" for f in critical_findings)
    # Should have WARNING for delay > 5 seconds
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert any(f.data.get("check") == "screen_lock_delay" for f in warning_findings)
    # Should have WARNING for idle time > 10 minutes
    assert any(f.data.get("check") == "screensaver_idle_time" for f in warning_findings)


def test_screen_lock_required_enabled():
    """Test that enabled screen lock produces INFO finding"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_secure_config()):
        result = mod.check(_make_profile())
    # Find the screen lock required finding
    findings = [f for f in result.findings if f.data.get("check") == "screen_lock_required"]
    assert len(findings) == 1
    assert findings[0].data.get("value") == "enabled"
    assert findings[0].severity == Severity.INFO


def test_screen_lock_required_disabled():
    """Test that disabled screen lock produces CRITICAL finding"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_insecure_config()):
        result = mod.check(_make_profile())
    # Find the screen lock required finding
    findings = [f for f in result.findings if f.data.get("check") == "screen_lock_required"]
    assert len(findings) == 1
    assert findings[0].data.get("value") == "disabled"
    assert findings[0].severity == Severity.CRITICAL


def test_automatic_login_enabled():
    """Test that enabled automatic login produces CRITICAL finding"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_insecure_config()):
        result = mod.check(_make_profile())
    # Find the auto login finding
    findings = [f for f in result.findings if f.data.get("check") == "automatic_login"]
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


def test_screen_lock_delay_acceptable():
    """Test that low screen lock delay produces INFO finding"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_secure_config()):
        result = mod.check(_make_profile())
    # Find the delay finding
    findings = [f for f in result.findings if f.data.get("check") == "screen_lock_delay"]
    assert len(findings) == 1
    assert findings[0].data.get("value") == 0
    assert findings[0].severity == Severity.INFO


def test_screen_lock_delay_high():
    """Test that high screen lock delay produces WARNING finding"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_insecure_config()):
        result = mod.check(_make_profile())
    # Find the delay finding
    findings = [f for f in result.findings if f.data.get("check") == "screen_lock_delay"]
    assert len(findings) == 1
    assert findings[0].data.get("value") == 30
    assert findings[0].severity == Severity.WARNING


def test_screensaver_idle_acceptable():
    """Test that good screensaver idle time produces INFO finding"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_secure_config()):
        result = mod.check(_make_profile())
    # Find the idle time finding
    findings = [f for f in result.findings if f.data.get("check") == "screensaver_idle_time"]
    assert len(findings) == 1
    assert findings[0].data.get("value") == 5  # 300 seconds = 5 minutes
    assert findings[0].severity == Severity.INFO


def test_screensaver_idle_too_long():
    """Test that long screensaver idle time produces WARNING finding"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_insecure_config()):
        result = mod.check(_make_profile())
    # Find the idle time finding
    findings = [f for f in result.findings if f.data.get("check") == "screensaver_idle_time"]
    assert len(findings) == 1
    assert findings[0].data.get("value") == 30  # 1800 seconds = 30 minutes
    assert findings[0].severity == Severity.WARNING


def test_screensaver_disabled():
    """Test that disabled screensaver (idle time 0) produces WARNING finding"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_screensaver()):
        result = mod.check(_make_profile())
    # Find the idle time finding
    findings = [f for f in result.findings if f.data.get("check") == "screensaver_idle_time"]
    assert len(findings) == 1
    assert findings[0].data.get("value") == 0
    assert findings[0].severity == Severity.WARNING


def test_screensaver_idle_time_not_set():
    """Test that unset screensaver idle time produces INFO finding"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_idle_time_not_set()):
        result = mod.check(_make_profile())
    # Find the idle time finding
    findings = [f for f in result.findings if f.data.get("check") == "screensaver_idle_time"]
    assert len(findings) == 1
    assert findings[0].data.get("value") == "not_set"
    assert findings[0].severity == Severity.INFO


def test_password_hint_enabled():
    """Test that enabled password hint produces INFO finding"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_insecure_config()):
        result = mod.check(_make_profile())
    # Find the password hint finding
    findings = [f for f in result.findings if f.data.get("check") == "password_hint"]
    assert len(findings) == 1
    assert findings[0].data.get("value") == 3
    assert findings[0].severity == Severity.INFO


def test_fix_is_informational():
    """Test that fix() always succeeds with informational messages"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_insecure_config()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed
    assert fix.all_succeeded
    # Should have at least one action
    assert len(fix.actions) > 0
    # All actions should be SAFE risk level
    assert all(a.risk_level == RiskLevel.SAFE for a in fix.actions)


def test_fix_screen_lock_required():
    """Test that screen lock required finding produces appropriate action"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_insecure_config()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # Should have action for screen lock
    actions = [a for a in fix.actions if "screen lock" in a.title.lower()]
    assert len(actions) > 0


def test_fix_automatic_login():
    """Test that automatic login finding produces appropriate action"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_insecure_config()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # Should have action for disabling auto login
    actions = [a for a in fix.actions if "automatic" in a.title.lower()]
    assert len(actions) > 0


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.screen_lock_check.") for c in declared)
