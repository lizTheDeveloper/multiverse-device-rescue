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
        os_version="13.0",
        architecture="arm64",
        cpu_model="Apple M1",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "login_password_policy")


def _make_run_result(
    auto_login=None,
    ask_password=None,
    password_delay=None,
    guest_auth=None,
    show_full_name=None,
    screensaver_timeout=None,
    remote_login=None,
):
    """Create a fake subprocess.run that returns security settings."""

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        # defaults read commands
        if "defaults" in cmd_str and "read" in cmd_str:
            if "autoLoginUser" in cmd_str:
                result.stdout = auto_login if auto_login else ""
                result.returncode = 1 if not auto_login else 0
            elif "askForPasswordDelay" in cmd_str:
                # Check this before askForPassword since it contains that string
                result.stdout = password_delay if password_delay else ""
                result.returncode = 0 if password_delay is not None else 1
            elif "askForPassword" in cmd_str and "-currentHost" not in cmd_str:
                result.stdout = ask_password if ask_password else ""
                result.returncode = 0 if ask_password is not None else 1
            elif "SHOWFULLNAME" in cmd_str:
                result.stdout = show_full_name if show_full_name is not None else "0"
                result.returncode = 0
            elif "idleTime" in cmd_str and "-currentHost" in cmd_str:
                result.stdout = screensaver_timeout if screensaver_timeout is not None else ""
                result.returncode = 0 if screensaver_timeout is not None else 1

        # dscl commands for guest account
        elif "dscl" in cmd_str and "Guest" in cmd_str:
            if guest_auth is not None:
                result.stdout = guest_auth
            else:
                result.stdout = "No such key"
            result.returncode = 0

        # systemsetup for remote login
        elif "systemsetup" in cmd_str and "getremotelogin" in cmd_str:
            if remote_login is not None:
                result.stdout = f"Remote Login: {remote_login}"
            else:
                result.stdout = "Remote Login: Off"
            result.returncode = 0

        return result

    return fake_run


def test_login_password_policy_discovered():
    mod = _get_module()
    assert mod.name == "login_password_policy"
    assert mod.category == "security"
    assert Platform.DARWIN in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_auto_login_enabled_critical():
    """Test CRITICAL finding when auto-login is enabled."""
    mod = _get_module()
    fake_run = _make_run_result(auto_login="testuser")
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    auto_login_findings = [
        f for f in result.findings if f.data.get("check") == "auto_login"
    ]
    assert len(auto_login_findings) == 1
    assert auto_login_findings[0].severity == Severity.CRITICAL


def test_auto_login_disabled():
    """Test no finding when auto-login is disabled."""
    mod = _get_module()
    fake_run = _make_run_result(
        auto_login=None,
        ask_password="1",
        password_delay="0",
        guest_auth="No such key",
        show_full_name="0",
        screensaver_timeout="600",
        remote_login="Off",
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    auto_login_findings = [
        f for f in result.findings if f.data.get("check") == "auto_login"
    ]
    assert len(auto_login_findings) == 0


def test_password_not_required_after_screensaver():
    """Test WARNING when password is not required after screensaver."""
    mod = _get_module()
    fake_run = _make_run_result(
        auto_login=None,
        ask_password="0",
        password_delay=None,
        guest_auth="No such key",
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    password_findings = [
        f for f in result.findings if f.data.get("check") == "ask_password"
    ]
    assert len(password_findings) == 1
    assert password_findings[0].severity == Severity.WARNING


def test_password_delay_too_long():
    """Test WARNING when password delay is > 5 seconds."""
    mod = _get_module()
    fake_run = _make_run_result(
        auto_login=None,
        ask_password="1",
        password_delay="10",
        guest_auth="No such key",
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    delay_findings = [
        f for f in result.findings if f.data.get("check") == "password_delay"
    ]
    assert len(delay_findings) == 1
    assert delay_findings[0].severity == Severity.WARNING
    assert delay_findings[0].data.get("seconds") == 10


def test_password_delay_acceptable():
    """Test no finding when password delay is <= 5 seconds."""
    mod = _get_module()
    fake_run = _make_run_result(
        auto_login=None,
        ask_password="1",
        password_delay="5",
        guest_auth="No such key",
        show_full_name="0",
        screensaver_timeout="600",
        remote_login="Off",
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    delay_findings = [
        f for f in result.findings if f.data.get("check") == "password_delay"
    ]
    assert len(delay_findings) == 0


def test_guest_account_enabled():
    """Test WARNING when guest account is enabled."""
    mod = _get_module()
    fake_run = _make_run_result(
        auto_login=None,
        ask_password="1",
        password_delay="0",
        guest_auth="AuthenticationAuthority: ;Kerberosv5;;guest@LKDC:SHA1...",
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    guest_findings = [
        f for f in result.findings if f.data.get("check") == "guest_account_enabled"
    ]
    assert len(guest_findings) == 1
    assert guest_findings[0].severity == Severity.WARNING


def test_guest_account_disabled():
    """Test no finding when guest account is disabled."""
    mod = _get_module()
    fake_run = _make_run_result(
        auto_login=None,
        ask_password="1",
        password_delay="0",
        guest_auth="No such key",
        show_full_name="0",
        screensaver_timeout="600",
        remote_login="Off",
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    guest_findings = [
        f for f in result.findings if f.data.get("check") == "guest_account_enabled"
    ]
    assert len(guest_findings) == 0


def test_login_window_display_reported():
    """Test that login window display is always reported (INFO)."""
    mod = _get_module()
    fake_run = _make_run_result(
        auto_login=None,
        ask_password="1",
        password_delay="0",
        guest_auth="No such key",
        show_full_name="0",
        screensaver_timeout="600",
        remote_login="Off",
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    display_findings = [
        f for f in result.findings if f.data.get("check") == "login_window_display"
    ]
    assert len(display_findings) == 1
    assert display_findings[0].severity == Severity.INFO


def test_screensaver_disabled():
    """Test WARNING when screensaver is disabled."""
    mod = _get_module()
    fake_run = _make_run_result(
        auto_login=None,
        ask_password="1",
        password_delay="0",
        guest_auth="No such key",
        screensaver_timeout="0",
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    timeout_findings = [
        f for f in result.findings if f.data.get("check") == "screensaver_timeout"
    ]
    assert len(timeout_findings) == 1
    assert timeout_findings[0].severity == Severity.WARNING


def test_screensaver_timeout_too_long():
    """Test WARNING when screensaver timeout > 10 minutes."""
    mod = _get_module()
    fake_run = _make_run_result(
        auto_login=None,
        ask_password="1",
        password_delay="0",
        guest_auth="No such key",
        screensaver_timeout="900",  # 15 minutes
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    timeout_findings = [
        f for f in result.findings if f.data.get("check") == "screensaver_timeout"
    ]
    assert len(timeout_findings) == 1
    assert timeout_findings[0].severity == Severity.WARNING
    assert timeout_findings[0].data.get("minutes") == 15


def test_screensaver_timeout_acceptable():
    """Test no finding when screensaver timeout <= 10 minutes."""
    mod = _get_module()
    fake_run = _make_run_result(
        auto_login=None,
        ask_password="1",
        password_delay="0",
        guest_auth="No such key",
        show_full_name="0",
        screensaver_timeout="600",  # 10 minutes
        remote_login="Off",
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    timeout_findings = [
        f for f in result.findings if f.data.get("check") == "screensaver_timeout"
    ]
    assert len(timeout_findings) == 0


def test_remote_login_enabled():
    """Test INFO when remote login is enabled."""
    mod = _get_module()
    fake_run = _make_run_result(
        auto_login=None,
        ask_password="1",
        password_delay="0",
        guest_auth="No such key",
        screensaver_timeout="600",
        remote_login="On",
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    ssh_findings = [
        f for f in result.findings if f.data.get("check") == "remote_login_enabled"
    ]
    assert len(ssh_findings) == 1
    assert ssh_findings[0].severity == Severity.INFO


def test_multiple_issues():
    """Test when multiple security issues are detected."""
    mod = _get_module()
    fake_run = _make_run_result(
        auto_login="testuser",
        ask_password="0",
        password_delay="10",
        guest_auth="AuthenticationAuthority: ;Kerberosv5;;guest@LKDC:SHA1...",
        screensaver_timeout="900",
        remote_login="On",
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    checks = [f.data.get("check") for f in result.findings]
    assert "auto_login" in checks
    assert "ask_password" in checks
    assert "password_delay" in checks
    assert "guest_account_enabled" in checks
    assert "screensaver_timeout" in checks
    assert "remote_login_enabled" in checks


def test_fix_auto_login():
    """Test fix action for auto-login."""
    mod = _get_module()
    fake_run = _make_run_result(auto_login="testuser")
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    auto_login_actions = [a for a in fix.actions if "auto-login" in a.title.lower()]
    assert len(auto_login_actions) > 0
    assert auto_login_actions[0].success


def test_fix_password_requirements():
    """Test fix action for password requirements."""
    mod = _get_module()
    fake_run = _make_run_result(ask_password="0")
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    password_actions = [a for a in fix.actions if "password" in a.title.lower()]
    assert len(password_actions) > 0


def test_fix_guest_account():
    """Test fix action for guest account."""
    mod = _get_module()
    fake_run = _make_run_result(
        auto_login=None,
        ask_password="1",
        password_delay="0",
        guest_auth="AuthenticationAuthority: ;Kerberosv5;;guest@LKDC:SHA1...",
    )
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    guest_actions = [a for a in fix.actions if "guest" in a.title.lower()]
    assert len(guest_actions) > 0


def test_handles_subprocess_error():
    """Test graceful handling of subprocess errors."""
    mod = _get_module()

    def error_run(cmd, **kwargs):
        raise OSError("Command failed")

    with patch("subprocess.run", side_effect=error_run):
        result = mod.check(_make_profile())
    # Should still complete without crashing
    assert isinstance(result.findings, list)
