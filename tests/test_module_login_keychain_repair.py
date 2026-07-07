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
    return next(m for m in modules if m.name == "login_keychain_repair")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_healthy(keychain_exists=True):
    """Normal case: no issues found"""

    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "show-keychain-info" in cmd_str:
            return _make_subprocess_result(
                'Keychain "/Users/test/Library/Keychains/login.keychain-db" lock timeout is 300 seconds\n'
                "Keychain: unlocked"
            )
        elif "default-keychain" in cmd_str:
            return _make_subprocess_result(
                '"/Users/test/Library/Keychains/login.keychain-db"'
            )
        return _make_subprocess_result()

    return fake_run


def _fake_run_locked_keychain():
    """Keychain is locked"""

    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "show-keychain-info" in cmd_str:
            return _make_subprocess_result(
                'Keychain "/Users/test/Library/Keychains/login.keychain-db" lock timeout is 300 seconds\n'
                "Keychain: locked"
            )
        elif "default-keychain" in cmd_str:
            return _make_subprocess_result(
                '"/Users/test/Library/Keychains/login.keychain-db"'
            )
        return _make_subprocess_result()

    return fake_run


def _fake_run_not_default_keychain():
    """Login keychain is not the default"""

    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "show-keychain-info" in cmd_str:
            return _make_subprocess_result(
                'Keychain "/Users/test/Library/Keychains/login.keychain-db" lock timeout is 300 seconds\n'
                "Keychain: unlocked"
            )
        elif "default-keychain" in cmd_str:
            return _make_subprocess_result(
                '"/Users/test/Library/Keychains/system.keychain"'
            )
        return _make_subprocess_result()

    return fake_run


def _fake_run_short_timeout():
    """Keychain has a very short lock timeout"""

    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "show-keychain-info" in cmd_str:
            return _make_subprocess_result(
                'Keychain "/Users/test/Library/Keychains/login.keychain-db" lock timeout is 60 seconds\n'
                "Keychain: unlocked"
            )
        elif "default-keychain" in cmd_str:
            return _make_subprocess_result(
                '"/Users/test/Library/Keychains/login.keychain-db"'
            )
        return _make_subprocess_result()

    return fake_run


def _fake_run_command_failure():
    """Security commands fail"""

    def fake_run(cmd, **kwargs):
        return _make_subprocess_result(returncode=1)

    return fake_run


def test_login_keychain_repair_discovered():
    mod = _get_module()
    assert mod.name == "login_keychain_repair"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE


def test_login_keychain_repair_healthy():
    """Test healthy keychain configuration"""
    mod = _get_module()
    with patch("pathlib.Path.exists", return_value=True):
        with patch("subprocess.run", side_effect=_fake_run_healthy()):
            result = mod.check(_make_profile())
    assert not result.has_issues


def test_login_keychain_repair_locked_keychain():
    """Test detection of locked keychain"""
    mod = _get_module()
    with patch("pathlib.Path.exists", return_value=True):
        with patch("subprocess.run", side_effect=_fake_run_locked_keychain()):
            result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "keychain_locked" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_login_keychain_repair_not_default():
    """Test detection of non-default keychain"""
    mod = _get_module()
    with patch("pathlib.Path.exists", return_value=True):
        with patch("subprocess.run", side_effect=_fake_run_not_default_keychain()):
            result = mod.check(_make_profile())
    assert result.has_issues
    assert any(
        f.data.get("check") == "not_default_keychain" for f in result.findings
    )
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_login_keychain_repair_short_timeout():
    """Test detection of short lock timeout"""
    mod = _get_module()
    with patch("pathlib.Path.exists", return_value=True):
        with patch("subprocess.run", side_effect=_fake_run_short_timeout()):
            result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "short_lock_timeout" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_login_keychain_repair_missing_keychain():
    """Test detection of missing keychain file"""
    mod = _get_module()
    with patch("pathlib.Path.exists", return_value=False):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "missing_login_keychain" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_login_keychain_repair_fix_is_informational():
    """Test that fix() is informational and always succeeds"""
    mod = _get_module()
    with patch("pathlib.Path.exists", return_value=True):
        with patch("subprocess.run", side_effect=_fake_run_locked_keychain()):
            check = mod.check(_make_profile())
            fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action
    assert len(fix.actions) > 0
