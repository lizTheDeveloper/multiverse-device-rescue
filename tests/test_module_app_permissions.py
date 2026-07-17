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
    return next(m for m in modules if m.name == "app_permissions")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_no_permissions():
    """No apps have any permissions"""
    def fake_run(cmd, **kwargs):
        # All queries return empty
        return _make_subprocess_result(stdout="")
    return fake_run


def _fake_run_some_permissions():
    """Some apps have various permissions"""
    def fake_run(cmd, **kwargs):
        system_db_path = "/Library/Application Support/com.apple.TCC/TCC.db"
        user_db_path = str(Path.home() / "Library/Application Support/com.apple.TCC/TCC.db")

        # Extract the database path from the command
        if isinstance(cmd, list) and len(cmd) >= 2:
            db_arg = cmd[1]
        else:
            db_arg = ""

        # System DB has some permissions
        if db_arg == system_db_path:
            return _make_subprocess_result(
                stdout="com.apple.Safari|kTCCServiceCamera|2\n"
                       "com.apple.FaceTime|kTCCServiceCamera|2\n"
                       "com.apple.FaceTime|kTCCServiceMicrophone|2\n"
                       "com.google.Chrome|kTCCServiceAccessibility|2\n"
            )
        # User DB has more permissions
        elif db_arg == user_db_path:
            return _make_subprocess_result(
                stdout="com.apple.Safari|kTCCServiceMicrophone|2\n"
                       "com.microsoft.VSCode|kTCCServiceAccessibility|2\n"
                       "com.apple.ScreenFloat|kTCCServiceScreenCapture|2\n"
            )
        return _make_subprocess_result(stdout="")
    return fake_run


def _fake_run_accessibility_threshold_10():
    """Exactly 10 apps with accessibility (should be INFO, not WARNING)"""
    def fake_run(cmd, **kwargs):
        apps = [f"com.app{i}|kTCCServiceAccessibility|2\n" for i in range(1, 11)]
        stdout = "".join(apps)
        return _make_subprocess_result(stdout=stdout)
    return fake_run


def _fake_run_accessibility_threshold_11():
    """11 apps with accessibility (should be WARNING)"""
    def fake_run(cmd, **kwargs):
        apps = [f"com.app{i}|kTCCServiceAccessibility|2\n" for i in range(1, 12)]
        stdout = "".join(apps)
        return _make_subprocess_result(stdout=stdout)
    return fake_run


def _fake_run_deduplication():
    """Same app in both system and user DB (should appear only once)"""
    def fake_run(cmd, **kwargs):
        system_db_path = "/Library/Application Support/com.apple.TCC/TCC.db"
        user_db_path = str(Path.home() / "Library/Application Support/com.apple.TCC/TCC.db")

        # Extract the database path from the command
        if isinstance(cmd, list) and len(cmd) >= 2:
            db_arg = cmd[1]
        else:
            db_arg = ""

        if db_arg == system_db_path:
            return _make_subprocess_result(
                stdout="com.apple.Safari|kTCCServiceCamera|2\n"
                       "com.google.Chrome|kTCCServiceAccessibility|2\n"
            )
        elif db_arg == user_db_path:
            return _make_subprocess_result(
                stdout="com.apple.Safari|kTCCServiceCamera|2\n"
                       "com.microsoft.VSCode|kTCCServiceAccessibility|2\n"
            )
        return _make_subprocess_result(stdout="")
    return fake_run


def _fake_run_system_denied_user_readable():
    """System DB permission denied, user DB is readable"""
    def fake_run(cmd, **kwargs):
        system_db_path = "/Library/Application Support/com.apple.TCC/TCC.db"
        user_db_path = str(Path.home() / "Library/Application Support/com.apple.TCC/TCC.db")

        # Extract the database path from the command
        if isinstance(cmd, list) and len(cmd) >= 2:
            db_arg = cmd[1]
        else:
            db_arg = ""

        if db_arg == system_db_path:
            return _make_subprocess_result(returncode=1, stderr="unable to open database")
        elif db_arg == user_db_path:
            return _make_subprocess_result(
                stdout="com.apple.FaceTime|kTCCServiceCamera|2\n"
                       "com.apple.FaceTime|kTCCServiceMicrophone|2\n"
            )
        return _make_subprocess_result(stdout="")
    return fake_run


def test_app_permissions_discovered():
    mod = _get_module()
    assert mod.name == "app_permissions"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE


def test_app_permissions_no_issues():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_permissions()):
        result = mod.check(_make_profile())
    assert not result.has_issues


def test_app_permissions_some_permissions():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_some_permissions()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have findings for each permission type
    assert any(f.data.get("check") == "camera_access" for f in result.findings)
    assert any(f.data.get("check") == "microphone_access" for f in result.findings)
    assert any(f.data.get("check") == "accessibility_access" for f in result.findings)
    assert any(f.data.get("check") == "screen_recording" for f in result.findings)


def test_app_permissions_accessibility_10_is_info():
    """Exactly 10 apps with accessibility should be INFO, not WARNING"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_accessibility_threshold_10()):
        result = mod.check(_make_profile())
    assert result.has_issues
    accessibility_findings = [f for f in result.findings if f.data.get("check") == "accessibility_access"]
    assert len(accessibility_findings) == 1
    assert accessibility_findings[0].severity == Severity.INFO


def test_app_permissions_accessibility_11_is_warning():
    """11 apps with accessibility should be WARNING"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_accessibility_threshold_11()):
        result = mod.check(_make_profile())
    assert result.has_issues
    accessibility_findings = [f for f in result.findings if f.data.get("check") == "accessibility_access"]
    assert len(accessibility_findings) == 1
    assert accessibility_findings[0].severity == Severity.WARNING


def test_app_permissions_deduplication():
    """Same app in both DBs should appear only once"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_deduplication()):
        result = mod.check(_make_profile())
    assert result.has_issues
    camera_findings = [f for f in result.findings if f.data.get("check") == "camera_access"]
    assert len(camera_findings) == 1
    # Safari should appear only once even though it's in both DBs
    apps = camera_findings[0].data.get("apps", [])
    assert apps.count("com.apple.Safari") == 1


def test_app_permissions_system_denied_user_readable():
    """System DB denied, user DB readable - should still find permissions from user DB"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_system_denied_user_readable()):
        result = mod.check(_make_profile())
    assert result.has_issues
    camera_findings = [f for f in result.findings if f.data.get("check") == "camera_access"]
    assert len(camera_findings) == 1
    assert "com.apple.FaceTime" in camera_findings[0].data.get("apps", [])


def test_app_permissions_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_some_permissions()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action
    assert len(fix.actions) > 0
    # All actions should be SAFE risk level
    assert all(a.risk_level == RiskLevel.SAFE for a in fix.actions)


def test_app_permissions_fix_creates_actions_per_finding():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_some_permissions()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # Should have one action per finding
    assert len(fix.actions) == len(check.findings)
