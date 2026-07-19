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
    return next(m for m in modules if m.name == "privacy_permissions_audit")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_healthy():
    """Normal case: no apps with privacy permissions or very few"""
    def fake_run(cmd, **kwargs):
        # All databases return empty results
        return _make_subprocess_result(stdout="")
    return fake_run


def _fake_run_minimal_permissions():
    """Few apps with camera/microphone access only (no dangerous combos)"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "sqlite3" in cmd_str:
            # Different results based on service - ensure no overlap
            if "kTCCServiceCamera" in cmd_str:
                return _make_subprocess_result(stdout="com.apple.FaceTime\n")
            elif "kTCCServiceMicrophone" in cmd_str:
                return _make_subprocess_result(stdout="com.apple.Skype\n")
            else:
                return _make_subprocess_result(stdout="")
        return _make_subprocess_result()
    return fake_run


def _fake_run_excessive_camera():
    """More than 10 apps with camera access"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "sqlite3" in cmd_str and "kTCCServiceCamera" in cmd_str:
            apps = "\n".join([f"com.app.cam{i}" for i in range(12)])
            return _make_subprocess_result(stdout=apps + "\n")
        return _make_subprocess_result(stdout="")
    return fake_run


def _fake_run_excessive_microphone():
    """More than 10 apps with microphone access"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "sqlite3" in cmd_str and "kTCCServiceMicrophone" in cmd_str:
            apps = "\n".join([f"com.app.mic{i}" for i in range(11)])
            return _make_subprocess_result(stdout=apps + "\n")
        return _make_subprocess_result(stdout="")
    return fake_run


def _fake_run_camera_microphone_combo():
    """Apps with both camera and microphone access"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "sqlite3" in cmd_str:
            if "kTCCServiceCamera" in cmd_str:
                return _make_subprocess_result(
                    stdout="com.apple.FaceTime\ncom.zoom.videomeetings\ncom.google.meet\n"
                )
            elif "kTCCServiceMicrophone" in cmd_str:
                return _make_subprocess_result(
                    stdout="com.apple.FaceTime\ncom.zoom.videomeetings\ncom.google.meet\ncom.slack.Slack\n"
                )
            else:
                return _make_subprocess_result(stdout="")
        return _make_subprocess_result()
    return fake_run


def _fake_run_screen_accessibility_combo():
    """Apps with both screen recording and accessibility access"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "sqlite3" in cmd_str:
            if "kTCCServiceScreenCapture" in cmd_str:
                return _make_subprocess_result(
                    stdout="com.apple.ScreenTime\ncom.suspicious.spyware\n"
                )
            elif "kTCCServiceAccessibility" in cmd_str:
                return _make_subprocess_result(
                    stdout="com.apple.ScreenTime\ncom.suspicious.spyware\ncom.apple.Finder\n"
                )
            else:
                return _make_subprocess_result(stdout="")
        return _make_subprocess_result()
    return fake_run


def _fake_run_database_error():
    """Database query fails"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "sqlite3" in cmd_str:
            return _make_subprocess_result(stderr="Error: unable to open database", returncode=1)
        return _make_subprocess_result()
    return fake_run


def test_privacy_permissions_audit_discovered():
    mod = _get_module()
    assert mod.name == "privacy_permissions_audit"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.DARWIN in mod.platforms


def test_privacy_permissions_audit_healthy():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        result = mod.check(_make_profile())
    assert not result.has_issues


def test_privacy_permissions_audit_minimal_permissions():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_minimal_permissions()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have INFO findings about camera and microphone access
    assert any(f.severity == Severity.INFO for f in result.findings)
    # Should not have any warnings (only 2-3 apps, no dangerous combos)
    assert not any(f.severity == Severity.WARNING for f in result.findings)


def test_privacy_permissions_audit_excessive_camera():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_excessive_camera()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have WARNING about excessive camera access
    assert any(f.data.get("check") == "excessive_camera" for f in result.findings)
    excessive_finding = next(
        (f for f in result.findings if f.data.get("check") == "excessive_camera"),
        None,
    )
    assert excessive_finding is not None
    assert excessive_finding.severity == Severity.WARNING
    assert excessive_finding.data.get("count") == 12


def test_privacy_permissions_audit_excessive_microphone():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_excessive_microphone()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have WARNING about excessive microphone access
    assert any(f.data.get("check") == "excessive_microphone" for f in result.findings)
    excessive_finding = next(
        (f for f in result.findings if f.data.get("check") == "excessive_microphone"),
        None,
    )
    assert excessive_finding is not None
    assert excessive_finding.severity == Severity.WARNING
    assert excessive_finding.data.get("count") == 11


def test_privacy_permissions_audit_camera_microphone_combo():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_camera_microphone_combo()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have WARNING about camera + microphone combo
    assert any(f.data.get("check") == "camera_microphone_combo" for f in result.findings)
    combo_finding = next(
        (f for f in result.findings if f.data.get("check") == "camera_microphone_combo"),
        None,
    )
    assert combo_finding is not None
    assert combo_finding.severity == Severity.WARNING
    # FaceTime, Zoom, and Meet should be in the combo (all have both permissions)
    apps = combo_finding.data.get("apps", [])
    assert len(apps) == 3


def test_privacy_permissions_audit_screen_accessibility_combo():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_screen_accessibility_combo()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have WARNING about screen recording + accessibility combo
    assert any(f.data.get("check") == "screen_accessibility_combo" for f in result.findings)
    combo_finding = next(
        (f for f in result.findings if f.data.get("check") == "screen_accessibility_combo"),
        None,
    )
    assert combo_finding is not None
    assert combo_finding.severity == Severity.WARNING
    # ScreenTime and spyware should be in the combo
    apps = combo_finding.data.get("apps", [])
    assert len(apps) == 2
    assert "com.suspicious.spyware" in apps


def test_privacy_permissions_audit_database_error():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_database_error()):
        result = mod.check(_make_profile())
    # On database error, should return no findings (graceful failure)
    assert not result.has_issues


def test_privacy_permissions_audit_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_camera_microphone_combo()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have actions for findings
    assert len(fix.actions) > 0
    # Actions should describe how to manage permissions
    assert any("System Settings" in a.description for a in fix.actions)


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.privacy_permissions_audit.") for c in declared)
