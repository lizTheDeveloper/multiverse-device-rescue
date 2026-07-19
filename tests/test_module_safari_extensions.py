import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
import tempfile

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
    return next(m for m in modules if m.name == "safari_extensions")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_no_extensions():
    """No extensions installed, no content blockers"""
    def fake_run(cmd, **kwargs):
        # All pluginkit queries return empty (no extensions found)
        # Return returncode=1 to indicate no results found
        return _make_subprocess_result(stdout="", returncode=1)
    return fake_run


def _fake_run_with_legacy_extensions(tmp_path):
    """Create legacy .safariextz files"""
    def fake_run(cmd, **kwargs):
        # Create fake extension files in temp directory
        ext_dir = tmp_path / "Library" / "Safari" / "Extensions"
        ext_dir.mkdir(parents=True, exist_ok=True)
        (ext_dir / "BadExtension.safariextz").touch()
        (ext_dir / "OldExtension.safariextz").touch()
        return _make_subprocess_result(stdout="")
    return fake_run


def _fake_run_with_app_extensions():
    """Some modern Safari app extensions"""
    def fake_run(cmd, **kwargs):
        if len(cmd) > 2 and "com.apple.Safari.extension" in cmd:
            return _make_subprocess_result(
                stdout="/path/to/Adblock.app/Contents/PlugIns/Adblock.safariextension - (Safari Extension)\n"
                       "/path/to/Privacy.app/Contents/PlugIns/Privacy.safariextension - (Safari Extension)\n"
                       "/path/to/Speedup.app/Contents/PlugIns/Speedup.safariextension - (Safari Extension)\n"
            )
        elif len(cmd) > 2 and "com.apple.Safari.content-blocker" in cmd:
            return _make_subprocess_result(stdout="", returncode=1)
        return _make_subprocess_result(stdout="")
    return fake_run


def _fake_run_with_many_extensions():
    """Many Safari app extensions (>5)"""
    def fake_run(cmd, **kwargs):
        if len(cmd) > 2 and "com.apple.Safari.extension" in cmd:
            extensions = []
            for i in range(1, 8):
                extensions.append(f"/path/to/Ext{i}.app/Contents/PlugIns/Ext{i}.safariextension - (Safari Extension)\n")
            return _make_subprocess_result(stdout="".join(extensions))
        elif len(cmd) > 2 and "com.apple.Safari.content-blocker" in cmd:
            return _make_subprocess_result(stdout="", returncode=1)
        return _make_subprocess_result(stdout="")
    return fake_run


def _fake_run_with_content_blockers():
    """Content blockers are enabled"""
    def fake_run(cmd, **kwargs):
        if len(cmd) > 2 and "com.apple.Safari.content-blocker" in cmd:
            return _make_subprocess_result(
                stdout="/path/to/ContentBlocker1.app - (Content Blocker)\n"
                       "/path/to/ContentBlocker2.app - (Content Blocker)\n"
            )
        return _make_subprocess_result(stdout="")
    return fake_run


def _fake_run_no_content_blockers():
    """No content blockers enabled"""
    def fake_run(cmd, **kwargs):
        if len(cmd) > 2 and "com.apple.Safari.content-blocker" in cmd:
            return _make_subprocess_result(stdout="", returncode=1)
        return _make_subprocess_result(stdout="")
    return fake_run


def _fake_run_pluginkit_error():
    """pluginkit command fails"""
    def fake_run(cmd, **kwargs):
        # Return error for all pluginkit commands
        return _make_subprocess_result(returncode=127, stderr="command not found")
    return fake_run


def test_safari_extensions_discovered():
    mod = _get_module()
    assert mod.name == "safari_extensions"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE


def test_safari_extensions_no_issues(tmp_path):
    mod = _get_module()
    with patch.object(Path, "home", return_value=tmp_path):
        with patch("subprocess.run", side_effect=_fake_run_no_extensions()):
            result = mod.check(_make_profile())
    assert not result.has_issues


def test_safari_extensions_legacy_extensions_found(tmp_path):
    mod = _get_module()
    # Create legacy extension files
    ext_dir = tmp_path / "Library" / "Safari" / "Extensions"
    ext_dir.mkdir(parents=True, exist_ok=True)
    (ext_dir / "BadExtension.safariextz").touch()
    (ext_dir / "OldExtension.safariextz").touch()

    with patch.object(Path, "home", return_value=tmp_path):
        with patch("subprocess.run", side_effect=_fake_run_no_extensions()):
            result = mod.check(_make_profile())

    assert result.has_issues
    legacy_findings = [f for f in result.findings if f.data.get("check") == "legacy_extensions"]
    assert len(legacy_findings) == 1
    assert legacy_findings[0].severity == Severity.WARNING
    extensions = legacy_findings[0].data.get("extensions", [])
    assert "BadExtension" in extensions
    assert "OldExtension" in extensions


def test_safari_extensions_app_extensions_found():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_with_app_extensions()):
        result = mod.check(_make_profile())

    assert result.has_issues
    app_findings = [f for f in result.findings if f.data.get("check") == "app_extensions"]
    assert len(app_findings) == 1
    assert app_findings[0].severity == Severity.INFO
    extensions = app_findings[0].data.get("extensions", [])
    assert len(extensions) > 0


def test_safari_extensions_many_extensions_warning():
    """More than 5 extensions should trigger a warning"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_with_many_extensions()):
        result = mod.check(_make_profile())

    assert result.has_issues
    bloat_findings = [f for f in result.findings if f.data.get("check") == "extension_bloat"]
    assert len(bloat_findings) == 1
    assert bloat_findings[0].severity == Severity.WARNING
    assert bloat_findings[0].data.get("count") == 7


def test_safari_extensions_content_blockers_enabled():
    """Content blockers found should result in INFO finding"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_with_content_blockers()):
        result = mod.check(_make_profile())

    blocker_findings = [f for f in result.findings if f.data.get("check") == "content_blockers"]
    assert len(blocker_findings) == 1
    assert blocker_findings[0].severity == Severity.INFO
    # Only one finding when content blockers are found
    assert blocker_findings[0].data.get("enabled") is True


def test_safari_extensions_content_blockers_disabled():
    """Content blockers not found should result in no findings (None = unable to determine)"""
    mod = _get_module()
    # We need a fake that returns error for content-blocker query
    def fake_run(cmd, **kwargs):
        if len(cmd) > 2 and "com.apple.Safari.content-blocker" in cmd:
            return _make_subprocess_result(stdout="", returncode=1)
        return _make_subprocess_result(stdout="")

    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())

    # No content blocker findings if unable to determine
    blocker_findings = [f for f in result.findings if f.data.get("check") == "content_blockers"]
    assert len(blocker_findings) == 0


def test_safari_extensions_pluginkit_error():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_pluginkit_error()):
        result = mod.check(_make_profile())
    # Should not crash, gracefully handle errors
    assert not result.has_issues


def test_safari_extensions_fix_legacy_extensions(tmp_path):
    mod = _get_module()
    # Create legacy extension files
    ext_dir = tmp_path / "Library" / "Safari" / "Extensions"
    ext_dir.mkdir(parents=True, exist_ok=True)
    (ext_dir / "BadExtension.safariextz").touch()

    with patch.object(Path, "home", return_value=tmp_path):
        with patch("subprocess.run", side_effect=_fake_run_no_extensions()):
            check = mod.check(_make_profile())
            fix = mod.fix(check, Mode.MANUAL)

    assert fix.all_succeeded
    assert len(fix.actions) > 0
    assert any(a.title == "Remove legacy Safari extensions" for a in fix.actions)


def test_safari_extensions_fix_app_extensions():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_with_app_extensions()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    assert fix.all_succeeded
    assert any(a.title == "Review Safari extensions" for a in fix.actions)


def test_safari_extensions_fix_extension_bloat():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_with_many_extensions()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    assert fix.all_succeeded
    assert any(a.title == "Reduce number of Safari extensions" for a in fix.actions)


def test_safari_extensions_fix_content_blockers():
    """Test fix with content blockers - should have no actions since we don't report missing blockers"""
    mod = _get_module()
    def fake_run(cmd, **kwargs):
        # Return empty for all queries
        return _make_subprocess_result(stdout="", returncode=1)

    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    # No findings means no actions
    assert fix.all_succeeded
    assert len(fix.actions) == 0


def test_safari_extensions_fix_all_safe_risk_level(tmp_path):
    """All fix actions should be SAFE risk level"""
    mod = _get_module()
    # Create multiple issues
    ext_dir = tmp_path / "Library" / "Safari" / "Extensions"
    ext_dir.mkdir(parents=True, exist_ok=True)
    (ext_dir / "OldExt.safariextz").touch()

    with patch.object(Path, "home", return_value=tmp_path):
        with patch("subprocess.run", side_effect=_fake_run_with_many_extensions()):
            check = mod.check(_make_profile())
            fix = mod.fix(check, Mode.MANUAL)

    # All actions should be SAFE
    assert all(a.risk_level == RiskLevel.SAFE for a in fix.actions)


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.safari_extensions.") for c in declared)
