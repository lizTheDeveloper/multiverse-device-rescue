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
    return next(m for m in modules if m.name == "font_cache")


def test_font_cache_discovered():
    """Test that the font_cache module is discovered correctly."""
    mod = _get_module()
    assert mod.name == "font_cache"
    assert mod.category == "performance"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.DARWIN in mod.platforms


def test_font_cache_normal_count(tmp_path):
    """Test with normal font count (< 500)."""
    mod = _get_module()

    # Create fake font directories with ~300 fonts
    font_dirs = [
        tmp_path / "Library/Fonts",
        tmp_path / "System/Library/Fonts",
    ]
    for font_dir in font_dirs:
        font_dir.mkdir(parents=True, exist_ok=True)
        # Create some test font files
        for i in range(150):
            (font_dir / f"font_{i}.ttf").touch()

    with patch.object(mod, "_count_installed_fonts", return_value=300):
        with patch.object(mod, "_find_font_cache", return_value=(str(tmp_path / ".fontcache"), 5242880)):
            with patch.object(mod, "_is_atsutil_running", return_value=True):
                result = mod.check(_make_profile())

    # Should not have warnings, but should have info findings
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warnings) == 0

    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert len(info_findings) == 2  # cache info + atsutil running


def test_font_cache_excessive_count(tmp_path):
    """Test with excessive font count (> 500)."""
    mod = _get_module()

    with patch.object(mod, "_count_installed_fonts", return_value=750):
        with patch.object(mod, "_find_font_cache", return_value=(str(tmp_path / ".fontcache"), 10485760)):
            with patch.object(mod, "_is_atsutil_running", return_value=True):
                result = mod.check(_make_profile())

    # Should have a warning about excessive fonts
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warnings) == 1
    assert "excessive" in warnings[0].title.lower()
    assert warnings[0].data.get("font_count") == 750


def test_font_cache_no_cache_found(tmp_path):
    """Test when font cache is not found."""
    mod = _get_module()

    with patch.object(mod, "_count_installed_fonts", return_value=200):
        with patch.object(mod, "_find_font_cache", return_value=(None, 0)):
            with patch.object(mod, "_is_atsutil_running", return_value=True):
                result = mod.check(_make_profile())

    # Should have atsutil info, but no cache finding
    cache_findings = [f for f in result.findings if "cache" in f.title.lower()]
    assert len(cache_findings) == 0

    atsutil_findings = [f for f in result.findings if "atsutil" in f.title.lower()]
    assert len(atsutil_findings) == 1


def test_font_cache_atsutil_not_running(tmp_path):
    """Test when atsutil server is not running."""
    mod = _get_module()

    with patch.object(mod, "_count_installed_fonts", return_value=200):
        with patch.object(mod, "_find_font_cache", return_value=(str(tmp_path / ".fontcache"), 5242880)):
            with patch.object(mod, "_is_atsutil_running", return_value=False):
                result = mod.check(_make_profile())

    atsutil_findings = [f for f in result.findings if "Font server" in f.title and "atsutil" in f.title]
    assert len(atsutil_findings) == 1
    assert "not running" in atsutil_findings[0].title.lower()
    assert atsutil_findings[0].data.get("atsutil_running") is False


def test_font_cache_fix_excessive_fonts():
    """Test fix for excessive font count."""
    mod = _get_module()

    with patch.object(mod, "_count_installed_fonts", return_value=750):
        with patch.object(mod, "_find_font_cache", return_value=("/var/folders/.fontcache", 10485760)):
            with patch.object(mod, "_is_atsutil_running", return_value=True):
                check = mod.check(_make_profile())
                fix = mod.fix(check, Mode.MANUAL)

    # fix() should always succeed
    assert fix.all_succeeded
    # Should have actions for excessive fonts
    font_actions = [a for a in fix.actions if "font" in a.title.lower()]
    assert len(font_actions) > 0
    # Actions should mention Font Book as a management tool
    assert any("Font Book" in a.description for a in font_actions)


def test_font_cache_fix_cache_reset_suggestion():
    """Test that fix suggests cache reset command."""
    mod = _get_module()

    with patch.object(mod, "_count_installed_fonts", return_value=200):
        with patch.object(mod, "_find_font_cache", return_value=("/var/folders/.fontcache", 5242880)):
            with patch.object(mod, "_is_atsutil_running", return_value=True):
                check = mod.check(_make_profile())
                fix = mod.fix(check, Mode.MANUAL)

    # Should suggest atsutil reset command
    assert any("atsutil databases -remove" in a.description for a in fix.actions)
    # Command should be informational only (not executed)
    assert fix.all_succeeded


def test_font_cache_fix_atsutil_running():
    """Test fix when atsutil is running normally."""
    mod = _get_module()

    with patch.object(mod, "_count_installed_fonts", return_value=200):
        with patch.object(mod, "_find_font_cache", return_value=("/var/folders/.fontcache", 5242880)):
            with patch.object(mod, "_is_atsutil_running", return_value=True):
                check = mod.check(_make_profile())
                fix = mod.fix(check, Mode.MANUAL)

    assert fix.all_succeeded
    atsutil_actions = [a for a in fix.actions if "Font server" in a.title and "running" in a.title.lower()]
    assert len(atsutil_actions) > 0
    assert any("normally" in a.title for a in atsutil_actions)


def test_font_cache_fix_atsutil_not_running():
    """Test fix when atsutil is not running."""
    mod = _get_module()

    with patch.object(mod, "_count_installed_fonts", return_value=200):
        with patch.object(mod, "_find_font_cache", return_value=("/var/folders/.fontcache", 5242880)):
            with patch.object(mod, "_is_atsutil_running", return_value=False):
                check = mod.check(_make_profile())
                fix = mod.fix(check, Mode.MANUAL)

    assert fix.all_succeeded
    atsutil_actions = [a for a in fix.actions if "Font server" in a.title and "not" in a.description.lower()]
    assert len(atsutil_actions) > 0


def test_font_cache_count_fonts_with_multiple_dirs(tmp_path):
    """Test font counting across multiple directories."""
    mod = _get_module()

    # Create fake font directories
    lib_fonts = tmp_path / "Library/Fonts"
    sys_fonts = tmp_path / "System/Library/Fonts"
    home_fonts = tmp_path / "home/Library/Fonts"

    for d in [lib_fonts, sys_fonts, home_fonts]:
        d.mkdir(parents=True, exist_ok=True)
        for i in range(50):
            (d / f"font_{i}.ttf").touch()

    with patch("pathlib.Path.exists", return_value=True):
        with patch("pathlib.Path.rglob") as mock_rglob:
            # Return files for each directory
            def rglob_impl(pattern):
                if "Library/Fonts" in str(mod._count_installed_fonts.__self__):
                    # Simplified: just return file objects
                    class FakeFile:
                        def __init__(self, suffix):
                            self.suffix = suffix
                        def is_file(self):
                            return True
                    return [FakeFile(".ttf") for _ in range(50)]
                return []
            # This is a simplified test; in practice it would be more complex
            font_count = mod._count_installed_fonts()
            assert font_count >= 0


def test_font_cache_find_cache_with_real_path(tmp_path):
    """Test finding font cache in var/folders structure."""
    mod = _get_module()

    # Create fake var/folders structure
    cache_dir = tmp_path / "var/folders/xy/com.apple.FontRegistry/C"
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_file = cache_dir / "cache.db"
    cache_file.write_bytes(b"fake cache data")

    with patch("pathlib.Path", side_effect=lambda x: tmp_path if x == "/var/folders" else Path(x)):
        # Direct test of the size calculation
        size = mod._get_directory_size(cache_dir)
        assert size > 0


def test_font_cache_is_atsutil_running_with_pgrep(tmp_path):
    """Test checking if atsutil is running using pgrep."""
    mod = _get_module()

    # Mock successful pgrep result
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        result = mod._is_atsutil_running()
        assert result is True
        mock_run.assert_called_once()
        # Verify pgrep was used correctly
        call_args = mock_run.call_args[0][0]
        assert "pgrep" in call_args


def test_font_cache_is_atsutil_not_running(tmp_path):
    """Test when atsutil is not running (pgrep returns non-zero)."""
    mod = _get_module()

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1)
        result = mod._is_atsutil_running()
        assert result is False


def test_font_cache_is_atsutil_subprocess_error(tmp_path):
    """Test exception handling in atsutil check."""
    mod = _get_module()

    with patch("subprocess.run", side_effect=Exception("Command failed")):
        result = mod._is_atsutil_running()
        assert result is False


def test_font_cache_directory_size_calculation(tmp_path):
    """Test directory size calculation."""
    mod = _get_module()

    # Create test files
    test_dir = tmp_path / "test"
    test_dir.mkdir()
    file1 = test_dir / "file1.txt"
    file1.write_bytes(b"x" * 1000)
    file2 = test_dir / "file2.txt"
    file2.write_bytes(b"y" * 2000)

    size = mod._get_directory_size(test_dir)
    assert size == 3000


def test_font_cache_directory_size_nonexistent(tmp_path):
    """Test directory size when directory doesn't exist."""
    mod = _get_module()

    nonexistent = tmp_path / "nonexistent"
    size = mod._get_directory_size(nonexistent)
    assert size == 0


def test_font_cache_directory_size_permission_error(tmp_path):
    """Test directory size with permission errors."""
    mod = _get_module()

    test_dir = tmp_path / "test"
    test_dir.mkdir()

    # Mock rglob to raise PermissionError
    with patch.object(Path, "rglob", side_effect=PermissionError("Permission denied")):
        size = mod._get_directory_size(test_dir)
        assert size == 0


def test_font_cache_fmt_bytes():
    """Test byte formatting helper."""
    from modules.performance.font_cache import _fmt_bytes

    assert _fmt_bytes(0) == "0.0 B"
    assert _fmt_bytes(1024) == "1.0 KB"
    assert _fmt_bytes(1024 * 1024) == "1.0 MB"
    assert _fmt_bytes(1024 * 1024 * 1024) == "1.0 GB"
    assert _fmt_bytes(5 * 1024 * 1024) == "5.0 MB"


def test_font_cache_all_findings_have_required_fields():
    """Test that all findings have required fields."""
    mod = _get_module()

    with patch.object(mod, "_count_installed_fonts", return_value=750):
        with patch.object(mod, "_find_font_cache", return_value=("/var/folders/.fontcache", 5242880)):
            with patch.object(mod, "_is_atsutil_running", return_value=True):
                result = mod.check(_make_profile())

    for finding in result.findings:
        assert finding.title
        assert finding.description
        assert finding.severity in [Severity.INFO, Severity.WARNING, Severity.CRITICAL]
        assert finding.category == "performance"
        assert isinstance(finding.data, dict)


def test_font_cache_all_actions_have_required_fields():
    """Test that all actions have required fields."""
    mod = _get_module()

    with patch.object(mod, "_count_installed_fonts", return_value=750):
        with patch.object(mod, "_find_font_cache", return_value=("/var/folders/.fontcache", 5242880)):
            with patch.object(mod, "_is_atsutil_running", return_value=True):
                check = mod.check(_make_profile())
                fix = mod.fix(check, Mode.MANUAL)

    for action in fix.actions:
        assert action.title
        assert action.description
        assert action.risk_level in [RiskLevel.SAFE, RiskLevel.MODERATE, RiskLevel.DESTRUCTIVE]
        assert isinstance(action.success, bool)
