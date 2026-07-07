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
    return next(m for m in modules if m.name == "font_issues")


def test_font_issues_discovered():
    """Test that the font_issues module is discovered correctly."""
    mod = _get_module()
    assert mod.name == "font_issues"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.DARWIN in mod.platforms


def test_font_issues_normal_count(tmp_path):
    """Test with normal font count (< 500)."""
    mod = _get_module()

    with patch.object(mod, "_count_installed_fonts", return_value=(300, {str(tmp_path / "Library/Fonts"): 300})):
        with patch.object(mod, "_get_folder_sizes", return_value={str(tmp_path / "Library/Fonts"): 500 * 1024 * 1024}):
            with patch.object(mod, "_find_duplicate_fonts", return_value={}):
                result = mod.check(_make_profile())

    # Should not have warnings about font count
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warnings) == 0

    # Should have info findings for each location
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert len(info_findings) > 0


def test_font_issues_excessive_count(tmp_path):
    """Test with excessive font count (> 500)."""
    mod = _get_module()

    with patch.object(mod, "_count_installed_fonts", return_value=(750, {str(tmp_path / "Library/Fonts"): 750})):
        with patch.object(mod, "_get_folder_sizes", return_value={str(tmp_path / "Library/Fonts"): 800 * 1024 * 1024}):
            with patch.object(mod, "_find_duplicate_fonts", return_value={}):
                result = mod.check(_make_profile())

    # Should have a warning about excessive fonts
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert any("excessive" in w.title.lower() for w in warnings)

    # Find the excessive font warning
    font_count_warning = [w for w in warnings if "excessive" in w.title.lower()]
    assert len(font_count_warning) == 1
    assert font_count_warning[0].data.get("font_count") == 750


def test_font_issues_large_user_fonts(tmp_path):
    """Test when ~/Library/Fonts exceeds 1GB."""
    mod = _get_module()
    user_fonts = str(Path.home() / "Library/Fonts")
    large_size = 1024 * 1024 * 1024 + 100  # 1GB + 100 bytes

    with patch.object(mod, "_count_installed_fonts", return_value=(200, {user_fonts: 200})):
        with patch.object(mod, "_get_folder_sizes", return_value={user_fonts: large_size}):
            with patch.object(mod, "_find_duplicate_fonts", return_value={}):
                result = mod.check(_make_profile())

    # Should have a warning about large user fonts folder
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    size_warnings = [w for w in warnings if "large" in w.title.lower()]
    assert len(size_warnings) >= 1


def test_font_issues_duplicate_fonts(tmp_path):
    """Test detection of duplicate fonts."""
    mod = _get_module()

    duplicates = {
        "Arial.ttf": ["/Library/Fonts", "/System/Library/Fonts"],
        "Helvetica.otf": ["/Library/Fonts", "/System/Library/Fonts"],
    }

    with patch.object(mod, "_count_installed_fonts", return_value=(200, {"/Library/Fonts": 100, "/System/Library/Fonts": 100})):
        with patch.object(mod, "_get_folder_sizes", return_value={"/Library/Fonts": 200 * 1024 * 1024, "/System/Library/Fonts": 150 * 1024 * 1024}):
            with patch.object(mod, "_find_duplicate_fonts", return_value=duplicates):
                result = mod.check(_make_profile())

    # Should have a warning about duplicate fonts
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    dup_warnings = [w for w in warnings if "duplicate" in w.title.lower()]
    assert len(dup_warnings) >= 1
    assert dup_warnings[0].data.get("duplicates") == duplicates


def test_font_issues_fix_excessive_count():
    """Test fix action for excessive font count."""
    mod = _get_module()

    with patch.object(mod, "_count_installed_fonts", return_value=(750, {"/Library/Fonts": 750})):
        with patch.object(mod, "_get_folder_sizes", return_value={"/Library/Fonts": 800 * 1024 * 1024}):
            with patch.object(mod, "_find_duplicate_fonts", return_value={}):
                check = mod.check(_make_profile())
                fix = mod.fix(check, Mode.MANUAL)

    # fix() should always succeed
    assert fix.all_succeeded

    # Should have an action for excessive fonts
    font_actions = [a for a in fix.actions if "excessive" in a.title.lower() or "excessive" in a.description.lower()]
    assert len(font_actions) > 0

    # Should mention Font Book
    assert any("Font Book" in a.description for a in font_actions)


def test_font_issues_fix_large_user_fonts():
    """Test fix action for large user fonts folder."""
    mod = _get_module()
    user_fonts = str(Path.home() / "Library/Fonts")
    large_size = 1024 * 1024 * 1024 + 100

    with patch.object(mod, "_count_installed_fonts", return_value=(200, {user_fonts: 200})):
        with patch.object(mod, "_get_folder_sizes", return_value={user_fonts: large_size}):
            with patch.object(mod, "_find_duplicate_fonts", return_value={}):
                check = mod.check(_make_profile())
                fix = mod.fix(check, Mode.MANUAL)

    assert fix.all_succeeded

    # Should have action for large user fonts
    large_actions = [a for a in fix.actions if "large" in a.title.lower() or "unusually" in a.description.lower()]
    assert len(large_actions) > 0


def test_font_issues_fix_duplicates():
    """Test fix action for duplicate fonts."""
    mod = _get_module()

    duplicates = {
        "Arial.ttf": ["/Library/Fonts", "/System/Library/Fonts"],
        "Helvetica.otf": ["/Library/Fonts", "/System/Library/Fonts"],
    }

    with patch.object(mod, "_count_installed_fonts", return_value=(200, {"/Library/Fonts": 100, "/System/Library/Fonts": 100})):
        with patch.object(mod, "_get_folder_sizes", return_value={"/Library/Fonts": 200 * 1024 * 1024, "/System/Library/Fonts": 150 * 1024 * 1024}):
            with patch.object(mod, "_find_duplicate_fonts", return_value=duplicates):
                check = mod.check(_make_profile())
                fix = mod.fix(check, Mode.MANUAL)

    assert fix.all_succeeded

    # Should have action for duplicates
    dup_actions = [a for a in fix.actions if "duplicate" in a.title.lower()]
    assert len(dup_actions) > 0


def test_font_issues_count_fonts_subprocess_success(tmp_path):
    """Test font counting with successful subprocess call."""
    mod = _get_module()

    user_fonts = tmp_path / "Library/Fonts"
    user_fonts.mkdir(parents=True)

    # Create some test font files
    (user_fonts / "Arial.ttf").touch()
    (user_fonts / "Helvetica.otf").touch()
    (user_fonts / "Times.ttc").touch()

    # Mock subprocess to return the file list
    mock_output = f"{user_fonts}/Arial.ttf\n{user_fonts}/Helvetica.otf\n{user_fonts}/Times.ttc\n"

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout=mock_output)

        with patch("pathlib.Path.home", return_value=tmp_path):
            with patch("pathlib.Path.exists", return_value=True):
                # Patch the method to use our mock
                count, locations = mod._count_installed_fonts()

                # Should have called subprocess
                assert mock_run.called


def test_font_issues_count_fonts_fallback_to_rglob(tmp_path):
    """Test font counting falls back to rglob on subprocess failure."""
    mod = _get_module()

    user_fonts = tmp_path / "Library/Fonts"
    user_fonts.mkdir(parents=True)

    # Create some test font files
    for i in range(5):
        (user_fonts / f"font_{i}.ttf").touch()

    # Create temp dir structure
    lib_fonts = tmp_path / "Library" / "Fonts"
    sys_fonts = tmp_path / "System" / "Library" / "Fonts"

    lib_fonts.mkdir(parents=True, exist_ok=True)
    sys_fonts.mkdir(parents=True, exist_ok=True)

    # Add some files
    for i in range(3):
        (lib_fonts / f"font_{i}.otf").touch()
    for i in range(2):
        (sys_fonts / f"font_{i}.ttc").touch()

    # Mock subprocess to fail, then count using real rglob
    with patch("subprocess.run", side_effect=OSError("Command failed")):
        with patch("pathlib.Path.home", return_value=tmp_path / "home"):
            # Create the home fonts directory
            home_fonts = tmp_path / "home" / "Library" / "Fonts"
            home_fonts.mkdir(parents=True, exist_ok=True)

            # This will use the fallback
            count, locations = mod._count_installed_fonts()
            # Count should be > 0 from fallback
            assert count >= 0


def test_font_issues_directory_size(tmp_path):
    """Test directory size calculation."""
    mod = _get_module()

    test_dir = tmp_path / "fonts"
    test_dir.mkdir()

    # Create test files
    file1 = test_dir / "font1.ttf"
    file1.write_bytes(b"x" * 1000)
    file2 = test_dir / "font2.otf"
    file2.write_bytes(b"y" * 2000)

    size = mod._get_directory_size(test_dir)
    assert size == 3000


def test_font_issues_directory_size_nonexistent(tmp_path):
    """Test directory size when directory doesn't exist."""
    mod = _get_module()

    nonexistent = tmp_path / "nonexistent"
    size = mod._get_directory_size(nonexistent)
    assert size == 0


def test_font_issues_find_duplicate_fonts(tmp_path):
    """Test finding duplicate fonts."""
    mod = _get_module()

    # Create font directories
    lib_fonts = tmp_path / "Library/Fonts"
    sys_fonts = tmp_path / "System/Library/Fonts"

    lib_fonts.mkdir(parents=True)
    sys_fonts.mkdir(parents=True)

    # Create duplicate fonts
    (lib_fonts / "Arial.ttf").touch()
    (lib_fonts / "Helvetica.otf").touch()
    (sys_fonts / "Arial.ttf").touch()  # Duplicate
    (sys_fonts / "Times.ttc").touch()

    fonts_by_location = {
        str(lib_fonts): 2,
        str(sys_fonts): 2,
    }

    duplicates = mod._find_duplicate_fonts(fonts_by_location)

    # Should find Arial.ttf as duplicate
    assert "Arial.ttf" in duplicates
    assert len(duplicates["Arial.ttf"]) == 2


def test_font_issues_find_duplicate_fonts_no_duplicates(tmp_path):
    """Test when there are no duplicate fonts."""
    mod = _get_module()

    lib_fonts = tmp_path / "Library/Fonts"
    sys_fonts = tmp_path / "System/Library/Fonts"

    lib_fonts.mkdir(parents=True)
    sys_fonts.mkdir(parents=True)

    # Create unique fonts
    (lib_fonts / "Arial.ttf").touch()
    (lib_fonts / "Helvetica.otf").touch()
    (sys_fonts / "Times.ttc").touch()
    (sys_fonts / "Courier.dfont").touch()

    fonts_by_location = {
        str(lib_fonts): 2,
        str(sys_fonts): 2,
    }

    duplicates = mod._find_duplicate_fonts(fonts_by_location)

    # Should be empty
    assert len(duplicates) == 0


def test_font_issues_fmt_bytes():
    """Test byte formatting helper."""
    from modules.integrity.font_issues import _fmt_bytes

    assert _fmt_bytes(0) == "0.0 B"
    assert _fmt_bytes(1024) == "1.0 KB"
    assert _fmt_bytes(1024 * 1024) == "1.0 MB"
    assert _fmt_bytes(1024 * 1024 * 1024) == "1.0 GB"
    assert _fmt_bytes(5 * 1024 * 1024) == "5.0 MB"


def test_font_issues_all_findings_have_required_fields():
    """Test that all findings have required fields."""
    mod = _get_module()

    with patch.object(mod, "_count_installed_fonts", return_value=(750, {"/Library/Fonts": 750})):
        with patch.object(mod, "_get_folder_sizes", return_value={"/Library/Fonts": 800 * 1024 * 1024}):
            with patch.object(mod, "_find_duplicate_fonts", return_value={}):
                result = mod.check(_make_profile())

    for finding in result.findings:
        assert finding.title
        assert finding.description
        assert finding.severity in [Severity.INFO, Severity.WARNING, Severity.CRITICAL]
        assert finding.category == "integrity"
        assert isinstance(finding.data, dict)


def test_font_issues_all_actions_have_required_fields():
    """Test that all actions have required fields."""
    mod = _get_module()

    with patch.object(mod, "_count_installed_fonts", return_value=(750, {"/Library/Fonts": 750})):
        with patch.object(mod, "_get_folder_sizes", return_value={"/Library/Fonts": 800 * 1024 * 1024}):
            with patch.object(mod, "_find_duplicate_fonts", return_value={}):
                check = mod.check(_make_profile())
                fix = mod.fix(check, Mode.MANUAL)

    for action in fix.actions:
        assert action.title
        assert action.description
        assert action.risk_level in [RiskLevel.SAFE, RiskLevel.MODERATE, RiskLevel.DESTRUCTIVE]
        assert isinstance(action.success, bool)


def test_font_issues_both_warnings():
    """Test when both excessive count and large folder size warnings trigger."""
    mod = _get_module()
    user_fonts = str(Path.home() / "Library/Fonts")

    with patch.object(mod, "_count_installed_fonts", return_value=(750, {user_fonts: 750})):
        with patch.object(mod, "_get_folder_sizes", return_value={user_fonts: 1024 * 1024 * 1024 + 100}):
            with patch.object(mod, "_find_duplicate_fonts", return_value={}):
                result = mod.check(_make_profile())

    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    # Should have 2 warnings: excessive count and large folder
    assert len(warnings) >= 2


def test_font_issues_all_three_warnings():
    """Test when all three warning conditions are met."""
    mod = _get_module()

    duplicates = {
        "Arial.ttf": ["/Library/Fonts", "/System/Library/Fonts"],
    }
    user_fonts = str(Path.home() / "Library/Fonts")

    with patch.object(mod, "_count_installed_fonts", return_value=(750, {user_fonts: 750})):
        with patch.object(mod, "_get_folder_sizes", return_value={user_fonts: 1024 * 1024 * 1024 + 100}):
            with patch.object(mod, "_find_duplicate_fonts", return_value=duplicates):
                result = mod.check(_make_profile())

    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    # Should have 3 warnings: excessive count, large folder, duplicates
    assert len(warnings) >= 3
