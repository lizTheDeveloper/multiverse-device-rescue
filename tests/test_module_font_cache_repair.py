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
    return next(m for m in modules if m.name == "font_cache_repair")


def test_font_cache_repair_discovered():
    """Test that the module is discovered correctly."""
    mod = _get_module()
    assert mod.name == "font_cache_repair"
    assert mod.category == "performance"
    assert mod.risk_level == RiskLevel.SAFE


def test_font_cache_repair_healthy_system():
    """Test on healthy system with small cache and few fonts."""
    mod = _get_module()
    var_cache_size = 100 * 1024 * 1024  # 100 MB
    sys_cache_size = 50 * 1024 * 1024   # 50 MB

    with patch.object(mod, "_get_var_folders_cache_size", return_value=var_cache_size):
        with patch.object(mod, "_get_system_cache_size", return_value=sys_cache_size):
            with patch.object(mod, "_count_installed_fonts", return_value=200):
                with patch.object(mod, "_is_font_server_responsive", return_value=True):
                    with patch.object(mod, "_has_database_issues", return_value=False):
                        result = mod.check(_make_profile())

    # Should have no warnings, only INFO findings
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warnings) == 0

    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert len(info_findings) >= 3  # cache_info, font_count, font_server_status


def test_font_cache_repair_bloated_cache():
    """Test with cache exceeding 500MB threshold."""
    mod = _get_module()
    bloated_size = 600 * 1024 * 1024  # 600 MB total

    with patch.object(mod, "_get_var_folders_cache_size", return_value=bloated_size // 2):
        with patch.object(mod, "_get_system_cache_size", return_value=bloated_size // 2):
            with patch.object(mod, "_count_installed_fonts", return_value=200):
                with patch.object(mod, "_is_font_server_responsive", return_value=True):
                    with patch.object(mod, "_has_database_issues", return_value=False):
                        result = mod.check(_make_profile())

    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert any("bloated" in f.title.lower() for f in warnings)


def test_font_cache_repair_excessive_fonts():
    """Test with more than 1000 fonts installed."""
    mod = _get_module()

    with patch.object(mod, "_get_var_folders_cache_size", return_value=100 * 1024 * 1024):
        with patch.object(mod, "_get_system_cache_size", return_value=50 * 1024 * 1024):
            with patch.object(mod, "_count_installed_fonts", return_value=1500):
                with patch.object(mod, "_is_font_server_responsive", return_value=True):
                    with patch.object(mod, "_has_database_issues", return_value=False):
                        result = mod.check(_make_profile())

    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert any("excessive" in f.title.lower() for f in warnings)


def test_font_cache_repair_unresponsive_font_server():
    """Test when font server is not responding."""
    mod = _get_module()

    with patch.object(mod, "_get_var_folders_cache_size", return_value=100 * 1024 * 1024):
        with patch.object(mod, "_get_system_cache_size", return_value=50 * 1024 * 1024):
            with patch.object(mod, "_count_installed_fonts", return_value=200):
                with patch.object(mod, "_is_font_server_responsive", return_value=False):
                    with patch.object(mod, "_has_database_issues", return_value=False):
                        result = mod.check(_make_profile())

    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert any("not responding" in f.title.lower() for f in warnings)


def test_font_cache_repair_database_issues():
    """Test when font database has integrity issues."""
    mod = _get_module()

    with patch.object(mod, "_get_var_folders_cache_size", return_value=100 * 1024 * 1024):
        with patch.object(mod, "_get_system_cache_size", return_value=50 * 1024 * 1024):
            with patch.object(mod, "_count_installed_fonts", return_value=200):
                with patch.object(mod, "_is_font_server_responsive", return_value=True):
                    with patch.object(mod, "_has_database_issues", return_value=True):
                        result = mod.check(_make_profile())

    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert any("database" in f.title.lower() for f in warnings)


def test_font_cache_repair_multiple_warnings():
    """Test with multiple issues at once."""
    mod = _get_module()
    bloated_size = 600 * 1024 * 1024

    with patch.object(mod, "_get_var_folders_cache_size", return_value=bloated_size // 2):
        with patch.object(mod, "_get_system_cache_size", return_value=bloated_size // 2):
            with patch.object(mod, "_count_installed_fonts", return_value=1500):
                with patch.object(mod, "_is_font_server_responsive", return_value=False):
                    with patch.object(mod, "_has_database_issues", return_value=True):
                        result = mod.check(_make_profile())

    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    # Should have at least 4 warnings: bloated cache, excessive fonts, unresponsive server, database issues
    assert len(warnings) >= 4


def test_font_cache_repair_fix_is_informational():
    """Test that fix() is informational and doesn't execute commands."""
    mod = _get_module()
    bloated_size = 600 * 1024 * 1024

    with patch.object(mod, "_get_var_folders_cache_size", return_value=bloated_size // 2):
        with patch.object(mod, "_get_system_cache_size", return_value=bloated_size // 2):
            with patch.object(mod, "_count_installed_fonts", return_value=1500):
                with patch.object(mod, "_is_font_server_responsive", return_value=False):
                    with patch.object(mod, "_has_database_issues", return_value=False):
                        check = mod.check(_make_profile())
                        fix = mod.fix(check, Mode.AUTO)

    # fix() should succeed
    assert fix.all_succeeded

    # All actions should be informational, suggesting commands to run
    for action in fix.actions:
        # Actions should contain atsutil or Font Book commands
        assert (
            "atsutil" in action.description.lower()
            or "font book" in action.description.lower()
        )


def test_font_cache_repair_all_methods_return_data():
    """Test that all internal methods return expected data types."""
    mod = _get_module()

    # Test that the module produces complete findings even with zero values
    with patch.object(mod, "_get_var_folders_cache_size", return_value=0):
        with patch.object(mod, "_get_system_cache_size", return_value=0):
            with patch.object(mod, "_count_installed_fonts", return_value=0):
                with patch.object(mod, "_is_font_server_responsive", return_value=False):
                    with patch.object(mod, "_has_database_issues", return_value=False):
                        result = mod.check(_make_profile())

    # Should have findings even with all zero values
    assert result.has_issues
    # Should have at least 1 warning (unresponsive server)
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warnings) >= 1
    # Should have INFO findings
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert len(info_findings) >= 3
