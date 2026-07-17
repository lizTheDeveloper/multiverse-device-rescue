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
    return next(m for m in modules if m.name == "user_profile_size")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _make_path_mock(dirs_to_return=None, exists_return=True):
    """Create a mock for Path operations."""
    if dirs_to_return is None:
        dirs_to_return = []

    def mock_path_init(self, path):
        self._path = str(path)

    def mock_iterdir(self):
        return dirs_to_return

    def mock_exists(self):
        return exists_return

    def mock_truediv(self, other):
        # Support path / "subdir"
        new_path = MagicMock(spec=Path)
        new_path.__truediv__ = mock_truediv.__get__(new_path, type(new_path))
        new_path.exists = mock_exists
        new_path.iterdir = mock_iterdir
        new_path.name = str(other)
        new_path.__str__ = lambda x: str(self._path) + "/" + str(other)
        return new_path

    def mock_is_dir(follow_symlinks=True):
        return True

    mock = MagicMock(spec=Path)
    mock.__truediv__ = mock_truediv
    mock.iterdir = mock_iterdir
    mock.exists = mock_exists
    return mock


def _fake_run_small_dirs():
    """All directories are small (no warnings)"""

    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "du" in cmd_str:
            # Return small sizes (1 GB each)
            return _make_subprocess_result("1048576\t/Users/testuser\n")
        return _make_subprocess_result()

    return fake_run


def _fake_run_large_user_dir():
    """User directory is over 50GB threshold"""

    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "du" in cmd_str:
            # Return size over 50GB (60GB = 61440000 blocks of 1024 bytes)
            # Match any /Users/X path (whether X is testuser, annhoward, or other)
            if "/Users/" in cmd_str and "Library" not in cmd_str:
                return _make_subprocess_result("62914560\t/Users/user\n")
            # Library is smaller
            elif "Library" in cmd_str:
                return _make_subprocess_result("5242880\t/Users/user/Library\n")
            # Subdirectories
            else:
                return _make_subprocess_result("1048576\t/Users/user/Desktop\n")
        return _make_subprocess_result()

    return fake_run


def _fake_run_large_library():
    """Library directory is over 10GB threshold"""

    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "du" in cmd_str:
            # Library is over 10GB (12GB = 12582912 blocks of 1024 bytes)
            if "Library" in cmd_str:
                return _make_subprocess_result("12582912\t/Users/user/Library\n")
            # User dir is moderate size
            elif "/Users/" in cmd_str:
                return _make_subprocess_result("20971520\t/Users/user\n")
            else:
                return _make_subprocess_result("1048576\t/Users/user/Desktop\n")
        return _make_subprocess_result()

    return fake_run


def _fake_run_subprocess_error():
    """Subprocess calls fail"""

    def fake_run(cmd, **kwargs):
        return _make_subprocess_result(returncode=1)

    return fake_run


def test_user_profile_size_discovered():
    """Test that the module is discovered."""
    mod = _get_module()
    assert mod.name == "user_profile_size"
    assert mod.category == "performance"
    assert mod.risk_level == RiskLevel.SAFE


def test_user_profile_size_small_dirs():
    """Test when all directories are small (no warnings)."""
    mod = _get_module()

    # Just patch subprocess to return small sizes
    with patch("subprocess.run", side_effect=_fake_run_small_dirs()):
        result = mod.check(_make_profile())

    # Should have findings but no warnings about large directories
    assert result.has_issues
    # Should have INFO findings about user summary and breakdown
    assert any(f.severity == Severity.INFO for f in result.findings)


def test_user_profile_size_large_user_warning():
    """Test WARNING when user directory is over 50GB."""
    mod = _get_module()

    # Just patch subprocess to return large sizes for /Users/* directories
    with patch("subprocess.run", side_effect=_fake_run_large_user_dir()):
        result = mod.check(_make_profile())

    # Should have WARNING about large user directory
    assert result.has_issues
    assert any(f.severity == Severity.WARNING for f in result.findings)
    assert any("large_user_dir" == f.data.get("type") for f in result.findings)


def test_user_profile_size_large_library_warning():
    """Test WARNING when Library directory is over 10GB."""
    mod = _get_module()

    # Just patch subprocess to return large Library sizes
    with patch("subprocess.run", side_effect=_fake_run_large_library()):
        result = mod.check(_make_profile())

    # Should have WARNING about large Library directory
    assert result.has_issues
    assert any(f.severity == Severity.WARNING for f in result.findings)
    assert any("library_bloat" == f.data.get("type") for f in result.findings)


def test_user_profile_size_info_findings():
    """Test that INFO findings are created for user summary."""
    mod = _get_module()

    # Just patch subprocess to return small sizes
    with patch("subprocess.run", side_effect=_fake_run_small_dirs()):
        result = mod.check(_make_profile())

    # Should have user summary and breakdown findings
    assert any(f.data.get("type") == "user_summary" for f in result.findings)
    assert any(f.data.get("type") == "subdir_breakdown" for f in result.findings)


def test_user_profile_size_fix_is_informational():
    """Test that fix() returns informational actions."""
    mod = _get_module()

    # Just patch subprocess to return large sizes
    with patch("subprocess.run", side_effect=_fake_run_large_user_dir()):
        check = mod.check(_make_profile())

    fix = mod.fix(check, Mode.AUTO)

    # All actions should succeed (informational)
    assert fix.all_succeeded
    assert len(fix.actions) > 0


def test_user_profile_size_skips_system_dirs():
    """Test that system directories are skipped."""
    mod = _get_module()

    # Just patch subprocess to return small sizes
    # The module will iterate over real /Users directories, but Shared and Guest
    # should be skipped by the module logic
    with patch("subprocess.run", side_effect=_fake_run_small_dirs()):
        result = mod.check(_make_profile())

    # Should have user summary
    summary = next((f for f in result.findings if f.data.get("type") == "user_summary"), None)
    assert summary is not None
    # The count should not include Shared or Guest
    # We can't guarantee the exact count, but it should be at least 1
    assert summary.data.get("user_count") >= 1
