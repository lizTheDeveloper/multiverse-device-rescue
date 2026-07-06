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
    return next(m for m in modules if m.name == "spotlight_status")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_indexing_active():
    """Spotlight indexing is currently active"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "mdutil -s" in cmd_str:
            return _make_subprocess_result(
                stdout="/: Indexing enabled.\n"
            )
        elif "defaults read" in cmd_str and "Spotlight" in cmd_str:
            return _make_subprocess_result(stderr="", returncode=1)
        return _make_subprocess_result()
    return fake_run


def _fake_run_indexing_disabled():
    """Spotlight indexing is disabled"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "mdutil -s" in cmd_str:
            return _make_subprocess_result(
                stdout="/: Indexing disabled.\n"
            )
        elif "defaults read" in cmd_str and "Spotlight" in cmd_str:
            return _make_subprocess_result(stderr="", returncode=1)
        return _make_subprocess_result()
    return fake_run


def _fake_run_indexing_enabled():
    """Spotlight indexing is enabled but not currently active"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "mdutil -s" in cmd_str:
            return _make_subprocess_result(
                stdout="/: Indexing enabled. (Indexing enabled, Spotlight is waiting to be used)\n"
            )
        elif "defaults read" in cmd_str and "Spotlight" in cmd_str:
            return _make_subprocess_result(
                stdout='(\n    {\n        Path = "/Volumes/Backup";\n    },\n    {\n        Path = "/Volumes/Archive";\n    }\n)\n'
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_mdutil_timeout():
    """mdutil command times out"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "mdutil -s" in cmd_str:
            import subprocess
            raise subprocess.TimeoutExpired("mdutil", 5)
        elif "defaults read" in cmd_str and "Spotlight" in cmd_str:
            return _make_subprocess_result(stderr="", returncode=1)
        return _make_subprocess_result()
    return fake_run


def test_spotlight_active():
    """Test detection of active Spotlight indexing (WARNING)"""
    module = _get_module()
    profile = _make_profile()

    with patch("subprocess.run", side_effect=_fake_run_indexing_active()):
        with patch("os.walk", return_value=[]):
            result = module.check(profile)

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.severity == Severity.WARNING
    assert "currently active" in finding.title
    assert finding.data["indexing_active"] is True


def test_spotlight_disabled():
    """Test detection of disabled Spotlight indexing (INFO)"""
    module = _get_module()
    profile = _make_profile()

    with patch("subprocess.run", side_effect=_fake_run_indexing_disabled()):
        with patch("os.walk", return_value=[]):
            result = module.check(profile)

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.severity == Severity.INFO
    assert "disabled" in finding.description
    assert finding.data["indexing_enabled"] is False
    assert finding.data["indexing_active"] is False


def test_spotlight_enabled_not_active():
    """Test detection of enabled but not active Spotlight indexing"""
    module = _get_module()
    profile = _make_profile()

    with patch("subprocess.run", side_effect=_fake_run_indexing_enabled()):
        with patch("os.walk", return_value=[]):
            result = module.check(profile)

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.severity == Severity.INFO
    assert "enabled" in finding.description
    assert finding.data["indexing_enabled"] is True
    assert finding.data["indexing_active"] is False


def test_excluded_paths_detection():
    """Test detection of excluded paths"""
    module = _get_module()
    profile = _make_profile()

    with patch("subprocess.run", side_effect=_fake_run_indexing_enabled()):
        with patch("os.walk", return_value=[]):
            result = module.check(profile)

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.data["excluded_paths_count"] == 2
    assert "/Volumes/Backup" in finding.data["excluded_paths"]
    assert "/Volumes/Archive" in finding.data["excluded_paths"]


def test_mdutil_timeout():
    """Test graceful handling of mdutil timeout"""
    module = _get_module()
    profile = _make_profile()

    with patch("subprocess.run", side_effect=_fake_run_mdutil_timeout()):
        with patch("os.walk", return_value=[]):
            result = module.check(profile)

    # Should still return a finding with INFO severity and default values
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.severity == Severity.INFO
    assert finding.data["indexing_enabled"] is False


def test_index_size_calculation():
    """Test calculation of Spotlight index size"""
    module = _get_module()
    profile = _make_profile()

    # Mock os.walk to return fake directory structure
    def fake_walk(path):
        if ".Spotlight-V100" in str(path):
            return [
                ("/Users/test/.Spotlight-V100", ["dir1"], ["file1", "file2"]),
                ("/Users/test/.Spotlight-V100/dir1", [], ["file3"]),
            ]
        return []

    with patch("subprocess.run", side_effect=_fake_run_indexing_enabled()):
        with patch("os.walk", side_effect=fake_walk):
            with patch("os.path.getsize") as mock_getsize:
                mock_getsize.side_effect = [1024, 2048, 4096]  # 3 files
                with patch.object(Path, "home", return_value=Path("/Users/test")):
                    with patch.object(Path, "exists", return_value=True):
                        result = module.check(profile)

    assert len(result.findings) == 1
    finding = result.findings[0]
    # Total size: 1024 + 2048 + 4096 = 7168 bytes
    assert finding.data["index_size_bytes"] == 7168
    assert finding.data["index_accessible"] is True


def test_fix_with_active_indexing():
    """Test fix recommendation when indexing is active"""
    module = _get_module()
    profile = _make_profile()

    with patch("subprocess.run", side_effect=_fake_run_indexing_active()):
        with patch("os.walk", return_value=[]):
            check_result = module.check(profile)

    fix_result = module.fix(check_result, Mode.AUTO)

    assert len(fix_result.actions) == 1
    action = fix_result.actions[0]
    assert "Wait for Spotlight indexing" in action.title
    assert action.success is True
    assert action.risk_level == RiskLevel.SAFE


def test_fix_with_disabled_indexing():
    """Test fix recommendation when indexing is disabled"""
    module = _get_module()
    profile = _make_profile()

    with patch("subprocess.run", side_effect=_fake_run_indexing_disabled()):
        with patch("os.walk", return_value=[]):
            check_result = module.check(profile)

    fix_result = module.fix(check_result, Mode.AUTO)

    assert len(fix_result.actions) == 1
    action = fix_result.actions[0]
    assert "Spotlight status report" in action.title
    assert action.success is True
    assert action.risk_level == RiskLevel.SAFE


def test_module_attributes():
    """Test that module has correct attributes"""
    module = _get_module()

    assert module.name == "spotlight_status"
    assert module.category == "performance"
    assert Platform.DARWIN in module.platforms
    assert module.risk_level == RiskLevel.SAFE
    assert isinstance(module.priority, int)
    assert isinstance(module.depends_on, list)
