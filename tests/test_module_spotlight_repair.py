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
    return next(m for m in modules if m.name == "spotlight_repair")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_healthy():
    """Spotlight is enabled, active, healthy"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "mdutil -s" in cmd_str:
            return _make_subprocess_result(
                stdout="/: Indexing enabled. (Indexing enabled, Spotlight is waiting to be used)\n"
            )
        elif "ps -eo" in cmd_str:
            return _make_subprocess_result(
                stdout="PID PCPU COMM\n100 0.5 mds\n"
            )
        elif "defaults read" in cmd_str and "Spotlight" in cmd_str:
            return _make_subprocess_result(stderr="", returncode=1)
        return _make_subprocess_result()
    return fake_run


def _fake_run_disabled():
    """Spotlight is disabled on boot volume"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "mdutil -s" in cmd_str:
            return _make_subprocess_result(
                stdout="/: Indexing disabled.\n"
            )
        elif "ps -eo" in cmd_str:
            return _make_subprocess_result(
                stdout="PID PCPU COMM\n100 0.1 mds\n"
            )
        elif "defaults read" in cmd_str and "Spotlight" in cmd_str:
            return _make_subprocess_result(stderr="", returncode=1)
        return _make_subprocess_result()
    return fake_run


def _fake_run_high_cpu():
    """mds process using excessive CPU"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "mdutil -s" in cmd_str:
            return _make_subprocess_result(
                stdout="/: Indexing enabled. (Indexing enabled)\n"
            )
        elif "ps -eo" in cmd_str:
            return _make_subprocess_result(
                stdout="PID PCPU COMM\n100 75.2 mds\n200 2.0 chrome\n"
            )
        elif "defaults read" in cmd_str and "Spotlight" in cmd_str:
            return _make_subprocess_result(stderr="", returncode=1)
        return _make_subprocess_result()
    return fake_run


def _fake_run_large_index():
    """Spotlight index is very large"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "mdutil -s" in cmd_str:
            return _make_subprocess_result(
                stdout="/: Indexing enabled.\n"
            )
        elif "ps -eo" in cmd_str:
            return _make_subprocess_result(
                stdout="PID PCPU COMM\n100 0.3 mds\n"
            )
        elif "defaults read" in cmd_str and "Spotlight" in cmd_str:
            return _make_subprocess_result(stderr="", returncode=1)
        return _make_subprocess_result()
    return fake_run


def test_spotlight_healthy():
    """Test healthy Spotlight status (no warnings)"""
    module = _get_module()
    profile = _make_profile()

    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        with patch("os.walk", return_value=[]):
            result = module.check(profile)

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.severity == Severity.INFO
    assert "Spotlight indexing status" in finding.title
    assert finding.data["indexing_enabled"] is True
    assert finding.data["mds_cpu_percent"] == 0.5


def test_spotlight_disabled():
    """Test detection of disabled Spotlight on boot volume"""
    module = _get_module()
    profile = _make_profile()

    with patch("subprocess.run", side_effect=_fake_run_disabled()):
        with patch("os.walk", return_value=[]):
            result = module.check(profile)

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.severity == Severity.WARNING
    assert "disabled on boot volume" in finding.title
    assert finding.data["issue_type"] == "disabled_indexing"
    assert finding.data["indexing_enabled"] is False


def test_high_cpu_mds():
    """Test detection of mds consuming excessive CPU (>50%)"""
    module = _get_module()
    profile = _make_profile()

    with patch("subprocess.run", side_effect=_fake_run_high_cpu()):
        with patch("os.walk", return_value=[]):
            result = module.check(profile)

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.severity == Severity.WARNING
    assert "excessive CPU" in finding.title
    assert finding.data["issue_type"] == "high_cpu_usage"
    assert finding.data["mds_cpu_percent"] == 75.2
    assert finding.data["high_cpu_mds"] is True


def test_large_index_size():
    """Test detection of very large Spotlight index (>5GB)"""
    module = _get_module()
    profile = _make_profile()

    def fake_walk(path):
        if ".Spotlight-V100" in str(path):
            return [
                ("/Users/test/.Spotlight-V100", ["dir1"], ["file1", "file2"]),
                ("/Users/test/.Spotlight-V100/dir1", [], ["file3"]),
            ]
        return []

    with patch("subprocess.run", side_effect=_fake_run_large_index()):
        with patch("os.walk", side_effect=fake_walk):
            with patch("os.path.getsize") as mock_getsize:
                # Create files larger than 5GB total
                mock_getsize.side_effect = [
                    2 * 1024**3,  # 2GB
                    2 * 1024**3,  # 2GB
                    1.5 * 1024**3,  # 1.5GB - total 5.5GB
                ]
                with patch.object(Path, "home", return_value=Path("/Users/test")):
                    with patch.object(Path, "exists", return_value=True):
                        result = module.check(profile)

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.severity == Severity.WARNING
    assert "very large" in finding.title
    assert finding.data["issue_type"] == "large_index"
    assert finding.data["very_large_index"] is True
    assert finding.data["index_size_bytes"] > 5 * 1024**3


def test_excluded_paths_detection():
    """Test detection of excluded paths/volumes"""
    module = _get_module()
    profile = _make_profile()

    def fake_run_with_exclusions(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "mdutil -s" in cmd_str:
            return _make_subprocess_result(
                stdout="/: Indexing enabled.\n"
            )
        elif "ps -eo" in cmd_str:
            return _make_subprocess_result(
                stdout="PID PCPU COMM\n100 0.2 mds\n"
            )
        elif "defaults read" in cmd_str and "Spotlight" in cmd_str:
            return _make_subprocess_result(
                stdout='(\n    {\n        Path = "/Volumes/Backup";\n    },\n    {\n        Path = "/Volumes/TimeMachine";\n    }\n)\n'
            )
        return _make_subprocess_result()

    with patch("subprocess.run", side_effect=fake_run_with_exclusions):
        with patch("os.walk", return_value=[]):
            result = module.check(profile)

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.data["excluded_paths_count"] == 2
    assert "/Volumes/Backup" in finding.data["excluded_paths"]
    assert "/Volumes/TimeMachine" in finding.data["excluded_paths"]


def test_fix_disabled_indexing():
    """Test fix suggestion for disabled Spotlight"""
    module = _get_module()
    profile = _make_profile()

    with patch("subprocess.run", side_effect=_fake_run_disabled()):
        with patch("os.walk", return_value=[]):
            check_result = module.check(profile)

    fix_result = module.fix(check_result, Mode.AUTO)

    assert len(fix_result.actions) == 1
    action = fix_result.actions[0]
    assert "Rebuild Spotlight index" in action.title
    assert "sudo mdutil -E /" in action.description
    assert action.success is True
    assert action.risk_level == RiskLevel.SAFE


def test_fix_high_cpu():
    """Test fix suggestion for high CPU usage"""
    module = _get_module()
    profile = _make_profile()

    with patch("subprocess.run", side_effect=_fake_run_high_cpu()):
        with patch("os.walk", return_value=[]):
            check_result = module.check(profile)

    fix_result = module.fix(check_result, Mode.AUTO)

    assert len(fix_result.actions) == 1
    action = fix_result.actions[0]
    assert "Rebuild Spotlight index" in action.title
    assert "sudo mdutil -E /" in action.description
    assert action.risk_level == RiskLevel.SAFE


def test_fix_healthy():
    """Test fix suggestion for healthy Spotlight (no action needed)"""
    module = _get_module()
    profile = _make_profile()

    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        with patch("os.walk", return_value=[]):
            check_result = module.check(profile)

    fix_result = module.fix(check_result, Mode.AUTO)

    assert len(fix_result.actions) == 1
    action = fix_result.actions[0]
    assert "Spotlight repair status" in action.title
    assert "No repair needed" in action.description
    assert action.success is True
    assert action.risk_level == RiskLevel.SAFE


def test_module_attributes():
    """Test that module has correct attributes"""
    module = _get_module()

    assert module.name == "spotlight_repair"
    assert module.category == "performance"
    assert Platform.DARWIN in module.platforms
    assert module.risk_level == RiskLevel.SAFE
    assert isinstance(module.priority, int)
    assert isinstance(module.depends_on, list)


def test_mdutil_timeout():
    """Test graceful handling of mdutil timeout"""
    module = _get_module()
    profile = _make_profile()

    def fake_run_timeout(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "mdutil -s" in cmd_str:
            import subprocess
            raise subprocess.TimeoutExpired("mdutil", 5)
        elif "ps -eo" in cmd_str:
            return _make_subprocess_result(
                stdout="PID PCPU COMM\n100 0.1 mds\n"
            )
        elif "defaults read" in cmd_str and "Spotlight" in cmd_str:
            return _make_subprocess_result(stderr="", returncode=1)
        return _make_subprocess_result()

    with patch("subprocess.run", side_effect=fake_run_timeout):
        with patch("os.walk", return_value=[]):
            result = module.check(profile)

    # Should return findings despite timeout
    assert len(result.findings) >= 1
    finding = result.findings[0]
    # When mdutil times out, indexing_enabled defaults to False
    assert finding.data["indexing_enabled"] is False
