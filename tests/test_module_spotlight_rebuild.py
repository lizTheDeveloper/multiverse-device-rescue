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
    return next(m for m in modules if m.name == "spotlight_rebuild")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_healthy():
    """Normal case: Spotlight enabled, actively indexing, normal CPU, reasonable index size"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "mdutil" in cmd_str and "-s /" in cmd_str:
            return _make_subprocess_result(
                "/: Indexing enabled. (Spotlight is running)\n"
            )
        elif "ps" in cmd_str and "-eo" in cmd_str:
            return _make_subprocess_result(
                "PID %CPU COMMAND\n"
                "1 0.0 kernel_task\n"
                "123 2.5 mds\n"
                "124 1.0 mds_stores\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_stuck_indexing():
    """Stuck indexing: Spotlight enabled but waiting (not actively indexing)"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "mdutil" in cmd_str and "-s /" in cmd_str:
            return _make_subprocess_result(
                "/: Indexing enabled. (Spotlight is waiting for network to stabilize)\n"
            )
        elif "ps" in cmd_str and "-eo" in cmd_str:
            return _make_subprocess_result(
                "PID %CPU COMMAND\n"
                "1 0.0 kernel_task\n"
                "123 2.5 mds\n"
                "124 1.0 mds_stores\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_high_cpu_mds():
    """High CPU: mds process consuming >50% CPU"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "mdutil" in cmd_str and "-s /" in cmd_str:
            return _make_subprocess_result(
                "/: Indexing enabled. (Spotlight is running)\n"
            )
        elif "ps" in cmd_str and "-eo" in cmd_str:
            return _make_subprocess_result(
                "PID %CPU COMMAND\n"
                "1 0.0 kernel_task\n"
                "123 65.5 mds\n"
                "124 15.0 mds_stores\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_large_index():
    """Large index: >5GB"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "mdutil" in cmd_str and "-s /" in cmd_str:
            return _make_subprocess_result(
                "/: Indexing enabled. (Spotlight is running)\n"
            )
        elif "ps" in cmd_str and "-eo" in cmd_str:
            return _make_subprocess_result(
                "PID %CPU COMMAND\n"
                "1 0.0 kernel_task\n"
                "123 2.5 mds\n"
                "124 1.0 mds_stores\n"
            )
        return _make_subprocess_result()
    return fake_run


def test_spotlight_rebuild_discovered():
    mod = _get_module()
    assert mod.name == "spotlight_rebuild"
    assert mod.category == "performance"
    assert mod.risk_level == RiskLevel.SAFE


def test_spotlight_rebuild_healthy():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        with patch("pathlib.Path.home") as mock_home:
            mock_home.return_value = Path("/Users/testuser")
            with patch("pathlib.Path.exists", return_value=False):
                result = mod.check(_make_profile())
    # Should have INFO finding, no warnings
    assert result.has_issues
    assert any(f.severity == Severity.INFO for f in result.findings)
    assert not any(f.severity == Severity.WARNING for f in result.findings)


def test_spotlight_rebuild_stuck_indexing():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_stuck_indexing()):
        with patch("pathlib.Path.home") as mock_home:
            mock_home.return_value = Path("/Users/testuser")
            with patch("pathlib.Path.exists", return_value=False):
                result = mod.check(_make_profile())
    # Should have WARNING about stuck indexing
    assert result.has_issues
    assert any(
        f.severity == Severity.WARNING
        and f.data.get("issue_type") == "stuck_indexing"
        for f in result.findings
    )


def test_spotlight_rebuild_high_cpu_mds():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_high_cpu_mds()):
        with patch("pathlib.Path.home") as mock_home:
            mock_home.return_value = Path("/Users/testuser")
            with patch("pathlib.Path.exists", return_value=False):
                result = mod.check(_make_profile())
    # Should have WARNING about high CPU
    assert result.has_issues
    assert any(
        f.severity == Severity.WARNING
        and f.data.get("issue_type") == "high_cpu_usage"
        for f in result.findings
    )
    # Verify CPU percentage is captured
    assert any(
        f.data.get("mds_cpu_percent", 0) > 50
        for f in result.findings
    )


def test_spotlight_rebuild_large_index():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_large_index()):
        with patch("pathlib.Path.home") as mock_home:
            mock_home.return_value = Path("/Users/testuser")
            # Mock the index size check
            def mock_walk(path):
                # Return one "file" that's 6GB
                return [
                    ("/Users/testuser/.Spotlight-V100", [], ["store.db"]),
                ]

            def mock_getsize(path):
                # Return 6GB
                return 6 * 1024**3

            with patch("os.walk", mock_walk):
                with patch("os.path.getsize", mock_getsize):
                    with patch("pathlib.Path.exists", return_value=True):
                        result = mod.check(_make_profile())
    # Should have WARNING about large index
    assert result.has_issues
    assert any(
        f.severity == Severity.WARNING
        and f.data.get("issue_type") == "large_index"
        for f in result.findings
    )


def test_spotlight_rebuild_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_stuck_indexing()):
        with patch("pathlib.Path.home") as mock_home:
            mock_home.return_value = Path("/Users/testuser")
            with patch("pathlib.Path.exists", return_value=False):
                check = mod.check(_make_profile())
                fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action
    assert len(fix.actions) > 0
    # Actions should be SAFE risk level
    assert all(a.risk_level == RiskLevel.SAFE for a in fix.actions)
