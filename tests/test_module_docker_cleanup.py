import sys
import json
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
    return next(m for m in modules if m.name == "docker_cleanup")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_docker_not_installed():
    """Docker is not installed"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and cmd[0] == "which" and "docker" in cmd:
            return _make_subprocess_result(stdout="", returncode=1)
        return _make_subprocess_result()

    return fake_run


def _fake_run_docker_healthy():
    """Normal case: Docker installed with low usage"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            if cmd[0] == "which" and "docker" in cmd:
                return _make_subprocess_result(stdout="/usr/local/bin/docker\n")
            elif cmd[0] == "docker" and cmd[1] == "system" and cmd[2] == "df":
                # Return JSON format with low usage
                data = {
                    "Images": "5.2 GB",
                    "Containers": "500 MB",
                    "Volumes": "100 MB",
                }
                return _make_subprocess_result(stdout=json.dumps(data) + "\n")
            elif cmd[0] == "docker" and cmd[1] == "images" and any("dangling" in str(c) for c in cmd):
                # No dangling images
                return _make_subprocess_result(stdout="")
            elif cmd[0] == "docker" and cmd[1] == "ps" and any("exited" in str(c) for c in cmd):
                # Few stopped containers
                return _make_subprocess_result(stdout="container1\ncontainer2\n")
        return _make_subprocess_result()

    return fake_run


def _fake_run_high_docker_usage():
    """High Docker usage scenario"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            if cmd[0] == "which" and "docker" in cmd:
                return _make_subprocess_result(stdout="/usr/local/bin/docker\n")
            elif cmd[0] == "docker" and cmd[1] == "system" and cmd[2] == "df":
                # Return JSON format with high usage (>20GB)
                data = {
                    "Images": "15.2 GB",
                    "Containers": "8.5 GB",
                    "Volumes": "2.1 GB",
                }
                return _make_subprocess_result(stdout=json.dumps(data) + "\n")
            elif cmd[0] == "docker" and cmd[1] == "images" and any("dangling" in str(c) for c in cmd):
                return _make_subprocess_result(stdout="")
            elif cmd[0] == "docker" and cmd[1] == "ps" and any("exited" in str(c) for c in cmd):
                return _make_subprocess_result(stdout="container1\ncontainer2\n")
        return _make_subprocess_result()

    return fake_run


def _fake_run_dangling_images():
    """Dangling images scenario"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            if cmd[0] == "which" and "docker" in cmd:
                return _make_subprocess_result(stdout="/usr/local/bin/docker\n")
            elif cmd[0] == "docker" and cmd[1] == "system" and cmd[2] == "df":
                data = {
                    "Images": "5.2 GB",
                    "Containers": "500 MB",
                    "Volumes": "100 MB",
                }
                return _make_subprocess_result(stdout=json.dumps(data) + "\n")
            elif cmd[0] == "docker" and cmd[1] == "images" and any("dangling" in str(c) for c in cmd):
                # Multiple dangling images
                return _make_subprocess_result(
                    stdout="sha256:abc123\nsha256:def456\nsha256:ghi789\n"
                )
            elif cmd[0] == "docker" and cmd[1] == "ps" and any("exited" in str(c) for c in cmd):
                return _make_subprocess_result(stdout="container1\ncontainer2\n")
        return _make_subprocess_result()

    return fake_run


def _fake_run_many_stopped_containers():
    """Many stopped containers scenario"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            if cmd[0] == "which" and "docker" in cmd:
                return _make_subprocess_result(stdout="/usr/local/bin/docker\n")
            elif cmd[0] == "docker" and cmd[1] == "system" and cmd[2] == "df":
                data = {
                    "Images": "5.2 GB",
                    "Containers": "500 MB",
                    "Volumes": "100 MB",
                }
                return _make_subprocess_result(stdout=json.dumps(data) + "\n")
            elif cmd[0] == "docker" and cmd[1] == "images" and any("dangling" in str(c) for c in cmd):
                return _make_subprocess_result(stdout="")
            elif cmd[0] == "docker" and cmd[1] == "ps" and any("exited" in str(c) for c in cmd):
                # Many stopped containers (>10)
                containers = "\n".join([f"container{i}" for i in range(15)])
                return _make_subprocess_result(stdout=containers + "\n")
        return _make_subprocess_result()

    return fake_run


class TestDockerCleanupDiscovery:
    def test_module_discovered(self):
        mod = _get_module()
        assert mod.name == "docker_cleanup"
        assert mod.category == "performance"
        assert mod.risk_level == RiskLevel.SAFE
        assert Platform.DARWIN in mod.platforms

    def test_module_properties(self):
        mod = _get_module()
        assert mod.priority == 65
        assert mod.estimated_duration == "5s"
        assert mod.depends_on == []


class TestDockerCleanupDockerNotInstalled:
    def test_docker_not_installed(self):
        mod = _get_module()
        with patch("subprocess.run", side_effect=_fake_run_docker_not_installed()):
            result = mod.check(_make_profile())
        assert not result.has_issues


class TestDockerCleanupHealthy:
    def test_docker_healthy(self):
        mod = _get_module()
        with patch("subprocess.run", side_effect=_fake_run_docker_healthy()):
            result = mod.check(_make_profile())
        # Should have at least an INFO finding about docker usage
        assert result.has_issues
        usage_finding = next(
            (f for f in result.findings if f.data.get("type") == "docker_disk_usage"),
            None,
        )
        assert usage_finding is not None
        assert usage_finding.severity == Severity.INFO

    def test_docker_healthy_no_warnings(self):
        mod = _get_module()
        with patch("subprocess.run", side_effect=_fake_run_docker_healthy()):
            result = mod.check(_make_profile())
        # Should not have WARNING severity findings (only INFO)
        warnings = [f for f in result.findings if f.severity == Severity.WARNING]
        assert len(warnings) == 0


class TestDockerCleanupHighUsage:
    def test_high_docker_usage(self):
        mod = _get_module()
        with patch("subprocess.run", side_effect=_fake_run_high_docker_usage()):
            result = mod.check(_make_profile())
        assert result.has_issues
        high_usage = next(
            (
                f
                for f in result.findings
                if f.data.get("type") == "high_docker_usage"
            ),
            None,
        )
        assert high_usage is not None
        assert high_usage.severity == Severity.WARNING

    def test_high_docker_usage_breakdown(self):
        mod = _get_module()
        with patch("subprocess.run", side_effect=_fake_run_high_docker_usage()):
            result = mod.check(_make_profile())
        high_usage = next(
            (
                f
                for f in result.findings
                if f.data.get("type") == "high_docker_usage"
            ),
            None,
        )
        assert high_usage is not None
        assert high_usage.data["images_bytes"] > 0
        assert high_usage.data["containers_bytes"] > 0
        assert high_usage.data["volumes_bytes"] > 0


class TestDockerCleanupDanglingImages:
    def test_dangling_images_detected(self):
        mod = _get_module()
        with patch("subprocess.run", side_effect=_fake_run_dangling_images()):
            result = mod.check(_make_profile())
        assert result.has_issues
        dangling = next(
            (
                f
                for f in result.findings
                if f.data.get("type") == "dangling_images"
            ),
            None,
        )
        assert dangling is not None
        assert dangling.severity == Severity.WARNING
        assert dangling.data["count"] == 3

    def test_dangling_images_no_warning_if_none(self):
        mod = _get_module()
        with patch("subprocess.run", side_effect=_fake_run_docker_healthy()):
            result = mod.check(_make_profile())
        dangling = next(
            (
                f
                for f in result.findings
                if f.data.get("type") == "dangling_images"
            ),
            None,
        )
        assert dangling is None


class TestDockerCleanupStoppedContainers:
    def test_many_stopped_containers(self):
        mod = _get_module()
        with patch("subprocess.run", side_effect=_fake_run_many_stopped_containers()):
            result = mod.check(_make_profile())
        assert result.has_issues
        stopped = next(
            (
                f
                for f in result.findings
                if f.data.get("type") == "stopped_containers"
            ),
            None,
        )
        assert stopped is not None
        assert stopped.severity == Severity.WARNING
        assert stopped.data["count"] == 15

    def test_few_stopped_containers_no_warning(self):
        mod = _get_module()
        with patch("subprocess.run", side_effect=_fake_run_docker_healthy()):
            result = mod.check(_make_profile())
        stopped = next(
            (
                f
                for f in result.findings
                if f.data.get("type") == "stopped_containers"
            ),
            None,
        )
        assert stopped is None  # No warning if <= 10


class TestDockerCleanupFix:
    def test_fix_is_informational(self):
        mod = _get_module()
        with patch("subprocess.run", side_effect=_fake_run_high_docker_usage()):
            check = mod.check(_make_profile())
            fix = mod.fix(check, Mode.MANUAL)
        # fix() should always succeed with informational messages
        assert fix.all_succeeded
        # Should have actions for each finding
        assert len(fix.actions) > 0

    def test_fix_suggests_docker_system_prune(self):
        mod = _get_module()
        with patch("subprocess.run", side_effect=_fake_run_high_docker_usage()):
            check = mod.check(_make_profile())
            fix = mod.fix(check, Mode.MANUAL)
        high_usage_action = next(
            (a for a in fix.actions if "docker system prune" in a.description),
            None,
        )
        assert high_usage_action is not None

    def test_fix_never_runs_commands(self):
        """Fix should never actually execute docker commands"""
        mod = _get_module()
        with patch("subprocess.run", side_effect=_fake_run_dangling_images()):
            check = mod.check(_make_profile())
            # Reset mock to verify fix doesn't call subprocess
            with patch("subprocess.run") as mock_run:
                fix = mod.fix(check, Mode.MANUAL)
                # fix() should not call subprocess.run
                mock_run.assert_not_called()
