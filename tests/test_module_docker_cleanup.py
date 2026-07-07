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


def _docker_df_ndjson(images="0B", containers="0B", volumes="0B", build_cache="0B"):
    """Build realistic NDJSON output for 'docker system df --format {{json .}}'.

    Real Docker emits one JSON object per line, one line per row type
    (Images, Containers, Local Volumes, Build Cache) -- NOT a single JSON
    blob.
    """
    rows = [
        {"Type": "Images", "TotalCount": 10, "Active": 5, "Size": images, "Reclaimable": "0B (0%)"},
        {"Type": "Containers", "TotalCount": 3, "Active": 1, "Size": containers, "Reclaimable": "0B (0%)"},
        {"Type": "Local Volumes", "TotalCount": 2, "Active": 1, "Size": volumes, "Reclaimable": "0B (0%)"},
        {"Type": "Build Cache", "TotalCount": 0, "Active": 0, "Size": build_cache, "Reclaimable": "0B"},
    ]
    return "\n".join(json.dumps(row) for row in rows) + "\n"


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
                # Return realistic NDJSON output with low usage
                return _make_subprocess_result(
                    stdout=_docker_df_ndjson(
                        images="5.2GB", containers="500MB", volumes="100MB"
                    )
                )
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
                # Return realistic NDJSON output with high usage (>20GB)
                return _make_subprocess_result(
                    stdout=_docker_df_ndjson(
                        images="15.2GB", containers="8.5GB", volumes="2.1GB"
                    )
                )
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
                return _make_subprocess_result(
                    stdout=_docker_df_ndjson(
                        images="5.2GB", containers="500MB", volumes="100MB"
                    )
                )
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
                return _make_subprocess_result(
                    stdout=_docker_df_ndjson(
                        images="5.2GB", containers="500MB", volumes="100MB"
                    )
                )
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


class TestDockerCleanupParseDockerSize:
    """Docker's real Size strings (go-units HumanSize) have no space
    between the number and unit, e.g. '5.2GB', not '5.2 GB'."""

    def test_parses_no_space_format(self):
        mod = _get_module()
        assert mod._parse_docker_size("5.2GB") == int(5.2 * 1024 ** 3)
        assert mod._parse_docker_size("500MB") == 500 * 1024 ** 2
        assert mod._parse_docker_size("0B") == 0

    def test_parses_spaced_format_too(self):
        mod = _get_module()
        assert mod._parse_docker_size("5.2 GB") == int(5.2 * 1024 ** 3)


class TestDockerCleanupNdjsonParsing:
    """Regression tests for the NDJSON parsing bug.

    'docker system df --format "{{json .}}"' emits one JSON object per
    line (NDJSON), not a single JSON blob. json.loads() on the whole
    multi-line string used to raise JSONDecodeError, which was silently
    swallowed and killed the entire disk-usage check.
    """

    def test_multiline_ndjson_is_parsed_correctly(self):
        mod = _get_module()

        def fake_run(cmd, **kwargs):
            if isinstance(cmd, list):
                if cmd[0] == "which" and "docker" in cmd:
                    return _make_subprocess_result(stdout="/usr/local/bin/docker\n")
                elif cmd[0] == "docker" and cmd[1] == "system" and cmd[2] == "df":
                    return _make_subprocess_result(
                        stdout=_docker_df_ndjson(
                            images="2GB", containers="1GB", volumes="512MB"
                        )
                    )
                elif cmd[0] == "docker" and cmd[1] == "images" and any(
                    "dangling" in str(c) for c in cmd
                ):
                    return _make_subprocess_result(stdout="")
                elif cmd[0] == "docker" and cmd[1] == "ps" and any(
                    "exited" in str(c) for c in cmd
                ):
                    return _make_subprocess_result(stdout="")
            return _make_subprocess_result()

        with patch("subprocess.run", side_effect=fake_run):
            result = mod.check(_make_profile())

        # The check must not silently bail out -- it should produce a
        # docker_disk_usage (or high_docker_usage) finding with correctly
        # summed byte totals from all four NDJSON rows it understands.
        usage_finding = next(
            (
                f
                for f in result.findings
                if f.data.get("type") in ("docker_disk_usage", "high_docker_usage")
            ),
            None,
        )
        assert usage_finding is not None
        assert usage_finding.data["images_bytes"] == 2 * 1024 ** 3
        assert usage_finding.data["containers_bytes"] == 1 * 1024 ** 3
        assert usage_finding.data["volumes_bytes"] == 512 * 1024 ** 2
        expected_total = 2 * 1024 ** 3 + 1 * 1024 ** 3 + 512 * 1024 ** 2
        assert usage_finding.data["total_bytes"] == expected_total

    def test_malformed_line_is_skipped_not_fatal(self):
        """A single bad line in the NDJSON stream shouldn't kill the whole check."""
        mod = _get_module()

        def fake_run(cmd, **kwargs):
            if isinstance(cmd, list):
                if cmd[0] == "which" and "docker" in cmd:
                    return _make_subprocess_result(stdout="/usr/local/bin/docker\n")
                elif cmd[0] == "docker" and cmd[1] == "system" and cmd[2] == "df":
                    good_rows = _docker_df_ndjson(
                        images="1GB", containers="1GB", volumes="1GB"
                    )
                    # Inject a corrupted/truncated line into the NDJSON stream.
                    stdout = "{not valid json\n" + good_rows
                    return _make_subprocess_result(stdout=stdout)
                elif cmd[0] == "docker" and cmd[1] == "images" and any(
                    "dangling" in str(c) for c in cmd
                ):
                    return _make_subprocess_result(stdout="")
                elif cmd[0] == "docker" and cmd[1] == "ps" and any(
                    "exited" in str(c) for c in cmd
                ):
                    return _make_subprocess_result(stdout="")
            return _make_subprocess_result()

        with patch("subprocess.run", side_effect=fake_run):
            result = mod.check(_make_profile())

        usage_finding = next(
            (
                f
                for f in result.findings
                if f.data.get("type") in ("docker_disk_usage", "high_docker_usage")
            ),
            None,
        )
        assert usage_finding is not None
        assert usage_finding.data["total_bytes"] == 3 * 1024 ** 3


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
