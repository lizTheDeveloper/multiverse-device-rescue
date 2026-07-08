import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
import tempfile
import os

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


def _make_profile():
    return SystemProfile(
        platform=Platform.DARWIN,
        os_name="macOS",
        os_version="13.5",
        architecture="arm64",
        cpu_model="Apple M1",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "notification_center_check")


def test_notification_center_check_discovered():
    """Test that module is discoverable and has correct metadata."""
    mod = _get_module()
    assert mod.name == "notification_center_check"
    assert mod.category == "performance"
    assert Platform.DARWIN in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_notification_center_check_clean():
    """Test when notification center is clean (no issues)."""
    mod = _get_module()

    def mock_walk(path):
        return []

    with patch("os.walk", side_effect=mock_walk):
        with patch("subprocess.run") as mock_run:
            # Mock defaults read to return minimal output
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = "some defaults output"
            mock_run.return_value = mock_result

            result = mod.check(_make_profile())

    # Should have at most configuration summary info finding
    assert not any(f.severity == Severity.WARNING for f in result.findings)
    assert not any(f.severity == Severity.CRITICAL for f in result.findings)


def test_notification_center_check_large_database():
    """Test detection of bloated notification database."""
    mod = _get_module()

    def mock_walk(path):
        # Return fake files that add up to 600MB
        return [
            (str(path), [], ["db1.db", "db2.db"]),
        ]

    def mock_stat(self):
        # Each file is 300MB
        result = MagicMock()
        result.st_size = 300 * 1024 * 1024
        return result

    # Patch os.walk in the module where it's imported
    with patch("modules.performance.notification_center_check.os.walk", side_effect=mock_walk):
        with patch("modules.performance.notification_center_check.Path.stat", side_effect=mock_stat):
            with patch("modules.performance.notification_center_check.Path.exists", return_value=True):
                result = mod.check(_make_profile())

    # Should have WARNING about database size
    assert any(f.severity == Severity.WARNING for f in result.findings)
    db_findings = [
        f for f in result.findings if f.data.get("check") == "database_size"
    ]
    assert len(db_findings) == 1
    assert "bloated" in db_findings[0].title.lower()
    assert db_findings[0].data.get("db_size_bytes") > 500 * 1024 * 1024


def test_notification_center_check_too_many_apps():
    """Test detection of too many apps with notification permissions."""
    mod = _get_module()

    # Create defaults output with 60 apps
    defaults_output = "\n".join(
        [f"com.example.app{i} = {{" for i in range(60)]
    )

    with patch("os.walk", return_value=[]):
        with patch("subprocess.run") as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = defaults_output
            mock_run.return_value = mock_result

            result = mod.check(_make_profile())

    # Should have WARNING about too many apps
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warnings) > 0
    app_warnings = [f for f in warnings if f.data.get("check") == "app_permission_count"]
    assert len(app_warnings) > 0
    assert "overload" in app_warnings[0].title.lower()


def test_notification_center_check_too_many_alerts():
    """Test detection of too many apps using Alerts style."""
    mod = _get_module()

    # Create defaults output with 15 apps using alertStyle = 1 (Alerts)
    defaults_output = "\n".join(
        [
            "com.example.app0 = {",
            "    alertStyle = 1;",
            "}",
        ]
        * 15
    )

    with patch("os.walk", return_value=[]):
        with patch("subprocess.run") as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = defaults_output
            mock_run.return_value = mock_result

            result = mod.check(_make_profile())

    # Should have WARNING about too many alerts
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warnings) > 0
    alert_warnings = [f for f in warnings if f.data.get("check") == "alert_style_count"]
    assert len(alert_warnings) > 0
    assert "alerts" in alert_warnings[0].title.lower()


def test_notification_center_check_dnd_active():
    """Test detection of active Do Not Disturb."""
    mod = _get_module()

    defaults_output = """
    com.example.app1 = {
        alertStyle = 0;
    };
    doNotDisturb = 1;
    """

    with patch("os.walk", return_value=[]):
        with patch("subprocess.run") as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = defaults_output
            mock_run.return_value = mock_result

            result = mod.check(_make_profile())

    # Should have INFO about dnd being active
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert len(info_findings) > 0
    summary_findings = [f for f in info_findings if f.data.get("check") == "configuration_summary"]
    assert len(summary_findings) > 0
    assert summary_findings[0].data.get("dnd_active") is True


def test_notification_center_check_multiple_issues():
    """Test detection of multiple notification issues simultaneously."""
    mod = _get_module()

    # Create defaults output with >50 apps and >10 using alerts
    defaults_output = "\n".join(
        [
            "com.example.app0 = {",
            "    alertStyle = 1;",
            "}",
        ]
        * 15
        + [
            "com.example.app{} = {{\n    alertStyle = 0;\n}}".format(i)
            for i in range(15, 60)
        ]
    )

    def mock_walk(path):
        # Return fake files that add up to 600MB
        return [
            (str(path), [], ["db.db"]),
        ]

    def mock_stat(self):
        result = MagicMock()
        result.st_size = 600 * 1024 * 1024
        return result

    with patch("os.walk", side_effect=mock_walk):
        with patch("pathlib.Path.stat", side_effect=mock_stat):
            with patch("pathlib.Path.exists", return_value=True):
                with patch("subprocess.run") as mock_run:
                    mock_result = MagicMock()
                    mock_result.returncode = 0
                    mock_result.stdout = defaults_output
                    mock_run.return_value = mock_result

                    result = mod.check(_make_profile())

    # Should have all three warnings
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warnings) >= 2  # At least database and app count warnings

    checks = [f.data.get("check") for f in warnings]
    assert "database_size" in checks
    assert "app_permission_count" in checks


def test_notification_center_check_fix_database():
    """Test fix recommendations for bloated database."""
    mod = _get_module()

    # Create a finding about bloated database
    def mock_walk(path):
        return [(str(path), [], ["db.db"])]

    def mock_stat(self):
        result = MagicMock()
        result.st_size = 600 * 1024 * 1024
        return result

    with patch("os.walk", side_effect=mock_walk):
        with patch("pathlib.Path.stat", side_effect=mock_stat):
            with patch("pathlib.Path.exists", return_value=True):
                with patch("subprocess.run") as mock_run:
                    mock_result = MagicMock()
                    mock_result.returncode = 0
                    mock_result.stdout = "app = {}"
                    mock_run.return_value = mock_result

                    check = mod.check(_make_profile())
                    fix = mod.fix(check, Mode.MANUAL)

    # Should have actions for database issues
    db_actions = [a for a in fix.actions if "database" in a.title.lower() or "bloated" in a.title.lower()]
    assert len(db_actions) > 0
    assert all(a.risk_level == RiskLevel.SAFE for a in db_actions)
    assert all(a.success is True for a in db_actions)


def test_notification_center_check_fix_app_permissions():
    """Test fix recommendations for too many app permissions."""
    mod = _get_module()

    defaults_output = "\n".join([f"com.example.app{i} = {{\n}}" for i in range(60)])

    with patch("os.walk", return_value=[]):
        with patch("subprocess.run") as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = defaults_output
            mock_run.return_value = mock_result

            check = mod.check(_make_profile())
            fix = mod.fix(check, Mode.MANUAL)

    # Should have actions for app permission issues
    app_actions = [
        a for a in fix.actions if "permission" in a.title.lower() or "overload" in a.title.lower()
    ]
    assert len(app_actions) > 0
    assert all(a.risk_level == RiskLevel.SAFE for a in app_actions)


def test_notification_center_check_fix_alerts():
    """Test fix recommendations for too many alerts."""
    mod = _get_module()

    defaults_output = "\n".join(
        [
            "com.example.app0 = {",
            "    alertStyle = 1;",
            "}",
        ]
        * 15
    )

    with patch("os.walk", return_value=[]):
        with patch("subprocess.run") as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = defaults_output
            mock_run.return_value = mock_result

            check = mod.check(_make_profile())
            fix = mod.fix(check, Mode.MANUAL)

    # Should have actions for alert style issues
    alert_actions = [a for a in fix.actions if "alert" in a.title.lower()]
    assert len(alert_actions) > 0
    assert all(a.risk_level == RiskLevel.SAFE for a in alert_actions)


def test_notification_center_check_subprocess_error():
    """Test graceful handling of subprocess errors."""
    mod = _get_module()

    def error_run(cmd, **kwargs):
        raise OSError("Command failed")

    with patch("os.walk", return_value=[]):
        with patch("subprocess.run", side_effect=error_run):
            result = mod.check(_make_profile())

    # Should complete without crashing
    assert isinstance(result.findings, list)


def test_notification_center_check_subprocess_timeout():
    """Test graceful handling of subprocess timeout."""
    mod = _get_module()

    def timeout_run(cmd, **kwargs):
        raise Exception("Timeout")

    with patch("os.walk", return_value=[]):
        with patch("subprocess.run", side_effect=timeout_run):
            result = mod.check(_make_profile())

    # Should complete without crashing
    assert isinstance(result.findings, list)


def test_notification_center_check_missing_prefs():
    """Test handling when preferences file doesn't exist."""
    mod = _get_module()

    with patch("os.walk", return_value=[]):
        with patch("pathlib.Path.exists", return_value=False):
            result = mod.check(_make_profile())

    # Should complete without crashing
    assert isinstance(result.findings, list)


def test_notification_center_check_empty_database():
    """Test when notification database is very small."""
    mod = _get_module()

    def mock_walk(path):
        # Return empty - no database files
        return []

    with patch("os.walk", side_effect=mock_walk):
        with patch("pathlib.Path.exists", return_value=False):
            with patch("subprocess.run") as mock_run:
                mock_result = MagicMock()
                mock_result.returncode = 0
                mock_result.stdout = "minimal"
                mock_run.return_value = mock_result

                result = mod.check(_make_profile())

    # Should have no warnings when clean
    assert not any(f.severity == Severity.WARNING for f in result.findings)
