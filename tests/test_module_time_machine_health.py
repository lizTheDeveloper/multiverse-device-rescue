import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta

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
    return next(m for m in modules if m.name == "time_machine_health")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_healthy():
    """Normal case: Time Machine with healthy backup and good space"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "tmutil" in cmd_str and "latestbackup" in cmd_str:
            # Return a recent backup path
            return _make_subprocess_result(
                stdout="/Volumes/BackupDisk/Backups.backupdb/MyMac/Latest\n"
            )
        elif "tmutil" in cmd_str and "destinationinfo" in cmd_str:
            return _make_subprocess_result(
                stdout=(
                    "     Name: External Drive\n"
                    "     ID: ABC123DEF456\n"
                    "     Kind: Physical\n"
                    "     Mounted: Yes\n"
                    "     Bytes Available: 1000000000\n"
                    "     Bytes Total: 5000000000\n"
                )
            )
        elif "tmutil" in cmd_str and "status" in cmd_str:
            return _make_subprocess_result(
                stdout="Backup not running\n"
            )
        elif "log" in cmd_str and "show" in cmd_str:
            return _make_subprocess_result(stdout="")
        return _make_subprocess_result()
    return fake_run


def _fake_run_no_destination():
    """No backup destination configured"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "tmutil" in cmd_str and "destinationinfo" in cmd_str:
            return _make_subprocess_result(stdout="", returncode=1)
        return _make_subprocess_result()
    return fake_run


def _fake_run_destination_disconnected():
    """Backup destination is disconnected"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "tmutil" in cmd_str and "latestbackup" in cmd_str:
            return _make_subprocess_result(
                stdout="/Volumes/BackupDisk/Backups.backupdb/MyMac/Latest\n"
            )
        elif "tmutil" in cmd_str and "destinationinfo" in cmd_str:
            return _make_subprocess_result(
                stdout=(
                    "     Name: External Drive\n"
                    "     ID: ABC123DEF456\n"
                    "     Kind: Physical\n"
                    "     Mounted: No\n"
                    "     Bytes Available: 1000000000\n"
                    "     Bytes Total: 5000000000\n"
                )
            )
        elif "tmutil" in cmd_str and "status" in cmd_str:
            return _make_subprocess_result(stdout="")
        elif "log" in cmd_str and "show" in cmd_str:
            return _make_subprocess_result(stdout="")
        return _make_subprocess_result()
    return fake_run


def _fake_run_stale_backup():
    """Backup is older than 7 days"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "tmutil" in cmd_str and "latestbackup" in cmd_str:
            return _make_subprocess_result(
                stdout="/Volumes/BackupDisk/Backups.backupdb/MyMac/2026-06-25\n"
            )
        elif "tmutil" in cmd_str and "destinationinfo" in cmd_str:
            return _make_subprocess_result(
                stdout=(
                    "     Name: External Drive\n"
                    "     ID: ABC123DEF456\n"
                    "     Kind: Physical\n"
                    "     Mounted: Yes\n"
                    "     Bytes Available: 1000000000\n"
                    "     Bytes Total: 5000000000\n"
                )
            )
        elif "tmutil" in cmd_str and "status" in cmd_str:
            return _make_subprocess_result(stdout="")
        elif "log" in cmd_str and "show" in cmd_str:
            return _make_subprocess_result(stdout="")
        return _make_subprocess_result()
    return fake_run


def _fake_run_low_space():
    """Backup destination has low free space"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "tmutil" in cmd_str and "latestbackup" in cmd_str:
            return _make_subprocess_result(
                stdout="/Volumes/BackupDisk/Backups.backupdb/MyMac/Latest\n"
            )
        elif "tmutil" in cmd_str and "destinationinfo" in cmd_str:
            # Only 5% free space
            return _make_subprocess_result(
                stdout=(
                    "     Name: External Drive\n"
                    "     ID: ABC123DEF456\n"
                    "     Kind: Physical\n"
                    "     Mounted: Yes\n"
                    "     Bytes Available: 500000000\n"
                    "     Bytes Total: 10000000000\n"
                )
            )
        elif "tmutil" in cmd_str and "status" in cmd_str:
            return _make_subprocess_result(stdout="")
        elif "log" in cmd_str and "show" in cmd_str:
            return _make_subprocess_result(stdout="")
        return _make_subprocess_result()
    return fake_run


def _fake_run_with_errors():
    """Backup has recent errors in system log"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "tmutil" in cmd_str and "latestbackup" in cmd_str:
            return _make_subprocess_result(
                stdout="/Volumes/BackupDisk/Backups.backupdb/MyMac/Latest\n"
            )
        elif "tmutil" in cmd_str and "destinationinfo" in cmd_str:
            return _make_subprocess_result(
                stdout=(
                    "     Name: External Drive\n"
                    "     ID: ABC123DEF456\n"
                    "     Kind: Physical\n"
                    "     Mounted: Yes\n"
                    "     Bytes Available: 1000000000\n"
                    "     Bytes Total: 5000000000\n"
                )
            )
        elif "tmutil" in cmd_str and "status" in cmd_str:
            return _make_subprocess_result(stdout="")
        elif "log" in cmd_str and "show" in cmd_str:
            return _make_subprocess_result(
                stdout="Error: Backup failed due to permission denied\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_backup_running():
    """Backup is currently running"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "tmutil" in cmd_str and "latestbackup" in cmd_str:
            return _make_subprocess_result(
                stdout="/Volumes/BackupDisk/Backups.backupdb/MyMac/Latest\n"
            )
        elif "tmutil" in cmd_str and "destinationinfo" in cmd_str:
            return _make_subprocess_result(
                stdout=(
                    "     Name: External Drive\n"
                    "     ID: ABC123DEF456\n"
                    "     Kind: Physical\n"
                    "     Mounted: Yes\n"
                    "     Bytes Available: 1000000000\n"
                    "     Bytes Total: 5000000000\n"
                )
            )
        elif "tmutil" in cmd_str and "status" in cmd_str:
            return _make_subprocess_result(
                stdout="Running: backing up (1.2 GB of 42.5 GB)\n"
            )
        elif "log" in cmd_str and "show" in cmd_str:
            return _make_subprocess_result(stdout="")
        return _make_subprocess_result()
    return fake_run


def test_time_machine_health_discovered():
    mod = _get_module()
    assert mod.name == "time_machine_health"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE


def test_time_machine_health_healthy():
    """Test healthy Time Machine status"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        with patch("modules.integrity.time_machine_health.Path.stat") as mock_stat:
            # Mock recent backup date
            recent_time = (datetime.now() - timedelta(days=2)).timestamp()
            mock_stat.return_value.st_mtime = recent_time
            result = mod.check(_make_profile())
    # Healthy status should have findings but no CRITICAL or WARNING
    assert len(result.findings) > 0
    assert not any(f.severity == Severity.CRITICAL for f in result.findings)
    assert not any(f.severity == Severity.WARNING for f in result.findings)


def test_time_machine_health_no_destination():
    """Test with no backup destination configured"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_destination()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "no_destination_configured" for f in result.findings)
    assert any(f.severity == Severity.CRITICAL for f in result.findings)


def test_time_machine_health_destination_disconnected():
    """Test with disconnected destination"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_destination_disconnected()):
        with patch("modules.integrity.time_machine_health.Path.stat") as mock_stat:
            recent_time = (datetime.now() - timedelta(days=2)).timestamp()
            mock_stat.return_value.st_mtime = recent_time
            result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "destination_disconnected" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_time_machine_health_stale_backup():
    """Test with stale backup (>7 days old)"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_stale_backup()):
        with patch("modules.integrity.time_machine_health.Path.stat") as mock_stat:
            # Mock old backup date (10 days ago)
            old_time = (datetime.now() - timedelta(days=10)).timestamp()
            mock_stat.return_value.st_mtime = old_time
            result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "backup_stale" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_time_machine_health_low_space():
    """Test with low free space on destination"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_low_space()):
        with patch("modules.integrity.time_machine_health.Path.stat") as mock_stat:
            recent_time = (datetime.now() - timedelta(days=2)).timestamp()
            mock_stat.return_value.st_mtime = recent_time
            result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "low_destination_space" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_time_machine_health_recent_errors():
    """Test with recent backup errors in system log"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_with_errors()):
        with patch("modules.integrity.time_machine_health.Path.stat") as mock_stat:
            recent_time = (datetime.now() - timedelta(days=2)).timestamp()
            mock_stat.return_value.st_mtime = recent_time
            result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "recent_errors" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_time_machine_health_backup_running():
    """Test with backup currently running"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_backup_running()):
        with patch("modules.integrity.time_machine_health.Path.stat") as mock_stat:
            recent_time = (datetime.now() - timedelta(days=2)).timestamp()
            mock_stat.return_value.st_mtime = recent_time
            result = mod.check(_make_profile())
    # Should have an INFO finding about backup running
    assert any(f.data.get("check") == "backup_running" for f in result.findings)
    assert any(f.severity == Severity.INFO for f in result.findings)


def test_time_machine_health_fix_no_destination():
    """Test fix guidance for missing destination"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_destination()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert any("backup destination" in a.title.lower() for a in fix.actions)
    assert all(a.risk_level == RiskLevel.SAFE for a in fix.actions)


def test_time_machine_health_fix_destination_disconnected():
    """Test fix guidance for disconnected destination"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_destination_disconnected()):
        with patch("modules.integrity.time_machine_health.Path.stat") as mock_stat:
            recent_time = (datetime.now() - timedelta(days=2)).timestamp()
            mock_stat.return_value.st_mtime = recent_time
            check = mod.check(_make_profile())
            fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert any("reconnect" in a.title.lower() for a in fix.actions)


def test_time_machine_health_fix_stale_backup():
    """Test fix guidance for stale backup"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_stale_backup()):
        with patch("modules.integrity.time_machine_health.Path.stat") as mock_stat:
            old_time = (datetime.now() - timedelta(days=10)).timestamp()
            mock_stat.return_value.st_mtime = old_time
            check = mod.check(_make_profile())
            fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert any("backup" in a.title.lower() for a in fix.actions)


def test_time_machine_health_fix_low_space():
    """Test fix guidance for low destination space"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_low_space()):
        with patch("modules.integrity.time_machine_health.Path.stat") as mock_stat:
            recent_time = (datetime.now() - timedelta(days=2)).timestamp()
            mock_stat.return_value.st_mtime = recent_time
            check = mod.check(_make_profile())
            fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert any("space" in a.title.lower() for a in fix.actions)


def test_time_machine_health_format_bytes():
    """Test byte formatting utility"""
    mod = _get_module()
    assert "B" in mod._format_bytes(512)
    assert "KB" in mod._format_bytes(1024 * 100)
    assert "MB" in mod._format_bytes(1024 * 1024 * 50)
    assert "GB" in mod._format_bytes(1024 * 1024 * 1024 * 5)


def test_time_machine_health_parse_destination_info():
    """Test parsing of destination info"""
    mod = _get_module()
    output = (
        "     Name: External Drive\n"
        "     ID: ABC123DEF456\n"
        "     Kind: Physical\n"
        "     Mounted: Yes\n"
        "     Bytes Available: 1000000000\n"
        "     Bytes Total: 5000000000\n"
    )
    result = mod._parse_destination_info(output)
    assert result is not None
    assert result["name"] == "External Drive"
    assert result["id"] == "ABC123DEF456"
    assert result["kind"] == "Physical"
    assert result["connected"] is True
    assert result["bytes_available"] == 1000000000
    assert result["bytes_total"] == 5000000000
