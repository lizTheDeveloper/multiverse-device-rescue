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
    return next(m for m in modules if m.name == "backup_status")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_healthy():
    """Normal case: Time Machine enabled with recent backup"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "defaults" in cmd_str and "AutoBackup" in cmd_str:
            return _make_subprocess_result(stdout="1\n")
        elif "tmutil" in cmd_str and "latestbackup" in cmd_str:
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
        return _make_subprocess_result()
    return fake_run


def _fake_run_disabled():
    """Time Machine is disabled"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "defaults" in cmd_str and "AutoBackup" in cmd_str:
            return _make_subprocess_result(stdout="0\n")
        elif "tmutil" in cmd_str and "latestbackup" in cmd_str:
            return _make_subprocess_result(stdout="", returncode=1)
        elif "tmutil" in cmd_str and "destinationinfo" in cmd_str:
            return _make_subprocess_result(stdout="", returncode=1)
        return _make_subprocess_result()
    return fake_run


def _fake_run_no_destination():
    """Time Machine enabled but no destination configured"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "defaults" in cmd_str and "AutoBackup" in cmd_str:
            return _make_subprocess_result(stdout="1\n")
        elif "tmutil" in cmd_str and "latestbackup" in cmd_str:
            return _make_subprocess_result(stdout="", returncode=1)
        elif "tmutil" in cmd_str and "destinationinfo" in cmd_str:
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

        if "defaults" in cmd_str and "AutoBackup" in cmd_str:
            return _make_subprocess_result(stdout="1\n")
        elif "tmutil" in cmd_str and "latestbackup" in cmd_str:
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
                )
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_stale_backup():
    """Backup is older than 7 days"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "defaults" in cmd_str and "AutoBackup" in cmd_str:
            return _make_subprocess_result(stdout="1\n")
        elif "tmutil" in cmd_str and "latestbackup" in cmd_str:
            # Return a path that will fail stat check, simulating old backup
            return _make_subprocess_result(
                stdout="/Volumes/BackupDisk/Backups.backupdb/MyMac/2026-06-25-101010\n"
            )
        elif "tmutil" in cmd_str and "destinationinfo" in cmd_str:
            return _make_subprocess_result(
                stdout=(
                    "     Name: External Drive\n"
                    "     ID: ABC123DEF456\n"
                    "     Kind: Physical\n"
                    "     Mounted: Yes\n"
                )
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_timemachine_status_unknown():
    """Unable to determine Time Machine status"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "defaults" in cmd_str and "AutoBackup" in cmd_str:
            return _make_subprocess_result(stderr="error", returncode=1)
        elif "tmutil" in cmd_str and "latestbackup" in cmd_str:
            return _make_subprocess_result(stdout="", returncode=1)
        elif "tmutil" in cmd_str and "destinationinfo" in cmd_str:
            return _make_subprocess_result(stdout="", returncode=1)
        return _make_subprocess_result()
    return fake_run


def test_backup_status_discovered():
    mod = _get_module()
    assert mod.name == "backup_status"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE


def test_backup_status_healthy():
    """Test healthy Time Machine status"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        result = mod.check(_make_profile())
    # Healthy status should have at least INFO findings (backup current, destination info)
    assert result.has_issues or len(result.findings) > 0
    # Should not have critical or warning issues
    assert not any(f.severity == Severity.CRITICAL for f in result.findings)


def test_backup_status_disabled():
    """Test Time Machine disabled"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_disabled()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "timemachine_disabled" for f in result.findings)
    assert any(f.severity == Severity.CRITICAL for f in result.findings)


def test_backup_status_no_destination():
    """Test Time Machine with no destination configured"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_destination()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "no_destination" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_backup_status_destination_disconnected():
    """Test Time Machine with disconnected destination"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_destination_disconnected()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "destination_disconnected" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_backup_status_stale_backup():
    """Test Time Machine with stale backup"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_stale_backup()):
        with patch("modules.integrity.backup_status.Path.stat") as mock_stat:
            # Mock old backup date (more than 7 days ago)
            old_time = (datetime.now() - timedelta(days=10)).timestamp()
            mock_stat.return_value.st_mtime = old_time
            result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "backup_stale" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_backup_status_unknown_status():
    """Test when Time Machine status cannot be determined"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_timemachine_status_unknown()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "timemachine_status_unknown" for f in result.findings)


def test_backup_status_fix_is_informational():
    """Test that fix() returns informational actions only"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_disabled()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action
    assert len(fix.actions) > 0
    # All actions should be SAFE risk level
    assert all(a.risk_level == RiskLevel.SAFE for a in fix.actions)


def test_backup_status_fix_disabled():
    """Test fix guidance for disabled Time Machine"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_disabled()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert any("Enable Time Machine" in a.title for a in fix.actions)


def test_backup_status_fix_no_destination():
    """Test fix guidance for missing destination"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_destination()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert any("backup destination" in a.title.lower() for a in fix.actions)


def test_backup_status_fix_destination_disconnected():
    """Test fix guidance for disconnected destination"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_destination_disconnected()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert any("Reconnect" in a.title or "connect" in a.title.lower() for a in fix.actions)


def test_backup_status_parse_destination_info():
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
