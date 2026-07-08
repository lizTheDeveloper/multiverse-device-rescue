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
    return next(m for m in modules if m.name == "time_machine_check")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_not_configured():
    """Time Machine not configured at all"""
    def fake_run(cmd, **kwargs):
        if cmd[0] == "defaults" and "TimeMachine" in cmd:
            return _make_subprocess_result(stdout="", returncode=1)
        return _make_subprocess_result(stdout="")
    return fake_run


def _fake_run_recent_backup():
    """Time Machine configured with recent backup (1 day old)"""
    def fake_run(cmd, **kwargs):
        if cmd[0] == "defaults" and "TimeMachine" in " ".join(cmd) and "ExcludeByPath" not in cmd:
            # defaults read /Library/Preferences/com.apple.TimeMachine
            return _make_subprocess_result(stdout="{ some = settings; }")
        elif cmd[0] == "tmutil" and "latestbackup" in cmd:
            # 1 day ago
            backup_date = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d-%H%M%S")
            return _make_subprocess_result(stdout=f"/Volumes/BackupDisk/Backups.backupdb/MacBook/{backup_date}")
        elif cmd[0] == "tmutil" and "status" in cmd:
            return _make_subprocess_result(stdout="AutoBackup = 1;")
        elif cmd[0] == "tmutil" and "destinationinfo" in cmd:
            return _make_subprocess_result(stdout="""Backup Destination Information
Name: My Backup Disk
Kind: Local
Mount Point: /Volumes/BackupDisk
ID: ABC123DEF456
""")
        elif cmd[0] == "defaults" and "ExcludeByPath" in cmd:
            return _make_subprocess_result(stdout="", returncode=1)
        return _make_subprocess_result(stdout="")
    return fake_run


def _fake_run_aging_backup():
    """Time Machine configured with aging backup (10 days old)"""
    def fake_run(cmd, **kwargs):
        if cmd[0] == "defaults" and "TimeMachine" in " ".join(cmd) and "ExcludeByPath" not in cmd:
            return _make_subprocess_result(stdout="{ some = settings; }")
        elif cmd[0] == "tmutil" and "latestbackup" in cmd:
            # 10 days ago
            backup_date = (datetime.now() - timedelta(days=10)).strftime("%Y-%m-%d-%H%M%S")
            return _make_subprocess_result(stdout=f"/Volumes/BackupDisk/Backups.backupdb/MacBook/{backup_date}")
        elif cmd[0] == "tmutil" and "status" in cmd:
            return _make_subprocess_result(stdout="AutoBackup = 1;")
        elif cmd[0] == "tmutil" and "destinationinfo" in cmd:
            return _make_subprocess_result(stdout="""Backup Destination Information
Name: My Backup Disk
Kind: Local
Mount Point: /Volumes/BackupDisk
ID: ABC123DEF456
""")
        elif cmd[0] == "defaults" and "ExcludeByPath" in cmd:
            return _make_subprocess_result(stdout="", returncode=1)
        return _make_subprocess_result(stdout="")
    return fake_run


def _fake_run_stale_backup():
    """Time Machine configured with stale backup (40 days old)"""
    def fake_run(cmd, **kwargs):
        if cmd[0] == "defaults" and "TimeMachine" in " ".join(cmd) and "ExcludeByPath" not in cmd:
            return _make_subprocess_result(stdout="{ some = settings; }")
        elif cmd[0] == "tmutil" and "latestbackup" in cmd:
            # 40 days ago
            backup_date = (datetime.now() - timedelta(days=40)).strftime("%Y-%m-%d-%H%M%S")
            return _make_subprocess_result(stdout=f"/Volumes/BackupDisk/Backups.backupdb/MacBook/{backup_date}")
        elif cmd[0] == "tmutil" and "status" in cmd:
            return _make_subprocess_result(stdout="AutoBackup = 1;")
        elif cmd[0] == "tmutil" and "destinationinfo" in cmd:
            return _make_subprocess_result(stdout="""Backup Destination Information
Name: My Backup Disk
Kind: Local
Mount Point: /Volumes/BackupDisk
ID: ABC123DEF456
""")
        elif cmd[0] == "defaults" and "ExcludeByPath" in cmd:
            return _make_subprocess_result(stdout="", returncode=1)
        return _make_subprocess_result(stdout="")
    return fake_run


def _fake_run_backups_disabled():
    """Time Machine configured but automatic backups disabled"""
    def fake_run(cmd, **kwargs):
        if cmd[0] == "defaults" and "TimeMachine" in " ".join(cmd) and "ExcludeByPath" not in cmd:
            return _make_subprocess_result(stdout="{ some = settings; }")
        elif cmd[0] == "tmutil" and "latestbackup" in cmd:
            # 3 days ago
            backup_date = (datetime.now() - timedelta(days=3)).strftime("%Y-%m-%d-%H%M%S")
            return _make_subprocess_result(stdout=f"/Volumes/BackupDisk/Backups.backupdb/MacBook/{backup_date}")
        elif cmd[0] == "tmutil" and "status" in cmd:
            return _make_subprocess_result(stdout="AutoBackup = 0;")
        elif cmd[0] == "tmutil" and "destinationinfo" in cmd:
            return _make_subprocess_result(stdout="""Backup Destination Information
Name: My Backup Disk
Kind: Local
Mount Point: /Volumes/BackupDisk
ID: ABC123DEF456
""")
        elif cmd[0] == "defaults" and "ExcludeByPath" in cmd:
            return _make_subprocess_result(stdout="", returncode=1)
        return _make_subprocess_result(stdout="")
    return fake_run


def _fake_run_with_exclusions():
    """Time Machine configured with exclusions"""
    def fake_run(cmd, **kwargs):
        if cmd[0] == "defaults" and "TimeMachine" in " ".join(cmd) and "ExcludeByPath" not in cmd:
            return _make_subprocess_result(stdout="{ some = settings; }")
        elif cmd[0] == "tmutil" and "latestbackup" in cmd:
            backup_date = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d-%H%M%S")
            return _make_subprocess_result(stdout=f"/Volumes/BackupDisk/Backups.backupdb/MacBook/{backup_date}")
        elif cmd[0] == "tmutil" and "status" in cmd:
            return _make_subprocess_result(stdout="AutoBackup = 1;")
        elif cmd[0] == "tmutil" and "destinationinfo" in cmd:
            return _make_subprocess_result(stdout="""Backup Destination Information
Name: My Backup Disk
Kind: Local
Mount Point: /Volumes/BackupDisk
ID: ABC123DEF456
""")
        elif cmd[0] == "defaults" and "ExcludeByPath" in cmd:
            return _make_subprocess_result(stdout="""(
    "/Volumes/Downloads",
    "/Users/user/Library/Caches",
    "/private/var/tmp"
)""")
        return _make_subprocess_result(stdout="")
    return fake_run


def test_time_machine_check_discovered():
    """Module should be discoverable with correct properties"""
    mod = _get_module()
    assert mod.name == "time_machine_check"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.DARWIN in mod.platforms


def test_time_machine_not_configured():
    """Time Machine not configured should produce CRITICAL finding"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_not_configured()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert len(result.findings) == 1
    assert result.findings[0].severity == Severity.CRITICAL
    assert "not configured" in result.findings[0].title.lower()
    assert result.findings[0].data.get("check") == "not_configured"


def test_time_machine_recent_backup():
    """Recent backup (1 day) should produce INFO finding"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_recent_backup()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have recent_backup INFO, destination INFO
    recent_findings = [f for f in result.findings if "recent" in f.title.lower()]
    assert len(recent_findings) > 0
    assert recent_findings[0].severity == Severity.INFO
    assert "1 day" in recent_findings[0].title.lower() or "1 days" in recent_findings[0].title.lower()
    assert recent_findings[0].data.get("check") == "recent_backup"
    assert recent_findings[0].data.get("days_ago") == 1


def test_time_machine_aging_backup():
    """Aging backup (10 days) should produce WARNING finding"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_aging_backup()):
        result = mod.check(_make_profile())
    assert result.has_issues
    aging_findings = [f for f in result.findings if "aging" in f.title.lower()]
    assert len(aging_findings) > 0
    assert aging_findings[0].severity == Severity.WARNING
    assert "10 day" in aging_findings[0].title.lower()
    assert aging_findings[0].data.get("check") == "aging_backup"
    assert aging_findings[0].data.get("days_ago") == 10


def test_time_machine_stale_backup():
    """Stale backup (40 days) should produce CRITICAL finding"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_stale_backup()):
        result = mod.check(_make_profile())
    assert result.has_issues
    stale_findings = [f for f in result.findings if "stale" in f.title.lower()]
    assert len(stale_findings) > 0
    assert stale_findings[0].severity == Severity.CRITICAL
    assert "40 day" in stale_findings[0].title.lower()
    assert stale_findings[0].data.get("check") == "stale_backup"
    assert stale_findings[0].data.get("days_ago") == 40


def test_time_machine_backups_disabled():
    """Disabled automatic backups should produce WARNING finding"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_backups_disabled()):
        result = mod.check(_make_profile())
    assert result.has_issues
    disabled_findings = [f for f in result.findings if "disabled" in f.title.lower()]
    assert len(disabled_findings) > 0
    assert disabled_findings[0].severity == Severity.WARNING
    assert disabled_findings[0].data.get("check") == "backups_disabled"


def test_time_machine_with_exclusions():
    """Exclusions should be reported as INFO finding"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_with_exclusions()):
        result = mod.check(_make_profile())
    assert result.has_issues
    exclusion_findings = [f for f in result.findings if "exclusion" in f.title.lower()]
    assert len(exclusion_findings) > 0
    assert exclusion_findings[0].severity == Severity.INFO
    assert exclusion_findings[0].data.get("check") == "exclusions"
    assert exclusion_findings[0].data.get("count") == 3
    exclusions = exclusion_findings[0].data.get("exclusions", [])
    assert "/Volumes/Downloads" in exclusions
    assert "/Users/user/Library/Caches" in exclusions
    assert "/private/var/tmp" in exclusions


def test_time_machine_destination_info():
    """Destination info should be included as INFO finding"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_recent_backup()):
        result = mod.check(_make_profile())
    dest_findings = [f for f in result.findings if "destination" in f.title.lower()]
    assert len(dest_findings) > 0
    assert dest_findings[0].severity == Severity.INFO
    assert dest_findings[0].data.get("check") == "destination_info"
    assert "My Backup Disk" in dest_findings[0].data.get("name", "")


def test_time_machine_fix_is_informational():
    """fix() should return informational actions, never modify system"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_not_configured()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed
    assert fix.all_succeeded
    # Should have actions
    assert len(fix.actions) > 0
    # All actions should be SAFE risk level (informational)
    assert all(a.risk_level == RiskLevel.SAFE for a in fix.actions)
    # All actions should mark success=True
    assert all(a.success for a in fix.actions)


def test_time_machine_fix_creates_actions_per_finding():
    """Should create one action per finding"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_stale_backup()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # Should have one action per finding
    assert len(fix.actions) == len(check.findings)


def test_time_machine_fix_not_configured_has_guidance():
    """Fix for not configured should provide setup guidance"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_not_configured()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # Find action for not configured
    not_config_actions = [a for a in fix.actions if "enable" in a.title.lower() or "configure" in a.title.lower()]
    assert len(not_config_actions) > 0
    action = not_config_actions[0]
    # Should mention System Settings
    assert "System Settings" in action.description or "settings" in action.description.lower()


def test_time_machine_fix_stale_has_remediation():
    """Fix for stale backup should provide remediation steps"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_stale_backup()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # Find action for stale backup
    stale_actions = [a for a in fix.actions if "stale" in a.title.lower() or "address" in a.title.lower()]
    assert len(stale_actions) > 0
    action = stale_actions[0]
    # Should mention backup now or reconnect
    description = action.description.lower()
    assert "backup now" in description or "connect" in description or "backup" in description
