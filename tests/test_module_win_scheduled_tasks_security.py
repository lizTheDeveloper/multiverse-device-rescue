import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


def _make_profile():
    return SystemProfile(
        platform=Platform.WIN32,
        os_name="Windows 11",
        os_version="10.0.22621",
        architecture="AMD64",
        cpu_model="Intel(R) Core(TM) i7-9700K",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "win_scheduled_tasks_security")


def _make_csv_output(
    tasks=None,
    expect_empty=False,
):
    """Create fake schtasks CSV output.

    Args:
        tasks: List of task dicts to include in output
        expect_empty: If True, return empty CSV (no tasks)
    """
    if expect_empty:
        # Return just headers with no data rows
        return (
            "HostName,TaskName,Next Run Time,Status,LogonMode,ScheduleType,LastRunTime,"
            "LastResult,Author,TaskPath,RunAsUser,DeletedWhen,DeletedFrom,Attributes,"
            "\"Task To Run\",Created\n"
        )

    # Build CSV with headers and task rows
    headers = (
        "HostName,TaskName,Next Run Time,Status,LogonMode,ScheduleType,LastRunTime,"
        "LastResult,Author,TaskPath,RunAsUser,DeletedWhen,DeletedFrom,Attributes,"
        "\"Task To Run\",Created"
    )

    rows = [headers]

    if tasks:
        for task in tasks:
            row = (
                f"{task.get('HostName', 'DESKTOP')},"
                f'"{task.get("TaskName", "Task")}","'
                f'{task.get("Next Run Time", "")}",'
                f'"{task.get("Status", "Ready")}","'
                f'{task.get("LogonMode", "Interactive only")}","'
                f'{task.get("ScheduleType", "")}",'
                f'"{task.get("LastRunTime", "")}",'
                f"{task.get("LastResult", "0")},"
                f'"{task.get("Author", "")}",'
                f'"{task.get("TaskPath", "\\\\")}",'
                f'"{task.get("RunAsUser", "")}",'
                f'"{task.get("DeletedWhen", "")}",'
                f'"{task.get("DeletedFrom", "")}",'
                f'"{task.get("Attributes", "")}",'
                f'"{task.get("Task To Run", "")}",'
                f'"{task.get("Created", "")}"'
            )
            rows.append(row)

    return "\n".join(rows)


def _make_run_result(tasks=None, expect_empty=False):
    """Create a fake subprocess.run for schtasks command."""

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""

        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        if "schtasks" in cmd_str and "/query" in cmd_str:
            result.stdout = _make_csv_output(tasks=tasks, expect_empty=expect_empty)
        else:
            result.stdout = ""

        return result

    return fake_run


def test_win_scheduled_tasks_security_discovered():
    mod = _get_module()
    assert mod.name == "win_scheduled_tasks_security"
    assert mod.category == "security"
    assert Platform.WIN32 in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_win_scheduled_tasks_security_no_tasks():
    """Test when no scheduled tasks are found."""
    mod = _get_module()
    fake_run = _make_run_result(expect_empty=True)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    # Should have at least one INFO finding about inventory
    assert any(f.severity == Severity.INFO for f in result.findings)


def test_win_scheduled_tasks_security_encoded_powershell():
    """Test detection of encoded PowerShell commands (CRITICAL)."""
    mod = _get_module()
    tasks = [
        {
            "HostName": "DESKTOP",
            "TaskName": "MalwareTask",
            "TaskPath": "\\",
            "RunAsUser": "SYSTEM",
            "ScheduleType": "At logon",
            "Task To Run": "powershell -enc JABlAH4AeQBkAG8AZwBlAA==",
            "Created": "1/1/2025 10:00:00 AM",
            "Attributes": "",
        }
    ]
    fake_run = _make_run_result(tasks=tasks)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert len(critical) > 0
    assert any("encoded" in f.title.lower() for f in critical)


def test_win_scheduled_tasks_security_temp_directory_system():
    """Test detection of temp directory execution as SYSTEM (CRITICAL)."""
    mod = _get_module()
    tasks = [
        {
            "HostName": "DESKTOP",
            "TaskName": "SuspiciousTask",
            "TaskPath": "\\",
            "RunAsUser": "SYSTEM",
            "ScheduleType": "At logon",
            "Task To Run": "C:\\Users\\User\\AppData\\Local\\Temp\\malware.exe",
            "Created": "1/1/2025 10:00:00 AM",
            "Attributes": "",
        }
    ]
    fake_run = _make_run_result(tasks=tasks)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert len(critical) > 0
    assert any("temp" in f.title.lower() for f in critical)


def test_win_scheduled_tasks_security_system_task():
    """Test detection of non-Microsoft SYSTEM tasks (WARNING)."""
    mod = _get_module()
    tasks = [
        {
            "HostName": "DESKTOP",
            "TaskName": "CustomTask",
            "TaskPath": "\\",
            "RunAsUser": "SYSTEM",
            "ScheduleType": "At logon",
            "Task To Run": "C:\\Program Files\\SomeApp\\app.exe",
            "Created": "1/1/2025 10:00:00 AM",
            "Attributes": "",
        }
    ]
    fake_run = _make_run_result(tasks=tasks)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert any("SYSTEM" in f.title for f in warnings)


def test_win_scheduled_tasks_security_frequent_schedule():
    """Test detection of frequent execution schedules (WARNING)."""
    mod = _get_module()
    tasks = [
        {
            "HostName": "DESKTOP",
            "TaskName": "BeaconTask",
            "TaskPath": "\\",
            "RunAsUser": "user",
            "ScheduleType": "Every 3 minutes",
            "Task To Run": "C:\\Program Files\\App\\beacon.exe",
            "Created": "1/1/2025 10:00:00 AM",
            "Attributes": "",
        }
    ]
    fake_run = _make_run_result(tasks=tasks)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert any("frequency" in f.title.lower() for f in warnings)


def test_win_scheduled_tasks_security_recent_boot_task():
    """Test detection of recently created boot/logon tasks (WARNING)."""
    mod = _get_module()
    from datetime import datetime, timedelta

    # Create a date string for 2 days ago
    two_days_ago = (datetime.now() - timedelta(days=2)).strftime("%m/%d/%Y %I:%M:%S %p")

    tasks = [
        {
            "HostName": "DESKTOP",
            "TaskName": "RecentTask",
            "TaskPath": "\\",
            "RunAsUser": "user",
            "ScheduleType": "At logon",
            "Task To Run": "C:\\Program Files\\App\\app.exe",
            "Created": two_days_ago,
            "Attributes": "",
        }
    ]
    fake_run = _make_run_result(tasks=tasks)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert any("recent" in f.title.lower() for f in warnings)


def test_win_scheduled_tasks_security_hidden_task():
    """Test detection of hidden task attributes (INFO)."""
    mod = _get_module()
    tasks = [
        {
            "HostName": "DESKTOP",
            "TaskName": "HiddenTask",
            "TaskPath": "\\",
            "RunAsUser": "user",
            "ScheduleType": "At logon",
            "Task To Run": "C:\\Program Files\\App\\app.exe",
            "Created": "1/1/2025 10:00:00 AM",
            "Attributes": "H",
        }
    ]
    fake_run = _make_run_result(tasks=tasks)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    # Should have hidden attributes info and inventory info
    assert any("hidden" in f.title.lower() for f in info_findings)


def test_win_scheduled_tasks_security_microsoft_task_ignored():
    """Test that Microsoft tasks are properly ignored."""
    mod = _get_module()
    tasks = [
        {
            "HostName": "DESKTOP",
            "TaskName": "UpdateTask",
            "TaskPath": "\\Microsoft\\Windows\\",
            "RunAsUser": "SYSTEM",
            "ScheduleType": "At logon",
            "Task To Run": "C:\\Windows\\System32\\update.exe",
            "Created": "1/1/2025 10:00:00 AM",
            "Attributes": "",
        }
    ]
    fake_run = _make_run_result(tasks=tasks)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    # Should only have inventory finding (Microsoft task ignored)
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warnings) == 0


def test_win_scheduled_tasks_security_multiple_issues():
    """Test when multiple issues are detected."""
    mod = _get_module()
    from datetime import datetime, timedelta

    two_days_ago = (datetime.now() - timedelta(days=2)).strftime("%m/%d/%Y %I:%M:%S %p")

    tasks = [
        {
            "HostName": "DESKTOP",
            "TaskName": "EncodedTask",
            "TaskPath": "\\",
            "RunAsUser": "SYSTEM",
            "ScheduleType": "At startup",
            "Task To Run": "powershell -enc JABkAGEAdABhAA==",
            "Created": two_days_ago,
            "Attributes": "",
        },
        {
            "HostName": "DESKTOP",
            "TaskName": "TempTask",
            "TaskPath": "\\",
            "RunAsUser": "SYSTEM",
            "ScheduleType": "At logon",
            "Task To Run": "C:\\Windows\\Temp\\payload.exe",
            "Created": two_days_ago,
            "Attributes": "",
        },
        {
            "HostName": "DESKTOP",
            "TaskName": "FreqTask",
            "TaskPath": "\\",
            "RunAsUser": "user",
            "ScheduleType": "Every 2 minutes",
            "Task To Run": "C:\\Program Files\\App\\beacon.exe",
            "Created": "1/1/2025 10:00:00 AM",
            "Attributes": "",
        },
    ]
    fake_run = _make_run_result(tasks=tasks)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have CRITICAL for encoded and temp+SYSTEM
    critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert len(critical) >= 2
    # Should have WARNING for frequent schedule
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert any("frequency" in f.title.lower() for f in warnings)


def test_win_scheduled_tasks_security_fix_critical():
    """Test fix recommendations for CRITICAL findings."""
    mod = _get_module()
    tasks = [
        {
            "HostName": "DESKTOP",
            "TaskName": "MalwareTask",
            "TaskPath": "\\",
            "RunAsUser": "SYSTEM",
            "ScheduleType": "At logon",
            "Task To Run": "powershell -enc JABlAH4AeQBkAG8AZwBlAA==",
            "Created": "1/1/2025 10:00:00 AM",
            "Attributes": "",
        }
    ]
    fake_run = _make_run_result(tasks=tasks)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    # Critical tasks should have delete recommendations
    assert any("remove" in a.title.lower() or "delete" in a.title.lower() for a in fix.actions)


def test_win_scheduled_tasks_security_fix_warning():
    """Test fix recommendations for WARNING findings."""
    mod = _get_module()
    tasks = [
        {
            "HostName": "DESKTOP",
            "TaskName": "CustomTask",
            "TaskPath": "\\",
            "RunAsUser": "SYSTEM",
            "ScheduleType": "At logon",
            "Task To Run": "C:\\Program Files\\App\\app.exe",
            "Created": "1/1/2025 10:00:00 AM",
            "Attributes": "",
        }
    ]
    fake_run = _make_run_result(tasks=tasks)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    # Warning tasks should have review recommendations
    assert any("review" in a.title.lower() for a in fix.actions)


def test_win_scheduled_tasks_security_handles_subprocess_error():
    """Test graceful handling of subprocess errors."""
    mod = _get_module()

    def error_run(cmd, **kwargs):
        raise OSError("Command failed")

    with patch("subprocess.run", side_effect=error_run):
        result = mod.check(_make_profile())
    # Should still complete without crashing
    assert isinstance(result.findings, list)
    # Should have an informational message about inability to enumerate
    assert any("Unable" in f.title for f in result.findings)


def test_win_scheduled_tasks_security_inventory_finding():
    """Test that inventory finding is always present."""
    mod = _get_module()
    tasks = [
        {
            "HostName": "DESKTOP",
            "TaskName": "Task1",
            "TaskPath": "\\",
            "RunAsUser": "user",
            "ScheduleType": "At startup",
            "Task To Run": "C:\\Program Files\\App\\app.exe",
            "Created": "1/1/2025 10:00:00 AM",
            "Attributes": "",
        },
        {
            "HostName": "DESKTOP",
            "TaskName": "Task2",
            "TaskPath": "\\",
            "RunAsUser": "user",
            "ScheduleType": "At startup",
            "Task To Run": "C:\\Program Files\\App2\\app2.exe",
            "Created": "1/1/2025 10:00:00 AM",
            "Attributes": "",
        },
    ]
    fake_run = _make_run_result(tasks=tasks)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    # Should have inventory info finding
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert any("inventory" in f.title.lower() for f in info_findings)
    # Inventory should have total_count data
    inventory = [f for f in info_findings if "inventory" in f.title.lower()]
    assert inventory[0].data.get("total_count") >= 2


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.win_scheduled_tasks_security.") for c in declared)
