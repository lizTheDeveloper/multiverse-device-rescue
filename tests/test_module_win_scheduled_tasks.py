import json
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
    return next(m for m in modules if m.name == "win_scheduled_tasks")


def _fake_run(tasks_json):
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = tasks_json
        return result
    return fake_run


# Healthy system - no non-Microsoft tasks
EMPTY_TASKS = "[]"

# Single legitimate task
LEGITIMATE_TASK = json.dumps([
    {
        "TaskName": "OneDrive Standalone Update Task",
        "TaskPath": "\\OneDrive\\",
        "State": "Ready",
        "Actions": [
            {
                "Execute": "C:\\Program Files\\Microsoft OneDrive\\OneDriveStandaloneUpdater.exe",
                "Arguments": ""
            }
        ]
    }
])

# Task with suspicious temp path
SUSPICIOUS_PATH_TASK = json.dumps([
    {
        "TaskName": "MalwareTask",
        "TaskPath": "\\CustomTasks\\",
        "State": "Ready",
        "Actions": [
            {
                "Execute": "powershell.exe",
                "Arguments": "-Command \"C:\\Users\\admin\\AppData\\Local\\Temp\\malware.exe\""
            }
        ]
    }
])

# Task with encoded PowerShell command
ENCODED_COMMAND_TASK = json.dumps([
    {
        "TaskName": "UpdateTask",
        "TaskPath": "\\CustomTasks\\",
        "State": "Ready",
        "Actions": [
            {
                "Execute": "powershell.exe",
                "Arguments": "-enc JABjID0gJ0Mw'"
            }
        ]
    }
])

# Task with -encodedcommand flag
ENCODEDCOMMAND_FLAG_TASK = json.dumps([
    {
        "TaskName": "SystemUpdate",
        "TaskPath": "\\CustomTasks\\",
        "State": "Ready",
        "Actions": [
            {
                "Execute": "powershell.exe",
                "Arguments": "-encodedcommand JABjID0gJ0Mw'"
            }
        ]
    }
])

# Multiple tasks with mixed issues
MIXED_TASKS = json.dumps([
    {
        "TaskName": "SafeTask",
        "TaskPath": "\\SafeApp\\",
        "State": "Ready",
        "Actions": [
            {
                "Execute": "C:\\Program Files\\SafeApp\\safeapp.exe",
                "Arguments": "/update"
            }
        ]
    },
    {
        "TaskName": "TempTask",
        "TaskPath": "\\CustomTasks\\",
        "State": "Ready",
        "Actions": [
            {
                "Execute": "cmd.exe",
                "Arguments": "/c C:\\temp\\script.bat"
            }
        ]
    },
    {
        "TaskName": "EncodedTask",
        "TaskPath": "\\CustomTasks\\",
        "State": "Ready",
        "Actions": [
            {
                "Execute": "powershell.exe",
                "Arguments": "-enc aW52b2tlLXJlc3RtZXRob2Qgasc2Mtdmc="
            }
        ]
    }
])

# Task with base64 in arguments
BASE64_TASK = json.dumps([
    {
        "TaskName": "ObfuscatedTask",
        "TaskPath": "\\CustomTasks\\",
        "State": "Ready",
        "Actions": [
            {
                "Execute": "powershell.exe",
                "Arguments": "[System.Convert]::FromBase64String('JABjID0gJ0Mw')"
            }
        ]
    }
])

# Task with AppData in path
APPDATA_TASK = json.dumps([
    {
        "TaskName": "AppDataTask",
        "TaskPath": "\\CustomTasks\\",
        "State": "Ready",
        "Actions": [
            {
                "Execute": "cmd.exe",
                "Arguments": "/c C:\\Users\\admin\\AppData\\Roaming\\malware.exe"
            }
        ]
    }
])

# Task with Downloads path
DOWNLOADS_TASK = json.dumps([
    {
        "TaskName": "DownloadTask",
        "TaskPath": "\\CustomTasks\\",
        "State": "Ready",
        "Actions": [
            {
                "Execute": "C:\\Users\\admin\\Downloads\\installer.exe",
                "Arguments": ""
            }
        ]
    }
])


def test_win_scheduled_tasks_discovered():
    mod = _get_module()
    assert mod.name == "win_scheduled_tasks"
    assert mod.category == "security"
    assert Platform.WIN32 in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_win_scheduled_tasks_healthy():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(EMPTY_TASKS)):
        result = mod.check(_make_profile())
    assert not result.has_issues


def test_win_scheduled_tasks_no_output():
    mod = _get_module()

    def failed_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 1
        result.stderr = "PowerShell error"
        result.stdout = ""
        return result

    with patch("subprocess.run", side_effect=failed_run):
        result = mod.check(_make_profile())
    assert not result.has_issues


def test_win_scheduled_tasks_lists_tasks():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(LEGITIMATE_TASK)):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(
        f.severity == Severity.INFO
        and f.data.get("check") == "non_microsoft_tasks"
        for f in result.findings
    )
    assert any(
        "OneDrive Standalone Update Task" in f.data.get("tasks", [])
        for f in result.findings
    )


def test_win_scheduled_tasks_detects_temp_path():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(SUSPICIOUS_PATH_TASK)):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(
        f.severity == Severity.WARNING
        and f.data.get("check") == "suspicious_path"
        and f.data.get("task_name") == "MalwareTask"
        for f in result.findings
    )


def test_win_scheduled_tasks_detects_encoded_enc_flag():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(ENCODED_COMMAND_TASK)):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(
        f.severity == Severity.WARNING
        and f.data.get("check") == "encoded_command"
        and f.data.get("task_name") == "UpdateTask"
        for f in result.findings
    )


def test_win_scheduled_tasks_detects_encodedcommand_flag():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(ENCODEDCOMMAND_FLAG_TASK)):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(
        f.severity == Severity.WARNING
        and f.data.get("check") == "encoded_command"
        for f in result.findings
    )


def test_win_scheduled_tasks_detects_base64():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(BASE64_TASK)):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(
        f.severity == Severity.WARNING
        and f.data.get("check") == "encoded_command"
        for f in result.findings
    )


def test_win_scheduled_tasks_detects_appdata():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(APPDATA_TASK)):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(
        f.severity == Severity.WARNING
        and f.data.get("check") == "suspicious_path"
        for f in result.findings
    )


def test_win_scheduled_tasks_detects_downloads():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(DOWNLOADS_TASK)):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(
        f.severity == Severity.WARNING
        and f.data.get("check") == "suspicious_path"
        for f in result.findings
    )


def test_win_scheduled_tasks_multiple_issues():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(MIXED_TASKS)):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have INFO for all tasks, WARNING for temp path, WARNING for encoded
    info_findings = [
        f for f in result.findings if f.data.get("check") == "non_microsoft_tasks"
    ]
    suspicious_findings = [
        f for f in result.findings if f.data.get("check") == "suspicious_path"
    ]
    encoded_findings = [
        f for f in result.findings if f.data.get("check") == "encoded_command"
    ]
    assert len(info_findings) == 1
    assert len(suspicious_findings) == 1
    assert len(encoded_findings) == 1


def test_win_scheduled_tasks_fix_non_microsoft():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(LEGITIMATE_TASK)):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert any(
        a.title == "Review non-Microsoft scheduled tasks"
        for a in fix.actions
    )


def test_win_scheduled_tasks_fix_suspicious_path():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(SUSPICIOUS_PATH_TASK)):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert any(
        "execution path" in a.title
        and a.data.get("task_name") == "MalwareTask"
        for a in fix.actions
    )


def test_win_scheduled_tasks_fix_encoded_command():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(ENCODED_COMMAND_TASK)):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert any(
        "encoded command" in a.title
        and a.data.get("task_name") == "UpdateTask"
        for a in fix.actions
    )
