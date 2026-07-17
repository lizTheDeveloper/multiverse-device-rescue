import json
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


# Sample process output
CLEAN_PROCESSES = [
    {
        "Name": "explorer.exe",
        "Id": 1234,
        "Path": "C:\\Windows\\explorer.exe",
        "CPU": 1.5,
        "WorkingSet64": 100000000,
    },
    {
        "Name": "svchost.exe",
        "Id": 5678,
        "Path": "C:\\Windows\\System32\\svchost.exe",
        "CPU": 0.5,
        "WorkingSet64": 50000000,
    },
]

MALWARE_PROCESS = [
    {
        "Name": "xmrig.exe",
        "Id": 9999,
        "Path": "C:\\Windows\\System32\\xmrig.exe",
        "CPU": 95.0,
        "WorkingSet64": 500000000,
    },
]

TEMP_PATH_PROCESS = [
    {
        "Name": "suspicious.exe",
        "Id": 8888,
        "Path": "C:\\Users\\admin\\AppData\\Local\\Temp\\suspicious.exe",
        "CPU": 10.0,
        "WorkingSet64": 150000000,
    },
]

NO_PATH_PROCESS = [
    {
        "Name": "injected.exe",
        "Id": 7777,
        "Path": "",
        "CPU": 5.0,
        "WorkingSet64": 75000000,
    },
]

NICEHASH_PROCESS = [
    {
        "Name": "nicehash.exe",
        "Id": 6666,
        "Path": "C:\\Program Files\\NiceHash\\nicehash.exe",
        "CPU": 80.0,
        "WorkingSet64": 400000000,
    },
]

TRICKBOT_PROCESS = [
    {
        "Name": "trickbot.dll",
        "Id": 5555,
        "Path": "C:\\Windows\\Temp\\trickbot.dll",
        "CPU": 20.0,
        "WorkingSet64": 200000000,
    },
]

ENCODED_POWERSHELL_CMD = (
    "powershell.exe -NoProfile -EncodedCommand JABvAG==",
)


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
    return next(
        m for m in modules if m.name == "win_suspicious_processes"
    )


def _fake_process_run(
    processes=None,
    powershell_cmds=None,
    ps_cmd_failure=False,
):
    """Create a fake subprocess.run that returns process data."""

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        cmd_list = cmd if isinstance(cmd, list) else cmd.split()

        # Get-Process command for listing processes
        if "Get-Process" in " ".join(cmd_list) and "powershell" not in "".join(
            cmd_list[3:]
        ).lower():
            if processes is not None:
                result.stdout = json.dumps(processes)
            else:
                result.stdout = json.dumps(CLEAN_PROCESSES)

        # Get-Process powershell for encoded commands
        elif "Get-Process powershell" in " ".join(cmd_list):
            if ps_cmd_failure:
                result.returncode = 1
                result.stderr = "Error getting powershell process"
            elif powershell_cmds is not None:
                result.stdout = json.dumps(powershell_cmds)
            else:
                result.stdout = json.dumps([])

        return result

    return fake_run


def test_win_suspicious_processes_discovered():
    mod = _get_module()
    assert mod.name == "win_suspicious_processes"
    assert mod.category == "security"
    assert Platform.WIN32 in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_win_suspicious_processes_clean():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_process_run()):
        result = mod.check(_make_profile())
    assert not result.has_issues


def test_win_suspicious_processes_detects_known_malware():
    mod = _get_module()
    with patch(
        "subprocess.run",
        side_effect=_fake_process_run(processes=CLEAN_PROCESSES + MALWARE_PROCESS),
    ):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have summary + malware finding
    assert len(result.findings) >= 2
    malware_finding = next(
        (f for f in result.findings if f.data.get("type") == "known_malware"),
        None,
    )
    assert malware_finding is not None
    assert malware_finding.severity == Severity.CRITICAL


def test_win_suspicious_processes_detects_temp_path():
    mod = _get_module()
    with patch(
        "subprocess.run",
        side_effect=_fake_process_run(processes=CLEAN_PROCESSES + TEMP_PATH_PROCESS),
    ):
        result = mod.check(_make_profile())
    assert result.has_issues
    temp_finding = next(
        (f for f in result.findings if f.data.get("type") == "suspicious_path"),
        None,
    )
    assert temp_finding is not None
    assert temp_finding.severity == Severity.WARNING


def test_win_suspicious_processes_detects_no_path():
    mod = _get_module()
    with patch(
        "subprocess.run",
        side_effect=_fake_process_run(processes=CLEAN_PROCESSES + NO_PATH_PROCESS),
    ):
        result = mod.check(_make_profile())
    assert result.has_issues
    no_path_finding = next(
        (f for f in result.findings if f.data.get("type") == "no_file_path"), None
    )
    assert no_path_finding is not None
    assert no_path_finding.severity == Severity.WARNING


def test_win_suspicious_processes_detects_nicehash():
    mod = _get_module()
    with patch(
        "subprocess.run",
        side_effect=_fake_process_run(processes=CLEAN_PROCESSES + NICEHASH_PROCESS),
    ):
        result = mod.check(_make_profile())
    assert result.has_issues
    mining_finding = next(
        (
            f
            for f in result.findings
            if f.data.get("type") == "mining_software"
        ),
        None,
    )
    assert mining_finding is not None
    assert mining_finding.severity == Severity.WARNING


def test_win_suspicious_processes_detects_trickbot():
    mod = _get_module()
    with patch(
        "subprocess.run",
        side_effect=_fake_process_run(processes=CLEAN_PROCESSES + TRICKBOT_PROCESS),
    ):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Trickbot is both known malware AND in temp path, but should be flagged as malware
    malware_finding = next(
        (f for f in result.findings if f.data.get("type") == "known_malware"),
        None,
    )
    assert malware_finding is not None
    assert malware_finding.severity == Severity.CRITICAL


def test_win_suspicious_processes_fix_creates_actions():
    mod = _get_module()
    with patch(
        "subprocess.run",
        side_effect=_fake_process_run(processes=CLEAN_PROCESSES + MALWARE_PROCESS),
    ):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # Should have actions for non-summary findings
    assert len(fix.actions) > 0
    # Actions should be informational (success=True)
    assert all(a.success for a in fix.actions)


def test_win_suspicious_processes_fix_action_details():
    mod = _get_module()
    with patch(
        "subprocess.run",
        side_effect=_fake_process_run(processes=CLEAN_PROCESSES + MALWARE_PROCESS),
    ):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # Should have details in action
    action = fix.actions[0]
    assert "Investigate" in action.title or "xmrig" in action.title
    assert action.risk_level in [RiskLevel.MODERATE, RiskLevel.SAFE]
