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
        os_version="14.0",
        architecture="arm64",
        cpu_model="Apple M1",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "suspicious_processes")


def _make_ps_output(processes_list):
    """Create fake ps aux output from a list of process info dicts.

    Each dict should have: pid, user, cpu, mem, command
    """
    header = "USER             PID  %CPU %MEM      VSZ    RSS   TT  STAT STARTED      TIME COMMAND\n"
    lines = [header]
    for proc in processes_list:
        line = (
            f"{proc['user']:<16} {proc['pid']:>5} {proc['cpu']:>4} {proc['mem']:>4} "
            f"9999999  999999   ??  Ss   10:00AM   0:00.00 {proc['command']}"
        )
        lines.append(line)
    return "".join([line + "\n" for line in lines])


def _make_run_result(ps_output=None, expect_clean=False):
    """Create a fake subprocess.run that returns appropriate results."""

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        cmd_list = cmd if isinstance(cmd, list) else cmd.split()

        # ps aux command
        if cmd_list[0] == "ps" and "aux" in cmd_list:
            if ps_output is not None:
                result.stdout = ps_output
            else:
                # Default to clean output
                result.stdout = _make_ps_output([])

        # defaults read command (for bundle ID check)
        elif cmd_list[0] == "defaults" and "read" in cmd_list:
            if expect_clean:
                result.stdout = "com.example.app\n"
            else:
                result.returncode = 1
                result.stderr = "No such key"

        return result

    return fake_run


def test_suspicious_processes_discovered():
    mod = _get_module()
    assert mod.name == "suspicious_processes"
    assert mod.category == "security"
    assert Platform.DARWIN in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_suspicious_processes_clean():
    """Test when no suspicious processes are found."""
    mod = _get_module()
    ps_output = _make_ps_output(
        [
            {
                "user": "user",
                "pid": "100",
                "cpu": "0.5",
                "mem": "2.0",
                "command": "/usr/bin/python3",
            },
            {
                "user": "user",
                "pid": "101",
                "cpu": "1.0",
                "mem": "3.0",
                "command": "/Applications/Chrome.app/Contents/MacOS/Chrome",
            },
        ]
    )
    fake_run = _make_run_result(ps_output=ps_output, expect_clean=True)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    # Should have INFO for clean status
    assert any(f.data.get("check") == "all_clean" for f in result.findings)


def test_suspicious_processes_known_malware():
    """Test detection of known malware processes."""
    mod = _get_module()
    ps_output = _make_ps_output(
        [
            {
                "user": "user",
                "pid": "123",
                "cpu": "0.5",
                "mem": "2.0",
                "command": "/Applications/genio",
            },
            {
                "user": "user",
                "pid": "124",
                "cpu": "0.5",
                "mem": "2.0",
                "command": "/Library/vsearch",
            },
        ]
    )
    fake_run = _make_run_result(ps_output=ps_output)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    malware_findings = [f for f in result.findings if f.data.get("check") == "known_malware"]
    assert len(malware_findings) > 0
    assert malware_findings[0].severity == Severity.CRITICAL


def test_suspicious_processes_suspicious_paths():
    """Test detection of processes from suspicious locations."""
    mod = _get_module()
    ps_output = _make_ps_output(
        [
            {
                "user": "user",
                "pid": "200",
                "cpu": "0.5",
                "mem": "2.0",
                "command": "/tmp/malware_runner",
            },
            {
                "user": "user",
                "pid": "201",
                "cpu": "0.5",
                "mem": "2.0",
                "command": "/var/tmp/backdoor",
            },
        ]
    )
    fake_run = _make_run_result(ps_output=ps_output)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    path_findings = [f for f in result.findings if f.data.get("check") == "suspicious_paths"]
    assert len(path_findings) > 0
    assert path_findings[0].severity == Severity.WARNING


def test_suspicious_processes_suspicious_names():
    """Test detection of processes with suspicious names."""
    mod = _get_module()
    ps_output = _make_ps_output(
        [
            {
                "user": "user",
                "pid": "300",
                "cpu": "0.5",
                "mem": "2.0",
                "command": "/usr/bin/.hidden_process",
            },
            {
                "user": "user",
                "pid": "301",
                "cpu": "0.5",
                "mem": "2.0",
                "command": "/usr/bin/a1b2c3d4e5f6",
            },
        ]
    )
    fake_run = _make_run_result(ps_output=ps_output)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    name_findings = [f for f in result.findings if f.data.get("check") == "suspicious_names"]
    assert len(name_findings) > 0
    assert name_findings[0].severity == Severity.INFO


def test_suspicious_processes_high_cpu():
    """Test detection of high-CPU processes (potential crypto miners)."""
    mod = _get_module()
    ps_output = _make_ps_output(
        [
            {
                "user": "user",
                "pid": "400",
                "cpu": "85.5",
                "mem": "10.0",
                "command": "/Applications/SuspiciousMiner.app/MacOS/miner",
            },
        ]
    )
    fake_run = _make_run_result(ps_output=ps_output)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    cpu_findings = [f for f in result.findings if f.data.get("check") == "high_cpu"]
    assert len(cpu_findings) > 0
    assert cpu_findings[0].severity == Severity.WARNING


def test_suspicious_processes_multiple_issues():
    """Test when multiple types of issues are detected."""
    mod = _get_module()
    ps_output = _make_ps_output(
        [
            {
                "user": "user",
                "pid": "100",
                "cpu": "0.5",
                "mem": "2.0",
                "command": "/Applications/genio",
            },
            {
                "user": "user",
                "pid": "200",
                "cpu": "0.5",
                "mem": "2.0",
                "command": "/tmp/malware_runner",
            },
            {
                "user": "user",
                "pid": "300",
                "cpu": "90.0",
                "mem": "15.0",
                "command": "/usr/local/bin/cryptominer",
            },
        ]
    )
    fake_run = _make_run_result(ps_output=ps_output)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    checks = [f.data.get("check") for f in result.findings]
    assert "known_malware" in checks
    assert "suspicious_paths" in checks
    assert "high_cpu" in checks


def test_suspicious_processes_fix_malware():
    """Test fix recommendation for known malware."""
    mod = _get_module()
    ps_output = _make_ps_output(
        [
            {
                "user": "user",
                "pid": "123",
                "cpu": "0.5",
                "mem": "2.0",
                "command": "/Applications/genio",
            },
        ]
    )
    fake_run = _make_run_result(ps_output=ps_output)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    malware_actions = [a for a in fix.actions if "malware" in a.title.lower()]
    assert len(malware_actions) > 0
    # Fix should be informational, not actually execute
    assert not malware_actions[0].success


def test_suspicious_processes_fix_suspicious_paths():
    """Test fix recommendation for suspicious paths."""
    mod = _get_module()
    ps_output = _make_ps_output(
        [
            {
                "user": "user",
                "pid": "200",
                "cpu": "0.5",
                "mem": "2.0",
                "command": "/tmp/malware",
            },
        ]
    )
    fake_run = _make_run_result(ps_output=ps_output)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    path_actions = [a for a in fix.actions if "suspicious paths" in a.title.lower()]
    assert len(path_actions) > 0


def test_suspicious_processes_handles_subprocess_error():
    """Test graceful handling of subprocess errors."""
    mod = _get_module()

    def error_run(cmd, **kwargs):
        raise OSError("Command failed")

    with patch("subprocess.run", side_effect=error_run):
        result = mod.check(_make_profile())
    # Should still complete without crashing
    assert isinstance(result.findings, list)
    # When ps fails, we should have no findings (graceful failure, not "clean")
    assert len(result.findings) == 0


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.suspicious_processes.") for c in declared)
