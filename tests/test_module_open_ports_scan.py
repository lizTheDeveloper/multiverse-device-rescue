import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.command import CommandResult
from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules

FIX = Path(__file__).parent / "fixtures" / "conn"


def _make_profile(platform=Platform.DARWIN):
    return SystemProfile(
        platform=platform,
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
    return next(m for m in modules if m.name == "open_ports_scan")


def _make_subprocess_result(stdout="", stderr="", returncode=0, error=None):
    return CommandResult(
        args=[], returncode=returncode, stdout=stdout, stderr=stderr,
        timed_out=False, error=error, duration_s=0.0, truncated=False,
    )


def _fake_run(lsof=None, ss=None, win=None, error=None):
    """A stand-in for rescue.command.run that answers the collector's commands."""
    def run(args, **kwargs):
        if error:
            return _make_subprocess_result(returncode=None, error=error)
        if args[0] == "lsof" and lsof is not None:
            return _make_subprocess_result(lsof, returncode=0 if lsof.strip() else 1)
        if args[0] == "ss" and "-tunapH" in args and ss is not None:
            return _make_subprocess_result(ss)
        if args[0] == "powershell" and win is not None:
            return _make_subprocess_result(win)
        return _make_subprocess_result(returncode=1)
    return run


def _check(platform=Platform.DARWIN, **kw):
    mod = _get_module()
    with patch("rescue.command.run", side_effect=_fake_run(**kw)):
        return mod.check(_make_profile(platform))


def _warnings(result):
    return [f for f in result.findings if f.severity in (Severity.WARNING, Severity.CRITICAL)]


def _win_output(tcp, proc, udp="[]"):
    return "\n".join(part.strip() for part in (tcp, udp, proc)) + "\n"


def _fake_run_no_ports():
    """No listening ports: lsof prints nothing and exits 1"""
    def fake_run(cmd, **kwargs):
        if cmd[0] == "lsof":
            return _make_subprocess_result("", returncode=1)
        return _make_subprocess_result(returncode=1)
    return fake_run


def _fake_run_normal_ports():
    """Normal listening ports: SSH and HTTP"""
    def fake_run(cmd, **kwargs):
        if cmd[0] == "lsof":
            return _make_subprocess_result(
                "COMMAND   PID  USER  FD   TYPE             DEVICE SIZE/OFF NODE NAME\n"
                "sshd      123 root   4  IPv4  0x123456 0t0 TCP 0.0.0.0:22 (LISTEN)\n"
                "nginx     456 www    5  IPv4  0x234567 0t0 TCP 0.0.0.0:80 (LISTEN)\n"
                "nginx     456 www    6  IPv4  0x345678 0t0 TCP 0.0.0.0:443 (LISTEN)\n"
            )
        return _make_subprocess_result(returncode=1)
    return fake_run


def _fake_run_exposed_mysql():
    """MySQL exposed to 0.0.0.0 - risky"""
    def fake_run(cmd, **kwargs):
        if cmd[0] == "lsof":
            return _make_subprocess_result(
                "COMMAND   PID  USER  FD   TYPE             DEVICE SIZE/OFF NODE NAME\n"
                "sshd      123 root   4  IPv4  0x123456 0t0 TCP 0.0.0.0:22 (LISTEN)\n"
                "mysqld    789 mysql  7  IPv4  0x456789 0t0 TCP 0.0.0.0:3306 (LISTEN)\n"
            )
        return _make_subprocess_result(returncode=1)
    return fake_run


def _fake_run_localhost_mysql():
    """MySQL bound to localhost - safe"""
    def fake_run(cmd, **kwargs):
        if cmd[0] == "lsof":
            return _make_subprocess_result(
                "COMMAND   PID  USER  FD   TYPE             DEVICE SIZE/OFF NODE NAME\n"
                "mysqld    789 mysql  7  IPv4  0x456789 0t0 TCP 127.0.0.1:3306 (LISTEN)\n"
            )
        return _make_subprocess_result(returncode=1)
    return fake_run


def _fake_run_multiple_risky():
    """Multiple risky ports exposed"""
    def fake_run(cmd, **kwargs):
        if cmd[0] == "lsof":
            return _make_subprocess_result(
                "COMMAND   PID  USER  FD   TYPE             DEVICE SIZE/OFF NODE NAME\n"
                "mysqld    123 mysql  4  IPv4  0x123456 0t0 TCP 0.0.0.0:3306 (LISTEN)\n"
                "postgres  456 postgres 5 IPv4 0x234567 0t0 TCP 0.0.0.0:5432 (LISTEN)\n"
                "mongod    789 mongodb  6  IPv4  0x345678 0t0 TCP 0.0.0.0:27017 (LISTEN)\n"
            )
        return _make_subprocess_result(returncode=1)
    return fake_run


def test_open_ports_scan_discovered():
    mod = _get_module()
    assert mod.name == "open_ports_scan"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE


def test_open_ports_scan_no_ports():
    mod = _get_module()
    with patch("rescue.command.run", side_effect=_fake_run_no_ports()):
        result = mod.check(_make_profile())
    assert not result.has_issues


def test_open_ports_scan_normal_ports():
    mod = _get_module()
    with patch("rescue.command.run", side_effect=_fake_run_normal_ports()):
        result = mod.check(_make_profile())
    # Normal ports should show as INFO, no warnings
    assert result.has_issues
    assert any(f.data.get("check") == "listening_ports" for f in result.findings)
    assert not any(f.severity == Severity.WARNING for f in result.findings)


def test_open_ports_scan_exposed_mysql():
    mod = _get_module()
    with patch("rescue.command.run", side_effect=_fake_run_exposed_mysql()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "exposed_risky_ports" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_open_ports_scan_localhost_mysql():
    mod = _get_module()
    with patch("rescue.command.run", side_effect=_fake_run_localhost_mysql()):
        result = mod.check(_make_profile())
    # MySQL on localhost is safe, should be INFO only
    assert result.has_issues
    assert any(f.data.get("check") == "listening_ports" for f in result.findings)
    assert not any(f.severity == Severity.WARNING for f in result.findings)


def test_open_ports_scan_multiple_risky():
    mod = _get_module()
    with patch("rescue.command.run", side_effect=_fake_run_multiple_risky()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have warning for exposed risky ports
    assert any(f.severity == Severity.WARNING for f in result.findings)
    # Should have info for listening ports
    assert any(f.data.get("check") == "listening_ports" for f in result.findings)


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.open_ports_scan.") for c in declared)


def test_open_ports_scan_fix_is_informational():
    mod = _get_module()
    with patch("rescue.command.run", side_effect=_fake_run_exposed_mysql()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action per finding
    assert len(fix.actions) > 0


def test_open_ports_scan_lsof_star_is_all_interfaces():
    """lsof writes "every network" as *, not 0.0.0.0."""
    lsof = (
        "COMMAND   PID  USER  FD   TYPE             DEVICE SIZE/OFF NODE NAME\n"
        "postgres  456 me    5  IPv4  0x234567 0t0 TCP *:5432 (LISTEN)\n"
    )
    result = _check(lsof=lsof)
    assert any(f.data.get("check") == "exposed_risky_ports" for f in _warnings(result))


# --- every platform ------------------------------------------------------------


def test_runs_on_every_platform():
    assert set(_get_module().platforms) == {Platform.DARWIN, Platform.LINUX, Platform.WIN32}


def test_linux_clean_machine_no_warnings():
    result = _check(Platform.LINUX, ss=(FIX / "clean_linux_ss.txt").read_text())
    assert not _warnings(result)
    listed = [f for f in result.findings if f.data.get("check") == "listening_ports"]
    assert listed and listed[0].data["count"] == 3


def test_windows_clean_machine_no_warnings():
    win = _win_output((FIX / "clean_win_listen.json").read_text(), (FIX / "win_proc.json").read_text())
    result = _check(Platform.WIN32, win=win)
    assert not _warnings(result)
    listed = [f for f in result.findings if f.data.get("check") == "listening_ports"]
    assert listed and listed[0].data["count"] == 5


def test_linux_exposed_database_warns():
    ss = 'tcp   LISTEN 0 128 0.0.0.0:5432 0.0.0.0:* users:(("postgres",pid=9,fd=3))\n'
    assert any(
        f.data.get("check") == "exposed_risky_ports" for f in _warnings(_check(Platform.LINUX, ss=ss))
    )


def test_unnamed_listener_is_info():
    ss = (FIX / "ss_tunap_linux_nonroot.txt").read_text() + (
        "tcp   LISTEN 0      128          0.0.0.0:8000       0.0.0.0:*\n"
    )
    result = _check(Platform.LINUX, ss=ss)
    assert not _warnings(result)
    listed = [f for f in result.findings if f.data.get("check") == "listening_ports"]
    assert len(listed) == 1 and listed[0].severity == Severity.INFO
    assert "couldn't see which program" in listed[0].description
    assert listed[0].data["unseen"] == 2


@pytest.mark.parametrize("platform", [Platform.DARWIN, Platform.LINUX, Platform.WIN32])
def test_collector_error_is_couldnt_check(platform):
    result = _check(platform, error="not found")
    assert not _warnings(result)
    assert len(result.findings) == 1
    assert result.findings[0].severity == Severity.INFO
    assert result.findings[0].code == "security.open_ports_scan.couldnt_check"
    assert "not the same as a clean result" in result.findings[0].description


def test_advice_names_platform_tool():
    mod = _get_module()
    ss = 'tcp   LISTEN 0 128 0.0.0.0:8000 0.0.0.0:* users:(("app",pid=9,fd=3))\n'
    tcp = json.dumps({"LocalAddress": "0.0.0.0", "LocalPort": 8000, "RemoteAddress": "0.0.0.0",
                      "RemotePort": 0, "State": 2, "OwningProcess": 9})
    proc = json.dumps({"Id": 9, "ProcessName": "app", "Path": "C:\\Users\\sam\\app.exe"})
    texts = {}
    for platform, kw in (
        (Platform.LINUX, {"ss": ss}),
        (Platform.WIN32, {"win": _win_output(tcp, proc)}),
    ):
        check = _check(platform, **kw)
        fix = mod.fix(check, Mode.MANUAL)
        texts[platform] = "\n".join(
            [f.description for f in check.findings] + [a.description for a in fix.actions]
        )
    assert "Task Manager" in texts[Platform.WIN32] or "Resource Monitor" in texts[Platform.WIN32]
    assert "ss -tlnp" in texts[Platform.LINUX]
    for text in texts.values():
        assert "Activity Monitor" not in text
        assert "lsof" not in text
        assert "kill" not in text.lower()


def test_exposed_database_warns_even_when_program_not_visible():
    ss = "tcp   LISTEN 0      128          0.0.0.0:5432       0.0.0.0:*\n"
    warned = _warnings(_check(Platform.LINUX, ss=ss))
    assert len(warned) == 1 and warned[0].data["check"] == "exposed_risky_ports"
    assert "program not visible" in warned[0].description


def test_listener_without_address_is_not_exposed():
    mod = _get_module()
    rec = {"proto": "tcp", "state": "LISTEN", "local_addr": None, "local_port": 5432,
           "remote_addr": None, "remote_port": None, "pid": 9, "process": "postgres", "exe": None}
    ports = mod._listening_ports([rec])
    assert ports[0]["address"] not in ("0.0.0.0", "*", "::")


def test_skips_data_count_commands():
    seen = []
    ss = 'tcp   LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=8,fd=3))\n'
    fake = _fake_run(ss=ss)

    def run(args, **kw):
        seen.append(args)
        return fake(args, **kw)

    with patch("rescue.command.run", side_effect=run):
        _get_module().check(_make_profile(Platform.LINUX))
    assert seen == [["ss", "-tunapH"]]
