import json
import re
import sys

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.command import CommandResult
from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules
from rescue.runtime import load_content_module

FIX = Path(__file__).parent / "fixtures" / "conn"
COLLECT = load_content_module("modules/network/conn_common/collect.py", "rescue_conn_common_collect")



_POSIX_PATHS = pytest.mark.skipif(
    sys.platform == "win32", reason="resolves POSIX SIP paths with os.path.realpath, which Windows rewrites to a drive path"
)

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
    return next(m for m in modules if m.name == "suspicious_connections")


def _result(stdout="", returncode=0, error=None):
    return CommandResult(
        args=[], returncode=returncode, stdout=stdout, stderr="",
        timed_out=False, error=error, duration_s=0.0, truncated=False,
    )


def _fake_run(lsof="", ss="", win=None, error=None):
    """A stand-in for rescue.command.run that answers the collector's commands."""
    def run(args, **kwargs):
        if error:
            return _result(returncode=None, error=error)
        if args[0] == "lsof":
            return _result(lsof, returncode=0 if lsof.strip() else 1)
        if args[0] == "ss" and "-tunapH" in args:
            return _result(ss)
        if args[0] == "powershell" and win is not None:
            return _result(win)
        # nettop, ss -tni and codesign: not available here
        return _result(returncode=1)
    return run


def _check(platform=Platform.DARWIN, **kw):
    mod = _get_module()
    with patch("rescue.command.run", side_effect=_fake_run(**kw)):
        return mod.check(_make_profile(platform))


def _fake_lsof_output(lsof_text):
    """Feed lsof text through the shared collector's runner."""
    return _fake_run(lsof=lsof_text)


def _win_output(tcp, proc, udp="[]"):
    return "\n".join(part.strip() for part in (tcp, udp, proc)) + "\n"


def test_suspicious_connections_discovered():
    mod = _get_module()
    assert mod.name == "suspicious_connections"
    assert mod.risk_level == RiskLevel.SAFE
    assert mod.category == "security"


def test_suspicious_connections_healthy_standard_ports():
    """No suspicious activity when only standard ports are used."""
    mod = _get_module()
    lsof_output = """COMMAND     PID     USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
Safari    12345     user   10u  IPv4 0x1234567890123456      0t0  TCP *:443 (LISTEN)
Mail      12346     user   11u  IPv4 0x1234567890123457      0t0  TCP *:993 (LISTEN)
Chrome    12347     user   12u  IPv4 0x1234567890123458      0t0  TCP *:80 (LISTEN)"""

    with patch("rescue.command.run", side_effect=_fake_lsof_output(lsof_output)):
        result = mod.check(_make_profile())

    assert not result.has_issues


def test_suspicious_connections_unusual_listening_port():
    """Detect unusual listening ports."""
    mod = _get_module()
    lsof_output = """COMMAND     PID     USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
Safari    12345     user   10u  IPv4 0x1234567890123456      0t0  TCP *:443 (LISTEN)
BadApp    12348     user   13u  IPv4 0x1234567890123459      0t0  TCP *:8888 (LISTEN)"""

    with patch("rescue.command.run", side_effect=_fake_lsof_output(lsof_output)):
        result = mod.check(_make_profile())

    assert result.has_issues
    assert len(result.findings) == 1
    assert "waiting for connections" in result.findings[0].title.lower()
    assert result.findings[0].severity == Severity.WARNING
    assert result.findings[0].data["port"] == 8888


def test_suspicious_connections_unusual_outbound_connection():
    """Detect unusual outbound connections to non-standard ports."""
    mod = _get_module()
    lsof_output = """COMMAND     PID     USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
Safari    12345     user   10u  IPv4 0x1234567890123456      0t0  TCP 192.168.1.1:50000 (ESTABLISHED)
BadApp    12348     user   13u  IPv4 0x1234567890123459      0t0  TCP 10.0.0.1:9999 (ESTABLISHED)"""

    with patch("rescue.command.run", side_effect=_fake_lsof_output(lsof_output)):
        result = mod.check(_make_profile())

    # Safari is known safe, so should not flag it
    # BadApp is not known safe and uses non-standard port, so should flag it
    assert result.has_issues
    findings_about_badapp = [f for f in result.findings if "BadApp" in f.data.get("process", "")]
    assert len(findings_about_badapp) >= 1
    assert findings_about_badapp[0].data["port"] == 9999


def test_suspicious_connections_known_safe_process():
    """Known safe processes shouldn't be flagged even with unusual ports."""
    mod = _get_module()
    lsof_output = """COMMAND     PID     USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
Safari    12345     user   10u  IPv4 0x1234567890123456      0t0  TCP 192.168.1.1:9999 (ESTABLISHED)
Chrome    12346     user   11u  IPv4 0x1234567890123457      0t0  TCP 192.168.1.2:8888 (ESTABLISHED)"""

    with patch("rescue.command.run", side_effect=_fake_lsof_output(lsof_output)):
        result = mod.check(_make_profile())

    # Familiar names are not alarming, but they stay listed (as info) because
    # a process name can be chosen by any program.
    assert not [f for f in result.findings if f.severity != Severity.INFO]
    assert [f for f in result.findings if f.data.get("check") == "familiar_connections"]


def test_suspicious_connections_high_connection_count():
    """Detect processes with unusually high connection counts."""
    mod = _get_module()
    # Create a process with 12 connections (exceeds threshold of 10)
    connections = [
        "MalwareApp 12348     user   13u  IPv4 0x1234567890123459      0t0  TCP 192.168.1.1:5000 (ESTABLISHED)"
        for _ in range(12)
    ]
    lsof_output = """COMMAND     PID     USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
""" + "\n".join(connections)

    with patch("rescue.command.run", side_effect=_fake_lsof_output(lsof_output)):
        result = mod.check(_make_profile())

    # Should detect high connection count
    high_conn_findings = [
        f for f in result.findings
        if f.data.get("check") == "high_connection_count"
    ]
    assert len(high_conn_findings) >= 1
    assert high_conn_findings[0].severity == Severity.INFO


def test_suspicious_connections_multiple_issues():
    """Detect multiple issues in a single scan."""
    mod = _get_module()
    lsof_output = """COMMAND     PID     USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
Safari    12345     user   10u  IPv4 0x1234567890123456      0t0  TCP *:443 (LISTEN)
MalApp1   12348     user   13u  IPv4 0x1234567890123459      0t0  TCP *:7777 (LISTEN)
MalApp2   12349     user   14u  IPv4 0x1234567890123460      0t0  TCP 192.168.1.1:6666 (ESTABLISHED)
MalApp2   12349     user   15u  IPv4 0x1234567890123461      0t0  TCP 192.168.1.2:6666 (ESTABLISHED)
MalApp2   12349     user   16u  IPv4 0x1234567890123462      0t0  TCP 192.168.1.3:6666 (ESTABLISHED)"""

    with patch("rescue.command.run", side_effect=_fake_lsof_output(lsof_output)):
        result = mod.check(_make_profile())

    assert result.has_issues
    assert len(result.findings) >= 2


def test_suspicious_connections_fix_is_informational():
    """fix() should be informational only, never kill processes."""
    mod = _get_module()
    lsof_output = """COMMAND     PID     USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
BadApp    12348     user   13u  IPv4 0x1234567890123459      0t0  TCP *:8888 (LISTEN)"""

    with patch("rescue.command.run", side_effect=_fake_lsof_output(lsof_output)):
        check = mod.check(_make_profile())

    # Patch the command runners to verify no kill commands are issued
    with patch("subprocess.run") as mock_run, patch("rescue.command.run") as mock_cmd:
        fix = mod.fix(check, Mode.MANUAL)

    # Verify no commands were run (fix is informational)
    mock_run.assert_not_called()
    mock_cmd.assert_not_called()

    # Verify fix succeeded with informational actions
    assert fix.all_succeeded
    assert len(fix.actions) == 1
    assert fix.actions[0].success is True
    assert fix.actions[0].error is None


def test_suspicious_connections_empty_lsof():
    """lsof prints nothing (and exits 1) when no program has a connection open."""
    mod = _get_module()

    with patch("rescue.command.run", side_effect=_fake_lsof_output("")):
        result = mod.check(_make_profile())

    assert not result.has_issues


def test_suspicious_connections_lsof_unavailable():
    """A missing lsof is reported as couldn't-check, never as a clean result."""
    result = _check(error="not found")
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.severity == Severity.INFO
    assert finding.code == "security.suspicious_connections.couldnt_check"


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.suspicious_connections.") for c in declared)


# --- false-alarm regressions -------------------------------------------------

_HDR = "COMMAND     PID     USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME\n"


def _run_with(lsof_text, kernel=None, apple_signed=True):
    """kernel: {pid_int: kernel-reported path}; apple_signed: result of the signature check."""
    mod = _get_module()
    kernel = kernel or {}

    with patch("rescue.command.run", side_effect=_fake_run(lsof=lsof_text)), patch.object(
        type(mod), "_kernel_path", staticmethod(lambda pid: kernel.get(int(pid)))
    ), patch.object(type(mod), "_apple_signed", lambda self, path: apple_signed):
        return mod.check(_make_profile())


def test_loopback_listeners_do_not_warn_and_are_aggregated():
    lsof = _HDR + (
        "node 100 u 10u IPv4 0x1 0t0 TCP 127.0.0.1:3100 (LISTEN)\n"
        "redis-ser 101 u 10u IPv6 0x2 0t0 TCP [::1]:6390 (LISTEN)\n"
        "postgres 102 u 10u IPv4 0x3 0t0 TCP 127.0.0.1:54329 (LISTEN)\n"
    )
    result = _run_with(lsof)
    assert not [f for f in result.findings if f.severity == Severity.WARNING]
    infos = [f for f in result.findings if f.severity == Severity.INFO]
    assert len(infos) == 1


def test_network_listener_still_warns_one_finding_per_process():
    lsof = _HDR + (
        "node 100 u 10u IPv4 0x1 0t0 TCP *:8765 (LISTEN)\n"
        "node 100 u 11u IPv4 0x1 0t0 TCP *:8766 (LISTEN)\n"
    )
    result = _run_with(lsof)
    warns = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warns) == 1
    assert warns[0].data["ports"] == [8765, 8766]


@_POSIX_PATHS
def test_apple_daemon_listener_by_kernel_path_and_signature_is_ignored():
    lsof = _HDR + "rapportd 998 u 10u IPv4 0x1 0t0 TCP *:50584 (LISTEN)\n"
    assert not _run_with(lsof, {998: "/usr/libexec/rapportd"}).has_issues


def test_same_name_outside_system_path_still_warns():
    lsof = _HDR + "rapportd 998 u 10u IPv4 0x1 0t0 TCP *:50584 (LISTEN)\n"
    assert _run_with(lsof, {998: "/tmp/evil/rapportd"}).has_issues


def test_unknown_kernel_path_still_warns():
    lsof = _HDR + "rapportd 998 u 10u IPv4 0x1 0t0 TCP *:50584 (LISTEN)\n"
    assert _run_with(lsof, {}).has_issues


def test_system_path_without_apple_signature_still_warns():
    lsof = _HDR + "rapportd 998 u 10u IPv4 0x1 0t0 TCP *:50584 (LISTEN)\n"
    assert _run_with(lsof, {998: "/usr/libexec/rapportd"}, apple_signed=False).has_issues


def test_system_interpreter_listener_still_warns():
    lsof = _HDR + "python3 998 u 10u IPv4 0x1 0t0 TCP *:50584 (LISTEN)\n"
    assert _run_with(lsof, {998: "/usr/bin/python3"}).has_issues


def test_loopback_to_loopback_connection_is_not_outbound():
    lsof = _HDR + (
        "postgres 6839 u 10u IPv6 0x1 0t0 TCP [::1]:54329->[::1]:57148 (ESTABLISHED)\n"
        "ssh 22527 u 10u IPv4 0x1 0t0 TCP 127.0.0.1:55000->127.0.0.1:64456 (ESTABLISHED)\n"
    )
    assert not _run_with(lsof).has_issues


def test_fcm_port_5228_is_normal():
    lsof = _HDR + "Slack 5 u 10u IPv4 0x1 0t0 TCP 192.168.1.5:50000->142.250.1.1:5228 (ESTABLISHED)\n"
    result = _run_with(lsof)
    assert not [f for f in result.findings if f.severity != Severity.INFO]
    # ...but it stays listed: a port number proves nothing about who is talking
    assert [f for f in result.findings if f.data.get("check") == "familiar_connections"]


def test_familiar_name_or_push_port_does_not_hide_odd_connection():
    lsof = _HDR + (
        "Chrome 7 u 10u IPv4 0x1 0t0 TCP 192.168.1.5:50000->8.8.8.8:9999 (ESTABLISHED)\n"
        "backdoor 8 u 10u IPv4 0x1 0t0 TCP 192.168.1.5:50001->8.8.8.8:5228 (ESTABLISHED)\n"
    )
    result = _run_with(lsof, {7: "/private/tmp/Chrome", 8: "/private/tmp/backdoor"})
    listed = [f for f in result.findings if f.data.get("check") == "familiar_connections"]
    assert len(listed) == 1
    assert listed[0].severity == Severity.INFO
    assert {p["process"] for p in listed[0].data["items"]} == {"Chrome", "backdoor"}


def test_remote_unusual_port_collapses_per_process():
    lsof = _HDR + "".join(
        f"BadApp 7 u {i}u IPv4 0x1 0t0 TCP 192.168.1.5:5000{i}->8.8.8.8:{9990 + i} (ESTABLISHED)\n"
        for i in range(3)
    )
    result = _run_with(lsof)
    out = [f for f in result.findings if f.data.get("check") == "unusual_outbound_connection"]
    assert len(out) == 1
    assert out[0].data["ports"] == [9990, 9991, 9992]


# --- every platform ------------------------------------------------------------


def _warnings(result):
    return [f for f in result.findings if f.severity in (Severity.WARNING, Severity.CRITICAL)]


def test_runs_on_every_platform():
    assert set(_get_module().platforms) == {Platform.DARWIN, Platform.LINUX, Platform.WIN32}


def test_linux_clean_machine_no_warnings():
    result = _check(Platform.LINUX, ss=(FIX / "clean_linux_ss.txt").read_text())
    assert not _warnings(result)


def test_windows_clean_machine_no_warnings():
    win = _win_output((FIX / "clean_win_listen.json").read_text(), (FIX / "win_proc.json").read_text())
    result = _check(Platform.WIN32, win=win)
    assert not _warnings(result)
    # every listener is a verified Windows service, so nothing is even noted
    assert not [f for f in result.findings if f.data.get("check") == "unnamed_listeners"]


def test_windows_pathless_services_are_noted_not_warned():
    """Without admin, Windows hides svchost's path: an info note, never a warning or silence."""
    win = _win_output(
        (FIX / "clean_win_listen.json").read_text(), (FIX / "win_proc_nopath.json").read_text()
    )
    result = _check(Platform.WIN32, win=win)
    assert not _warnings(result)
    noted = [f for f in result.findings if f.data.get("check") == "unnamed_listeners"]
    assert len(noted) == 1
    assert "couldn't confirm which program" in noted[0].description
    assert {i["port"] for i in noted[0].data["items"]} == {135, 7680, 49664}


def test_listening_verdict_windows():
    mod = _get_module()
    recs = COLLECT.parse_win_connections(
        (FIX / "clean_win_listen.json").read_text(), "[]", (FIX / "win_proc_nopath.json").read_text()
    )
    svchost = next(r for r in recs if r["local_port"] == 49664)
    assert mod.listening_verdict("win32", svchost) == "unnamed"
    system = next(r for r in recs if r["local_port"] == 445)
    assert mod.listening_verdict("win32", system) == "expected"
    rundll = {**svchost, "local_port": 49670, "process": "rundll32", "pid": 6000}
    assert mod.listening_verdict("win32", rundll) == "flag"
    with_path = {**svchost, "exe": "C:\\Windows\\System32\\svchost.exe"}
    assert mod.listening_verdict("win32", with_path) == "expected"


def test_listening_verdict_linux_and_ports():
    mod = _get_module()
    rec = {"proto": "tcp", "state": "LISTEN", "local_addr": "0.0.0.0", "local_port": 8000,
           "remote_addr": None, "remote_port": None, "pid": 9, "process": "python3", "exe": None}
    assert mod.listening_verdict("linux", rec) == "flag"
    assert mod.listening_verdict("linux", {**rec, "process": None, "pid": None}) == "unnamed"
    assert mod.listening_verdict("linux", {**rec, "local_addr": "127.0.0.1"}) == "expected"
    assert mod.listening_verdict("linux", {**rec, "local_port": 443}) == "expected"
    assert mod.listening_verdict("linux", {**rec, "process": "sshd", "local_port": 22}) == "expected"


def test_unnamed_listener_is_info():
    ss = (FIX / "ss_tunap_linux_nonroot.txt").read_text() + (
        "tcp   LISTEN 0      128          0.0.0.0:8000       0.0.0.0:*\n"
    )
    result = _check(Platform.LINUX, ss=ss)
    assert not _warnings(result)
    noted = [f for f in result.findings if f.data.get("check") == "unnamed_listeners"]
    assert len(noted) == 1
    assert noted[0].severity == Severity.INFO
    assert "couldn't see which program" in noted[0].description


def test_unnamed_outbound_is_info():
    ss = "tcp   ESTAB  0      0       192.168.1.30:51050   203.0.113.10:9999\n"
    result = _check(Platform.LINUX, ss=ss)
    assert not _warnings(result)
    noted = [f for f in result.findings if f.data.get("check") == "unnamed_connections"]
    assert len(noted) == 1 and noted[0].severity == Severity.INFO


@pytest.mark.parametrize("platform", [Platform.LINUX, Platform.WIN32])
def test_collector_error_is_couldnt_check(platform):
    result = _check(platform, error="not found")
    assert not _warnings(result)
    assert len(result.findings) == 1
    assert result.findings[0].severity == Severity.INFO
    assert "not the same as a clean result" in result.findings[0].description


def test_advice_names_platform_tool():
    ss = (
        "tcp   LISTEN 0 128 0.0.0.0:8000 0.0.0.0:* users:((\"backdoor\",pid=9,fd=3))\n"
        "tcp   ESTAB  0 0 192.168.1.30:51050 203.0.113.10:9999 users:((\"backdoor\",pid=9,fd=4))\n"
    )
    linux = _warnings(_check(Platform.LINUX, ss=ss))
    tcp = json.dumps([
        {"LocalAddress": "0.0.0.0", "LocalPort": 8000, "RemoteAddress": "0.0.0.0",
         "RemotePort": 0, "State": 2, "OwningProcess": 9},
        {"LocalAddress": "192.168.1.40", "LocalPort": 50712, "RemoteAddress": "203.0.113.10",
         "RemotePort": 9999, "State": 5, "OwningProcess": 9},
    ])
    proc = json.dumps([{"Id": 9, "ProcessName": "backdoor", "Path": "C:\\Users\\sam\\backdoor.exe"}])
    win = _warnings(_check(Platform.WIN32, win=_win_output(tcp, proc)))
    assert len(linux) == 2 and len(win) == 2
    for f in win:
        assert "Task Manager" in f.description or "Resource Monitor" in f.description
    for f in linux:
        assert "`ss " in f.description
    for f in linux + win:
        assert "Activity Monitor" not in f.description
        assert "System Settings" not in f.description
        assert "kill" not in f.description.lower()
        assert "end task" not in f.description.lower()


def test_linux_clean_machine_outbound_no_warnings():
    result = _check(Platform.LINUX, ss=(FIX / "clean_linux_ss_outbound.txt").read_text())
    assert not _warnings(result)
    familiar = [f for f in result.findings if f.data.get("check") == "familiar_connections"]
    # still listed: a name proves nothing. Browsers and calls on 443 are ordinary
    # and not listed; only the push-notification port is.
    assert {i["process"] for i in familiar[0].data["items"]} == {"chrome"}


def test_windows_clean_machine_outbound_no_warnings():
    win = _win_output((FIX / "clean_win_outbound.json").read_text(), (FIX / "win_proc.json").read_text())
    result = _check(Platform.WIN32, win=win)
    assert not _warnings(result)
    # System's file sharing and svchost's updates are the OS's own: not even noted
    noted = [f for f in result.findings if f.data.get("check") == "unnamed_connections"]
    assert not noted


def test_windows_pathless_update_service_is_noted_not_warned():
    win = _win_output(
        (FIX / "clean_win_outbound.json").read_text(), (FIX / "win_proc_nopath.json").read_text()
    )
    result = _check(Platform.WIN32, win=win)
    assert not _warnings(result)
    noted = [f for f in result.findings if f.data.get("check") == "unnamed_connections"]
    assert len(noted) == 1
    assert [i["port"] for i in noted[0].data["items"]] == [7680]
    assert "couldn't confirm which program" in noted[0].description
    assert "limits" in noted[0].data


def test_windows_smb_from_other_program_still_warns():
    tcp = json.dumps([
        {"LocalAddress": "0.0.0.0", "LocalPort": 135, "RemoteAddress": "0.0.0.0",
         "RemotePort": 0, "State": 2, "OwningProcess": 1044},
        {"LocalAddress": "192.168.1.40", "LocalPort": 50101, "RemoteAddress": "203.0.113.50",
         "RemotePort": 445, "State": 5, "OwningProcess": 7000},
    ])
    proc = json.dumps([{"Id": 7000, "ProcessName": "updater", "Path": "C:\\Users\\sam\\updater.exe"}])
    warned = _warnings(_check(Platform.WIN32, win=_win_output(tcp, proc)))
    assert [f.data["process"] for f in warned] == ["updater"]


def test_unnamed_listener_title_counts_ports():
    ss = (
        "tcp   LISTEN 0 128 0.0.0.0:8000 0.0.0.0:*\n"
        "tcp   LISTEN 0 128 [::]:8000 [::]:*\n"
    )
    result = _check(Platform.LINUX, ss=ss)
    noted = [f for f in result.findings if f.data.get("check") == "unnamed_listeners"]
    assert noted[0].title.startswith("1 listening port(s)")


def test_skips_data_count_commands():
    seen = []
    fake = _fake_run(ss=(FIX / "clean_linux_ss.txt").read_text())

    def run(args, **kw):
        seen.append(args)
        return fake(args, **kw)

    with patch("rescue.command.run", side_effect=run):
        _get_module().check(_make_profile(Platform.LINUX))
    assert seen == [["ss", "-tunapH"]]


def test_windows_closed_connections_are_not_named_idle():
    """TIME_WAIT rows sit on PID 0 ("Idle"): no finding may name Idle as their program."""
    tcp = json.loads((FIX / "clean_win_listen.json").read_text()) + [
        {"LocalAddress": "192.168.1.40", "LocalPort": 50111, "RemoteAddress": "192.168.1.9",
         "RemotePort": 7680, "State": 11, "OwningProcess": 0},
        {"LocalAddress": "192.168.1.40", "LocalPort": 50112, "RemoteAddress": "203.0.113.5",
         "RemotePort": 8080, "State": 11, "OwningProcess": 0},
    ]
    proc = json.loads((FIX / "win_proc.json").read_text()) + [
        {"Id": 0, "ProcessName": "Idle", "Path": None}
    ]
    result = _check(Platform.WIN32, win=_win_output(json.dumps(tcp), json.dumps(proc)))
    for f in result.findings:
        assert "Idle" not in f.title + f.description + json.dumps(f.data, default=str), f.title


def test_linux_unnamed_note_gives_a_command_that_works():
    """Without sudo, ss shows the same unnamed sockets: the advice must say sudo."""
    ss = "tcp   LISTEN 0 128 0.0.0.0:8000 0.0.0.0:*\n"
    noted = [
        f for f in _check(Platform.LINUX, ss=ss).findings
        if f.data.get("check") == "unnamed_listeners"
    ]
    assert noted and "`sudo ss -tnap`" in noted[0].description


def test_admin_ss_advice_always_says_sudo():
    """Wherever modules or guides say an administrator sees every owner, the ss command has sudo."""
    root = Path(__file__).resolve().parents[1]
    files = list((root / "guides").rglob("*.md")) + list((root / "modules").rglob("*.py"))
    files.append(root / "rescue" / "watch.py")
    near = re.compile(
        r"administrator[^`]{0,160}`(ss\b[^`]*)`"
        r"|`(ss -[^`]*)`[^`]{0,160}?administrator(?![^`]{0,40}`sudo )",
        re.I,
    )
    bad = []
    for path in files:
        text = " ".join(path.read_text(encoding="utf-8").split())
        for m in near.finditer(text):
            bad.append(f"{path.relative_to(root)}: {m.group(1) or m.group(2)}")
    assert not bad, bad
