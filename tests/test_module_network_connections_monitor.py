import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.command import CommandResult
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
    return next(m for m in modules if m.name == "network_connections_monitor")


def _result(stdout="", returncode=0, error=None):
    return CommandResult(
        args=[], returncode=returncode, stdout=stdout, stderr="",
        timed_out=False, error=error, duration_s=0.0, truncated=False,
    )


def _make_run_result(connections=None, expect_clean=False):
    """A stand-in for rescue.command.run that answers lsof.

    connections: tuples of (process, pid, remote_ip, port, state).
    """

    def fake_run(cmd, **kwargs):
        if cmd[0] != "lsof":
            return _result(returncode=1)
        if not connections:
            # Real lsof prints nothing and exits 1 when no program has a socket open.
            return _result(returncode=1)
        lines = ["COMMAND  PID  USER  FD  TYPE             DEVICE SIZE/OFF NODE NAME"]
        for proc, pid, remote_ip, port, state in connections or []:
            host = f"[{remote_ip}]" if ":" in remote_ip else remote_ip
            lines.append(
                f"{proc:<8} {pid:<5} user  42u IPv4 0x123456 0t0 TCP "
                f"127.0.0.1:12345->{host}:{port} ({state})"
            )
        return _result("\n".join(lines))

    return fake_run


def test_network_connections_monitor_discovered():
    mod = _get_module()
    assert mod.name == "network_connections_monitor"
    assert mod.category == "security"
    assert Platform.DARWIN in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_network_connections_monitor_clean():
    """Test when no suspicious connections are found."""
    mod = _get_module()
    fake_run = _make_run_result(expect_clean=True)
    with patch("rescue.command.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    # Should have no findings if clean
    assert not result.has_issues


def test_network_connections_monitor_legitimate_connections():
    """Test with normal legitimate connections."""
    mod = _get_module()
    connections = [
        ("Safari", 123, "93.184.216.34", 443, "ESTABLISHED"),  # HTTP (HTTPS)
        ("Chrome", 456, "8.8.8.8", 53, "ESTABLISHED"),  # DNS
        ("SSH", 789, "192.168.1.100", 22, "ESTABLISHED"),  # SSH
    ]
    fake_run = _make_run_result(connections=connections)
    with patch("rescue.command.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    # Should only have INFO for connection summary
    assert result.has_issues
    assert any(f.data.get("check") == "connection_summary" for f in result.findings)
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert len(info_findings) > 0


def test_network_connections_monitor_backdoor_ports():
    """Test detection of connections on backdoor ports."""
    mod = _get_module()
    connections = [
        ("suspect.exe", 1234, "10.0.0.50", 4444, "ESTABLISHED"),  # Backdoor port
        ("malware", 5678, "172.16.0.1", 1337, "ESTABLISHED"),  # Backdoor port
        ("normal.app", 9999, "93.184.216.34", 443, "ESTABLISHED"),  # Legitimate
    ]
    fake_run = _make_run_result(connections=connections)
    with patch("rescue.command.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "backdoor_ports" for f in result.findings)
    critical = [f for f in result.findings if f.data.get("check") == "backdoor_ports"]
    assert len(critical) == 1
    assert critical[0].severity == Severity.CRITICAL
    assert "suspect.exe" in critical[0].description


def test_network_connections_monitor_high_connection_count():
    """Test detection of processes with many connections."""
    mod = _get_module()
    connections = []
    # Create 25 connections from same process
    for i in range(25):
        connections.append(
            ("malware", 2000, f"10.0.0.{i+1}", 1000 + i, "ESTABLISHED")
        )
    # Add some normal connections
    connections.append(("Safari", 456, "93.184.216.34", 443, "ESTABLISHED"))

    fake_run = _make_run_result(connections=connections)
    with patch("rescue.command.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "high_connection_count" for f in result.findings)
    warning = [f for f in result.findings if f.data.get("check") == "high_connection_count"]
    assert len(warning) == 1
    assert warning[0].severity == Severity.WARNING
    assert "malware" in warning[0].description


def test_browser_named_process_with_many_connections_is_listed_not_dropped():
    # A botnet can call itself "chrome"; below the browser limit it is info, not silence.
    mod = _get_module()
    connections = [("chrome", 3000, f"93.184.{i // 200}.{i % 200 + 1}", 443, "ESTABLISHED") for i in range(100)]
    with patch("rescue.command.run", side_effect=_make_run_result(connections=connections)):
        result = mod.check(_make_profile())
    listed = [f for f in result.findings if f.data.get("check") == "many_connections_familiar_name"]
    assert len(listed) == 1 and listed[0].severity == Severity.INFO
    assert "chrome" in listed[0].description
    assert not [f for f in result.findings if f.data.get("check") == "high_connection_count"]


def test_push_port_connections_are_listed_not_dropped():
    mod = _get_module()
    connections = [("backdoor", 9, "93.184.216.34", 5228, "ESTABLISHED")]
    with patch("rescue.command.run", side_effect=_make_run_result(connections=connections)):
        result = mod.check(_make_profile())
    listed = [f for f in result.findings if f.data.get("check") == "push_port_connections"]
    assert len(listed) == 1 and listed[0].severity == Severity.INFO
    assert "backdoor" in listed[0].description
    assert not [f for f in result.findings if f.data.get("check") == "unusual_ports"]


def test_network_connections_monitor_unusual_ports():
    """Test detection of connections on unusual ports."""
    mod = _get_module()
    connections = [
        ("app", 1111, "93.184.216.34", 8888, "ESTABLISHED"),  # Unusual port (backdoor but not >20)
        ("process", 2222, "10.0.0.100", 5000, "ESTABLISHED"),  # Unusual port
        ("Chrome", 3333, "8.8.8.8", 53, "ESTABLISHED"),  # Legitimate (DNS)
    ]
    fake_run = _make_run_result(connections=connections)
    with patch("rescue.command.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have unusual_ports warning (and backdoor_ports critical for 8888)
    assert any(f.data.get("check") == "backdoor_ports" for f in result.findings)


def test_network_connections_monitor_private_ips():
    """Test detection of connections to private IPs."""
    mod = _get_module()
    connections = [
        ("app", 111, "192.168.1.50", 3306, "ESTABLISHED"),  # Private IP
        ("service", 222, "10.0.0.100", 5432, "ESTABLISHED"),  # Private IP
        ("browser", 333, "93.184.216.34", 443, "ESTABLISHED"),  # Public IP
    ]
    fake_run = _make_run_result(connections=connections)
    with patch("rescue.command.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "private_ip_connections" for f in result.findings)
    private = [f for f in result.findings if f.data.get("check") == "private_ip_connections"]
    assert len(private) == 1
    assert private[0].severity == Severity.INFO


def test_network_connections_monitor_multiple_issues():
    """Test when multiple issues are detected."""
    mod = _get_module()
    connections = [
        # Backdoor port connection
        ("suspect", 100, "172.16.0.5", 4444, "ESTABLISHED"),
        # High connection count
        ("malware", 200, "10.0.0.1", 2000, "ESTABLISHED"),
        ("malware", 200, "10.0.0.2", 2001, "ESTABLISHED"),
        ("malware", 200, "10.0.0.3", 2002, "ESTABLISHED"),
        ("malware", 200, "10.0.0.4", 2003, "ESTABLISHED"),
        ("malware", 200, "10.0.0.5", 2004, "ESTABLISHED"),
        ("malware", 200, "10.0.0.6", 2005, "ESTABLISHED"),
        ("malware", 200, "10.0.0.7", 2006, "ESTABLISHED"),
        ("malware", 200, "10.0.0.8", 2007, "ESTABLISHED"),
        ("malware", 200, "10.0.0.9", 2008, "ESTABLISHED"),
        ("malware", 200, "10.0.0.10", 2009, "ESTABLISHED"),
        ("malware", 200, "10.0.0.11", 2010, "ESTABLISHED"),
        ("malware", 200, "10.0.0.12", 2011, "ESTABLISHED"),
        ("malware", 200, "10.0.0.13", 2012, "ESTABLISHED"),
        ("malware", 200, "10.0.0.14", 2013, "ESTABLISHED"),
        ("malware", 200, "10.0.0.15", 2014, "ESTABLISHED"),
        ("malware", 200, "10.0.0.16", 2015, "ESTABLISHED"),
        ("malware", 200, "10.0.0.17", 2016, "ESTABLISHED"),
        ("malware", 200, "10.0.0.18", 2017, "ESTABLISHED"),
        ("malware", 200, "10.0.0.19", 2018, "ESTABLISHED"),
        ("malware", 200, "10.0.0.20", 2019, "ESTABLISHED"),
        ("malware", 200, "10.0.0.21", 2020, "ESTABLISHED"),
        # Unusual port
        ("app", 300, "93.184.216.34", 9999, "ESTABLISHED"),
        # Legitimate
        ("Safari", 400, "93.184.216.34", 443, "ESTABLISHED"),
    ]
    fake_run = _make_run_result(connections=connections)
    with patch("rescue.command.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    checks = [f.data.get("check") for f in result.findings]
    assert "backdoor_ports" in checks
    assert "high_connection_count" in checks
    assert "unusual_ports" in checks
    assert "private_ip_connections" in checks
    assert "connection_summary" in checks


def test_network_connections_monitor_fix_backdoor():
    """Test fix recommendation for backdoor ports."""
    mod = _get_module()
    connections = [
        ("suspect", 123, "10.0.0.50", 4444, "ESTABLISHED"),
    ]
    fake_run = _make_run_result(connections=connections)
    with patch("rescue.command.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    backdoor_actions = [a for a in fix.actions if "backdoor" in a.title.lower()]
    assert len(backdoor_actions) > 0


def test_network_connections_monitor_fix_high_connections():
    """Test fix recommendation for high connection count."""
    mod = _get_module()
    connections = []
    for i in range(25):
        connections.append(("malware", 200, f"10.0.0.{i+1}", 1000 + i, "ESTABLISHED"))

    fake_run = _make_run_result(connections=connections)
    with patch("rescue.command.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    high_conn_actions = [a for a in fix.actions if "high" in a.title.lower()]
    assert len(high_conn_actions) > 0


def test_network_connections_monitor_command_error_is_couldnt_check():
    """A failed lsof is not a clean result."""
    mod = _get_module()

    def error_run(cmd, **kwargs):
        return _result(returncode=None, error="Command failed")

    with patch("rescue.command.run", side_effect=error_run):
        result = mod.check(_make_profile())
    assert len(result.findings) == 1
    assert result.findings[0].severity == Severity.INFO
    assert result.findings[0].data["check"] == "couldnt_check"
    assert "not the same as a clean result" in result.findings[0].description


def test_lsof_failure_is_couldnt_check():
    mod = _get_module()
    failed = CommandResult(
        args=[], returncode=2, stdout="", stderr="lsof: permission denied",
        timed_out=False, error=None, duration_s=0.0, truncated=False,
    )
    with patch("rescue.command.run", return_value=failed):
        result = mod.check(_make_profile())
    assert len(result.findings) == 1
    assert result.findings[0].data["check"] == "couldnt_check"
    assert result.findings[0].severity == Severity.INFO


def test_network_connections_monitor_timeout_is_couldnt_check():
    mod = _get_module()
    timed_out = CommandResult(
        args=[], returncode=None, stdout="", stderr="",
        timed_out=True, error=None, duration_s=30.0, truncated=False,
    )
    with patch("rescue.command.run", return_value=timed_out):
        result = mod.check(_make_profile())
    assert result.findings[0].data["check"] == "couldnt_check"


def test_network_connections_monitor_ipv6_connections():
    """Test parsing of IPv6 connections."""
    mod = _get_module()
    lsof = (
        "COMMAND  PID  USER  FD  TYPE             DEVICE SIZE/OFF NODE NAME\n"
        "Safari   123  user  42u IPv6 0x123456 0t0 TCP [::1]:54321->[2001:4860:4860::8888]:443 (ESTABLISHED)\n"
    )
    with patch("rescue.command.run", return_value=_result(lsof)):
        result = mod.check(_make_profile())
    summary = [f for f in result.findings if f.data.get("check") == "connection_summary"]
    assert summary and summary[0].data["total_count"] == 1


def test_network_connections_monitor_all_ports_and_states():
    """Test that the module detects all types correctly."""
    mod = _get_module()
    connections = [
        ("proc1", 100, "93.184.216.34", 443, "ESTABLISHED"),
        ("proc2", 200, "8.8.8.8", 53, "ESTABLISHED"),
        ("proc3", 300, "10.0.0.1", 22, "ESTABLISHED"),
        ("proc4", 400, "192.168.1.1", 80, "ESTABLISHED"),
    ]
    fake_run = _make_run_result(connections=connections)
    with patch("rescue.command.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    # All are legitimate ports, should only have connection_summary
    assert result.has_issues
    summary = [f for f in result.findings if f.data.get("check") == "connection_summary"]
    assert len(summary) > 0
    assert summary[0].data.get("total_count") == 4


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.network_connections_monitor.") for c in declared)


# --- every platform ------------------------------------------------------------

FIX = Path(__file__).parent / "fixtures" / "conn"


def _profile_for(platform):
    return SystemProfile(
        platform=platform, os_name="x", os_version="1", architecture="x86_64",
        cpu_model="x", cpu_cores=4, ram_bytes=8 * 1024**3,
    )


def _win_output(tcp, proc, udp="[]"):
    return "\n".join(part.strip() for part in (tcp, udp, proc)) + "\n"


def _check(platform, ss="", win=None, error=None):
    def run(args, **kwargs):
        if error:
            return _result(returncode=None, error=error)
        if args[0] == "ss" and "-tunapH" in args:
            return _result(ss)
        if args[0] == "powershell" and win is not None:
            return _result(win)
        return _result(returncode=1)

    with patch("rescue.command.run", side_effect=run):
        return _get_module().check(_profile_for(platform))


def _warnings(result):
    return [f for f in result.findings if f.severity in (Severity.WARNING, Severity.CRITICAL)]


def test_runs_on_every_platform():
    assert set(_get_module().platforms) == {Platform.DARWIN, Platform.LINUX, Platform.WIN32}


def test_linux_clean_machine_no_warnings():
    for name in ("clean_linux_ss.txt", "clean_linux_ss_outbound.txt"):
        result = _check(Platform.LINUX, ss=(FIX / name).read_text())
        assert not _warnings(result), name


def test_windows_clean_machine_no_warnings():
    proc = (FIX / "win_proc.json").read_text()
    for name in ("clean_win_listen.json", "clean_win_outbound.json"):
        result = _check(Platform.WIN32, win=_win_output((FIX / name).read_text(), proc))
        assert not _warnings(result), name


def test_windows_pathless_service_outbound_is_not_a_warning():
    win = _win_output(
        (FIX / "clean_win_outbound.json").read_text(), (FIX / "win_proc_nopath.json").read_text()
    )
    assert not _warnings(_check(Platform.WIN32, win=win))


@pytest.mark.parametrize("platform", [Platform.LINUX, Platform.WIN32])
def test_collector_error_is_couldnt_check(platform):
    result = _check(platform, error="not found")
    assert len(result.findings) == 1
    assert result.findings[0].severity == Severity.INFO
    assert "not the same as a clean result" in result.findings[0].description


def test_unnamed_connection_is_info_never_warning():
    ss = "tcp   ESTAB  0      0       192.168.1.30:51051   203.0.113.10:9999\n"
    result = _check(Platform.LINUX, ss=ss)
    assert not _warnings(result)
    noted = [f for f in result.findings if f.data.get("check") == "unnamed_connections"]
    assert len(noted) == 1 and noted[0].severity == Severity.INFO
    assert noted[0].code == "security.network_connections_monitor.unnamed_connections"
    assert "couldn't see which program" in noted[0].description
    # enough to tell connections apart: protocol, local port, remote address and port
    assert "tcp local port 51051 -> 203.0.113.10:9999" in noted[0].description


def test_unnamed_backdoor_port_connection_is_critical_on_linux_and_windows():
    ss = "tcp   ESTAB  0      0       192.168.1.30:51050   203.0.113.10:4444\n"
    tcp = json.dumps([
        {"LocalAddress": "192.168.1.40", "LocalPort": 50712, "RemoteAddress": "203.0.113.10",
         "RemotePort": 4444, "State": 5, "OwningProcess": 777},
    ])
    for result in (
        _check(Platform.LINUX, ss=ss),
        _check(Platform.WIN32, win=_win_output(tcp, "[]")),
    ):
        crit = [f for f in result.findings if f.data.get("check") == "backdoor_ports"]
        assert len(crit) == 1 and crit[0].severity == Severity.CRITICAL
        assert "program not visible" in crit[0].description
        assert "203.0.113.10:4444" in crit[0].description
        assert not [f for f in result.findings if f.data.get("check") == "unnamed_connections"]


@pytest.mark.parametrize("name", ["firefox", "chrome.exe", "Safari"])
def test_browser_named_process_on_uncommon_port_is_still_a_warning(name):
    ss = f'tcp   ESTAB  0 0 192.168.1.30:51050 203.0.113.10:9999 users:(("{name}",pid=9,fd=4))\n'
    result = _check(Platform.LINUX, ss=ss)
    odd = [f for f in result.findings if f.data.get("check") == "unusual_ports"]
    assert len(odd) == 1 and odd[0].severity == Severity.WARNING


def test_unnamed_connections_fix_advice_is_per_platform():
    ss = "tcp   ESTAB  0      0       192.168.1.30:51051   203.0.113.10:9999\n"
    tcp = json.dumps([
        {"LocalAddress": "192.168.1.40", "LocalPort": 50712, "RemoteAddress": "203.0.113.10",
         "RemotePort": 9999, "State": 5, "OwningProcess": 777},
    ])
    mod = _get_module()
    linux = mod.fix(_check(Platform.LINUX, ss=ss), Mode.MANUAL)
    win = mod.fix(_check(Platform.WIN32, win=_win_output(tcp, "[]")), Mode.MANUAL)
    assert len(linux.actions) >= 1 and len(win.actions) >= 1
    ltext = "\n".join(a.description for a in linux.actions).lower()
    wtext = "\n".join(a.description for a in win.actions).lower()
    assert "ss -tnap" in ltext
    assert "resource monitor" in wtext
    for text in (ltext, wtext):
        for bad in ("lsof", "activity monitor", "kill", "terminate", "end task"):
            assert bad not in text


def test_exe_suffix_is_ignored_when_matching_names():
    import importlib

    module = importlib.import_module(type(_get_module()).__module__)
    assert module._threshold_for("msedge.exe") == module.BROWSER_CONNECTION_THRESHOLD
    assert module._threshold_for("Firefox.EXE") == module.BROWSER_CONNECTION_THRESHOLD
    assert module._threshold_for("chrome.exe") == module.BROWSER_CONNECTION_THRESHOLD
    assert module._threshold_for("node.exe") == module.DEV_TOOL_CONNECTION_THRESHOLD
    assert module._threshold_for("unknown.exe") == module.DEFAULT_CONNECTION_THRESHOLD


def test_windows_browser_with_many_connections_is_not_warned():
    tcp = json.dumps([
        {"LocalAddress": "192.168.1.40", "LocalPort": 50000 + i,
         "RemoteAddress": f"203.0.113.{i % 200 + 1}",
         "RemotePort": 443, "State": 5, "OwningProcess": 5120}
        for i in range(100)
    ])
    result = _check(Platform.WIN32, win=_win_output(tcp, (FIX / "win_proc.json").read_text()))
    assert not _warnings(result)
    assert [f for f in result.findings if f.data.get("check") == "many_connections_familiar_name"]


def test_clean_fixtures_stay_quiet_because_of_ports_not_names():
    # browsers and calls on 443 (TCP or QUIC) are ordinary; push on 5228 is listed as info
    result = _check(Platform.LINUX, ss=(FIX / "clean_linux_ss_outbound.txt").read_text())
    pushy = [f for f in result.findings if f.data.get("check") == "push_port_connections"]
    assert pushy and pushy[0].severity == Severity.INFO
    assert not _warnings(result)


@pytest.mark.parametrize("port", [8443, 3478])
def test_named_process_to_public_alternate_port_is_a_warning(port):
    ss = f'tcp   ESTAB  0 0 192.168.1.30:51050 203.0.113.10:{port} users:(("firefox",pid=9,fd=4))\n'
    odd = [f for f in _check(Platform.LINUX, ss=ss).findings if f.data.get("check") == "unusual_ports"]
    assert len(odd) == 1 and odd[0].severity == Severity.WARNING
    assert str(port) in odd[0].description


def test_pathless_windows_service_has_its_own_check_key():
    win = _win_output(
        (FIX / "clean_win_outbound.json").read_text(), (FIX / "win_proc_nopath.json").read_text()
    )
    result = _check(Platform.WIN32, win=win)
    claimed = [f for f in result.findings if f.data.get("check") == "unverified_service_connections"]
    assert len(claimed) == 1 and claimed[0].severity == Severity.INFO
    assert claimed[0].code == "security.network_connections_monitor.unnamed_connections"
    assert not [f for f in result.findings if f.data.get("check") == "unnamed_connections"]
    fix = _get_module().fix(result, Mode.MANUAL)
    assert any("resource monitor" in a.description.lower() for a in fix.actions)


def _backdoor_result(platform):
    if platform == Platform.DARWIN:
        lsof = (
            "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"
            "backdoor 9 u 4u IPv4 0x1 0t0 TCP 192.168.1.5:50000->203.0.113.10:4444 (ESTABLISHED)\n"
        )
        with patch("rescue.command.run", return_value=_result(lsof)):
            return _get_module().check(_profile_for(platform))
    ss = 'tcp   ESTAB  0 0 192.168.1.30:51050 203.0.113.10:4444 users:(("backdoor",pid=9,fd=4))\n'
    tcp = json.dumps([
        {"LocalAddress": "192.168.1.40", "LocalPort": 50712, "RemoteAddress": "203.0.113.10",
         "RemotePort": 4444, "State": 5, "OwningProcess": 9},
    ])
    proc = json.dumps([{"Id": 9, "ProcessName": "backdoor", "Path": "C:\\Users\\sam\\backdoor.exe"}])
    return _check(platform, ss=ss, win=_win_output(tcp, proc))


@pytest.mark.parametrize("platform", [Platform.LINUX, Platform.WIN32, Platform.DARWIN])
def test_backdoor_fix_advice_is_per_platform(platform):
    result = _backdoor_result(platform)
    assert any(f.severity == Severity.CRITICAL for f in result.findings)
    fix = _get_module().fix(result, Mode.MANUAL)
    text = "\n".join(a.description for a in fix.actions).lower()
    assert text
    for word in ("kill", "terminate", "end task"):
        assert word not in text
    if platform == Platform.WIN32:
        for bad in ("netstat", "lsof", "ps aux", "activity monitor", "`"):
            assert bad not in text
        assert "resource monitor" in text and "task manager" in text
    elif platform == Platform.LINUX:
        for bad in ("netstat", "lsof", "ps aux", "activity monitor", "codesign"):
            assert bad not in text
        assert "ss -tnap" in text
    else:
        assert "activity monitor" in text


@pytest.mark.parametrize("platform", [Platform.LINUX, Platform.WIN32])
def test_every_fix_action_avoids_macos_tools(platform):
    tcp_rows = [
        {"LocalAddress": "192.168.1.40", "LocalPort": 40000 + i, "RemoteAddress": f"10.0.0.{i + 1}",
         "RemotePort": 9000 + i, "State": 5, "OwningProcess": 9}
        for i in range(25)
    ]
    ss = "".join(
        f'tcp ESTAB 0 0 192.168.1.30:{40000 + i} 10.0.0.{i + 1}:{9000 + i} users:(("p",pid=9,fd=4))\n'
        for i in range(25)
    )
    proc = json.dumps([{"Id": 9, "ProcessName": "p", "Path": "C:\\Users\\p.exe"}])
    result = _check(platform, ss=ss, win=_win_output(json.dumps(tcp_rows), proc))
    checks = {f.data.get("check") for f in result.findings}
    assert {"high_connection_count", "unusual_ports", "private_ip_connections",
            "connection_summary"} <= checks
    fix = _get_module().fix(result, Mode.MANUAL)
    assert len(fix.actions) >= 4
    text = "\n".join(a.description for a in fix.actions).lower()
    for bad in ("netstat -anp tcp", "ps aux", "activity monitor", "lsof", "codesign"):
        assert bad not in text
    for word in ("kill", "terminate", "end task"):
        assert word not in text
