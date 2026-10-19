import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.command import CommandResult
from rescue.runtime import load_content_module

C = load_content_module(
    "modules/network/conn_common/collect.py", "rescue_conn_common_collect"
)
FIX = Path(__file__).parent / "fixtures" / "conn"


def fx(name):
    return (FIX / name).read_text()


def result(stdout="", returncode=0, error=None, timed_out=False, stderr=""):
    return CommandResult(
        args=[], returncode=returncode, stdout=stdout, stderr=stderr,
        timed_out=timed_out, error=error, duration_s=0.0, truncated=False,
    )


def test_parse_lsof_ipv4_ipv6_and_listen():
    recs = C.parse_lsof(fx("lsof_mac.txt"))
    assert recs[0] == {
        "proto": "tcp", "state": "LISTEN", "local_addr": "*", "local_port": 7000,
        "remote_addr": None, "remote_port": None, "pid": 686,
        "process": "ControlCe", "exe": None,
    }
    chrome4 = next(r for r in recs if r["local_port"] == 52814)
    assert chrome4["process"] == "Google Chrome"
    assert chrome4["state"] == "ESTABLISHED"
    assert (chrome4["remote_addr"], chrome4["remote_port"]) == ("203.0.113.9", 443)
    chrome6 = next(r for r in recs if r["local_port"] == 52900)
    assert chrome6["local_addr"] == "2001:db8::20"
    assert (chrome6["remote_addr"], chrome6["remote_port"]) == ("2001:db8:1::5", 443)
    udp = next(r for r in recs if r["proto"] == "udp" and r["local_port"] == 5353)
    assert udp["state"] is None and udp["pid"] == 410
    wild = next(r for r in recs if r["pid"] == 734)
    assert (wild["local_addr"], wild["local_port"]) == ("*", None)
    assert next(r for r in recs if r["pid"] == 9001)["state"] == "SYN_SENT"


def test_parse_ss_with_and_without_process():
    recs = C.parse_ss(fx("ss_tunap_linux.txt"))
    stub = recs[0]
    assert (stub["proto"], stub["state"], stub["local_addr"], stub["local_port"]) == (
        "udp", "UNCONN", "127.0.0.53", 53)
    assert (stub["process"], stub["pid"], stub["remote_addr"]) == ("systemd-resolve", 612, None)
    ssh6 = next(r for r in recs if r["local_addr"] == "::" and r["local_port"] == 22)
    assert ssh6["state"] == "LISTEN" and ssh6["process"] == "sshd"
    est = next(r for r in recs if r["local_port"] == 51044)
    assert est["state"] == "ESTABLISHED"
    assert (est["remote_addr"], est["remote_port"], est["pid"]) == ("203.0.113.9", 443, 2210)
    v6 = next(r for r in recs if r["local_port"] == 51100)
    assert v6["local_addr"] == "2001:db8::30" and v6["process"] == "firefox"

    nonroot = C.parse_ss(fx("ss_tunap_linux_nonroot.txt"))
    assert len(nonroot) == 4
    assert nonroot[0]["pid"] is None and nonroot[0]["process"] is None
    assert nonroot[3]["pid"] is None and nonroot[3]["remote_addr"] == "203.0.113.10"
    assert nonroot[2]["pid"] == 2210


def test_parse_win_connections_object_or_list_and_numeric_state():
    recs = C.parse_win_connections(fx("win_tcp.json"), fx("win_udp.json"), fx("win_proc.json"))
    tcp = [r for r in recs if r["proto"] == "tcp"]
    assert tcp[0]["state"] == "LISTEN" and tcp[0]["local_port"] == 135
    assert tcp[0]["remote_addr"] is None and tcp[0]["remote_port"] is None
    assert tcp[0]["process"] == "svchost"
    assert tcp[0]["exe"] == "C:\\Windows\\System32\\svchost.exe"
    assert tcp[1]["state"] == "ESTABLISHED"
    assert (tcp[1]["remote_addr"], tcp[1]["remote_port"]) == ("203.0.113.9", 443)
    assert tcp[1]["process"] == "chrome"
    assert tcp[2]["state"] == "LISTEN" and tcp[2]["pid"] == 4 and tcp[2]["exe"] is None
    assert tcp[3]["state"] == "ESTABLISHED"
    # udp fixture is a single object, not a list
    udp = [r for r in recs if r["proto"] == "udp"]
    assert len(udp) == 1
    assert (udp[0]["local_port"], udp[0]["pid"], udp[0]["process"], udp[0]["state"]) == (
        5353, 5120, "chrome", None)
    # a single process object works too
    one = C.parse_win_connections("[]", "[]", json.dumps({"Id": 1, "ProcessName": "x"}))
    assert one == []


def test_parse_nettop_name_dot_pid():
    assert C.parse_nettop(fx("nettop_mac.csv")) == {
        1: (0, 0), 371: (12889957, 4157155), 4312: (9120044, 310220), 410: (2048, 1024),
    }


def test_parse_ss_bytes():
    got = C.parse_ss_bytes(fx("ss_tni_linux.txt"))
    assert got == {
        ("192.168.1.30", 51044, "203.0.113.9", 443): (48213, 1520),
        ("2001:db8::30", 51100, "2001:db8:1::5", 443): (7000, 900),
    }


def test_parse_win_dns_types():
    assert C.parse_win_dns(fx("win_dns.json")) == [
        {"name": "example.com", "type": "A"},
        {"name": "www.example.com", "type": "CNAME"},
        {"name": "example.com", "type": "AAAA"},
        {"name": "mail.example.com", "type": "15"},
    ]
    assert C.parse_win_dns('{"Entry":"a.test","Type":1}') == [{"name": "a.test", "type": "A"}]


def test_garbage_lines_skipped():
    g = "garbage\n\n"
    assert C.parse_lsof(g) == []
    assert C.parse_ss(g) == []
    assert C.parse_nettop(g) == {}
    assert C.parse_ss_bytes(g) == {}
    assert C.parse_win_connections(g, g, g) == []
    assert C.parse_win_dns(g) == []
    assert C.parse_win_dns("[1, 2]") == []


def test_snapshot_uses_numeric_flags():
    calls = []

    def run(args, **kw):
        calls.append(list(args))
        return result(fx("nettop_mac.csv") if args[0] == "nettop" else fx("lsof_mac.txt"))

    snap = C.snapshot("darwin", run=run)
    assert snap["error"] is None and snap["records"]
    assert snap["bytes"][371] == (12889957, 4157155)
    assert calls[0] == ["lsof", "-i", "-n", "-P"]
    assert all("-n" in argv for argv in calls)


def test_missing_command_is_couldnt_check():
    for platform in ("darwin", "linux", "win32"):
        snap = C.snapshot(platform, run=lambda a, **k: result(returncode=None, error="not found"))
        assert snap["error"] and "not found" in snap["error"]
        assert snap["records"] == []
    snap = C.snapshot("linux", run=lambda a, **k: result(returncode=None, timed_out=True))
    assert snap["error"] and snap["records"] == []


def test_linux_nonroot_adds_limit():
    def run(args, **kw):
        return result(fx("ss_tunap_linux_nonroot.txt") if args == C.SS_ARGS else fx("ss_tni_linux.txt"))

    snap = C.snapshot("linux", run=run)
    assert any("only for your own programs unless the check runs as admin" in s for s in snap["limits"])
    assert snap["bytes"] is not None

    root = C.snapshot("linux", run=lambda a, **k: result(fx("ss_tunap_linux.txt")))
    assert not any("own programs" in s for s in root["limits"])


def test_bytes_failure_does_not_fail_snapshot():
    def run(args, **kw):
        if args[0] == "nettop":
            return result(returncode=None, error="not found")
        return result(fx("lsof_mac.txt"))

    snap = C.snapshot("darwin", run=run)
    assert snap["error"] is None and snap["bytes"] is None and snap["limits"]


def test_windows_blank_tcp_document_is_an_error():
    out = "\n".join(["", fx("win_udp.json").strip(), fx("win_proc.json").strip()])
    snap = C.snapshot("win32", run=lambda a, **k: result(out))
    assert snap["error"] and snap["records"] == []
    bad = C.snapshot("win32", run=lambda a, **k: result("not json\n\n\n"))
    assert bad["error"] and bad["records"] == []


def test_unparseable_output_is_an_error_on_unix():
    for platform in ("darwin", "linux"):
        snap = C.snapshot(platform, run=lambda a, **k: result("totally new format\n"))
        assert snap["error"] and snap["records"] == []


def test_lsof_exit_one_without_output_means_no_connections():
    snap = C.snapshot("darwin", run=lambda a, **k: result("", returncode=1))
    assert snap["error"] is None and snap["records"] == []


def test_darwin_limit_when_not_admin(monkeypatch):
    run = lambda a, **k: result(fx("lsof_mac.txt"))  # noqa: E731
    monkeypatch.setattr(C.os, "geteuid", lambda: 501, raising=False)
    assert any("programs running as you" in s for s in C.snapshot("darwin", run=run)["limits"])
    monkeypatch.setattr(C.os, "geteuid", lambda: 0, raising=False)
    assert not any("programs running as you" in s for s in C.snapshot("darwin", run=run)["limits"])


def test_ss_states_use_underscores():
    line = 'tcp   SYN-SENT 0 0 192.168.1.30:51044 203.0.113.9:443\n' \
           'tcp   TIME-WAIT 0 0 192.168.1.30:51045 203.0.113.9:443\n'
    assert [r["state"] for r in C.parse_ss(line)] == ["SYN_SENT", "TIME_WAIT"]


def test_windows_bytes_none_with_limit():
    out = "\n".join(
        json.dumps(json.loads(fx(n))) for n in ("win_tcp.json", "win_udp.json", "win_proc.json")
    )
    seen = []

    def run(args, **kw):
        seen.append(args)
        return result(out)

    snap = C.snapshot("win32", run=run)
    assert snap["bytes"] is None
    assert any("how much data each connection carried" in s for s in snap["limits"])
    assert len(snap["records"]) == 5
    assert seen[0][:4] == ["powershell", "-NoProfile", "-NonInteractive", "-Command"]


def test_dns_cache_mac_and_linux_reason():
    mac = C.dns_cache("darwin")
    assert mac == {
        "names": None,
        "reason": "macOS doesn't show which names were looked up unless you're an admin.",
    }
    lin = C.dns_cache("linux")
    assert lin["names"] is None and "resolvectl monitor needs root" in lin["reason"]
    win = C.dns_cache("win32", run=lambda a, **k: result(fx("win_dns.json")))
    assert win["reason"] is None and len(win["names"]) == 4
    bad = C.dns_cache("win32", run=lambda a, **k: result(returncode=None, error="not found"))
    assert bad["names"] is None and bad["reason"]


def test_expected_listeners_clean_windows():
    recs = C.parse_win_connections(fx("clean_win_listen.json"), "[]", fx("win_proc.json"))
    listeners = [r for r in recs if r["state"] == "LISTEN"]
    assert len(listeners) == 5
    assert all(C.is_expected_listener("win32", r) for r in listeners)


def test_expected_listeners_clean_linux():
    recs = C.parse_ss(fx("clean_linux_ss.txt"))
    assert len(recs) == 6
    ok = lambda p: "/usr/sbin/avahi-daemon"  # noqa: E731
    assert all(C.is_expected_listener("linux", r, readlink=ok) for r in recs)


def test_linux_avahi_needs_verified_exe():
    avahi = {"process": "avahi-daemon", "pid": 701, "local_port": 5353, "local_addr": "0.0.0.0"}
    assert C.is_expected_listener("linux", avahi, readlink=lambda p: "/usr/sbin/avahi-daemon")
    assert not C.is_expected_listener("linux", avahi, readlink=lambda p: "/tmp/avahi-daemon")

    def gone(path):
        raise FileNotFoundError(path)

    assert not C.is_expected_listener("linux", avahi, readlink=gone)
    assert not C.is_expected_listener("linux", {**avahi, "pid": None}, readlink=gone)
    # name alone is not enough on an unprivileged port
    assert not C.is_expected_listener("linux", {**avahi, "process": "sshd", "local_port": 2222})


def test_expected_windows_listeners_without_paths():
    recs = C.parse_win_connections(fx("clean_win_listen.json"), "[]", fx("win_proc_nopath.json"))
    listeners = [r for r in recs if r["state"] == "LISTEN"]
    assert all(r["exe"] is None for r in listeners)
    # Fail closed: only PID 4 (System) is expected without a path...
    expected = [r for r in listeners if C.is_expected_listener("win32", r)]
    assert {r["local_port"] for r in expected} == {139, 445}
    assert all(r["pid"] == 4 for r in expected)
    # ...and the pathless svchost listeners only claim to be services.
    svchost = [r for r in listeners if r["pid"] == 1044]
    assert len(svchost) == 3
    assert all(C.claims_expected_service("win32", r) for r in svchost)
    assert not any(C.claims_expected_service("win32", r) for r in expected)
    # a pathless program that is not a service host claims nothing
    odd = {**svchost[0], "process": "chrome", "pid": 5120}
    assert not C.is_expected_listener("win32", odd)
    assert not C.claims_expected_service("win32", odd)


def test_claims_expected_service_needs_windows_no_path_and_allowlisted_name():
    rec = {"local_port": 49670, "pid": 900, "process": "lsass", "exe": None, "local_addr": "0.0.0.0"}
    assert C.claims_expected_service("win32", rec)
    assert not C.claims_expected_service("win32", {**rec, "process": "rundll32"})
    assert not C.claims_expected_service("win32", {**rec, "exe": "C:\\Windows\\System32\\lsass.exe"})
    assert not C.claims_expected_service("win32", {**rec, "local_port": 8080})
    assert not C.claims_expected_service("win32", {**rec, "local_port": 445, "process": "svchost"})
    assert not C.claims_expected_service("linux", rec)
    assert not C.claims_expected_service("darwin", rec)


def test_windows_expected_needs_exact_system32_program():
    base = {"local_port": 135, "pid": 1044, "process": "svchost", "local_addr": "0.0.0.0"}
    sys32 = "C:\\Windows\\System32\\"
    assert C.is_expected_listener("win32", {**base, "exe": sys32 + "svchost.exe"}, windows_dir="C:\\Windows")
    assert not C.is_expected_listener("win32", {**base, "exe": "C:\\Users\\x\\svchost.exe"})
    rundll = {**base, "local_port": 49670, "process": "rundll32", "exe": sys32 + "rundll32.exe"}
    assert not C.is_expected_listener("win32", rundll)
    assert not C.is_expected_listener("win32", {**rundll, "exe": None})
    assert C.is_expected_listener("win32", {**rundll, "process": "lsass", "exe": sys32 + "lsass.exe"})
    # 445 is the System process only
    assert not C.is_expected_listener("win32", {**base, "local_port": 445, "exe": sys32 + "svchost.exe"})


def test_unexpected_listener():
    py = {"process": "python3", "local_port": 8000, "local_addr": "0.0.0.0", "pid": 9, "exe": None}
    assert not C.is_expected_listener("linux", py)
    # sshd on the wrong port, and the DNS stub on a public address
    assert not C.is_expected_listener("linux", {**py, "process": "sshd", "local_port": 2222})
    assert not C.is_expected_listener("linux", {**py, "process": "systemd-resolve", "local_port": 53})
    app = {"process": "app", "local_port": 445, "local_addr": "0.0.0.0", "pid": 7000,
           "exe": "C:\\Users\\sam\\AppData\\app.exe"}
    assert not C.is_expected_listener("win32", app)
    assert not C.is_expected_listener("win32", {**app, "exe": "C:\\Windows\\SysWOW64\\svchost.exe"})
    assert not C.is_expected_listener("win32", {**app, "exe": "C:\\Windows\\System32\\svchost.exe", "local_port": 8080})
    assert not C.is_expected_listener("darwin", py)


def test_expected_outbound_windows_fail_closed():
    recs = C.parse_win_connections(fx("clean_win_outbound.json"), "[]", fx("win_proc.json"))
    out = {r["remote_port"]: r for r in recs if r["state"] == "ESTABLISHED"}
    assert C.is_expected_outbound("win32", out[445], windows_dir="C:\\Windows")
    assert C.is_expected_outbound("win32", out[7680], windows_dir="C:\\Windows")
    assert not C.is_expected_outbound("win32", out[443])
    # SMB is the System process only; 7680 needs svchost's exact System32 path
    assert not C.is_expected_outbound("win32", {**out[445], "pid": 5120})
    assert not C.is_expected_outbound("win32", {**out[7680], "exe": "C:\\Users\\x\\svchost.exe"})
    pathless = {**out[7680], "exe": None}
    assert not C.is_expected_outbound("win32", pathless)
    assert C.claims_expected_outbound("win32", pathless)
    assert not C.claims_expected_outbound("win32", {**pathless, "process": "rundll32"})
    assert not C.claims_expected_outbound("win32", {**pathless, "remote_port": 9999})
    assert not C.is_expected_outbound("linux", out[445])
    assert not C.claims_expected_outbound("linux", pathless)


def test_expected_outbound_needs_a_local_remote_address():
    smb = {"proto": "tcp", "state": "ESTABLISHED", "local_addr": "192.168.1.40", "local_port": 50101,
           "remote_addr": "192.168.1.10", "remote_port": 445, "pid": 4, "process": "System", "exe": None}
    assert C.is_expected_outbound("win32", smb)
    assert not C.is_expected_outbound("win32", {**smb, "remote_addr": "203.0.113.5"})
    svc = {**smb, "remote_addr": "198.51.100.7", "remote_port": 7680, "pid": 1044,
           "process": "svchost", "exe": "C:\\Windows\\System32\\svchost.exe"}
    assert not C.is_expected_outbound("win32", svc, windows_dir="C:\\Windows")
    assert C.is_expected_outbound("win32", {**svc, "remote_addr": "10.1.2.3"}, windows_dir="C:\\Windows")
    pathless = {**svc, "exe": None}
    assert not C.claims_expected_outbound("win32", pathless)
    assert C.claims_expected_outbound("win32", {**pathless, "remote_addr": "fe80::1"})
    assert C.claims_expected_outbound("win32", {**pathless, "remote_addr": "fd00::5"})
    assert not C.is_expected_outbound("win32", {**smb, "remote_addr": "2001:db8::1"})
    assert not C.is_expected_outbound("win32", {**smb, "remote_addr": None})


def test_snapshot_without_bytes_skips_data_count_commands():
    seen = []

    def run(args, **kw):
        seen.append(args)
        if args[0] == "ss":
            return result(fx("ss_tunap_linux.txt"))
        if args[0] == "lsof":
            return result(fx("lsof_mac.txt"))
        return result(fx("win_tcp.json").strip() + "\n[]\n" + fx("win_proc.json"))

    for platform in ("darwin", "linux", "win32"):
        seen.clear()
        snap = C.snapshot(platform, run=run, with_bytes=False)
        assert snap["error"] is None and snap["records"]
        assert snap["bytes"] is None
        assert len(seen) == 1
        assert not any("data" in s for s in snap["limits"])
