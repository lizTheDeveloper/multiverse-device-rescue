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
    assert all(C.is_expected_listener("linux", r) for r in recs)


def test_unexpected_listener():
    py = {"process": "python3", "local_port": 8000, "local_addr": "0.0.0.0", "pid": 9, "exe": None}
    assert not C.is_expected_listener("linux", py)
    # sshd on the wrong port, and the DNS stub on a public address
    assert not C.is_expected_listener("linux", {**py, "process": "sshd", "local_port": 2222})
    assert not C.is_expected_listener("linux", {**py, "process": "systemd-resolve", "local_port": 53})
    app = {"process": "app", "local_port": 445, "local_addr": "0.0.0.0", "pid": 7000,
           "exe": "C:\\Users\\sam\\AppData\\app.exe"}
    assert not C.is_expected_listener("win32", app)
    sys32 = {**app, "exe": "C:\\Windows\\SysWOW64\\x.exe"}
    assert not C.is_expected_listener("win32", sys32)
    assert not C.is_expected_listener("win32", {**app, "exe": "C:\\Windows\\System32\\x.exe", "local_port": 8080})
    assert C.is_expected_listener("win32", {**app, "exe": "c:\\windows\\system32\\x.exe"})
    assert not C.is_expected_listener("darwin", py)
