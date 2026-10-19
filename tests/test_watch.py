"""The connection watch: repeated snapshots, summarised per app.

Every test drives ``run_watch`` with a scripted collector and a fake clock, so
nothing runs a real command and nothing waits.
"""

import re
from pathlib import Path

import pytest

from rescue.models import Severity
from rescue.watch import MAX_PAIRS, MAX_STAMPS, WATCH_CODES, WatchModule, run_watch

_ROOT = Path(__file__).resolve().parents[1]


class FakeTime:
    def __init__(self):
        self.t = 0.0

    def clock(self):
        return self.t

    def sleep(self, seconds):
        self.t += seconds


def rec(process, remote, rport, lport, *, proto="tcp", state="ESTABLISHED", pid=100,
        laddr="192.168.1.5"):
    return {
        "proto": proto, "state": state, "local_addr": laddr, "local_port": lport,
        "remote_addr": remote, "remote_port": rport, "pid": pid, "process": process,
        "exe": None,
    }


def listener(process, port, *, pid=200, addr="0.0.0.0"):
    return rec(process, None, None, port, state="LISTEN", pid=pid, laddr=addr)


def snap(records, *, bytes_=None, limits=(), error=None):
    return {"records": list(records), "bytes": bytes_, "limits": list(limits), "error": error}


def scripted(snaps):
    """A collector that hands out ``snaps`` in order, then repeats the last one."""
    calls = []

    def collect(platform):
        calls.append(platform)
        return snaps[min(len(calls) - 1, len(snaps) - 1)]

    collect.calls = calls
    return collect


def no_dns(platform):
    return {"names": None, "reason": "macOS doesn't show which names were looked up."}


def watch(snaps, *, platform="darwin", minutes=1, interval=5, dns=no_dns, should_stop=None,
          verdict=None, on_progress=None):
    fake = FakeTime()
    return run_watch(
        platform, minutes, interval,
        collect=scripted(snaps) if not callable(snaps) else snaps,
        dns=dns, clock=fake.clock, sleep=fake.sleep,
        should_stop=should_stop or (lambda: False),
        on_progress=on_progress,
        verdict=verdict or (lambda platform, record: "expected"),
    )


def by_code(result, slug):
    return [f for f in result.findings if f.code == f"network.connection_watch.{slug}"]


def test_bounds_refused():
    for minutes, interval in ((0, 5), (31, 5), (5, 1), (5, 61)):
        with pytest.raises(ValueError):
            watch([snap([])], minutes=minutes, interval=interval)


def test_snapshots_taken_over_the_whole_watch():
    collect = scripted([snap([])])
    progress = []
    result = watch(collect, minutes=1, interval=5, on_progress=progress.append)
    assert len(collect.calls) == 12
    assert progress[-1] == {"phase": "watch", "elapsed": 55, "total": 60, "snapshots": 12}
    assert result.module_name == "connection_watch"


def test_summary_per_process_stable_target():
    records = [
        rec("Safari", "17.253.1.1", 443, 50001),
        rec("Safari", "17.253.1.2", 443, 50002),
        rec("Dropbox", "162.125.1.1", 443, 50003, pid=300),
        rec(None, "8.8.8.8", 53, 50004, proto="udp", pid=None),
    ]
    result = watch([snap(records[:2]), snap(records)])
    summaries = {f.data["target"]: f for f in by_code(result, "watch_summary")}
    assert set(summaries) == {"Safari", "Dropbox", "unknown"}
    safari = summaries["Safari"]
    assert [d["address"] for d in safari.data["destinations"]] == ["17.253.1.1", "17.253.1.2"]
    assert safari.data["destinations"][0]["snapshots"] == 12
    assert summaries["Dropbox"].data["destinations"][0]["snapshots"] == 11
    assert safari.data["more"] == 0
    assert safari.data["bytes_in"] is None and safari.data["bytes_out"] is None
    for f in summaries.values():
        assert f.data["minutes"] == 1
        assert f.data["snapshots"] == 12
        assert f.data["stopped_early"] is False


def _checkin_snaps(change_at, remote="93.184.216.34", count=12):
    """A connection to ``remote`` whose local port changes at the given snapshot indexes."""
    snaps, port = [], 50000
    for i in range(count):
        if i in change_at:
            port += 1
        snaps.append(snap([rec("Slack", remote, 443, port)]))
    return snaps


def test_regular_vs_jittery_vs_too_few():
    steady = watch(_checkin_snaps({2, 4, 6, 8, 10}))
    [found] = by_code(steady, "regular_checkins")
    assert found.confidence == 0.5
    assert found.severity == Severity.INFO
    assert "most apps do this to check for updates or messages" in found.description
    assert found.data["target"] == "Slack"
    assert found.data["address"] == "93.184.216.34"
    assert found.data["median_gap"] == 10
    assert found.data["new_connections"] == 5

    jittery = watch(_checkin_snaps({1, 2, 5, 6, 11}))
    assert by_code(jittery, "regular_checkins") == []

    too_few = watch(_checkin_snaps({2, 4, 6}))
    assert by_code(too_few, "regular_checkins") == []


def test_private_destination_never_regular():
    for remote in ("192.168.1.20", "10.0.0.7", "172.16.4.4", "169.254.3.3", "fd00::1",
                   "fe80::1", "127.0.0.1"):
        result = watch(_checkin_snaps({2, 4, 6, 8, 10}, remote=remote))
        assert by_code(result, "regular_checkins") == [], remote


def test_upload_heavy_needs_known_bytes():
    records = [rec("Backup", "52.1.1.1", 443, 50001, pid=100)]
    heavy = watch([
        snap(records, bytes_={100: (1_000, 0)}),
        snap(records, bytes_={100: (2_000_000, 25_000_000)}),
    ])
    [found] = by_code(heavy, "upload_heavy")
    assert found.data["target"] == "Backup"
    assert found.data["bytes_out"] == 25_000_000
    assert found.data["bytes_in"] == 1_999_000
    [summary] = by_code(heavy, "watch_summary")
    assert summary.data["bytes_out"] == 25_000_000

    balanced = watch([
        snap(records, bytes_={100: (0, 0)}),
        snap(records, bytes_={100: (5_000_000, 11_000_000)}),
    ])
    assert by_code(balanced, "upload_heavy") == []

    small = watch([
        snap(records, bytes_={100: (0, 0)}),
        snap(records, bytes_={100: (0, 9_000_000)}),
    ])
    assert by_code(small, "upload_heavy") == []

    unknown = watch([snap(records, limits=["Windows doesn't show how much data."])],
                    platform="win32", dns=lambda p: {"names": [], "reason": None})
    assert by_code(unknown, "upload_heavy") == []
    [summary] = by_code(unknown, "watch_summary")
    assert summary.data["bytes_in"] is None and summary.data["bytes_out"] is None


def test_process_seen_later_uses_first_seen_bytes_as_baseline():
    early = rec("Safari", "17.253.1.1", 443, 50001, pid=100)
    late = rec("Zoom", "3.3.3.3", 443, 50002, pid=400)
    result = watch([
        snap([early], bytes_={100: (0, 0)}),
        snap([early, late], bytes_={100: (10, 10), 400: (5_000, 50_000_000)}),
        snap([early, late], bytes_={100: (20, 20), 400: (6_000, 70_000_000)}),
    ])
    summaries = {f.data["target"]: f for f in by_code(result, "watch_summary")}
    assert summaries["Zoom"].data["bytes_out"] == 20_000_000
    assert summaries["Zoom"].data["bytes_in"] == 1_000
    [found] = by_code(result, "upload_heavy")
    assert found.data["target"] == "Zoom"


def test_unknown_bytes_for_one_process_named_in_incomplete():
    known = rec("Safari", "17.253.1.1", 443, 50001, pid=100)
    unknown = rec("Mail", "17.42.1.1", 993, 50002, pid=500)
    result = watch([snap([known, unknown], bytes_={100: (0, 0)})])
    summaries = {f.data["target"]: f for f in by_code(result, "watch_summary")}
    assert summaries["Safari"].data["bytes_out"] == 0
    assert summaries["Mail"].data["bytes_out"] is None
    [incomplete] = by_code(result, "watch_incomplete")
    assert any("Mail" in r for r in incomplete.data["reasons"])


def test_linux_bytes_summed_per_process():
    a = rec("firefox", "1.1.1.1", 443, 40001, pid=10, laddr="10.0.0.2")
    b = rec("firefox", "1.0.0.1", 443, 40002, pid=10, laddr="10.0.0.2")
    key_a = ("10.0.0.2", 40001, "1.1.1.1", 443)
    key_b = ("10.0.0.2", 40002, "1.0.0.1", 443)
    result = watch([
        snap([a], bytes_={key_a: (100, 100)}),
        snap([a, b], bytes_={key_a: (300, 1_100), key_b: (50, 50)}),
        snap([a, b], bytes_={key_a: (400, 2_100), key_b: (60, 550)}),
    ], platform="linux")
    [summary] = by_code(result, "watch_summary")
    assert summary.data["bytes_in"] == 300 + 10
    assert summary.data["bytes_out"] == 2_000 + 500


def test_new_listener_uses_verdict():
    calls = []

    def verdict(platform, record):
        calls.append((platform, record["local_port"]))
        return "flag"

    base = [listener("sshd", 22)]
    result = watch(
        [snap(base), snap(base), snap(base + [listener("node", 8080, pid=700)])],
        verdict=verdict,
    )
    [found] = by_code(result, "new_listener")
    assert found.data["target"] == "node"
    assert found.data["port"] == 8080
    assert found.data["next_checkup"] == "flag"
    assert found.severity == Severity.INFO
    assert calls == [("darwin", 8080)]


def test_caps_pairs_and_timestamps():
    many = [rec("Chrome", "142.250.1.1", port, 50000) for port in range(1, 3001)]
    result = watch([snap(many)])
    [summary] = by_code(result, "watch_summary")
    assert len(summary.data["destinations"]) == 50
    assert summary.data["more"] == MAX_PAIRS - 50
    [incomplete] = by_code(result, "watch_incomplete")
    assert any("2,000" in r for r in incomplete.data["reasons"])

    # 30 minutes at 2 s: 900 snapshots, each with a fresh connection.
    def collect(platform, _n=[0]):
        _n[0] += 1
        return snap([rec("Chrome", "142.250.1.1", 443, 10000 + _n[0])])

    result = watch(collect, minutes=30, interval=2)
    [summary] = by_code(result, "watch_summary")
    assert summary.data["snapshots"] == 900
    assert summary.data["destinations"][0]["new_connections"] == 899
    [incomplete] = by_code(result, "watch_incomplete")
    assert any(str(MAX_STAMPS) in r for r in incomplete.data["reasons"])


def test_stop_before_first_snapshot():
    collect = scripted([snap([rec("Safari", "17.253.1.1", 443, 50001)])])
    result = watch(collect, should_stop=lambda: True)
    assert collect.calls == []
    assert {f.code for f in result.findings} == {
        "network.connection_watch.watch_incomplete",
        "network.connection_watch.dns_not_visible",
    }
    [incomplete] = by_code(result, "watch_incomplete")
    assert incomplete.data["snapshots"] == 0
    assert incomplete.data["stopped_early"] is True
    assert "nothing" in incomplete.description.lower()


def test_stop_midway_keeps_gathered():
    collect = scripted([snap([rec("Safari", "17.253.1.1", 443, 50001)])])
    result = watch(collect, should_stop=lambda: len(collect.calls) >= 3)
    assert len(collect.calls) == 3
    [summary] = by_code(result, "watch_summary")
    assert summary.data["snapshots"] == 3
    assert summary.data["stopped_early"] is True
    [incomplete] = by_code(result, "watch_incomplete")
    assert any("stopped early" in r for r in incomplete.data["reasons"])


def test_snapshot_errors_reported_and_all_failed_gathers_nothing():
    good = snap([rec("Safari", "17.253.1.1", 443, 50001)])
    bad = snap([], error="lsof didn't finish.")
    result = watch([good, bad, good])
    [incomplete] = by_code(result, "watch_incomplete")
    assert any("lsof didn't finish." in r for r in incomplete.data["reasons"])
    assert incomplete.data["snapshots"] == 11

    nothing = watch([bad])
    assert {f.code for f in nothing.findings} == {
        "network.connection_watch.watch_incomplete",
        "network.connection_watch.dns_not_visible",
    }


def test_dns_windows_and_not_visible_elsewhere():
    lookups = iter([
        [{"name": "example.com", "type": "A"}],
        [{"name": "example.com", "type": "A"}, {"name": "update.local", "type": "AAAA"}],
    ])

    def dns(platform):
        return {"names": next(lookups, [{"name": "update.local", "type": "AAAA"}]),
                "reason": None}

    result = watch([snap([])], platform="win32", dns=dns)
    [found] = by_code(result, "dns_lookups")
    names = {n["name"]: n for n in found.data["names"]}
    assert names["example.com"] == {"name": "example.com", "type": "A",
                                    "first_seen_snapshot": 1, "snapshots": 2}
    assert names["update.local"]["first_seen_snapshot"] == 2
    assert names["update.local"]["snapshots"] == 11
    assert "doesn't record which program" in found.description
    assert by_code(result, "dns_not_visible") == []

    elsewhere = watch([snap([])], platform="linux",
                      dns=lambda p: {"names": None, "reason": "Linux shows names only to admins."})
    [hidden] = by_code(elsewhere, "dns_not_visible")
    assert "Linux shows names only to admins." in hidden.description
    assert by_code(elsewhere, "dns_lookups") == []


def test_loopback_counted_not_listed():
    records = [
        rec("node", "127.0.0.1", 5432, 50001),
        rec("node", "::1", 6379, 50002),
        rec("node", "104.16.1.1", 443, 50003),
    ]
    result = watch([snap(records)])
    [summary] = by_code(result, "watch_summary")
    assert [d["address"] for d in summary.data["destinations"]] == ["104.16.1.1"]
    assert summary.data["loopback_count"] == 2 * 12


def test_all_findings_info_and_codes_in_watch_codes():
    base = [listener("sshd", 22)]
    records = [rec("Backup", "52.1.1.1", 443, 50001)]
    snaps = [snap(base + records, bytes_={100: (0, 0)}, limits=["Some limit."])]
    for i in range(1, 12):
        snaps.append(snap(
            base + [listener("node", 8080), rec("Backup", "52.1.1.1", 443, 50001 + i // 2)],
            bytes_={100: (0, 40_000_000)},
        ))
    result = watch(snaps)
    codes = {f.code for f in result.findings}
    assert codes >= {
        "network.connection_watch.watch_summary",
        "network.connection_watch.regular_checkins",
        "network.connection_watch.new_listener",
        "network.connection_watch.upload_heavy",
        "network.connection_watch.dns_not_visible",
        "network.connection_watch.watch_incomplete",
    }
    for f in result.findings:
        assert f.severity == Severity.INFO
        assert f.code in WATCH_CODES
        assert f.category == "network"
        assert "kill" not in f.description.lower()
        assert "end the process" not in f.description.lower()


def test_every_code_literal_in_source_is_a_watch_code():
    source = (_ROOT / "rescue" / "watch.py").read_text(encoding="utf-8")
    literals = set(re.findall(r'code\s*=\s*["\']([a-z0-9_]+\.[a-z0-9_.]+)["\']', source))
    assert literals == set(WATCH_CODES)
    calls = source.count("Finding(")
    assert calls == len(re.findall(r'Finding\(\s*code="network\.connection_watch\.', source))


def test_watch_module_stand_in():
    assert WatchModule.name == "connection_watch"
    assert WatchModule.category == "network"
    assert WatchModule.emits_codes == WATCH_CODES
    assert {p.value for p in WatchModule.platforms} == {"darwin", "linux", "win32"}
