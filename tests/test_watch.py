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


def nobody_known(ips, **kw):
    """Lookups that answer with nothing, so tests about other things see no lookup notes."""
    return {"results": {}, "skipped": 0, "failed": 0, "over_budget": False, "stopped": False}


def watch(snaps, *, platform="darwin", minutes=1, interval=5, dns=no_dns, should_stop=None,
          verdict=None, on_progress=None, lookups=nobody_known):
    fake = FakeTime()
    return run_watch(
        platform, minutes, interval,
        collect=scripted(snaps) if not callable(snaps) else snaps,
        dns=dns, clock=fake.clock, sleep=fake.sleep,
        should_stop=should_stop or (lambda: False),
        on_progress=on_progress,
        verdict=verdict or (lambda platform, record: "expected"),
        lookups=lookups,
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
    # key_a was open at the start: last minus first. key_b opened during the
    # watch, and Linux counts each connection from zero, so all of it counts.
    assert summary.data["bytes_in"] == 300 + 60
    assert summary.data["bytes_out"] == 2_000 + 550


def test_linux_connection_seen_once_mid_watch_counts_in_full():
    a = rec("rsync", "5.5.5.5", 22, 40001, pid=10, laddr="10.0.0.2")
    key_a = ("10.0.0.2", 40001, "5.5.5.5", 22)
    result = watch([
        snap([], bytes_={}),
        snap([a], bytes_={key_a: (1_000, 30_000_000)}),
        snap([], bytes_={}),
    ], platform="linux")
    [found] = by_code(result, "upload_heavy")
    assert found.data["target"] == "rsync"
    assert found.data["bytes_out"] == 30_000_000


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
    assert summary.data["not_stored"] == 1000
    assert "1,000 more" in summary.description
    [incomplete] = by_code(result, "watch_incomplete")
    assert any("2,000" in r and "1,000 more" in r for r in incomplete.data["reasons"])

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


def _new_listener_watch(verdict):
    base = [listener("sshd", 22)]
    return watch([snap(base), snap(base + [listener("node", 8080, pid=700)])], verdict=verdict)


def test_failing_verdict_is_reported_not_dropped():
    def broken(platform, record):
        raise RuntimeError("rules missing")

    result = _new_listener_watch(broken)
    [found] = by_code(result, "new_listener")
    assert found.data["next_checkup"] is None
    [incomplete] = by_code(result, "watch_incomplete")
    assert any("Couldn't judge whether the new listening port" in r and "rules missing" in r
               for r in incomplete.data["reasons"])


def test_verdict_lookup_failure_is_reported(monkeypatch):
    import rescue.watch as watch_module

    def no_lookup():
        raise ImportError("no modules folder")

    monkeypatch.setattr(watch_module, "_default_verdict", no_lookup)
    fake = FakeTime()
    base = [listener("sshd", 22)]
    result = run_watch(
        "darwin", 1, 30, collect=scripted([snap(base), snap(base + [listener("node", 8080)])]),
        dns=no_dns, clock=fake.clock, sleep=fake.sleep,
    )
    [found] = by_code(result, "new_listener")
    assert found.data["next_checkup"] is None
    [incomplete] = by_code(result, "watch_incomplete")
    assert any("no modules folder" in r for r in incomplete.data["reasons"])


def test_raising_dns_reader_is_reported():
    def broken(platform):
        raise OSError("pipe closed")

    for platform in ("win32", "darwin"):
        result = watch([snap([])], platform=platform, dns=broken)
        [hidden] = by_code(result, "dns_not_visible")
        assert "pipe closed" in hidden.description
        [incomplete] = by_code(result, "watch_incomplete")
        assert any("pipe closed" in r for r in incomplete.data["reasons"])

    calls = []

    def sometimes(platform):
        calls.append(1)
        if len(calls) == 2:
            raise OSError("one bad read")
        return {"names": [{"name": "example.com", "type": "A"}], "reason": None}

    result = watch([snap([])], platform="win32", dns=sometimes)
    [found] = by_code(result, "dns_lookups")
    assert found.data["names"][0]["snapshots"] == 11
    [incomplete] = by_code(result, "watch_incomplete")
    assert any("one bad read" in r for r in incomplete.data["reasons"])


def test_raising_progress_is_ignored():
    collect = scripted([snap([rec("Safari", "17.253.1.1", 443, 50001)])])

    def broken(progress):
        raise BrokenPipeError("stderr closed")

    result = watch(collect, on_progress=broken)
    assert len(collect.calls) == 12
    [summary] = by_code(result, "watch_summary")
    assert summary.data["snapshots"] == 12


def test_multicast_and_shared_addresses_never_regular():
    for remote in ("224.0.0.251", "ff02::fb", "100.64.1.1", "0.0.0.0", "240.0.0.1",
                   "255.255.255.255"):
        result = watch(_checkin_snaps({2, 4, 6, 8, 10}, remote=remote))
        assert by_code(result, "regular_checkins") == [], remote


def test_listener_owner_flicker_is_not_new():
    named = listener("cupsd", 631)
    unnamed = dict(named, process=None, pid=None)
    result = watch([snap([named]), snap([unnamed]), snap([named])], platform="linux",
                   dns=lambda p: {"names": None, "reason": "Linux hides names."})
    assert by_code(result, "new_listener") == []


def test_listener_opened_and_closed_within_watch():
    base = [listener("sshd", 22)]
    result = watch([snap(base), snap(base + [listener("node", 8080)]), snap([])])
    [found] = by_code(result, "new_listener")
    assert found.data["target"] == "node"
    summaries = {f.data["target"]: f for f in by_code(result, "watch_summary")}
    assert summaries["node"].data["listeners_opened"] == [8080]
    assert summaries["node"].data["listeners_closed"] == [8080]
    assert summaries["sshd"].data["listeners_closed"] == [22]


def test_defaults_load_independently(monkeypatch):
    import rescue.watch as watch_module

    monkeypatch.setattr(watch_module, "_collector", lambda: None)
    fake = FakeTime()
    collect = scripted([snap([rec("Safari", "17.253.1.1", 443, 50001)])])
    result = run_watch("win32", 1, 30, collect=collect, clock=fake.clock, sleep=fake.sleep,
                       verdict=lambda p, r: "expected")
    assert result.error is None
    assert len(by_code(result, "watch_summary")) == 1
    [hidden] = by_code(result, "dns_not_visible")
    assert "Couldn't load" in hidden.description

    result = run_watch("darwin", 1, 30, dns=no_dns, clock=fake.clock, sleep=fake.sleep)
    assert result.error and "connections" in result.error


def test_listener_taken_over_by_another_program_is_new():
    first = listener("python3", 8000, pid=10)
    result = watch([snap([first]), snap([first]), snap([dict(first, process="nc", pid=11)])])
    [found] = by_code(result, "new_listener")
    assert found.data["target"] == "nc"
    assert found.data["port"] == 8000
    summaries = {f.data["target"]: f for f in by_code(result, "watch_summary")}
    assert summaries["nc"].data["listeners_opened"] == [8000]
    assert summaries["python3"].data["listeners_closed"] == [8000]


def test_hidden_owner_named_later_is_not_a_takeover():
    hidden = dict(listener("node", 3000), process=None, pid=None)
    result = watch([snap([]), snap([hidden]), snap([listener("node", 3000)])],
                   platform="linux", dns=lambda p: {"names": None, "reason": "Hidden."})
    [found] = by_code(result, "new_listener")
    assert found.data["target"] == "node"


def test_nat64_classified_by_embedded_ipv4():
    public = watch(_checkin_snaps({2, 4, 6, 8, 10}, remote="64:ff9b::808:808"))
    assert len(by_code(public, "regular_checkins")) == 1
    private = watch(_checkin_snaps({2, 4, 6, 8, 10}, remote="64:ff9b::c0a8:10a"))
    assert by_code(private, "regular_checkins") == []


def test_local_use_nat64_is_not_unwrapped():
    # 64:ff9b:1::/48's prefix length varies, so the embedded address (10.0.0.1
    # under a /96 reading) isn't trusted: the address counts as public.
    result = watch(_checkin_snaps({2, 4, 6, 8, 10}, remote="64:ff9b:1::a00:1"))
    assert len(by_code(result, "regular_checkins")) == 1


def test_ipv6_public_address_not_dropped_as_reserved():
    result = watch(_checkin_snaps({2, 4, 6, 8, 10}, remote="2606:4700::1111"))
    assert len(by_code(result, "regular_checkins")) == 1


def test_bytes_baseline_is_first_snapshot_only():
    a = rec("curl", "9.9.9.9", 443, 40001, pid=10, laddr="10.0.0.2")
    key_a = ("10.0.0.2", 40001, "9.9.9.9", 443)
    # The first snapshot had no byte reading: a Linux connection seen later starts from 0.
    linux = watch([
        snap([a], bytes_=None, limits=["Couldn't read data counts."]),
        snap([a], bytes_={key_a: (500, 700)}),
        snap([a], bytes_={key_a: (600, 900)}),
    ], platform="linux")
    [summary] = by_code(linux, "watch_summary")
    assert (summary.data["bytes_in"], summary.data["bytes_out"]) == (600, 900)

    # macOS counts per program, so a later first reading is still the baseline.
    b = rec("curl", "9.9.9.9", 443, 40001, pid=10)
    darwin = watch([
        snap([b], bytes_=None, limits=["Couldn't read data counts."]),
        snap([b], bytes_={10: (500, 700)}),
        snap([b], bytes_={10: (600, 900)}),
    ])
    [summary] = by_code(darwin, "watch_summary")
    assert (summary.data["bytes_in"], summary.data["bytes_out"]) == (100, 200)


def test_shared_listening_port_is_not_new():
    shared = [listener("sh", 8000, pid=10), listener("node", 8000, pid=11)]
    result = watch([snap(shared)] * 4)
    assert by_code(result, "new_listener") == []
    summaries = {f.data["target"]: f for f in by_code(result, "watch_summary")}
    assert summaries == {}


def test_second_program_joining_a_port_is_new_once():
    sh = listener("sh", 8000, pid=10)
    nc = listener("nc", 8000, pid=12)
    result = watch([snap([sh]), snap([sh, nc]), snap([nc, sh]), snap([sh])])
    [found] = by_code(result, "new_listener")
    assert found.data["target"] == "nc"
    summaries = {f.data["target"]: f for f in by_code(result, "watch_summary")}
    assert summaries["nc"].data["listeners_opened"] == [8000]
    assert summaries["nc"].data["listeners_closed"] == [8000]
    assert "sh" not in summaries


def test_hidden_owner_on_a_port_open_from_the_start_is_not_new():
    hidden = dict(listener("cupsd", 631), process=None, pid=None)
    result = watch([snap([hidden]), snap([listener("cupsd", 631)])], platform="linux",
                   dns=lambda p: {"names": None, "reason": "Hidden."})
    assert by_code(result, "new_listener") == []


def test_watch_ends_by_the_clock_when_snapshots_are_slow():
    # Each snapshot takes 12 s against a 5 s interval: the watch still stops
    # at its deadline, not after 12 snapshots' worth of time.
    fake = FakeTime()
    starts = []

    def slow_collect(platform):
        starts.append(fake.t)
        fake.t += 12
        return snap([rec("Safari", "17.253.1.1", 443, 50001)])

    result = run_watch(
        "darwin", 1, 5, collect=slow_collect, dns=no_dns, clock=fake.clock,
        sleep=fake.sleep, should_stop=lambda: False,
        verdict=lambda platform, record: "expected",
    )
    assert starts and all(t < 60 for t in starts)
    assert 60 <= fake.t < 60 + 12
    assert len(starts) == 5
    summary = by_code(result, "watch_summary")[0]
    assert summary.data["elapsed"] == 60
    assert summary.data["stopped_early"] is False


def test_windows_closed_connections_are_not_named_idle():
    """TIME_WAIT rows on PID 0 ("Idle") must not become a program in the watch."""
    import json

    from rescue.command import CommandResult
    from rescue.runtime import load_content_module

    collector = load_content_module(
        "modules/network/conn_common/collect.py", "rescue_conn_common_collect"
    )
    proc = json.dumps([
        {"Id": 0, "ProcessName": "Idle", "Path": None},
        {"Id": 1044, "ProcessName": "svchost", "Path": "C:\\Windows\\System32\\svchost.exe"},
    ])
    listen = {"LocalAddress": "0.0.0.0", "LocalPort": 135, "RemoteAddress": "0.0.0.0",
              "RemotePort": 0, "State": 2, "OwningProcess": 1044}
    looks = iter(range(10_000))

    def run(args, **kwargs):
        n = next(looks)
        closed = {"LocalAddress": "192.168.1.40", "LocalPort": 50000 + n,
                  "RemoteAddress": "203.0.113.5", "RemotePort": 8080, "State": 11,
                  "OwningProcess": 0}
        out = "\n".join([json.dumps([listen, closed]), "[]", proc]) + "\n"
        return CommandResult(args=args, returncode=0, stdout=out, stderr="",
                             timed_out=False, error=None, duration_s=0.0, truncated=False)

    result = watch(
        lambda platform: collector.snapshot(platform, run=run), platform="win32",
        dns=lambda platform: {"names": [], "reason": None},
    )
    for f in result.findings:
        text = f.title + f.description + json.dumps(f.data, default=str)
        assert "Idle" not in text, f.title


# --- who runs each address --------------------------------------------------


def who(*, registrant=None, as_name=None, hostname=None, confirmed=False, unavailable=()):
    return {"hostname": hostname, "hostname_confirmed": confirmed, "asn": None,
            "as_name": as_name, "prefix": None, "network": None, "registrant": registrant,
            "country": None, "unavailable": list(unavailable)}


def fake_lookups(answers, *, skipped=0, failed=0, over_budget=False, stopped=False, calls=None):
    def lookups(ips, *, should_stop, on_progress, budget):
        if calls is not None:
            calls.append(list(ips))
        lookups.budgets.append(budget)
        results = {ip: answers[ip] for ip in ips if ip in answers}
        on_progress(len(results), len(ips))
        return {"results": results, "skipped": skipped, "failed": failed,
                "over_budget": over_budget, "stopped": stopped}

    lookups.budgets = []
    return lookups


def _busy_snaps():
    """Chrome sees 8.8.8.8 in every look, 8.8.4.4 in two, 1.1.1.1 and the router in one."""
    steady = [rec("Chrome", "8.8.8.8", 443, 50000), rec("Chrome", "8.8.4.4", 443, 50001)]
    return [
        snap(steady + [rec("Chrome", "1.1.1.1", 443, 50002), rec("Chrome", "192.168.1.1", 80, 50003)]),
        snap(steady),
        snap([rec("Chrome", "8.8.8.8", 443, 50000)]),
    ]


def reasons_of(result):
    found = by_code(result, "watch_incomplete")
    return found[0].data["reasons"] if found else []


def test_watch_attaches_who():
    from rescue.whois import SOURCES

    calls = []
    answers = {
        "8.8.8.8": who(registrant="Google LLC", as_name="GOOGLE - Google LLC", hostname="dns.google",
                       confirmed=True),
        "8.8.4.4": who(as_name="GOOGLE - Google LLC"),
        # The registry names APNIC; the network's holder is who runs it.
        "1.1.1.1": who(as_name="CLOUDFLARENET - Cloudflare, Inc.",
                       registrant="APNIC Research and Development"),
    }
    result = watch(_busy_snaps(), lookups=fake_lookups(answers, calls=calls))
    # One call, busiest first, private addresses left out.
    assert calls == [["8.8.8.8", "8.8.4.4", "1.1.1.1"]]
    (summary,) = by_code(result, "watch_summary")
    by_address = {d["address"]: d["who"] for d in summary.data["destinations"]}
    assert by_address["8.8.8.8"] == answers["8.8.8.8"]
    assert by_address["1.1.1.1"]["registrant"] == "APNIC Research and Development"  # kept as it is
    assert by_address["192.168.1.1"] is None
    assert summary.data["lookup_sources"] == SOURCES
    assert "Mostly Google LLC and Cloudflare, Inc." in summary.description
    assert not by_code(result, "watch_incomplete")


def test_owner_is_holder_then_registrant_then_confirmed_hostname():
    snaps = [snap([rec("App", ip, 443, 50000 + i) for i, ip in enumerate(
        ("8.8.8.8", "8.8.4.4", "9.9.9.9", "1.1.1.1"))])]

    def mostly(answers):
        (summary,) = by_code(watch(snaps, lookups=fake_lookups(answers)), "watch_summary")
        text = summary.description
        return text[text.index("Mostly"):].split(". This")[0] if "Mostly" in text else None

    # Equally busy: the order the destinations are listed in (8.8.4.4 first).
    assert mostly({"8.8.8.8": who(registrant="Google LLC"),
                   "8.8.4.4": who(hostname="dns.google", confirmed=True)}) == \
        "Mostly dns.google and Google LLC"
    # An unconfirmed hostname is never an owner; nor is a raw address.
    assert mostly({"8.8.8.8": who(hostname="www.apple.com"),
                   "9.9.9.9": who(registrant="Quad9")}) == "Mostly Quad9"
    # Nothing known about anyone: no sentence at all.
    assert mostly({"8.8.8.8": who(hostname="www.apple.com", unavailable=["owner", "registry"])}) is None
    assert mostly({}) is None


def test_network_name_reads_as_its_organisation():
    """RIPEstat's "GOOGLE - Google LLC" and the registry's "Google LLC" are one owner."""
    snaps = [snap([rec("Chrome", "8.8.8.8", 443, 50000), rec("Chrome", "8.8.4.4", 443, 50001),
                   rec("Chrome", "9.9.9.9", 443, 50002)])]
    answers = {"8.8.8.8": who(registrant="Google LLC"), "8.8.4.4": who(as_name="GOOGLE - Google LLC"),
               "9.9.9.9": who(as_name="LEXIS2-AS - RELX inc.")}
    result = watch(snaps, lookups=fake_lookups(answers))
    (summary,) = by_code(result, "watch_summary")
    assert "Mostly Google LLC and RELX inc. This" in summary.description


def test_one_owner_is_named_alone():
    snaps = [snap([rec("Chrome", "8.8.8.8", 443, 50000)])]
    result = watch(snaps, lookups=fake_lookups({"8.8.8.8": who(registrant="Google LLC")}))
    (summary,) = by_code(result, "watch_summary")
    assert "Mostly Google LLC." in summary.description


def test_no_lookups_turned_off():
    result = watch(_busy_snaps(), lookups=None)
    (summary,) = by_code(result, "watch_summary")
    assert all(d["who"] is None for d in summary.data["destinations"])
    assert summary.data["lookup_sources"] == []
    assert "Mostly" not in summary.description  # addresses are never named as owners
    assert "Looking up who runs each address was turned off." in reasons_of(result)

    # Nothing public seen: there was nothing to turn off.
    result = watch([snap([rec("App", "192.168.1.1", 443, 50000)])], lookups=None)
    assert reasons_of(result) == []


def test_watch_offline_lookups_still_returns():
    offline = who(unavailable=["dns", "owner", "registry"])
    answers = {ip: offline for ip in ("8.8.8.8", "8.8.4.4", "1.1.1.1")}
    result = watch(_busy_snaps(), lookups=fake_lookups(answers, failed=3))
    (summary,) = by_code(result, "watch_summary")
    assert summary.data["destinations"][0]["who"] == offline
    assert reasons_of(result) == [
        "Couldn't look up 3 address(es) (offline or the service didn't answer)."]

    def offline_call(ips, **kw):
        raise OSError("network is unreachable")

    result = watch(_busy_snaps(), lookups=offline_call)
    (summary,) = by_code(result, "watch_summary")
    assert all(d["who"] is None for d in summary.data["destinations"])
    assert reasons_of(result) == [
        "Couldn't look up 3 address(es) (offline or the service didn't answer)."]


def test_partial_lookup_failures_are_named():
    answers = {"8.8.8.8": who(registrant="Google LLC", unavailable=["registry"]),
               "8.8.4.4": who(as_name="GOOGLE - Google LLC", unavailable=["dns"]),
               "1.1.1.1": who(unavailable=["owner", "registry"])}
    result = watch(_busy_snaps(), lookups=fake_lookups(answers, failed=1))
    assert reasons_of(result) == [
        "Couldn't look up 1 address(es) (offline or the service didn't answer).",
        "Couldn't find out everything about 2 address(es): a lookup service didn't answer.",
    ]


def test_a_bug_in_the_lookups_is_not_called_offline():
    def broken(ips, **kw):
        raise KeyError("results")

    result = watch(_busy_snaps(), lookups=broken)
    (reason,) = reasons_of(result)
    assert "problem in Reclaim City itself" in reason and "KeyError" in reason
    assert "offline" not in reason
    assert by_code(result, "watch_summary")  # the watch itself is kept


def test_skipped_and_over_budget_lookups_are_named():
    result = watch(_busy_snaps(), lookups=fake_lookups({}, skipped=4, over_budget=True))
    assert reasons_of(result) == ["Only the busiest 150 addresses were looked up.",
                                  "Looking up stopped after 60 seconds."]
    (summary,) = by_code(result, "watch_summary")
    assert all(d["who"] is None for d in summary.data["destinations"])


def test_lookups_only_public_destinations():
    calls = []
    records = [rec("App", addr, 443, 50000 + i) for i, addr in enumerate((
        "10.0.0.1", "192.168.1.1", "172.16.0.9", "100.64.0.1", "224.0.0.251", "fe80::1",
        "fd00::1", "127.0.0.1", "0.0.0.0", "240.0.0.1", "8.8.8.8", "2001:4860:4860::8888"))]
    watch([snap(records)], lookups=fake_lookups({}, calls=calls))
    assert calls == [["8.8.8.8", "2001:4860:4860::8888"]]

    calls.clear()
    result = watch([snap([rec("App", "192.168.1.1", 443, 50000)])], lookups=fake_lookups({}, calls=calls))
    assert calls == []  # nothing public: nothing to ask
    assert not by_code(result, "watch_incomplete")


def test_same_address_two_ways_is_one_lookup():
    calls = []
    records = [rec("A", "::ffff:8.8.8.8", 443, 50000), rec("B", "8.8.8.8", 443, 50001)]
    result = watch([snap(records)], lookups=fake_lookups(
        {"::ffff:8.8.8.8": who(registrant="Google LLC")}, calls=calls))
    assert calls == [["::ffff:8.8.8.8"]]
    for summary in by_code(result, "watch_summary"):
        assert summary.data["destinations"][0]["who"]["registrant"] == "Google LLC"


def test_lookup_progress_lines():
    events = []
    watch(_busy_snaps(), on_progress=events.append,
          lookups=fake_lookups({"8.8.8.8": who(registrant="Google LLC")}))
    assert events[-1] == {"phase": "lookup", "done": 1, "total": 3}
    assert all(e["phase"] == "watch" for e in events[:-1])


def test_lookups_run_after_snapshots_and_nothing_reaches_disk(tmp_path, monkeypatch):
    """The real look_up_all, with fake services, after the last snapshot; nothing written."""
    from rescue import whois

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    events = []
    collect = scripted(_busy_snaps())
    bodies = {"stat.ripe.net": (_ROOT / "tests/fixtures/whois/ripe_8.8.8.8.json").read_bytes(),
              "rdap.org": (_ROOT / "tests/fixtures/whois/rdap_8.8.8.8.json").read_bytes()}

    def logged_collect(platform):
        events.append("snapshot")
        return collect(platform)

    def fetch(url, timeout):
        events.append("fetch")
        return next(body for host, body in bodies.items() if host in url)

    def resolve(ip):
        return ("dns.google", [], [ip])

    def lookups(ips, **kw):
        events.append("lookups")
        return whois.look_up_all(ips, fetch=fetch, resolve=resolve,
                                 forward=lambda name: ["8.8.8.8"], **kw)

    result = watch(logged_collect, minutes=1, interval=20, lookups=lookups)
    assert events[:4] == ["snapshot", "snapshot", "snapshot", "lookups"]
    assert set(events[4:]) == {"fetch"}
    (summary,) = by_code(result, "watch_summary")
    assert summary.data["destinations"][0]["who"]["registrant"] == "Google LLC"
    assert list(tmp_path.rglob("*")) == []


def test_stopped_watch_still_looks_up_briefly():
    from rescue.watch import STOPPED_BUDGET

    lookups = fake_lookups({"8.8.8.8": who(registrant="Google LLC")})
    stops = iter([False, True])
    result = watch(_busy_snaps(), lookups=lookups, should_stop=lambda: next(stops, True))
    assert STOPPED_BUDGET == 10
    assert lookups.budgets == [10]
    (summary,) = by_code(result, "watch_summary")
    by_address = {d["address"]: d["who"] for d in summary.data["destinations"]}
    assert by_address["8.8.8.8"]["registrant"] == "Google LLC"
    assert "Looking up stopped early." not in reasons_of(result)

    # A watch that ran its full time gets the full budget.
    lookups = fake_lookups({})
    watch(_busy_snaps(), lookups=lookups)
    assert lookups.budgets == [60]


def test_stopped_watch_lookups_end_only_on_a_new_stop():
    requests = {"n": 1}
    seen = []

    def lookups(ips, *, should_stop, on_progress, budget):
        seen.append(should_stop())  # the first stop doesn't end the lookups
        requests["n"] += 1          # ... a second one does
        seen.append(should_stop())
        return {"results": {}, "skipped": 0, "failed": 0, "over_budget": False, "stopped": True}

    fake = FakeTime()
    stops = iter([False, True])
    result = run_watch("darwin", 1, 5, collect=scripted(_busy_snaps()), dns=no_dns,
                       clock=fake.clock, sleep=fake.sleep, should_stop=lambda: next(stops, True),
                       verdict=lambda p, r: "expected", lookups=lookups,
                       stop_requests=lambda: requests["n"])
    assert seen == [False, True]
    assert "Looking up stopped early." in reasons_of(result)

    # Without a count of requests, only the shorter budget bounds it.
    budgets = []

    def plain(ips, *, should_stop, on_progress, budget):
        budgets.append((should_stop(), budget))
        return nobody_known(ips)

    stops = iter([False, True])
    watch(_busy_snaps(), lookups=plain, should_stop=lambda: next(stops, True))
    assert budgets == [(False, 10)]


def test_stopped_budget_running_out_is_named():
    stops = iter([False, True])
    result = watch(_busy_snaps(), lookups=fake_lookups({}, over_budget=True),
                   should_stop=lambda: next(stops, True))
    assert "Looking up stopped after 10 seconds." in reasons_of(result)


def test_holder_handles_are_dropped():
    from rescue.watch import _holder_company

    cases = {
        "GOOGLE - Google LLC": "Google LLC",
        "AKAMAI-ASN1 Akamai International B.V.": "Akamai International B.V.",
        "HETZNER-CLOUD3-AS Hetzner Online GmbH": "Hetzner Online GmbH",
        "AS13335 Cloudflare": "Cloudflare",
        "CLOUDFLARENET": "CLOUDFLARENET",          # nothing follows: kept
        "AKAMAI-ASN1": "AKAMAI-ASN1",
        "IBM Corporation": "IBM Corporation",      # no digit or hyphen: a word, kept
        "Fastly, Inc.": "Fastly, Inc.",
        "Akamai-Tech International": "Akamai-Tech International",  # not all capitals
        None: None,
    }
    for name, company in cases.items():
        assert _holder_company(name) == company, name
    snaps = [snap([rec("App", "23.1.1.1", 443, 50000)])]
    result = watch(snaps, lookups=fake_lookups(
        {"23.1.1.1": who(as_name="AKAMAI-ASN1 Akamai International B.V.")}))
    (summary,) = by_code(result, "watch_summary")
    assert "Mostly Akamai International B.V. This" in summary.description


def test_stop_during_lookups_returns_promptly():
    """A stop while the services hang: the watch returns with what it gathered."""
    import threading
    import time as real_time

    from rescue import whois

    stop = threading.Event()
    started = threading.Event()
    release = threading.Event()

    def hanging_fetch(url, timeout):
        started.set()
        release.wait(5)  # a service that doesn't answer until the test ends
        return b""

    def no_name(ip):
        raise OSError("no reverse name")

    def lookups(ips, **kw):
        return whois.look_up_all(ips, fetch=hanging_fetch, resolve=no_name,
                                 forward=lambda name: [], **kw)

    threading.Thread(target=lambda: started.wait(5) and stop.set(), daemon=True).start()
    begun = real_time.monotonic()
    try:
        result = watch(_busy_snaps(), lookups=lookups, should_stop=stop.is_set)
        assert real_time.monotonic() - begun < 2
    finally:
        release.set()
    assert reasons_of(result) == ["Looking up stopped early."]
    (summary,) = by_code(result, "watch_summary")
    assert all(d["who"] is None for d in summary.data["destinations"])
