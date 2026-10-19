"""Connection watch: repeated connection snapshots, summarised per app.

A module's ``check()`` has to stay cheap, so watching connections for minutes
at a time lives here instead, behind its own command. ``run_watch`` takes a
snapshot every ``interval`` seconds for ``minutes`` minutes, then turns what it
saw into info findings: one summary per program, plus notes about steady
check-ins, ports that started listening, heavy uploads and looked-up names.

Everything it needs from the outside world (the collector, the DNS reader, the
clock, sleeping and the stop signal) is passed in, so tests drive it with
scripted snapshots and a fake clock. Nothing here changes the computer.
"""

from __future__ import annotations

import ipaddress
import statistics
import time
from collections.abc import Callable

from rescue.models import CheckResult, Finding, Platform, Severity

WATCH_CODES: list[str] = [
    "network.connection_watch.watch_summary",
    "network.connection_watch.regular_checkins",
    "network.connection_watch.new_listener",
    "network.connection_watch.upload_heavy",
    "network.connection_watch.dns_lookups",
    "network.connection_watch.dns_not_visible",
    "network.connection_watch.watch_incomplete",
]

MAX_PAIRS = 2000
MAX_STAMPS = 200
MIN_MINUTES, MAX_MINUTES = 1, 30
MIN_INTERVAL, MAX_INTERVAL = 2, 60

_MODULE = "connection_watch"
_CATEGORY = "network"
_LISTED_DESTINATIONS = 50
_CHECKIN_MIN = 4
_CHECKIN_JITTER = 0.2
_UPLOAD_BYTES = 10_000_000
_UPLOAD_RATIO = 3
_UNKNOWN = "unknown"
_UNSTORED_LIMIT = 10 * MAX_PAIRS

# Shared address space used by carrier-grade NAT; not a destination on the internet.
_CGNAT = ipaddress.ip_network("100.64.0.0/10")

# The well-known NAT64 prefix only. In the local-use 64:ff9b:1::/48 the
# prefix length (and so where the IPv4 address sits) varies (RFC 6052 / 8215),
# so those addresses are left as they are and count as public: fail closed.
_NAT64_WKP = ipaddress.ip_network("64:ff9b::/96")

_PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",  # RFC 1918
        "127.0.0.0/8", "::1/128",                          # loopback
        "169.254.0.0/16", "fe80::/10",                     # link-local
        "fc00::/7",                                        # unique local (ULA)
    )
)


class WatchModule:
    """Stand-in for a module so ``checks_to_json`` can serialise the watch."""

    name = _MODULE
    category = _CATEGORY
    emits_codes = WATCH_CODES
    platforms = [Platform.DARWIN, Platform.LINUX, Platform.WIN32]


# --- addresses -------------------------------------------------------------


def _ip(addr: str | None):
    """The address, with an IPv4 address carried inside IPv6 unwrapped."""
    try:
        ip = ipaddress.ip_address((addr or "").split("%")[0])
    except ValueError:
        return None
    if ip.version == 6:
        if ip.ipv4_mapped is not None:
            return ip.ipv4_mapped
        if ip in _NAT64_WKP:
            # The well-known NAT64 prefix carries the IPv4 address in the last
            # 32 bits, so classify by that address.
            return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return ip


def _is_loopback(addr: str | None) -> bool:
    ip = _ip(addr)
    return ip is not None and ip.is_loopback


def _is_public(addr: str | None) -> bool:
    """True only for an address that is clearly not on this computer or network."""
    ip = _ip(addr)
    if ip is None or ip.is_multicast or ip.is_unspecified:
        return False
    # IPv4 "reserved" is 240.0.0.0/4 and broadcast. IPv6's is_reserved covers
    # whole unassigned ranges, which says nothing about where a connection goes.
    if ip.version == 4 and (ip.is_reserved or ip in _CGNAT):
        return False
    return not any(ip in net for net in _PRIVATE_NETWORKS if net.version == ip.version)


# --- gathering -------------------------------------------------------------


class _Gathered:
    """Everything kept between snapshots, bounded by MAX_PAIRS and MAX_STAMPS."""

    def __init__(self):
        self.snapshots = 0
        self.attempts = 0
        self.errors: list[str] = []
        self.limits: list[str] = []
        # (process, remote_addr, remote_port, proto) -> pair stats
        self.pairs: dict[tuple, dict] = {}
        self.pairs_capped = False
        self.stamps_capped = False
        # Distinct pairs past the cap, remembered only to count them, and
        # only up to _UNSTORED_LIMIT so memory stays bounded.
        self.unstored: set[tuple] = set()
        self.unstored_capped = False
        self.loopback: dict[str, int] = {}
        self.previous_open: set[tuple] | None = None
        # Listeners are keyed (proto, local_addr, local_port). Several programs
        # can hold one port at once (an inherited socket, SO_REUSEPORT), and
        # Linux without admin shows the owner only some of the time, so each
        # key keeps the SET of names seen in earlier snapshots. A missing name
        # never counts as a different owner.
        self.listener_snapshots = 0
        self.owners_seen: dict[tuple, set[str]] = {}
        self.last_owners: dict[tuple, set[str]] = {}
        # Each listener that opened during the watch: {"key", "owner", "record"},
        # at most one per (key, owner) for the whole watch.
        self.new_listeners: list[dict] = []
        self._unnamed_new: dict[tuple, dict] = {}
        # Byte counters: key (pid or 4-tuple) -> {"process", "first", "last"}
        self.counters: dict = {}
        self.bytes_seen = False
        self.first_byte_keys: set | None = None
        self.processes: set[str] = set()
        # DNS (Windows): (name, type) -> {"first_seen_snapshot", "snapshots"}
        self.names: dict[tuple, dict] = {}
        self.names_capped = False
        self.dns_read = False
        self.dns_reasons: list[str] = []
        self.dns_errors: list[str] = []

    def add_limit(self, text: str) -> None:
        if text and text not in self.limits:
            self.limits.append(text)

    def add_snapshot(self, snap: dict, at: float) -> None:
        self.snapshots += 1
        for text in snap.get("limits") or []:
            self.add_limit(text)
        records = snap.get("records") or []
        self._add_connections(records, at)
        self._add_listeners(records)
        self._add_bytes(snap.get("bytes"), records)

    def _add_connections(self, records: list[dict], at: float) -> None:
        open_now: set[tuple] = set()
        stamped: set[tuple] = set()
        for record in records:
            remote = record.get("remote_addr")
            if record.get("state") == "LISTEN" or remote is None:
                continue
            process = record.get("process") or _UNKNOWN
            self.processes.add(process)
            if _is_loopback(remote):
                self.loopback[process] = self.loopback.get(process, 0) + 1
                continue
            key = (process, remote, record.get("remote_port"), record.get("proto"))
            open_now.add(key + (record.get("local_port"),))
            pair = self.pairs.get(key)
            if pair is None:
                if len(self.pairs) >= MAX_PAIRS:
                    self.pairs_capped = True
                    if key not in self.unstored:
                        if len(self.unstored) < _UNSTORED_LIMIT:
                            self.unstored.add(key)
                        else:
                            self.unstored_capped = True
                    continue
                pair = self.pairs[key] = {
                    "snapshots": 0, "first_seen": at, "last_seen": at,
                    "new_connections": 0, "stamps": [], "_last_snapshot": None,
                }
            if pair["_last_snapshot"] != self.snapshots:
                pair["_last_snapshot"] = self.snapshots
                pair["snapshots"] += 1
                pair["last_seen"] = at
            # The first snapshot is the baseline: those connections were
            # already open, and when they opened isn't known.
            is_new = (
                self.previous_open is not None
                and key + (record.get("local_port"),) not in self.previous_open
            )
            if is_new:
                pair["new_connections"] += 1
                # One time stamp per snapshot, however many connections opened.
                if key not in stamped:
                    stamped.add(key)
                    if len(pair["stamps"]) < MAX_STAMPS:
                        pair["stamps"].append(at)
                    else:
                        self.stamps_capped = True
        self.previous_open = open_now

    def _add_listeners(self, records: list[dict]) -> None:
        # Gather the whole snapshot first, so names in one snapshot are never
        # compared with each other: name -> a record for it, per key.
        now: dict[tuple, dict[str | None, dict]] = {}
        for record in records:
            if record.get("state") != "LISTEN":
                continue
            key = (record.get("proto"), record.get("local_addr"), record.get("local_port"))
            now.setdefault(key, {}).setdefault(record.get("process") or None, record)
        baseline = self.listener_snapshots == 0
        self.listener_snapshots += 1
        for key, by_name in now.items():
            names = {n for n in by_name if n}
            seen = self.owners_seen.get(key)
            if not baseline:
                self._note_new_owners(key, by_name, names, seen)
            self.owners_seen[key] = (seen or set()) | names
        self.last_owners = {key: {n for n in by_name if n} for key, by_name in now.items()}

    def _note_new_owners(self, key, by_name, names, seen) -> None:
        if seen is None and not names:
            # A port nobody had open before, owner not shown: new, owner unknown.
            entry = self._add_new_listener(key, _UNKNOWN, by_name[None])
            self._unnamed_new[key] = entry
            return
        for name in sorted(names - (seen or set())):
            pending = self._unnamed_new.pop(key, None)
            if pending is not None:
                # The owner of a port that opened unnamed is now shown: same listener.
                pending["owner"] = name
            elif seen is None or seen:
                # A port that's new, or a named program not seen on it before.
                self._add_new_listener(key, name, by_name[name])
            # else: the port was there from earlier with its owner hidden; a
            # name showing up now isn't a new listener.

    def _add_new_listener(self, key: tuple, owner: str, record: dict) -> dict:
        entry = {"key": key, "owner": owner, "record": record}
        self.new_listeners.append(entry)
        return entry

    def listeners_by_owner(self) -> tuple[dict[str, list], dict[str, list]]:
        """Ports opened during the watch, and ports closed by its end, per program."""
        opened: dict[str, list] = {}
        closed: dict[str, list] = {}
        for entry in self.new_listeners:
            opened.setdefault(entry["owner"], []).append(entry["key"][2])
        for key, seen in self.owners_seen.items():
            if key not in self.last_owners:
                gone = seen or {_UNKNOWN}
            elif self.last_owners[key]:
                # Still open, under names that leave some earlier owners out.
                gone = seen - self.last_owners[key]
            else:
                # Still open with its owner hidden: no claim about who left.
                gone = set()
            for owner in sorted(gone):
                closed.setdefault(owner, []).append(key[2])
        return opened, closed

    def _add_bytes(self, counts, records: list[dict]) -> None:
        if self.first_byte_keys is None:
            # Only the first snapshot's reading is the baseline. If it had no
            # reading, nothing seen later was known to be open at the start, so
            # every Linux connection starts from 0 (its counters begin at 0
            # when it opens). macOS pids still keep their first reading below,
            # because nettop counts per program since the program started.
            self.first_byte_keys = set(counts or ())
        if counts is None:
            return
        self.bytes_seen = True
        by_pid = {r["pid"]: r.get("process") for r in records if r.get("pid") is not None}
        by_tuple = {
            (r.get("local_addr"), r.get("local_port"), r.get("remote_addr"), r.get("remote_port")):
                r.get("process")
            for r in records
        }
        for key, value in counts.items():
            process = by_tuple.get(key) if isinstance(key, tuple) else by_pid.get(key)
            entry = self.counters.get(key)
            if entry is None:
                if not process:
                    continue
                # Linux counts per connection from zero, so a connection that
                # opened during the watch starts from 0. macOS counts per
                # program since it started, so its first reading is the baseline.
                late_connection = isinstance(key, tuple) and key not in self.first_byte_keys
                first = (0, 0) if late_connection else value
                self.counters[key] = {"process": process, "first": first, "last": value}
            else:
                entry["last"] = value

    def add_dns(self, result: dict) -> None:
        names = result.get("names")
        if names is None:
            reason = result.get("reason")
            if reason and reason not in self.dns_reasons:
                self.dns_reasons.append(reason)
            return
        self.dns_read = True
        seen_now: set[tuple] = set()
        for item in names:
            key = (item.get("name"), item.get("type"))
            if key in seen_now:
                continue
            seen_now.add(key)
            entry = self.names.get(key)
            if entry is None:
                if len(self.names) >= MAX_PAIRS:
                    self.names_capped = True
                    continue
                entry = self.names[key] = {"first_seen_snapshot": self.snapshots, "snapshots": 0}
            entry["snapshots"] += 1

    def process_bytes(self) -> dict[str, tuple[int, int]]:
        totals: dict[str, tuple[int, int]] = {}
        for entry in self.counters.values():
            got_in = entry["last"][0] - entry["first"][0]
            got_out = entry["last"][1] - entry["first"][1]
            before = totals.get(entry["process"], (0, 0))
            totals[entry["process"]] = (before[0] + max(got_in, 0), before[1] + max(got_out, 0))
        return totals


# --- the watch -------------------------------------------------------------


def _collector():
    from rescue.runtime import load_content_module

    return load_content_module(
        "modules/network/conn_common/collect.py", "rescue_conn_common_collect"
    )


def _dns_unavailable(platform: str) -> dict:
    return {
        "names": None,
        "reason": "Couldn't load the part of Device Rescue that reads looked-up names.",
    }


def _default_verdict() -> Callable | None:
    from rescue.cli import _get_modules_dir
    from rescue.registry import discover_modules

    for module in discover_modules(_get_modules_dir()):
        if module.name == "suspicious_connections":
            return module.listening_verdict
    return None


def _read_dns(dns, platform: str, gathered: "_Gathered") -> None:
    try:
        result = dns(platform)
    except Exception as exc:  # a reader bug must not lose what was gathered
        reason = f"Couldn't read the list of looked-up names: {exc}"
        gathered.dns_errors.append(reason)
        result = {"names": None, "reason": reason}
    gathered.add_dns(result)


def _sleeper(clock: Callable[[], float], should_stop: Callable[[], bool]):
    def sleep(seconds: float) -> None:
        end = clock() + seconds
        while not should_stop():
            left = end - clock()
            if left <= 0:
                return
            time.sleep(min(left, 0.25))

    return sleep


def run_watch(
    platform: str,
    minutes: int,
    interval: int,
    *,
    collect: Callable[[str], dict] | None = None,
    dns: Callable[[str], dict] | None = None,
    clock: Callable[[], float] | None = None,
    sleep: Callable[[float], None] | None = None,
    should_stop: Callable[[], bool] | None = None,
    on_progress: Callable[[dict], None] | None = None,
    verdict: Callable[[str, dict], str] | None = None,
) -> CheckResult:
    """Watch this computer's connections and summarise them per program.

    ``sleep(seconds)`` waits up to ``seconds`` but returns early once
    ``should_stop()`` is true. ``on_progress`` gets one dict per snapshot:
    ``{"phase": "watch", "elapsed", "total", "snapshots"}``. Raises
    ValueError for minutes outside 1-30 or an interval outside 2-60 seconds.
    """
    if not MIN_MINUTES <= minutes <= MAX_MINUTES:
        raise ValueError(f"minutes must be {MIN_MINUTES}-{MAX_MINUTES}")
    if not MIN_INTERVAL <= interval <= MAX_INTERVAL:
        raise ValueError(f"interval must be {MIN_INTERVAL}-{MAX_INTERVAL} seconds")

    if collect is None or dns is None:
        helper = _collector()
        if collect is None:
            if helper is None:
                return CheckResult(
                    module_name=_MODULE,
                    error="Couldn't load the part of Device Rescue that reads connections.",
                )
            collect = helper.snapshot
        if dns is None:
            dns = helper.dns_cache if helper is not None else _dns_unavailable
    clock = clock or time.monotonic
    should_stop = should_stop or (lambda: False)
    sleep = sleep or _sleeper(clock, should_stop)

    total = minutes * 60
    gathered = _Gathered()
    stopped_early = False
    start = clock()
    while True:
        if should_stop():
            stopped_early = True
            break
        at = clock() - start
        gathered.attempts += 1
        try:
            snap = collect(platform)
        except Exception as exc:  # a collector bug must not lose what was gathered
            snap = {"records": [], "error": f"Reading connections failed: {exc}"}
        if snap.get("error"):
            if snap["error"] not in gathered.errors:
                gathered.errors.append(snap["error"])
        else:
            gathered.add_snapshot(snap, at)
            if platform == "win32":
                _read_dns(dns, platform, gathered)
        if on_progress is not None:
            try:
                on_progress({
                    "phase": "watch", "elapsed": int(at), "total": total,
                    "snapshots": gathered.snapshots,
                })
            except Exception:  # nosec - progress is a courtesy; the watch goes on
                pass
        next_at = gathered.attempts * interval
        if next_at >= total:
            break
        wait = start + next_at - clock()
        if wait > 0:
            sleep(wait)

    if platform != "win32":
        _read_dns(dns, platform, gathered)
    elapsed = clock() - start
    findings = _findings(platform, gathered, minutes, stopped_early, elapsed, verdict)
    return CheckResult(module_name=_MODULE, findings=findings)


# --- findings --------------------------------------------------------------


def _mb(count: int) -> str:
    return f"{count / 1_000_000:.1f} MB"


def _plural(n: int, word: str) -> str:
    return f"{n:,} {word}" if n == 1 else f"{n:,} {word}s"


def _label(process: str) -> str:
    return "A program Device Rescue couldn't name" if process == _UNKNOWN else process


def _checkin(pair: dict) -> float | None:
    """The median gap when new connections came at a steady pace, else None."""
    stamps = pair["stamps"]
    if len(stamps) < _CHECKIN_MIN:
        return None
    gaps = [b - a for a, b in zip(stamps, stamps[1:])]
    median = statistics.median(gaps)
    if median <= 0:
        return None
    if max(abs(gap - median) for gap in gaps) / median >= _CHECKIN_JITTER:
        return None
    return median


def _median_gap(pair: dict) -> float | None:
    stamps = pair["stamps"]
    if len(stamps) < 2:
        return None
    return statistics.median(b - a for a, b in zip(stamps, stamps[1:]))


def _findings(platform, gathered, minutes, stopped_early, elapsed, verdict) -> list[Finding]:
    facts = {
        "minutes": minutes,
        "snapshots": gathered.snapshots,
        "stopped_early": stopped_early,
        "elapsed": int(elapsed),
    }
    findings: list[Finding] = []
    reasons: list[str] = []

    if gathered.snapshots:
        findings.extend(_summaries(platform, gathered, facts, reasons))
        findings.extend(_checkins(gathered, facts))
        findings.extend(_listeners(platform, gathered, facts, verdict, reasons))
        findings.extend(_uploads(gathered, facts))
        if platform == "win32" and gathered.dns_read:
            findings.append(_dns_lookups(gathered, facts))
    if platform != "win32" or (gathered.snapshots and not gathered.dns_read):
        findings.append(_dns_not_visible(gathered, facts))
    elif gathered.dns_reasons:
        reasons.extend(gathered.dns_reasons)
    reasons.extend(e for e in gathered.dns_errors if e not in reasons)

    reasons[:0] = list(gathered.limits)
    if stopped_early:
        reasons.append(
            f"The watch was stopped early, after {elapsed / 60:.1f} of {minutes} minute(s)."
        )
    failed = gathered.attempts - gathered.snapshots
    if failed:
        reasons.append(
            f"{_plural(failed, 'snapshot')} of {gathered.attempts:,} couldn't be read: "
            + " ".join(gathered.errors)
        )
    if gathered.pairs_capped:
        more = f"{len(gathered.unstored):,}" + (" or more" if gathered.unstored_capped else "")
        reasons.append(
            f"More than {MAX_PAIRS:,} different program-and-destination pairs turned up, "
            f"so {more} more were counted but not listed."
        )
    if gathered.stamps_capped:
        reasons.append(
            f"Some connections opened more than {MAX_STAMPS} times; the timing of the later "
            "ones was counted but not kept."
        )
    if gathered.names_capped:
        reasons.append(
            f"More than {MAX_PAIRS:,} looked-up names turned up, so the rest weren't listed."
        )
    if reasons or not gathered.snapshots:
        findings.append(_incomplete(gathered, facts, reasons))
    return findings


def _summaries(platform, gathered, facts, reasons) -> list[Finding]:
    opened_by, closed_by = gathered.listeners_by_owner()
    per_process: dict[str, list] = {
        p: [] for p in gathered.processes | set(opened_by) | set(closed_by)
    }
    for key, pair in gathered.pairs.items():
        per_process[key[0]].append((key, pair))
    unstored_by: dict[str, int] = {}
    for key in gathered.unstored:
        unstored_by[key[0]] = unstored_by.get(key[0], 0) + 1
    byte_totals = gathered.process_bytes() if gathered.bytes_seen else {}
    no_bytes = []
    findings = []
    for process in sorted(per_process):
        pairs = sorted(
            per_process[process],
            key=lambda kp: (-kp[1]["snapshots"], str(kp[0][1]), kp[0][2] or 0, kp[0][3] or ""),
        )
        destinations = [
            {
                "address": key[1], "port": key[2], "protocol": key[3],
                "snapshots": pair["snapshots"],
                "first_seen": int(pair["first_seen"]), "last_seen": int(pair["last_seen"]),
                "new_connections": pair["new_connections"],
                "median_gap": _median_gap(pair),
                "regular": _checkin(pair) is not None,
            }
            for key, pair in pairs[:_LISTED_DESTINATIONS]
        ]
        opened = sorted(port for port in opened_by.get(process, []) if port is not None)
        closed = sorted(port for port in closed_by.get(process, []) if port is not None)
        loopback = gathered.loopback.get(process, 0)
        unstored = unstored_by.get(process, 0)
        sent = byte_totals.get(process)
        if sent is None:
            no_bytes.append(process)

        parts = [
            f"During the watch, {_label(process)} connected to "
            f"{_plural(len(pairs), 'place')} on the internet or your network"
        ]
        if unstored:
            parts.append(
                f" (plus {unstored:,} more that turned up after the watch's list was full)"
            )
        if loopback:
            parts.append(
                f", and made {_plural(loopback, 'connection')} to this computer itself "
                "(counted, not listed)"
            )
        text = "".join(parts) + "."
        if sent is not None:
            text += f" It received {_mb(sent[0])} and sent {_mb(sent[1])}."
        if opened:
            text += f" It started listening on port(s) {', '.join(map(str, opened))}."
        text += (
            " This is a record of what the program did, not a warning: most of it is "
            "ordinary app traffic."
        )
        findings.append(Finding(
            code="network.connection_watch.watch_summary",
            title=f"{_label(process)}: {_plural(len(pairs), 'destination')} during the watch",
            description=text,
            severity=Severity.INFO,
            category=_CATEGORY,
            data={
                "target": process,
                "destinations": destinations,
                "more": max(len(pairs) - _LISTED_DESTINATIONS, 0),
                "not_stored": unstored,
                "loopback_count": loopback,
                "bytes_in": sent[0] if sent is not None else None,
                "bytes_out": sent[1] if sent is not None else None,
                "listeners_opened": opened,
                "listeners_closed": closed,
                **facts,
            },
        ))
    if gathered.bytes_seen and no_bytes:
        reasons.append(
            "Couldn't tell how much data these programs sent or received: "
            + ", ".join(_label(p) for p in no_bytes) + "."
        )
    return findings


def _checkins(gathered, facts) -> list[Finding]:
    findings = []
    for key, pair in sorted(gathered.pairs.items(), key=lambda kp: str(kp[0])):
        process, address, port, proto = key
        if not _is_public(address):
            continue
        gap = _checkin(pair)
        if gap is None:
            continue
        findings.append(Finding(
            code="network.connection_watch.regular_checkins",
            title=f"{_label(process)} checked in with {address} about every {gap:g} seconds",
            description=(
                f"{_label(process)} opened a new connection to {address} (port {port}) "
                f"{_plural(pair['new_connections'], 'time')} during the watch, about every "
                f"{gap:g} seconds. That's a pattern worth knowing about: most apps do this "
                "to check for updates or messages. On its own it isn't a sign of a problem."
            ),
            severity=Severity.INFO,
            category=_CATEGORY,
            confidence=0.5,
            data={
                "target": process,
                "address": address,
                "port": port,
                "protocol": proto,
                "new_connections": pair["new_connections"],
                "median_gap": gap,
                **facts,
            },
        ))
    return findings


_NEXT_CHECKUP = {
    "expected": "It looks like an ordinary service, and the next checkup wouldn't raise it.",
    "unnamed": (
        "Device Rescue couldn't confirm which program owns it, so the next checkup "
        "would mention it without a warning."
    ),
    "flag": (
        "The next full checkup would point it out, so you can decide whether you "
        "expected it."
    ),
}


def _listeners(platform, gathered, facts, verdict, reasons) -> list[Finding]:
    if not gathered.new_listeners:
        return []
    problems: list[str] = []
    if verdict is None:
        try:
            verdict = _default_verdict()
        except Exception as exc:
            problems.append(str(exc) or type(exc).__name__)
        else:
            if verdict is None:
                problems.append("the listening-port check wasn't found")
    findings = []
    for entry in sorted(gathered.new_listeners, key=lambda e: (str(e["key"]), e["owner"])):
        proto, addr, port = entry["key"]
        process = entry["owner"]
        record = entry["record"]
        next_checkup = None
        if verdict is not None:
            try:
                next_checkup = verdict(platform, record)
            except Exception as exc:
                text = str(exc) or type(exc).__name__
                if text not in problems:
                    problems.append(text)
        findings.append(Finding(
            code="network.connection_watch.new_listener",
            title=f"{_label(process)} started listening on port {port} during the watch",
            description=(
                f"{_label(process)} began waiting for connections on port {port} "
                "while the watch was running. Apps do this for things like sharing, "
                "syncing and developer tools. "
                + _NEXT_CHECKUP.get(next_checkup, "")
            ).strip(),
            severity=Severity.INFO,
            category=_CATEGORY,
            data={
                "target": process,
                "port": port,
                "address": addr,
                "protocol": proto,
                "next_checkup": next_checkup,
                **facts,
            },
        ))
    if problems:
        reasons.append(
            "Couldn't judge whether the new listening port(s) would be pointed out by the "
            "next checkup (" + "; ".join(problems) + ")."
        )
    return findings


def _uploads(gathered, facts) -> list[Finding]:
    if not gathered.bytes_seen:
        return []
    findings = []
    for process, (got, sent) in sorted(gathered.process_bytes().items()):
        if sent <= _UPLOAD_BYTES or sent <= _UPLOAD_RATIO * got:
            continue
        findings.append(Finding(
            code="network.connection_watch.upload_heavy",
            title=f"{_label(process)} sent much more than it received",
            description=(
                f"During the watch, {_label(process)} sent {_mb(sent)} and received "
                f"{_mb(got)}. Sending far more than receiving is normal for backups, "
                "cloud sync and video calls. If you don't recognise the program, it's "
                "worth finding out what it is."
            ),
            severity=Severity.INFO,
            category=_CATEGORY,
            data={"target": process, "bytes_in": got, "bytes_out": sent, **facts},
        ))
    return findings


def _dns_lookups(gathered, facts) -> Finding:
    names = [
        {"name": name, "type": kind, **entry}
        for (name, kind), entry in sorted(
            gathered.names.items(),
            key=lambda kv: (kv[1]["first_seen_snapshot"], str(kv[0])),
        )
    ]
    return Finding(
        code="network.connection_watch.dns_lookups",
        title=f"{_plural(len(names), 'name')} looked up during the watch",
        description=(
            f"Your computer looked up {_plural(len(names), 'name')} (like website "
            "addresses) during the watch. Windows doesn't record which program asked for "
            "each name, so they can't be tied to a particular app; lining up when each "
            "name first appeared with the connection list is the closest you can get."
        ),
        severity=Severity.INFO,
        category=_CATEGORY,
        data={"names": names, **facts},
    )


def _dns_not_visible(gathered, facts) -> Finding:
    reason = " ".join(gathered.dns_reasons) or "The list of looked-up names couldn't be read."
    return Finding(
        code="network.connection_watch.dns_not_visible",
        title="Couldn't see which names were looked up",
        description=(
            f"{reason} A DNS filter that keeps a log can show them; that's part of a "
            "later level of the checkup."
        ),
        severity=Severity.INFO,
        category=_CATEGORY,
        data={"reason": reason, **facts},
    )


def _incomplete(gathered, facts, reasons) -> Finding:
    if gathered.snapshots:
        title = "Parts of the connection watch couldn't be seen"
        description = (
            "The watch ran, but some things were out of view, so it shows less than "
            "everything that happened: " + " ".join(reasons)
        )
    else:
        title = "The connection watch gathered nothing"
        description = (
            "Nothing was gathered, so this says nothing about your connections either "
            "way."
        )
        if reasons:
            description += " " + " ".join(reasons)
    return Finding(
        code="network.connection_watch.watch_incomplete",
        title=title,
        description=description,
        severity=Severity.INFO,
        category=_CATEGORY,
        data={"reasons": reasons, **facts},
    )
