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

import re
import statistics
import time
from collections.abc import Callable

from rescue.models import CheckResult, Finding, Platform, Severity
from rescue.netaddr import address_key, is_loopback, is_public
from rescue.whois import BUDGET, MAX_ADDRESSES, SOURCES, is_lookupable

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
# A watch stopped early still looks up what it gathered, but briefly: whoever
# stopped it is waiting (the desktop app waits 15 seconds before giving up).
# The time counts from when the stop is seen, and with less than
# STOPPED_MIN_LOOKUP left the lookups are skipped.
STOPPED_BUDGET = 10.0
STOPPED_MIN_LOOKUP = 2.0


class WatchModule:
    """Stand-in for a module so ``checks_to_json`` can serialise the watch."""

    name = _MODULE
    category = _CATEGORY
    emits_codes = WATCH_CODES
    platforms = [Platform.DARWIN, Platform.LINUX, Platform.WIN32]


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
            if is_loopback(remote):
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
        "reason": "Couldn't load the part of Reclaim City that reads looked-up names.",
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
    lookups: Callable[[list[str]], dict] | None = None,
    stop_requests: Callable[[], int] | None = None,
) -> CheckResult:
    """Watch this computer's connections and summarise them per program.

    ``sleep(seconds)`` waits up to ``seconds`` but returns early once
    ``should_stop()`` is true. ``on_progress`` gets one dict per snapshot:
    ``{"phase": "watch", "elapsed", "total", "snapshots"}``, then
    ``{"phase": "lookup", "done", "total"}`` as addresses are looked up.
    ``lookups(addresses, should_stop=, on_progress=, budget=)`` is called once
    after the last snapshot with the public destinations it may ask about
    (``rescue.whois.is_lookupable``), busiest first, and
    answers like ``rescue.whois.look_up_all``; None turns lookups off.

    A stop during the lookups ends them. A watch stopped while watching still
    looks up what it gathered, but for at most ``STOPPED_BUDGET`` seconds counted
    from when the stop is seen (skipping the lookups if under
    ``STOPPED_MIN_LOOKUP`` remain), and only a further stop request ends that:
    ``stop_requests()`` counts the stop requests so far (without it, only the shorter budget applies). Raises
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
                    error="Couldn't load the part of Reclaim City that reads connections.",
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
    stops_seen = 0
    stopped_at = None
    start = clock()
    while True:
        if should_stop():
            stopped_early = True
            if stopped_at is None:
                stopped_at = clock()
            # The request that stopped the watch is the first; any later one,
            # even one sent straight after it, ends the lookups below.
            stops_seen = min(stop_requests(), 1) if stop_requests is not None else 0
            break
        at = clock() - start
        gathered.attempts += 1
        try:
            snap = collect(platform)
        except Exception as exc:  # a collector bug must not lose what was gathered
            snap = {"records": [], "error": f"Reading connections failed: {exc}"}
        if stopped_at is None and should_stop():
            stopped_at = clock()  # a stop during a slow snapshot starts its time here
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
        # The watch ends at its deadline by the clock: a slow snapshot must
        # not stretch it. A snapshot may start before the deadline, none after.
        next_at = gathered.attempts * interval
        if next_at >= total or clock() - start >= total:
            break
        wait = start + next_at - clock()
        if wait > 0 and stopped_at is None:  # once stopped, no waiting for the next look
            sleep(wait)

    if platform != "win32":
        _read_dns(dns, platform, gathered)
    elapsed = clock() - start
    if not stopped_early:
        lookup_stop, budget = should_stop, BUDGET
    elif stop_requests is not None:
        lookup_stop, budget = (lambda: stop_requests() > stops_seen), STOPPED_BUDGET
    else:
        lookup_stop, budget = (lambda: False), STOPPED_BUDGET
    if stopped_early:
        budget -= clock() - stopped_at  # the time since the stop was seen is spent
    owners = _look_up(gathered, lookups, lookup_stop, on_progress, budget,
                      skip=stopped_early and budget < STOPPED_MIN_LOOKUP)
    findings = _findings(platform, gathered, minutes, stopped_early, elapsed, verdict, owners)
    return CheckResult(module_name=_MODULE, findings=findings)


# --- who runs each address -------------------------------------------------


class _Owners:
    """What the lookups found, keyed by address (an IPv4 address carried in
    IPv6 and the plain one are the same key), and what they couldn't do."""

    def __init__(self, on: bool):
        self.on = on
        self.who: dict[str, dict] = {}
        self.reasons: list[str] = []

    def for_address(self, address) -> dict | None:
        return self.who.get(address_key(address))


def _lookupable_by_busyness(gathered: "_Gathered") -> list[str]:
    """Each destination that may be looked up once, the ones seen in the most
    snapshots first."""
    seen: dict[str, int] = {}
    first_form: dict[str, str] = {}
    for (_, address, _, _), pair in gathered.pairs.items():
        if not is_lookupable(address):
            continue
        key = address_key(address)
        first_form.setdefault(key, address)
        seen[key] = seen.get(key, 0) + pair["snapshots"]
    order = sorted(seen, key=lambda key: -seen[key])  # ties keep first-seen order
    return [first_form[key] for key in order]


def _look_up(gathered: "_Gathered", lookups, should_stop, on_progress, budget,
             skip: bool = False) -> _Owners:
    owners = _Owners(on=lookups is not None)
    addresses = _lookupable_by_busyness(gathered)
    if not addresses:
        return owners
    if lookups is None:
        owners.reasons.append("Looking up who runs each address was turned off.")
        return owners
    if skip:
        owners.reasons.append("Looking up was skipped: the watch was stopped.")
        return owners
    def progress(done: int, total: int) -> None:
        if on_progress is not None:
            try:
                on_progress({"phase": "lookup", "done": done, "total": total})
            except Exception:  # nosec - progress is a courtesy; the lookups go on
                pass

    try:
        answer = lookups(addresses, should_stop=should_stop, on_progress=progress, budget=budget)
    except (OSError, ValueError):  # offline, refused, a service's bad answer
        owners.reasons.append(
            f"Couldn't look up {len(addresses):,} address(es) (offline or the service didn't answer)."
        )
        return owners
    except Exception as exc:  # a bug in Reclaim City, not the network: say so plainly
        owners.reasons.append(
            "Looking up who runs each address failed because of a problem in Reclaim City "
            f"itself ({type(exc).__name__}: {exc})."
        )
        return owners
    results = answer.get("results") or {}
    for address, found in results.items():
        owners.who[address_key(address)] = found
    failed = answer.get("failed", 0)
    partial = sum(
        1 for found in results.values()
        if found.get("unavailable") and not {"owner", "registry"} <= set(found["unavailable"])
    )
    if failed:
        owners.reasons.append(
            f"Couldn't look up {failed:,} address(es) (offline or the service didn't answer)."
        )
    if partial:
        owners.reasons.append(
            f"Couldn't find out everything about {partial:,} address(es): a lookup service "
            "didn't answer."
        )
    if answer.get("skipped"):
        owners.reasons.append(f"Only the busiest {MAX_ADDRESSES} addresses were looked up.")
    if answer.get("stopped"):
        owners.reasons.append("Looking up stopped early.")
    elif answer.get("over_budget"):
        owners.reasons.append(f"Looking up stopped after {budget:.0f} seconds.")
    return owners


_HANDLE = re.compile(r"[A-Z0-9-]*[0-9-][A-Z0-9-]*")


def _holder_company(name: str | None) -> str | None:
    """The company part of a network holder's name.

    RIPEstat writes "HANDLE - Company" ("GOOGLE - Google LLC") or, for some
    networks, "HANDLE Company" ("AKAMAI-ASN1 Akamai International B.V."). A
    handle is all capitals, digits and hyphens with at least one digit or
    hyphen; it is dropped only when a name follows it.
    """
    if not name:
        return name
    if " - " in name:
        return name.split(" - ", 1)[1].strip() or name
    first, _, rest = name.partition(" ")
    if rest.strip() and _HANDLE.fullmatch(first):
        return rest.strip()
    return name


def _owner(who: dict | None) -> str | None:
    """Who runs an address, as one name, or None when that isn't known.

    The network's holder comes first, by its company part only. Then the
    registrant, then a hostname that leads back to the address. A raw address
    is never an owner.
    """
    if not who:
        return None
    as_name = _holder_company(who.get("as_name"))
    hostname = who.get("hostname") if who.get("hostname_confirmed") else None
    return as_name or who.get("registrant") or hostname or None


def _mostly(pairs: list, owners: _Owners) -> str:
    """'Mostly X and Y.': the two known owners this program's destinations were
    seen with most, or nothing when no owner is known. ``pairs`` comes busiest
    first, and ties keep that order."""
    weight: dict[str, int] = {}
    for key, pair in pairs:
        name = _owner(owners.for_address(key[1]))
        if name:
            weight[name] = weight.get(name, 0) + pair["snapshots"]
    top = sorted(weight, key=lambda name: -weight[name])[:2]
    if not top:
        return ""
    text = " Mostly " + " and ".join(top)
    return text if text.endswith(".") else text + "."


# --- findings --------------------------------------------------------------


def _mb(count: int) -> str:
    return f"{count / 1_000_000:.1f} MB"


def _plural(n: int, word: str) -> str:
    return f"{n:,} {word}" if n == 1 else f"{n:,} {word}s"


def _label(process: str) -> str:
    return "A program Reclaim City couldn't name" if process == _UNKNOWN else process


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


def _findings(platform, gathered, minutes, stopped_early, elapsed, verdict,
              owners: _Owners) -> list[Finding]:
    facts = {
        "minutes": minutes,
        "snapshots": gathered.snapshots,
        "stopped_early": stopped_early,
        "elapsed": int(elapsed),
    }
    findings: list[Finding] = []
    reasons: list[str] = []

    if gathered.snapshots:
        findings.extend(_summaries(platform, gathered, facts, reasons, owners))
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
    reasons.extend(owners.reasons)
    if reasons or not gathered.snapshots:
        findings.append(_incomplete(gathered, facts, reasons))
    return findings


def _summaries(platform, gathered, facts, reasons, owners) -> list[Finding]:
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
                "who": owners.for_address(key[1]),
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
        text = "".join(parts) + "." + _mostly(pairs, owners)
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
                "lookup_sources": list(SOURCES) if owners.on else [],
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
        if not is_public(address):
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
        "Reclaim City couldn't confirm which program owns it, so the next checkup "
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
