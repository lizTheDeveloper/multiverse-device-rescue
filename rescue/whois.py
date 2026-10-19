"""Who runs a public address: reverse DNS, RIPEstat and RDAP.

The connection watch sees addresses, not names. This looks each public one up
in three places: the computer's own resolver (reverse DNS), RIPE NCC's RIPEstat
(which network announces it, and its AS number) and rdap.org (the registry
record: network name, registrant and country).

Only the address itself is sent. Nothing is written to disk; results live in
memory for one run. Every failure is "couldn't check" for that part of the
answer, never an error. The registries' text is untrusted, so every string is
capped and has control characters removed here; the renderer escapes it too.

The fetcher, resolver and clock are passed in, so tests never touch the network.
"""

from __future__ import annotations

import functools
import json
import socket
import ssl
import sys
import threading
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable

from rescue import __version__
from rescue.command import run
from rescue.netaddr import address_key, is_public, parse_ip

MAX_ADDRESSES = 150
WORKERS = 3
RDAP_AT_ONCE = 2  # rdap.org and the registries limit how fast one asker may go
TIMEOUT = 4.0
BUDGET = 60.0
MAX_BODY = 65536

SOURCES = [
    "reverse DNS (your computer's own resolver)",
    "RIPE NCC (stat.ripe.net)",
    "rdap.org, which passes it on to the regional registry for the address "
    "(ARIN, RIPE NCC, APNIC, LACNIC or AFRINIC)",
]

_MAX_TEXT = 200
_USER_AGENT = f"ReclaimCity/{__version__}"
_ROOTS_KEYCHAIN = "/System/Library/Keychains/SystemRootCertificates.keychain"

_READ_CHUNK = 8192
# The two services asked first, and the registries rdap.org redirects to.
_START_HOSTS = frozenset({"stat.ripe.net", "rdap.org"})
_REDIRECT_HOSTS = frozenset({"rdap.org", "rdap.arin.net", "rdap.db.ripe.net", "rdap.apnic.net",
                             "rdap.lacnic.net", "rdap.afrinic.net"})
# Reverse DNS errors that mean "there is no name" rather than "couldn't ask".
_NO_NAME_HERRORS = (1, 4)  # HOST_NOT_FOUND, NO_DATA
_NO_NAME_GAIERRORS = tuple(
    getattr(socket, name) for name in ("EAI_NONAME", "EAI_NODATA") if hasattr(socket, name))

_EMPTY_RIPE = {"asn": None, "as_name": None, "prefix": None}
_EMPTY_RDAP = {"network": None, "registrant": None, "country": None}


def is_lookupable(ip: str) -> bool:
    """True only for an address on the internet (never this computer or network)."""
    return is_public(ip)


def _clean(value) -> str | None:
    """Registry or DNS text made safe to keep: no control characters, capped."""
    if not isinstance(value, str):
        return None
    # Category C covers control characters and invisible formatting such as
    # right-to-left overrides, which could disguise a name.
    text = "".join(c for c in value if not unicodedata.category(c).startswith("C")).strip()
    return text[:_MAX_TEXT] or None


def _json(body: bytes):
    try:
        return json.loads(body)
    except (ValueError, TypeError):
        return None


# --- parsing ---------------------------------------------------------------


def parse_ripe(body: bytes) -> dict:
    """RIPEstat prefix-overview: the announcing AS number, its name and the prefix."""
    doc = _json(body)
    data = doc.get("data") if isinstance(doc, dict) else None
    if not isinstance(data, dict):
        return dict(_EMPTY_RIPE)
    asn = as_name = None
    asns = data.get("asns")
    if isinstance(asns, list) and asns and isinstance(asns[0], dict):
        number = asns[0].get("asn")
        if isinstance(number, int) and not isinstance(number, bool) and 0 < number < 2**32:
            asn = number
            as_name = _clean(asns[0].get("holder"))
    return {"asn": asn, "as_name": as_name, "prefix": _clean(data.get("resource"))}


def _vcard(entity: dict, field: str):
    card = entity.get("vcardArray")
    if not (isinstance(card, list) and len(card) > 1 and isinstance(card[1], list)):
        return None
    for prop in card[1]:
        if isinstance(prop, list) and len(prop) > 3 and prop[0] == field:
            return prop[3]
    return None


def _entities(doc: dict) -> list[dict]:
    """Top-level entities, then the ones nested one level inside them."""
    top = [e for e in doc.get("entities") or [] if isinstance(e, dict)] \
        if isinstance(doc.get("entities"), list) else []
    nested = []
    for entity in top:
        inner = entity.get("entities")
        if isinstance(inner, list):
            nested.extend(e for e in inner if isinstance(e, dict))
    return top + nested


def _has_role(entity: dict, role: str) -> bool:
    roles = entity.get("roles")
    return isinstance(roles, list) and role in roles


def _org_text(value) -> str | None:
    """A vCard "org" value: a name, or the name and its units (RFC 6350)."""
    if isinstance(value, list):
        value = ", ".join(part for part in value if isinstance(part, str) and part.strip())
    return _clean(value)


def _organisation_name(entity: dict) -> str | None:
    """The entity's name if it is a company or group, never a person.

    vCard kind "org" or "group" (any case): its full name. No kind at all: only
    an "org" property counts, because a bare full name could be anyone's.
    """
    kind = _vcard(entity, "kind")
    if kind is None:
        return _org_text(_vcard(entity, "org"))
    if isinstance(kind, str) and kind.lower() in ("org", "group"):
        return _clean(_vcard(entity, "fn"))
    return None


def _registrant(doc: dict) -> str | None:
    """The registering organisation's name, else the administrative one's.

    Registry records also name real people (and RIPE lists a maintainer handle
    as "registrant"), so only an organisation or group counts. With none, the
    answer is None and the network name stands in.
    """
    entities = _entities(doc)
    for role in ("registrant", "administrative"):
        for entity in entities:
            if _has_role(entity, role):
                name = _organisation_name(entity)
                if name:
                    return name
    return None


def parse_rdap(body: bytes) -> dict:
    """An RDAP IP network record: network name, registrant and country."""
    doc = _json(body)
    if not isinstance(doc, dict):
        return dict(_EMPTY_RDAP)
    country = _clean(doc.get("country"))
    return {"network": _clean(doc.get("name")), "registrant": _registrant(doc),
            "country": country.upper() if country else None}


# --- fetching --------------------------------------------------------------


@functools.lru_cache(maxsize=1)
def ssl_context() -> ssl.SSLContext:
    """A verifying TLS context.

    On macOS the packaged engine's Python may not find any root certificates,
    so it uses the system's own roots from the keychain, falling back to the
    default context if they can't be read.
    """
    if sys.platform == "darwin":
        result = run(["security", "find-certificate", "-a", "-p", _ROOTS_KEYCHAIN], timeout=10)
        if result.ok and "BEGIN CERTIFICATE" in result.stdout:
            try:
                return ssl.create_default_context(cadata=result.stdout)
            except (ssl.SSLError, ValueError):
                pass
    return ssl.create_default_context()


def _https_host(url: str, allowed: frozenset[str]) -> bool:
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port
    except ValueError:
        return False
    return parts.scheme == "https" and parts.hostname in allowed and port in (None, 443)


class _RegistryRedirects(urllib.request.HTTPRedirectHandler):
    """Follow redirects (rdap.org sends you to the registry) only to a registry."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not _https_host(newurl, _REDIRECT_HOSTS):
            raise OSError(f"refused a redirect to {newurl[:_MAX_TEXT]}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def default_fetch(url: str, timeout: float, *, opener=None,
                  clock: Callable[[], float] = time.monotonic) -> bytes:
    """GET ``url`` over HTTPS and return at most ``MAX_BODY`` bytes, or raise.

    The whole request, connecting and reading, has ``timeout`` seconds.
    """
    if not _https_host(url, _START_HOSTS):
        raise ValueError("lookups only go to stat.ripe.net and rdap.org over HTTPS")
    deadline = clock() + timeout
    if opener is None:
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ssl_context()), _RegistryRedirects())
    request = urllib.request.Request(
        url, headers={"User-Agent": _USER_AGENT, "Accept": "application/json"})
    body = bytearray()
    with opener.open(request, timeout=timeout) as response:
        read = getattr(response, "read1", response.read)
        while True:
            if clock() >= deadline:
                raise TimeoutError("the service took too long to answer")
            chunk = read(_READ_CHUNK)
            if not chunk:
                break
            body += chunk
            if len(body) > MAX_BODY:
                raise ValueError("answer too large")
    return bytes(body)


def _ripe_url(ip: str) -> str:
    return f"https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}&sourceapp=reclaim-city"


def _rdap_url(ip: str) -> str:
    return f"https://rdap.org/ip/{ip}"


# --- looking up ------------------------------------------------------------


def _bounded(call: Callable[[], object], timeout: float, what: str):
    """Name lookups have no timeout of their own, so give them one."""
    box: dict = {}

    def target():
        try:
            box["value"] = call()
        except BaseException as exc:  # noqa: BLE001 - reported to the caller below
            box["error"] = exc

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        raise TimeoutError(f"{what} didn't answer")
    if "error" in box:
        raise box["error"]
    return box.get("value")


def forward_addresses(name: str) -> list[str]:
    """The addresses a name resolves to, through this computer's own resolver."""
    return [info[4][0] for info in socket.getaddrinfo(name, None)]


def _no_reverse_name(exc: BaseException) -> bool:
    """The resolver answered "no such name" (an answer), not "try again" (a failure)."""
    if isinstance(exc, socket.gaierror):
        return exc.errno in _NO_NAME_GAIERRORS
    if isinstance(exc, socket.herror):
        return exc.errno in _NO_NAME_HERRORS
    return False


def _confirmed(name: str, query: str, forward, timeout: float) -> bool:
    """True only if ``name`` resolves back to ``query``.

    Whoever controls an address's reverse DNS can give it any name, even
    "www.apple.com"; a name that doesn't lead back to the address proves nothing.
    """
    try:
        found = _bounded(lambda: forward(name), timeout, "DNS")
    except Exception:  # noqa: BLE001 - can't confirm, so unconfirmed
        return False
    if not isinstance(found, (list, tuple)):
        return False
    return any(isinstance(a, str) and address_key(a) == query for a in found)


def _is_timeout(exc: BaseException) -> bool:
    if isinstance(exc, TimeoutError):  # socket.timeout too
        return True
    return isinstance(exc, urllib.error.URLError) and isinstance(exc.reason, TimeoutError)


_BUSY_CODES = (429, 503)  # too many requests; service unavailable
_BUSY_PAUSE = 1.0
_MAX_RETRY_AFTER = 2.0


def _busy_pause(exc: BaseException) -> float | None:
    """How long to wait before asking again, if the service said it was busy."""
    if not (isinstance(exc, urllib.error.HTTPError) and exc.code in _BUSY_CODES):
        return None
    try:
        asked = float((exc.headers or {}).get("Retry-After", ""))
    except (TypeError, ValueError):  # missing, or an HTTP date: not worth waiting for
        return _BUSY_PAUSE
    return asked if 0 <= asked <= _MAX_RETRY_AFTER else _BUSY_PAUSE


def _fetch_with_one_retry(fetch, url: str, timeout: float, *, busy_retry: bool,
                          sleep: Callable[[float], None]) -> bytes:
    """A slow answer gets one more try, and so (with ``busy_retry``) does a
    "too busy" one, after a short pause. Any other failure doesn't."""
    try:
        return fetch(url, timeout)
    except Exception as exc:  # noqa: BLE001 - re-raised unless worth one more try
        pause = _busy_pause(exc) if busy_retry else None
        if pause is None and not _is_timeout(exc):
            raise
    if pause:
        sleep(pause)
    return fetch(url, timeout)


def look_up(ip, *, fetch, resolve, timeout, forward=forward_addresses,
            rdap_gate=None, sleep: Callable[[float], None] = time.sleep) -> dict:
    """Everything that can be learned about one address.

    ``hostname_confirmed`` is true only when the hostname resolves back to the
    address. ``unavailable`` names each part that couldn't be checked: ``dns``,
    ``owner`` (RIPEstat) and ``registry`` (RDAP). ``rdap_gate`` (a semaphore)
    limits how many RDAP requests run at once across lookups.
    """
    query = str(parse_ip(ip))  # an IPv4 address carried in IPv6 is looked up as IPv4
    who = {"hostname": None, "hostname_confirmed": False, **_EMPTY_RIPE, **_EMPTY_RDAP,
           "unavailable": []}

    try:
        answer = _bounded(lambda: resolve(query), timeout, "reverse DNS")
        who["hostname"] = _clean(answer[0])
    except Exception as exc:  # noqa: BLE001 - any failure is couldn't-check
        if not _no_reverse_name(exc):
            who["unavailable"].append("dns")
    if who["hostname"]:
        who["hostname_confirmed"] = _confirmed(who["hostname"], query, forward, timeout)

    def rdap_fetch(url: str, seconds: float) -> bytes:
        if rdap_gate is None:
            return fetch(url, seconds)
        with rdap_gate:
            return fetch(url, seconds)

    for group, url, parse, get, busy_retry in (
            ("owner", _ripe_url(query), parse_ripe, fetch, False),
            ("registry", _rdap_url(query), parse_rdap, rdap_fetch, True)):
        try:
            found = parse(_fetch_with_one_retry(get, url, timeout, busy_retry=busy_retry,
                                                sleep=sleep))
        except Exception:  # noqa: BLE001 - offline, TLS, HTTP errors, oversized
            found = None
        if not found or all(v is None for v in found.values()):
            # Nothing usable (an error page, a captive portal): couldn't check.
            who["unavailable"].append(group)
        else:
            who.update(found)
    return who


def look_up_all(
    ips: list[str],
    *,
    fetch: Callable[[str, float], bytes] = default_fetch,
    resolve: Callable[[str], tuple] = socket.gethostbyaddr,
    forward: Callable[[str], list[str]] = forward_addresses,
    limit: int = MAX_ADDRESSES,
    workers: int = WORKERS,
    timeout: float = TIMEOUT,
    budget: float = BUDGET,
    clock: Callable[[], float] = time.monotonic,
    should_stop: Callable[[], bool] | None = None,
    on_progress: Callable[[int, int], None] | None = None,
    rdap_at_once: int = RDAP_AT_ONCE,
    sleep: Callable[[float], None] = time.sleep,
) -> dict:
    """Look up the first ``limit`` public addresses in ``ips`` (busiest first).

    ``skipped`` counts public addresses past the limit, ``failed`` the ones
    where neither RIPEstat nor RDAP answered, ``over_budget`` says the lookups
    stopped because ``budget`` seconds ran out, and ``stopped`` that
    ``should_stop()`` turned true: no new lookup starts and the ones under way
    are left behind. ``on_progress(done, total)`` is called from this thread
    as answers come in.
    """
    should_stop = should_stop or (lambda: False)
    wanted: list[str] = []
    seen: set[str] = set()
    for ip in ips:
        if not is_lookupable(ip):
            continue
        key = address_key(ip)  # ::ffff:8.8.8.8 and 8.8.8.8 are one address
        if key not in seen:
            seen.add(key)
            wanted.append(ip)
    queue = wanted[:limit]
    skipped = len(wanted) - len(queue)
    if not queue:
        return {"results": {}, "skipped": skipped, "failed": 0, "over_budget": False,
                "stopped": False}

    start = clock()
    lock = threading.Lock()
    results: dict[str, dict] = {}
    rdap_gate = threading.BoundedSemaphore(max(1, rdap_at_once))
    state = {"next": 0, "out_of_time": False, "stop": False, "closed": False, "running": 0}
    finished = threading.Event()

    def worker():
        while True:
            with lock:
                if state["closed"] or state["stop"] or state["next"] >= len(queue):
                    break
                if clock() - start >= budget:
                    state["out_of_time"] = True
                    break
                ip = queue[state["next"]]
                state["next"] += 1
            who = look_up(ip, fetch=fetch, resolve=resolve, timeout=timeout, forward=forward,
                          rdap_gate=rdap_gate, sleep=sleep)
            with lock:
                if state["closed"]:
                    break
                results[ip] = who
        with lock:
            state["running"] -= 1
            if state["running"] == 0:
                finished.set()

    def report(done: int) -> None:
        if on_progress is not None:
            try:
                on_progress(done, len(queue))
            except Exception:  # nosec - progress is a courtesy; the lookups go on
                pass

    count = max(1, min(workers, len(queue)))
    state["running"] = count
    # Daemon threads: a lookup stuck past the budget is left behind, never waited on.
    for _ in range(count):
        threading.Thread(target=worker, daemon=True).start()

    reported = 0
    stopped = False
    while not finished.is_set():
        if should_stop():
            stopped = True
            with lock:
                state["stop"] = True
            break
        remaining = budget - (clock() - start)
        if remaining <= 0:
            break
        finished.wait(min(remaining, 0.05))
        with lock:
            done_now = len(results)
        if done_now != reported:
            reported = done_now
            report(done_now)

    with lock:
        state["closed"] = True
        done = {ip: results[ip] for ip in queue if ip in results}
        over_budget = not stopped and (state["out_of_time"] or len(done) < len(queue))
    if len(done) != reported:
        report(len(done))
    failed = sum(1 for who in done.values() if {"owner", "registry"} <= set(who["unavailable"]))
    return {"results": done, "skipped": skipped, "failed": failed, "over_budget": over_budget,
            "stopped": stopped}
