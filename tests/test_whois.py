"""Looking up who runs a public address: reverse DNS, RIPEstat and RDAP.

Every test injects the fetcher, the resolver and the clock, so nothing here
touches the network. The fixtures are real responses captured with curl for
public infrastructure addresses. ``RESCUE_LIVE_NET=1`` turns on the one live
check at the bottom.
"""

import json
import os
import socket
import ssl
import threading
from pathlib import Path

import pytest

from rescue import __version__, whois

_FIX = Path(__file__).resolve().parent / "fixtures" / "whois"


def fixture(name: str) -> bytes:
    return (_FIX / name).read_bytes()


def no_name(ip):
    raise socket.herror(1, "Unknown host")


def fetch_from(table):
    """A fetcher answering from {url-substring: body}; anything else raises."""
    calls = []
    lock = threading.Lock()

    def fetch(url, timeout):
        with lock:
            calls.append(url)
        for key, body in table.items():
            if key in url:
                if isinstance(body, BaseException):
                    raise body
                return body
        raise OSError("no route")

    fetch.calls = calls
    return fetch


GOOGLE = {"stat.ripe.net": fixture("ripe_8.8.8.8.json"), "rdap.org": fixture("rdap_8.8.8.8.json")}


def test_constants():
    assert (whois.MAX_ADDRESSES, whois.WORKERS, whois.TIMEOUT, whois.BUDGET, whois.MAX_BODY) == (
        150, 6, 4.0, 60.0, 65536)
    assert whois.SOURCES == [
        "reverse DNS (your computer's own resolver)",
        "RIPE NCC (stat.ripe.net)",
        "rdap.org (the internet registries)",
    ]


def test_lookupable_ranges():
    for ip in ("8.8.8.8", "2001:4860:4860::8888"):
        assert whois.is_lookupable(ip), ip
    for ip in ("10.1.2.3", "172.16.0.9", "192.168.1.1", "127.0.0.1", "169.254.3.4",
               "100.64.0.1", "224.0.0.251", "::1", "fe80::1", "fc00::1", "0.0.0.0",
               "240.0.0.1", "", "not an address", "::ffff:192.168.1.1", "64:ff9b::a00:1"):
        assert not whois.is_lookupable(ip), ip


def test_parse_real_ripe_and_rdap():
    ripe = whois.parse_ripe(fixture("ripe_8.8.8.8.json"))
    assert ripe == {"asn": 15169, "as_name": "GOOGLE - Google LLC", "prefix": "8.8.8.0/24"}
    assert "Google" in ripe["as_name"]
    rdap = whois.parse_rdap(fixture("rdap_8.8.8.8.json"))
    assert rdap == {"network": "GOGL", "registrant": "Google LLC", "country": None}


def test_parse_ripe_region_and_apnic():
    ripe = whois.parse_ripe(fixture("ripe_ripe_region.json"))
    assert ripe["asn"] == 15169
    assert ripe["prefix"] == "2a00:1450:4001::/48"
    rdap = whois.parse_rdap(fixture("rdap_ripe_region.json"))
    # RIPE lists a maintainer handle as "registrant"; the organisation is the
    # administrative contact, so that is the name worth showing.
    assert rdap == {"network": "IE-GOOGLE-2a00-1450-4000-1", "registrant": "Google Ireland Limited",
                    "country": "IE"}
    apnic = whois.parse_rdap(fixture("rdap_apnic.json"))
    assert apnic == {"network": "APNIC-LABS", "registrant": "APNIC Research and Development",
                     "country": "AU"}


def test_rdap_404_and_garbage():
    empty_rdap = {"network": None, "registrant": None, "country": None}
    empty_ripe = {"asn": None, "as_name": None, "prefix": None}
    for body in (fixture("rdap_404.txt"), fixture("garbage.html"), b"", b"\xff\xfe\x00",
                 b"[1, 2]", b'{"entities": "nope", "name": 7}', b"null"):
        assert whois.parse_rdap(body) == empty_rdap
        assert whois.parse_ripe(body) == empty_ripe
    assert whois.parse_ripe(b'{"data": {"asns": [{"asn": "15169"}], "resource": 3}}') == empty_ripe
    assert whois.parse_ripe(b'{"data": {"asns": [{"asn": true}]}}') == empty_ripe


def test_garbage_answer_is_couldnt_check():
    """A captive portal's HTML page tells us nothing, so it can't count as an answer."""
    page = fixture("garbage.html")
    who = whois.look_up("8.8.8.8", fetch=fetch_from({"": page}), resolve=no_name, timeout=1)
    assert who["unavailable"] == ["owner", "registry"]
    assert who["registrant"] is None


class StubResponse:
    def __init__(self, body):
        self.body = body

    def read(self, n=-1):
        return self.body if n < 0 else self.body[:n]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class StubOpener:
    def __init__(self, body):
        self.body = body
        self.requests = []

    def open(self, request, timeout=None):
        self.requests.append((request, timeout))
        return StubResponse(self.body)


def test_hostile_bodies():
    # Too big: the fetcher refuses rather than reading on.
    with pytest.raises(ValueError):
        whois.default_fetch("https://rdap.org/ip/8.8.8.8", 4,
                            opener=StubOpener(b"x" * (whois.MAX_BODY + 1)))
    assert whois.default_fetch("https://rdap.org/ip/8.8.8.8", 4,
                               opener=StubOpener(b"x" * whois.MAX_BODY)) == b"x" * whois.MAX_BODY

    # Hostile registry text: control characters stripped, length capped.
    name = "<script>alert(1)</script>\x1b[31m‮evil\x00" + "A" * 10_000
    body = ('{"name": %s, "country": "US\\u0007", "entities": [{"roles": ["registrant"],'
            ' "vcardArray": ["vcard", [["fn", {}, "text", %s]]]}]}') % (
        json.dumps(name), json.dumps(name))
    ripe = ('{"data": {"resource": "8.8.8.0/24", "asns": [{"asn": 15169, "holder": %s}]}}'
            % json.dumps(name))

    def resolve(ip):
        return ("host\r\nx-evil: 1." + "b" * 500, [], [ip])

    who = whois.look_up("8.8.8.8", fetch=fetch_from({"stat.ripe.net": ripe.encode(),
                                                     "rdap.org": body.encode()}),
                        resolve=resolve, timeout=1)
    for field in ("hostname", "as_name", "network", "registrant", "country"):
        value = who[field]
        assert len(value) <= 200, field
        assert not any(ord(c) < 32 or 0x7F <= ord(c) < 0xA0 or c == "‮" for c in value), field
    assert who["network"].startswith("<script>alert(1)</script>[31mevil")
    assert who["country"] == "US"
    assert who["unavailable"] == []


def test_look_up_whole_record():
    def resolve(ip):
        return ("dns.google", [], [ip])

    fetch = fetch_from(GOOGLE)
    who = whois.look_up("8.8.8.8", fetch=fetch, resolve=resolve, timeout=2)
    assert who == {"hostname": "dns.google", "asn": 15169, "as_name": "GOOGLE - Google LLC",
                   "prefix": "8.8.8.0/24", "network": "GOGL", "registrant": "Google LLC",
                   "country": None, "unavailable": []}


def test_no_reverse_name_is_an_answer():
    who = whois.look_up("8.8.8.8", fetch=fetch_from(GOOGLE), resolve=no_name, timeout=1)
    assert who["hostname"] is None
    assert who["unavailable"] == []


def test_wrapped_ipv4_is_looked_up_as_ipv4():
    fetch = fetch_from(GOOGLE)
    whois.look_up("::ffff:8.8.8.8", fetch=fetch, resolve=no_name, timeout=1)
    assert any(url.endswith("resource=8.8.8.8&sourceapp=reclaim-city") for url in fetch.calls)
    assert "https://rdap.org/ip/8.8.8.8" in fetch.calls


def test_offline_marks_every_field_couldnt_check():
    def fetch(url, timeout):
        raise OSError("Network is unreachable")

    def resolve(ip):
        raise OSError("Network is unreachable")

    who = whois.look_up("8.8.8.8", fetch=fetch, resolve=resolve, timeout=1)
    assert who["unavailable"] == ["dns", "owner", "registry"]
    assert all(who[k] is None for k in who if k != "unavailable")

    out = whois.look_up_all(["8.8.8.8", "1.1.1.1"], fetch=fetch, resolve=resolve)
    assert out["failed"] == 2
    assert set(out["results"]) == {"8.8.8.8", "1.1.1.1"}
    assert out["over_budget"] is False


def test_tls_failure_is_couldnt_check():
    fetch = fetch_from({"": ssl.SSLError("CERTIFICATE_VERIFY_FAILED")})
    who = whois.look_up("8.8.8.8", fetch=fetch, resolve=no_name, timeout=1)
    assert who["unavailable"] == ["owner", "registry"]
    out = whois.look_up_all(["8.8.8.8"], fetch=fetch, resolve=no_name)
    assert out["failed"] == 1


def test_one_service_down_still_says_who():
    fetch = fetch_from({"stat.ripe.net": OSError("timed out"), "rdap.org": fixture("rdap_8.8.8.8.json")})
    out = whois.look_up_all(["8.8.8.8"], fetch=fetch, resolve=no_name)
    assert out["results"]["8.8.8.8"]["registrant"] == "Google LLC"
    assert out["results"]["8.8.8.8"]["unavailable"] == ["owner"]
    assert out["failed"] == 0


class FakeClock:
    def __init__(self):
        self.t = 0.0
        self.lock = threading.Lock()

    def __call__(self):
        with self.lock:
            return self.t

    def advance(self, seconds):
        with self.lock:
            self.t += seconds


def test_limit_and_budget():
    clock = FakeClock()
    attempted = set()
    lock = threading.Lock()

    def slow_fetch(url, timeout):
        clock.advance(0.5)
        return fixture("rdap_8.8.8.8.json")

    def resolve(ip):
        with lock:
            attempted.add(ip)
        raise socket.herror(1, "Unknown host")

    ips = [f"8.{i // 256}.{i % 256}.1" for i in range(1000)]
    out = whois.look_up_all(ips, fetch=slow_fetch, resolve=resolve, clock=clock)
    assert len(attempted) <= 150
    assert out["skipped"] == 1000 - 150
    assert out["over_budget"] is True
    assert 0 < len(out["results"]) < 150
    # Busiest first: what got looked up is from the front of the list.
    assert set(out["results"]) <= set(ips[:150])


def test_limit_without_budget_pressure():
    ips = ["10.0.0.1", "8.8.8.8", "8.8.8.8", "1.1.1.1", "9.9.9.9", "fe80::1"]
    fetch = fetch_from(GOOGLE)
    out = whois.look_up_all(ips, fetch=fetch, resolve=no_name, limit=2)
    assert list(out["results"]) == ["8.8.8.8", "1.1.1.1"]
    assert out["skipped"] == 1
    assert out["over_budget"] is False
    assert out["failed"] == 0


def test_no_calls_when_disabled():
    fetch = fetch_from(GOOGLE)
    calls = []
    out = whois.look_up_all([], fetch=fetch, resolve=lambda ip: calls.append(ip))
    assert out == {"results": {}, "skipped": 0, "failed": 0, "over_budget": False}
    assert fetch.calls == [] and calls == []
    out = whois.look_up_all(["192.168.1.1", "::1"], fetch=fetch, resolve=lambda ip: calls.append(ip))
    assert out["results"] == {} and fetch.calls == [] and calls == []


def test_user_agent_and_sourceapp():
    opener = StubOpener(b"{}")
    assert whois.default_fetch("https://rdap.org/ip/8.8.8.8", 4, opener=opener) == b"{}"
    request, timeout = opener.requests[0]
    assert request.get_header("User-agent") == f"ReclaimCity/{__version__}"
    assert timeout == 4

    fetch = fetch_from(GOOGLE)
    whois.look_up("8.8.8.8", fetch=fetch, resolve=no_name, timeout=1)
    assert fetch.calls == [
        "https://stat.ripe.net/data/prefix-overview/data.json?resource=8.8.8.8&sourceapp=reclaim-city",
        "https://rdap.org/ip/8.8.8.8",
    ]


def test_fetch_refuses_plain_http():
    with pytest.raises(ValueError):
        whois.default_fetch("http://rdap.org/ip/8.8.8.8", 4, opener=StubOpener(b"{}"))
    handler = whois._HTTPSOnlyRedirects()
    with pytest.raises(OSError):
        handler.redirect_request(None, None, 302, "Found", {}, "http://rdap.example/ip/8.8.8.8")


def test_ssl_context_is_cached_and_falls_back(monkeypatch):
    whois.ssl_context.cache_clear()
    calls = []

    def failing_run(args, **kw):
        calls.append(args)
        from rescue.command import CommandResult
        return CommandResult(args=list(args), returncode=1, stdout="", stderr="no", timed_out=False,
                             error=None, duration_s=0.0, truncated=False)

    monkeypatch.setattr(whois, "run", failing_run)
    monkeypatch.setattr(whois.sys, "platform", "darwin")
    try:
        first = whois.ssl_context()
        assert isinstance(first, ssl.SSLContext)
        assert first.verify_mode == ssl.CERT_REQUIRED and first.check_hostname
        assert whois.ssl_context() is first
        assert len(calls) == 1
        assert calls[0][:2] == ["security", "find-certificate"]
    finally:
        whois.ssl_context.cache_clear()


def test_nothing_written_to_disk(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    out = whois.look_up_all(["8.8.8.8", "1.1.1.1"], fetch=fetch_from(GOOGLE), resolve=no_name)
    assert len(out["results"]) == 2
    assert list(tmp_path.rglob("*")) == []


@pytest.mark.skipif(os.environ.get("RESCUE_LIVE_NET") != "1", reason="set RESCUE_LIVE_NET=1 to use the network")
def test_live_lookup():
    out = whois.look_up_all(["8.8.8.8"])
    who = out["results"]["8.8.8.8"]
    assert who["asn"] == 15169
    assert who["registrant"] == "Google LLC"
