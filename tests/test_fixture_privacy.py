"""Test fixtures never carry a real computer's details: no serial number, no
real MAC address, no saved Wi-Fi names, no real home folder or Desktop files.
Fixtures are synthetic (desktop/test/fixtures/make-ux6-fixtures.py) or
scrubbed to placeholders ("text 12")."""

import hashlib
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
FIXTURE_DIRS = [ROOT / "desktop" / "test" / "fixtures", *[p for p in (ROOT / "tests").rglob("fixtures") if p.is_dir()]]
FILES = sorted({p for d in FIXTURE_DIRS for p in d.rglob("*") if p.is_file() and p.suffix in (".json", ".txt", ".js", ".py", ".plist", ".log")})

# Strings from a real machine that once reached a fixture, kept only as
# SHA-256 hashes so this file doesn't repeat them.
KNOWN_REAL = {
    "12647a6367e7883647c93cbc77142a4b6ff5dc604ce6802a8ad67504c94edd6f",
    "61d4fcb7846af2cc352055e2fbb1091d7c7202a39583dd5e6cf110e471cd554a",
    "231f588945560999c3b18cb58010b8eb0f01cae474148841296aabdb51ff114e",
    "dd48e7c953bf5d3a133483d17bba3aa2702a715991ed66901596ebf3e9d0e482",
}
TOKEN = re.compile(r"[A-Za-z0-9_.-]{4,}")
MAC = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
DOC_MAC = re.compile(r"^00[:-]00[:-]5E[:-]00[:-]53[:-][0-9A-F]{2}$", re.I)  # RFC 7042 documentation range
HOME = re.compile(r"/(?:Users|home)/([^/\s\"'\\]+)")
TEST_HOMES = {"example", "ann", "me", "test", "user", "someone", "Shared", "you", "name", "alice", "bob", "runner", "username"}
SERIAL_KEYS = re.compile(r"serial", re.I)
TEST_SERIAL = re.compile(r"^(?:C02TEST\w*|TEST\w*|X{4,}\w*|text \d+|example\w*|0+|)$", re.I)
NETWORK_KEYS = re.compile(r"^(?:ssid|ssids|networks|known_networks|preferred_networks|current_network|wifi_network|network_name)$", re.I)
TEST_SSID = re.compile(r"^(?:Example\b.*|text \d+|Test\b.*|Home Wi-Fi|)$", re.I)


def test_there_are_fixtures_to_check():
    assert any(p.name.startswith("ux6-") for p in FILES)


@pytest.mark.parametrize("path", FILES, ids=lambda p: str(p.relative_to(ROOT)))
def test_no_real_device_details(path):
    text = path.read_text(encoding="utf-8", errors="replace")
    real = sorted({t for t in TOKEN.findall(text)
                   if hashlib.sha256(t.encode()).hexdigest() in KNOWN_REAL
                   or any(hashlib.sha256(part.encode()).hexdigest() in KNOWN_REAL for part in re.split(r"[_.-]", t))})
    assert not real, f"{path.name}: details from a real computer"
    macs = sorted({m for m in MAC.findall(text) if not DOC_MAC.match(m)})
    assert not macs, f"{path.name}: MAC addresses outside 00:00:5E:00:53:xx: {macs[:3]}"
    homes = sorted({h for h in HOME.findall(text) if h not in TEST_HOMES})
    assert not homes, f"{path.name}: a real-looking home folder: {homes[:3]}"
    assert not re.search(r"/(?:Users|home)/[^/\s\"']+/Desktop/", text), f"{path.name}: files from a Desktop"


def _walk(v, found):
    if isinstance(v, dict):
        for k, x in v.items():
            if SERIAL_KEYS.search(k) and isinstance(x, str) and not TEST_SERIAL.match(x):
                found.append(f"{k}: not a test value")
            if NETWORK_KEYS.match(k):
                for s in (x if isinstance(x, list) else [x]):
                    if isinstance(s, str) and not TEST_SSID.match(s):
                        found.append(f"{k}: a real-looking network name")
                    elif isinstance(s, dict):
                        name = s.get("ssid") or s.get("name")
                        if isinstance(name, str) and not TEST_SSID.match(name):
                            found.append(f"{k}: a real-looking network name")
            _walk(x, found)
    elif isinstance(v, list):
        for x in v:
            _walk(x, found)


@pytest.mark.parametrize("path", [p for p in FILES if p.suffix == ".json"], ids=lambda p: str(p.relative_to(ROOT)))
def test_no_real_serial_numbers_or_wifi_names(path):
    found = []
    _walk(json.loads(path.read_text(encoding="utf-8")), found)
    assert not found, f"{path.name}: {found[:5]}"
