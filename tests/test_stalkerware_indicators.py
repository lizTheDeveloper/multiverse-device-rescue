"""The Echap-derived signature list and the rules every detection entry follows.

All sightings here are synthetic: made-up process names and paths, no real
machine data.
"""

import json
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import Mode, Platform, Severity  # noqa: E402

from tests.test_module_stalkerware_scan import (  # noqa: E402
    _check,
    _get_module,
    _make_profile,
    _process,
)

DATA_DIR = Path(__file__).parent.parent / "modules" / "security" / "stalkerware_scan" / "data"
INDICATORS = json.loads((DATA_DIR / "stalkerware_indicators.json").read_text())
KNOWN = json.loads((DATA_DIR / "known_stalkerware.json").read_text())["entries"]

IDENTIFIER_FIELDS = [
    "android_packages", "android_certificates", "android_certificate_organizations",
    "android_certificate_name_patterns", "ios_bundle_ids", "websites",
    "distribution_domains", "c2_domains", "c2_ips", "android_sample_sha256",
]

# Words too ordinary to identify a product on their own.
GENERIC_WORDS = {
    "agent", "service", "services", "helper", "update", "updater", "monitor", "client",
    "server", "daemon", "system", "host", "app", "manager", "tracker", "spy", "keylogger",
    "logger", "remote", "support", "security", "control", "watch", "parent", "kids",
}


# ---------------- the derived list ----------------


def test_attribution_fields_are_present():
    source = INDICATORS["source"]
    assert source["url"] == "https://github.com/AssoEchap/stalkerware-indicators"
    assert re.fullmatch(r"[0-9a-f]{40}", source["commit"])
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", source["commit_date"])
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", source["fetched"])
    assert source["license"] == "CC-BY-4.0"
    assert source["license_url"] == "https://creativecommons.org/licenses/by/4.0/"
    assert "Echap" in source["attribution"] and "CC BY 4.0" in source["attribution"]
    assert source["changes"]  # CC BY asks that changes be indicated
    assert source["disclaimer"]


def test_every_entry_loads_and_validates():
    entries = INDICATORS["entries"]
    assert len(entries) >= 150
    for e in entries:
        assert e["name"], e
        assert e["category"] in {"stalkerware", "watchware"}, e["name"]
        assert e["source_file"] in {"ioc.yaml", "watchware.yaml"}, e["name"]
        assert set(e["platforms"]) <= {"android", "ios"}, e["name"]
        assert all(isinstance(a, str) and a for a in e["aliases"]), e["name"]
        for field in IDENTIFIER_FIELDS:
            values = e[field]
            assert isinstance(values, list), (e["name"], field)
            assert all(isinstance(v, str) and v for v in values), (e["name"], field)
            assert len(values) == len(set(values)), (e["name"], field)
        assert all(re.fullmatch(r"[0-9A-Fa-f]{40}", c) for c in e["android_certificates"]), e["name"]
        assert all(re.fullmatch(r"[0-9a-f]{64}", h) for h in e["android_sample_sha256"]), e["name"]
        assert all(re.fullmatch(r"[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)+", p) for p in e["android_packages"]), e["name"]


def test_platforms_follow_the_identifiers():
    for e in INDICATORS["entries"]:
        android = bool(e["android_packages"] or e["android_certificates"] or e["android_sample_sha256"])
        assert ("android" in e["platforms"]) == android, e["name"]
        assert ("ios" in e["platforms"]) == bool(e["ios_bundle_ids"]), e["name"]


def test_cross_references_name_real_detection_entries():
    known_names = {k["name"] for k in KNOWN}
    linked = [e for e in INDICATORS["entries"] if e["reclaim_city_entries"]]
    assert linked
    for e in linked:
        assert set(e["reclaim_city_entries"]) <= known_names, e["name"]


def test_the_check_does_not_read_the_reference_list():
    # Mobile identifiers and domains are reference data: no desktop matching,
    # no lookups.
    source = (Path(__file__).parent.parent / "modules" / "security" / "stalkerware_scan" / "__init__.py").read_text()
    assert "stalkerware_indicators" not in source


# ---------------- every detection entry ----------------


@pytest.mark.parametrize("entry", KNOWN, ids=lambda e: e["name"])
def test_no_entry_matches_on_a_generic_name(entry):
    pattern = entry["pattern"].lower()
    assert len(pattern.replace(" ", "")) >= 4, entry["name"]
    assert pattern not in GENERIC_WORDS, entry["name"]
    assert re.search(r"[a-z]", pattern), entry["name"]


# ---------------- products both lists know, per platform ----------------

LINKED_ENTRIES = sorted(
    {name for e in INDICATORS["entries"] for name in e["reclaim_city_entries"]}
)
_PLATFORM = {"darwin": Platform.DARWIN, "win32": Platform.WIN32, "linux": Platform.LINUX}


def _sighting(pattern, platform):
    """A synthetic running process for the product on that platform."""
    if platform == "darwin":
        return _process(pattern, f"/Applications/{pattern}.app/Contents/MacOS/{pattern}")
    if platform == "win32":
        return _process(f"{pattern}.exe", f"C:\\Program Files\\{pattern}\\{pattern}.exe")
    return _process(pattern, f"/opt/{pattern}/bin/{pattern}")


LINKED_SIGHTINGS = [
    (k, platform) for k in KNOWN if k["name"] in LINKED_ENTRIES for platform in k["platforms"]
]


@pytest.mark.parametrize(
    "entry,platform", LINKED_SIGHTINGS, ids=lambda v: v["name"] if isinstance(v, dict) else v
)
def test_linked_products_are_found_on_each_of_their_platforms(entry, platform):
    mod = _get_module()
    result = _check(mod, _make_profile(processes=[_sighting(entry["pattern"], platform)],
                                       platform=_PLATFORM[platform]))
    assert [f.data["stalkerware_name"] for f in result.findings] == [entry["name"]]
    finding = result.findings[0]
    assert finding.data["stalkerware_category"] == entry["category"]
    assert finding.severity == Severity(entry["severity"])
    assert "Removing it can alert whoever installed it" in finding.description


def test_linked_stalkerware_fix_still_leads_with_the_safety_warning():
    mod = _get_module()
    for platform in ("darwin", "win32", "linux"):
        entry = next(k for k in KNOWN if k["name"] in LINKED_ENTRIES
                     and k["category"] == "stalkerware" and platform in k["platforms"])
        result = _check(mod, _make_profile(processes=[_sighting(entry["pattern"], platform)],
                                           platform=_PLATFORM[platform]))
        titles = [a.title for a in mod.fix(result, Mode.CLI).actions]
        assert titles[0] == "Read this before removing the monitoring software", platform


def test_a_mobile_only_package_name_is_not_a_desktop_sighting():
    # An Android package id from the reference list, seen as a process name on
    # a computer, is not evidence of anything there.
    mod = _get_module()
    package = next(p for e in INDICATORS["entries"] for p in e["android_packages"]
                   if not any(re.search(rf"(?<![a-z0-9]){re.escape(k['pattern'])}(?![a-z0-9])", p.lower())
                              for k in KNOWN))
    for platform in _PLATFORM.values():
        result = _check(mod, _make_profile(processes=[_process(package)], platform=platform))
        assert not result.findings, (package, platform)
