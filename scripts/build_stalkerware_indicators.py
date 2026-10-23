#!/usr/bin/env python3
"""Build ``stalkerware_indicators.json`` from Echap's stalkerware-indicators.

Echap (https://github.com/AssoEchap/stalkerware-indicators) maintains the
public list of stalkerware and "watchware" apps, with their identifiers. It is
licensed CC BY 4.0, so a converted copy ships in this repo with attribution.
This script is how that copy is made; it never fetches or runs anything. Fetch
the source files yourself, as plain files, from one commit:

    https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/<commit>/ioc.yaml
    https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/<commit>/watchware.yaml
    https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/<commit>/samples.csv

then run::

    python scripts/build_stalkerware_indicators.py --source-dir <dir> \\
        --commit <sha> --commit-date <YYYY-MM-DD> --fetched <YYYY-MM-DD>

The source lists Android and iOS identifiers only (package names, signing
certificates, iOS bundle ids, domains, IPs, sample hashes). None of them can
be seen on a Mac, Windows or Linux computer, so this file is reference data:
``stalkerware_scan`` does not match on it, and no domain in it is ever looked
up. ``reclaim_city_entries`` links a source product to the entries in
``known_stalkerware.json`` that detect the desktop version of the same product.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_PATH = REPO_ROOT / "modules" / "security" / "stalkerware_scan" / "data" / "stalkerware_indicators.json"
SOURCE_URL = "https://github.com/AssoEchap/stalkerware-indicators"

# Reviewed by hand: the source product (by its "name") and the
# known_stalkerware.json entries (by "name") that detect the same product on a
# computer. Matched on the product name or one of the source's aliases for it.
RECLAIM_CITY_ENTRIES = {
    "TheTruthSpy": ["TheTruthSpy"],
    "Cocospy": ["Cocospy", "Spyzie"],
    "Hoverwatch": ["Hoverwatch", "Refog Personal Monitor"],
    "FlexiSpy": ["FlexiSPY"],
    "mSpy": ["mSpy"],
    "iKeyMonitor": ["iKeyMonitor"],
    "uMobix": ["uMobix"],
    "ClevGuard": ["ClevGuard / KidsGuard", "KidsGuard Pro"],
    "bark": ["Bark"],
    "XNSpy": ["XNSPY"],
    "pcTattletale": ["PC Tattletale"],
    "EvaSpy": ["Spyrix"],
    "KidsShield": ["KidLogger"],
    "WebWatcher": ["WebWatcher", "InterGuard"],
    "Qustodio": ["Qustodio"],
    "Netnanny": ["Net Nanny"],
}


def _list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return [str(v) for v in value]


def _unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out = []
    for v in values:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


def _entry(raw: dict, source_file: str) -> dict:
    c2 = raw.get("c2") or {}
    name = raw["name"]
    return {
        "name": name,
        "aliases": [a for a in _unique(_list(raw.get("names"))) if a != name],
        "category": raw["type"],
        "source_file": source_file,
        "platforms": [],
        "android_packages": _unique(_list(raw.get("packages"))),
        "android_certificates": _unique(_list(raw.get("certificates"))),
        "android_certificate_organizations": _unique(_list(raw.get("certificate_organizations"))),
        "android_certificate_name_patterns": _unique(_list(raw.get("certificate_cname_re"))),
        "ios_bundle_ids": _unique(_list(raw.get("ios_bundles"))),
        "websites": _unique(_list(raw.get("websites"))),
        "distribution_domains": _unique(_list(raw.get("distribution"))),
        "c2_domains": _unique(_list(c2.get("domains"))),
        "c2_ips": _unique(_list(c2.get("ips")) + _list(c2.get("ip"))),
        "android_sample_sha256": [],
        "reclaim_city_entries": [],
    }


def build(source_dir: Path, commit: str, commit_date: str, fetched: str) -> dict:
    entries: list[dict] = []
    for source_file in ("ioc.yaml", "watchware.yaml"):
        for raw in yaml.safe_load((source_dir / source_file).read_text()):
            entries.append(_entry(raw, source_file))

    by_alias: dict[str, list[dict]] = {}
    for e in entries:
        for alias in [e["name"], *e["aliases"]]:
            by_alias.setdefault(alias.lower(), []).append(e)

    with open(source_dir / "samples.csv", newline="") as f:
        for row in csv.DictReader(f):
            candidates = by_alias.get(row["App"].lower(), [])
            narrowed = [c for c in candidates if row["Package Name"] in c["android_packages"]]
            for e in narrowed or candidates:
                e["android_sample_sha256"].append(row["SHA256"].lower())

    for e in entries:
        e["android_sample_sha256"] = _unique(e["android_sample_sha256"])
        if e["android_packages"] or e["android_certificates"] or e["android_sample_sha256"]:
            e["platforms"].append("android")
        if e["ios_bundle_ids"]:
            e["platforms"].append("ios")
        if e["source_file"] == "ioc.yaml":
            e["reclaim_city_entries"] = RECLAIM_CITY_ENTRIES.get(e["name"], [])
        elif e["name"] in RECLAIM_CITY_ENTRIES:
            e["reclaim_city_entries"] = RECLAIM_CITY_ENTRIES[e["name"]]

    linked = {e["name"] for e in entries if e["reclaim_city_entries"]}
    missing = set(RECLAIM_CITY_ENTRIES) - linked
    if missing:
        raise SystemExit(f"cross-reference names not in the source: {sorted(missing)}")

    return {
        "source": {
            "name": "Echap stalkerware-indicators",
            "url": SOURCE_URL,
            "commit": commit,
            "commit_date": commit_date,
            "fetched": fetched,
            "files": ["ioc.yaml", "watchware.yaml", "samples.csv"],
            "license": "CC-BY-4.0",
            "license_url": "https://creativecommons.org/licenses/by/4.0/",
            "attribution": (
                "Stalkerware Indicators of Compromise by Echap (https://echap.eu.org/), "
                "maintained by Julien Voisin and Tek, "
                f"{SOURCE_URL}, licensed under CC BY 4.0."
            ),
            "changes": (
                "Converted from YAML and CSV to JSON by scripts/build_stalkerware_indicators.py: "
                "field names changed, duplicate values removed, sample hashes from samples.csv "
                "grouped under each app, and reclaim_city_entries added. Not included: "
                "rules.yar (YARA rules for app files), vendors/ (company details) and "
                "generated/ (other formats of the same indicators)."
            ),
            "disclaimer": (
                "From the source: these indicators are not a complete detection of stalkerware; "
                "no match does not mean no stalkerware is installed."
            ),
        },
        "note": (
            "Reference data only. Every identifier here is for Android or iOS (package names, "
            "signing certificates, bundle ids) or is a domain or IP; none can be seen on a Mac, "
            "Windows or Linux computer, so stalkerware_scan does not match on this file and "
            "nothing in it is ever looked up. 'category' is the source's own: 'stalkerware' or "
            "'watchware' (surveillance that does not hide, like child monitoring). "
            "'reclaim_city_entries' names the known_stalkerware.json entries that detect the "
            "desktop version of the same product."
        ),
        "entries": entries,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--commit-date", required=True)
    parser.add_argument("--fetched", required=True)
    parser.add_argument("--output", type=Path, default=OUTPUT_PATH)
    args = parser.parse_args()
    data = build(args.source_dir, args.commit, args.commit_date, args.fetched)
    args.output.write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n")
    print(f"Wrote {args.output} ({len(data['entries'])} entries)")


if __name__ == "__main__":
    main()
