"""Loader for the shared cryptojacking IOC data files.

Mirrors ``modules/security/ai_worm_iocs/loader.py``: parsed data is cached
per data directory so repeated module runs re-use one parse, and a missing
file degrades to an empty list rather than raising.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class MinerIOC:
    pattern: str
    name: str
    family: str
    severity: str
    platforms: tuple[str, ...]
    description: str


@dataclass(frozen=True)
class PoolIOC:
    domain: str
    coin: str
    severity: str
    description: str


@dataclass(frozen=True)
class BrowserScriptIOC:
    value: str
    severity: str
    description: str


@dataclass(frozen=True)
class BrowserExtensionIOC:
    name: str
    severity: str
    description: str


@dataclass
class CryptojackingIOCs:
    version: str
    miners: list[MinerIOC] = field(default_factory=list)
    pools: list[PoolIOC] = field(default_factory=list)
    pool_ports: tuple[int, ...] = ()
    browser_script_domains: list[BrowserScriptIOC] = field(default_factory=list)
    browser_script_markers: list[BrowserScriptIOC] = field(default_factory=list)
    browser_extensions: list[BrowserExtensionIOC] = field(default_factory=list)

    def miners_for(self, platform: str) -> list[MinerIOC]:
        return [m for m in self.miners if platform in m.platforms]


_cache: CryptojackingIOCs | None = None
_cache_dir: Path | None = None


def _clear_cache() -> None:
    global _cache, _cache_dir
    _cache = None
    _cache_dir = None


def load_cryptojacking_iocs(data_dir: Path | None = None) -> CryptojackingIOCs:
    global _cache, _cache_dir
    if data_dir is None:
        data_dir = Path(__file__).parent
    if _cache is not None and _cache_dir == data_dir:
        return _cache

    manifest = _load_json(data_dir / "manifest.json")
    db = CryptojackingIOCs(version=manifest.get("version", "unknown"))

    for entry in _load_entries(data_dir / "known_miners.json"):
        db.miners.append(
            MinerIOC(
                pattern=entry["pattern"],
                name=entry.get("name", entry["pattern"]),
                family=entry.get("family", "generic"),
                severity=entry.get("severity", "warning"),
                platforms=tuple(entry.get("platforms", ["darwin", "linux", "win32"])),
                description=entry.get("description", ""),
            )
        )

    pools_data = _load_json(data_dir / "known_pools.json")
    db.pool_ports = tuple(pools_data.get("ports", []))
    for entry in pools_data.get("entries", []):
        db.pools.append(
            PoolIOC(
                domain=entry["domain"],
                coin=entry.get("coin", "unknown"),
                severity=entry.get("severity", "warning"),
                description=entry.get("description", ""),
            )
        )

    browser_data = _load_json(data_dir / "browser_miners.json")
    for entry in browser_data.get("script_domains", []):
        db.browser_script_domains.append(
            BrowserScriptIOC(
                value=entry["domain"],
                severity=entry.get("severity", "warning"),
                description=entry.get("description", ""),
            )
        )
    for entry in browser_data.get("script_markers", []):
        db.browser_script_markers.append(
            BrowserScriptIOC(
                value=entry["marker"],
                severity=entry.get("severity", "warning"),
                description=entry.get("description", ""),
            )
        )
    for entry in browser_data.get("extensions", []):
        db.browser_extensions.append(
            BrowserExtensionIOC(
                name=entry["name"],
                severity=entry.get("severity", "warning"),
                description=entry.get("description", ""),
            )
        )

    _cache = db
    _cache_dir = data_dir
    return db


def _load_json(path: Path) -> dict:
    try:
        if not path.exists():
            return {}
        with open(path, "r") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _load_entries(path: Path) -> list[dict]:
    return _load_json(path).get("entries", [])
