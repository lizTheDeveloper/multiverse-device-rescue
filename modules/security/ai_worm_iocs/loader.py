from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class HashIOC:
    sha256: str
    threat: str
    name: str
    severity: str
    description: str
    source: str


@dataclass(frozen=True)
class PathIOC:
    path: str
    threat: str
    type: str
    severity: str
    platforms: tuple[str, ...]
    description: str
    source: str


@dataclass(frozen=True)
class GitPatternIOC:
    pattern: str
    threat: str
    type: str
    severity: str
    description: str
    source: str


@dataclass(frozen=True)
class MCPServerIOC:
    name: str
    threat: str
    severity: str
    description: str
    source: str


@dataclass
class IOCDatabase:
    version: str
    hashes: dict[str, HashIOC] = field(default_factory=dict)
    domains: set[str] = field(default_factory=set)
    ips: set[str] = field(default_factory=set)
    paths: list[PathIOC] = field(default_factory=list)
    git_patterns: list[GitPatternIOC] = field(default_factory=list)
    mcp_servers: list[MCPServerIOC] = field(default_factory=list)


_cache: IOCDatabase | None = None
_cache_dir: Path | None = None


def _clear_cache() -> None:
    global _cache, _cache_dir
    _cache = None
    _cache_dir = None


def load_iocs(data_dir: Path | None = None) -> IOCDatabase:
    global _cache, _cache_dir
    if data_dir is None:
        data_dir = Path(__file__).parent
    if _cache is not None and _cache_dir == data_dir:
        return _cache

    manifest = _load_json(data_dir / "manifest.json")
    version = manifest.get("version", "unknown")

    db = IOCDatabase(version=version)

    for entry in _load_entries(data_dir / "known_hashes.json"):
        sha = entry["sha256"]
        db.hashes[sha] = HashIOC(
            sha256=sha,
            threat=entry["threat"],
            name=entry.get("name", ""),
            severity=entry["severity"],
            description=entry["description"],
            source=entry["source"],
        )

    for entry in _load_entries(data_dir / "known_domains.json"):
        db.domains.add(entry["domain"])

    for entry in _load_entries(data_dir / "known_ips.json"):
        db.ips.add(entry["ip"])

    for entry in _load_entries(data_dir / "known_paths.json"):
        db.paths.append(
            PathIOC(
                path=entry["path"],
                threat=entry["threat"],
                type=entry.get("type", "unknown"),
                severity=entry["severity"],
                platforms=tuple(entry.get("platforms", ["darwin", "linux", "win32"])),
                description=entry["description"],
                source=entry["source"],
            )
        )

    for entry in _load_entries(data_dir / "known_git_patterns.json"):
        db.git_patterns.append(
            GitPatternIOC(
                pattern=entry["pattern"],
                threat=entry["threat"],
                type=entry.get("type", "unknown"),
                severity=entry["severity"],
                description=entry["description"],
                source=entry["source"],
            )
        )

    for entry in _load_entries(data_dir / "known_mcp_servers.json"):
        db.mcp_servers.append(
            MCPServerIOC(
                name=entry["name"],
                threat=entry["threat"],
                severity=entry["severity"],
                description=entry["description"],
                source=entry["source"],
            )
        )

    _cache = db
    _cache_dir = data_dir
    return db


def _load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    with open(path, "r") as f:
        return json.load(f)


def _load_entries(path: Path) -> list[dict]:
    data = _load_json(path)
    return data.get("entries", [])
