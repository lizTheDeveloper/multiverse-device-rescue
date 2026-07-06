"""Launch-time self-integrity check: a SHA-256 manifest of the tool's own
installed .py files, computed once at release time and shipped alongside
the package, recomputed and compared on every launch. Detects a tampered
or partially-replaced installation without needing any network access or
trust in anything beyond the local filesystem.

Scope: only rescue/**/*.py is covered. Module data (modules/*/data/*.json)
and guide content (guides/**/*.md) are deliberately excluded -- those are
exactly the files rescue.update is designed to legitimately change, so
hashing them would make every successful content update look like
tampering.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_INTEGRITY_MANIFEST_PATH = Path(__file__).parent / "integrity_manifest.json"
DEFAULT_PATTERNS = ("**/*.py",)


@dataclass(frozen=True)
class IntegrityManifest:
    files: dict[str, str]  # relative path (posix) -> sha256 hex

    def to_json_bytes(self) -> bytes:
        return json.dumps({"files": self.files}, indent=2, sort_keys=True).encode("utf-8")

    @staticmethod
    def from_json_bytes(data: bytes) -> "IntegrityManifest":
        obj = json.loads(data.decode("utf-8"))
        return IntegrityManifest(files=dict(obj["files"]))


@dataclass
class IntegrityCheckResult:
    ok: bool
    tampered: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    added: list[str] = field(default_factory=list)


def compute_package_manifest(
    package_root: Path, patterns: tuple[str, ...] = DEFAULT_PATTERNS
) -> IntegrityManifest:
    package_root = Path(package_root)
    files: dict[str, str] = {}
    for pattern in patterns:
        for path in sorted(package_root.glob(pattern)):
            if not path.is_file():
                continue
            rel = path.relative_to(package_root).as_posix()
            files[rel] = _hash_file(path)
    return IntegrityManifest(files=files)


def verify_package_integrity(package_root: Path, manifest: IntegrityManifest) -> IntegrityCheckResult:
    package_root = Path(package_root)
    tampered = []
    missing = []

    for rel, expected_hash in sorted(manifest.files.items()):
        path = package_root / rel
        try:
            actual_hash = _hash_file(path)
        except OSError:
            missing.append(rel)
            continue
        if actual_hash != expected_hash:
            tampered.append(rel)

    current = compute_package_manifest(package_root)
    added = sorted(set(current.files) - set(manifest.files))

    return IntegrityCheckResult(
        ok=not tampered and not missing,
        tampered=tampered,
        missing=missing,
        added=added,
    )


def write_integrity_manifest(package_root: Path, output_path: Path) -> None:
    """Release-time tool: (re)generate the shipped integrity manifest
    after intentional code changes. Never called by the running tool."""
    manifest = compute_package_manifest(package_root)
    output_path.write_bytes(manifest.to_json_bytes())


def _hash_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()
