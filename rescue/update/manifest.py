"""The content repository (module data + guide content) is an ordinary
git repository with this expected layout:

    content-repo/
      manifest.json          # {"content_version", "updated_at", "modules": [...], "guides": [...]}
      modules/<category>/<module>/*.json   # detection signatures, bloatware lists, etc.
      guides/<guide_name>/*.md              # walkthrough content

manifest.json is not itself a security boundary -- git's SHA hashing
already guarantees every file's integrity once a commit is trusted. It
exists purely as a table of contents so the update engine and CLI can
report what changed without walking the whole tree.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from pathlib import PurePosixPath

CONTENT_MANIFEST_FILENAME = "manifest.json"


class ManifestError(Exception):
    """Raised when manifest.json is missing or malformed."""


def validate_content_paths(paths: list[str]) -> None:
    allowed_suffixes = {".json", ".md", ".toml", ".txt", ".yaml", ".yml"}
    for raw_path in paths:
        path = PurePosixPath(raw_path)
        if (
            not raw_path
            or path.is_absolute()
            or ".." in path.parts
            or raw_path == CONTENT_MANIFEST_FILENAME
        ):
            raise ManifestError(f"invalid content path: {raw_path!r}")
        if path.parts[0] not in {"modules", "guides", "profiles"}:
            raise ManifestError(f"content path is outside approved directories: {raw_path}")
        if path.suffix not in allowed_suffixes:
            raise ManifestError(f"content path has unsupported file type: {raw_path}")
        if path.parts[0] == "guides" and path.suffix != ".md":
            raise ManifestError(f"guide content must be Markdown: {raw_path}")
        if path.parts[0] == "profiles" and path.suffix not in {".yaml", ".yml"}:
            raise ManifestError(f"profile content must be YAML: {raw_path}")


@dataclass(frozen=True)
class ContentManifest:
    content_version: str
    updated_at: str
    modules: list[str]
    guides: list[str]

    @staticmethod
    def from_json_bytes(data: bytes) -> "ContentManifest":
        try:
            obj = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ManifestError(f"manifest.json is not valid JSON: {exc}") from exc

        required = ("content_version", "updated_at", "modules", "guides")
        missing = [key for key in required if key not in obj]
        if missing:
            raise ManifestError(f"manifest.json is missing required key(s): {', '.join(missing)}")

        return ContentManifest(
            content_version=obj["content_version"],
            updated_at=obj["updated_at"],
            modules=list(obj["modules"]),
            guides=list(obj["guides"]),
        )


def load_content_manifest(repo_root: Path) -> ContentManifest:
    manifest_path = repo_root / CONTENT_MANIFEST_FILENAME
    if not manifest_path.exists():
        raise ManifestError(f"Content repo is missing {CONTENT_MANIFEST_FILENAME} at {repo_root}")
    return ContentManifest.from_json_bytes(manifest_path.read_bytes())
