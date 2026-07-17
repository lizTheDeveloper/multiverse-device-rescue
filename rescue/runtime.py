"""Resolve bundled, installed, and active content directories."""

from __future__ import annotations

import os
import sys
import sysconfig
from pathlib import Path


ASSET_DIRECTORY_NAME = "multiverse-device-rescue"


def bundled_root() -> Path:
    """Return the immutable root containing bundled module code and assets."""
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS)

    source_root = Path(__file__).parent.parent
    if (source_root / "modules").is_dir():
        return source_root

    override = os.environ.get("RESCUE_ASSETS_DIR")
    if override:
        return Path(override)

    return Path(sysconfig.get_path("data")) / "share" / ASSET_DIRECTORY_NAME


def active_content_root() -> Path | None:
    """Return the verified content checkout only after it has been applied."""
    override = os.environ.get("RESCUE_CONTENT_DIR")
    root = Path(override) if override else Path.home() / ".local" / "share" / "rescue" / "content"
    if not (root / ".git" / "rescue-applied-head").is_file():
        return None
    if not (root / "manifest.json").is_file():
        return None
    return root


def content_directory(name: str) -> Path:
    """Prefer applied content for data-only directories, else use bundled assets."""
    active_root = active_content_root()
    if active_root is not None:
        candidate = active_root / name
        if candidate.is_dir():
            return candidate
    return bundled_root() / name


def content_file(relative_path: str | Path) -> Path:
    """Resolve an updateable data file without allowing updated Python code."""
    relative = Path(relative_path)
    active_root = active_content_root()
    if active_root is not None:
        candidate = active_root / relative
        if candidate.is_file():
            return candidate
    return bundled_root() / relative
