"""Resolve bundled, installed, and active content directories."""

from __future__ import annotations

import importlib.util
import os
import sys
import sysconfig
from pathlib import Path
from types import ModuleType


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


def load_content_module(relative_path: str | Path, key: str) -> ModuleType | None:
    """Import a helper shipped alongside the modules, by path.

    Modules ship as data files rather than as an importable package (see
    `setup.py`), so a shared helper such as an IOC loader cannot be reached
    with a normal `import`. Loading it by path works in a source checkout, a
    pip install, and a PyInstaller bundle alike.

    Returns None when the helper is missing or fails to execute; every caller
    is expected to degrade to "this check is unavailable" rather than raise.
    """
    existing = sys.modules.get(key)
    if existing is not None:
        return existing

    path = content_file(relative_path)
    try:
        spec = importlib.util.spec_from_file_location(key, path)
        if spec is None or spec.loader is None:
            return None
        module = importlib.util.module_from_spec(spec)
        # Registered before execution: dataclasses defined in the helper look
        # their own module up in sys.modules while being constructed.
        sys.modules[key] = module
        try:
            spec.loader.exec_module(module)
        except Exception:
            del sys.modules[key]
            raise
        return module
    except Exception:
        return None


def content_file(relative_path: str | Path) -> Path:
    """Resolve an updateable data file without allowing updated Python code."""
    relative = Path(relative_path)
    active_root = active_content_root()
    if active_root is not None:
        candidate = active_root / relative
        if candidate.is_file():
            return candidate
    return bundled_root() / relative
