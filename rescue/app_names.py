"""App names for bundle ids, read-only.

Permission lists (TCC) name apps by bundle id: ``com.intelliscapesolutions.caffeine``
means nothing to most people, "Caffeine" does. This reads the Info.plist of the
apps in the usual Applications folders (no process is started, nothing is
written) and maps each bundle id to the name the app shows: CFBundleDisplayName,
then CFBundleName, then the ``.app`` folder's name. Anything it can't find keeps
its bundle id, so the evidence is never lost.

These names are chosen by whoever made the app: malware can call itself
"Zoom". So a name is only ever shown next to its bundle id, never instead of
it; control and format characters (bidi overrides, zero-width characters) are
removed; and Apple's own folders are read first, so an app someone installed
can't take over the name of an app that is part of macOS.

The index is built once per process and capped, so a scan stays light.
"""

from __future__ import annotations

import os
import plistlib
import unicodedata

MAX_APPS_PER_DIR = 600
_MAX_NAME = 128

_index_cache: dict[str, str] | None = None


def _default_dirs() -> list[str]:
    # Apple's folders first: the first app found for a bundle id wins, so an
    # app in /Applications can't shadow the name of one that is part of macOS.
    return [
        "/System/Applications",
        "/System/Applications/Utilities",
        "/Applications",
        "/Applications/Utilities",
        os.path.expanduser("~/Applications"),
    ]


def _clean(name) -> str | None:
    """A name fit to show: control and format characters (Unicode Cc/Cf: bidi
    overrides, zero-width characters, NUL...) removed, whitespace collapsed,
    cut to _MAX_NAME. None if nothing is left."""
    if not isinstance(name, str):
        return None
    name = "".join(ch for ch in name if unicodedata.category(ch) not in ("Cc", "Cf"))
    name = " ".join(name.split())[:_MAX_NAME].rstrip()
    return name or None


def _read_app(app_path: str) -> tuple[str | None, str | None]:
    """(bundle id, display name) of an .app bundle, or (None, None)."""
    try:
        with open(os.path.join(app_path, "Contents", "Info.plist"), "rb") as fh:
            info = plistlib.load(fh)
    except Exception:
        return None, None
    if not isinstance(info, dict):
        return None, None
    bid = info.get("CFBundleIdentifier")
    if not isinstance(bid, str) or not bid:
        return None, None
    stem = os.path.basename(app_path.rstrip("/"))
    stem = stem[:-4] if stem.endswith(".app") else stem
    name = _clean(info.get("CFBundleDisplayName")) or _clean(info.get("CFBundleName")) or _clean(stem)
    return bid, name


def build_index(app_dirs: list[str] | None = None) -> dict[str, str]:
    """bundle id -> app name for the apps in app_dirs (first one found wins)."""
    index: dict[str, str] = {}
    for d in app_dirs if app_dirs is not None else _default_dirs():
        try:
            names = sorted(os.listdir(d))[:MAX_APPS_PER_DIR]
        except OSError:
            continue
        for n in names:
            if not n.endswith(".app"):
                continue
            bid, name = _read_app(os.path.join(d, n))
            if bid and name:
                index.setdefault(bid, name)
    return index


def _index() -> dict[str, str]:
    global _index_cache
    if _index_cache is None:
        try:
            _index_cache = build_index()
        except Exception:
            _index_cache = {}
    return _index_cache


def display_name(app: str, index: dict[str, str] | None = None) -> str:
    """The name to show for one entry of a permission list. Falls back to the entry itself."""
    if not isinstance(app, str) or not app:
        return str(app)
    idx = _index() if index is None else index
    if app in idx:
        return idx[app]
    # Some lists name an app by path: ".../Foo.app" or ".../Foo.app/Contents/MacOS/foo".
    marker = app.find(".app/")
    path = app[: marker + 4] if marker != -1 else (app if app.endswith(".app") else None)
    if path and path.startswith("/"):
        _bid, name = _read_app(path)
        if name:
            return name
    return app


def app_rows(apps, index: dict[str, str] | None = None) -> list[dict]:
    """[{"id": entry, "name": name}] for a permission list, one row per distinct
    entry (never merged by name: two apps both called "Zoom" are two rows),
    sorted by name. A name is either cleaned (at most _MAX_NAME) or the entry itself."""
    if not isinstance(apps, (list, tuple)):
        return []
    entries = sorted({a for a in apps if isinstance(a, str) and a and "\0" not in a})
    rows = [{"id": a, "name": display_name(a, index)} for a in entries]
    return sorted(rows, key=lambda r: (r["name"].casefold(), r["id"]))
