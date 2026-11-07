"""Backup and sync tools other than Time Machine, read-only.

The Time Machine checks used to say "your Mac is not backing up" on any Mac
without a Time Machine disk, even one that backs up with Arq or Backblaze.
This looks for the other tools so those checks can say what they saw instead.

It only checks whether some names exist: app bundles in the Applications
folders, launchd job files whose name belongs to a tool, and a tool's own
settings folder in the home folder. No process is started, no file is opened,
and nothing under a sync folder is listed, so a scan stays light. The result
holds tool names only, never a path into the person's files.

Finding a tool is not proof that it backs up this Mac (it may be installed and
never set up), so the checks word it as "may be how you back up". Sync tools
(Dropbox, Google Drive, OneDrive, iCloud Drive) are reported apart from
backups: sync copies a deletion everywhere, so it is not a backup.

Only macOS is covered: the checks that use this only run there.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

BACKUP = "backup"
SYNC = "sync"

# The folders a scan looks in. Module-level so the test suite can point them
# at a fake layout (tests/conftest.py points them at empty folders).
ROOT = Path("/")
HOME: Path | None = None

# Cap on names read per folder, so an odd folder with huge numbers of entries
# can't slow a scan.
MAX_ENTRIES = 2000

# name, kind, app bundle names, launchd job-file prefixes (lower case), and
# paths relative to the home folder that exist only once the tool is set up.
_TOOLS: tuple[tuple[str, str, tuple[str, ...], tuple[str, ...], tuple[str, ...]], ...] = (
    ("Backblaze", BACKUP, ("Backblaze.app",), ("com.backblaze.",), ()),
    ("Arq", BACKUP, ("Arq.app", "Arq 7.app", "Arq Agent.app"), ("com.haystacksoftware.arq",), ()),
    ("Carbon Copy Cloner", BACKUP, ("Carbon Copy Cloner.app",), ("com.bombich.ccc",), ()),
    ("SuperDuper!", BACKUP, ("SuperDuper!.app",), ("com.blacey.superduper", "com.shirtpocket."), ()),
    ("ChronoSync", BACKUP, ("ChronoSync.app", "ChronoSync Express.app"), ("com.econtechnologies.",), ()),
    ("CrashPlan", BACKUP, ("CrashPlan.app", "Code42.app", "Code42 CrashPlan.app"),
     ("com.crashplan.", "com.code42."), ()),
    ("IDrive", BACKUP, ("IDrive.app",), ("com.idrive.",), ()),
    ("Acronis", BACKUP,
     ("Acronis True Image.app", "Acronis Cyber Protect Home Office.app"), ("com.acronis.",), ()),
    ("Carbonite", BACKUP, ("Carbonite.app",), ("com.carbonite.",), ()),
    ("restic", BACKUP, (), (), (".config/resticprofile", ".config/autorestic", ".autorestic.yml")),
    ("borg", BACKUP, ("Vorta.app",), ("com.borgbase.",),
     (".config/borg", ".config/borgmatic", ".config/borgmatic.d")),
    ("Kopia", BACKUP, ("KopiaUI.app",), (), (".config/kopia", "Library/Application Support/kopia")),
    ("rclone", BACKUP, (), (), (".config/rclone/rclone.conf",)),
    ("Duplicati", BACKUP, ("Duplicati.app",), ("com.duplicati.",),
     (".config/Duplicati", "Library/Application Support/Duplicati")),
    ("Dropbox", SYNC, ("Dropbox.app",), (), ("Library/CloudStorage/Dropbox", ".dropbox")),
    ("Google Drive", SYNC, ("Google Drive.app", "Backup and Sync.app"), (), ()),
    ("OneDrive", SYNC, ("OneDrive.app",), (), ()),
    ("iCloud Drive", SYNC, (), (), ("Library/Mobile Documents/com~apple~CloudDocs",)),
)
# Command-line backup tools have no vendor label: a scheduled job for one is
# named by whoever set it up (com.me.restic-nightly, homebrew.mxcl.borgmatic).
# A word of the job's file name that starts with one of these counts, so
# "borgmatic" matches borg but "cyborg" does not.
_JOB_WORDS = {"restic": "restic", "autorestic": "restic", "borg": "borg", "kopia": "Kopia",
              "rclone": "rclone", "duplicati": "Duplicati"}
# Sync folders whose names carry the account (Library/CloudStorage/OneDrive-Personal...).
_CLOUD_STORAGE_PREFIXES = (("Dropbox", "Dropbox"), ("GoogleDrive", "Google Drive"), ("OneDrive", "OneDrive"))


def _home() -> Path:
    return HOME if HOME is not None else Path(os.path.expanduser("~"))


def _names(folder: Path) -> set[str]:
    """The entry names in a folder (at most MAX_ENTRIES), or an empty set."""
    names: set[str] = set()
    try:
        with os.scandir(folder) as it:
            for entry in it:
                names.add(entry.name)
                if len(names) >= MAX_ENTRIES:
                    break
    except OSError:
        pass
    return names


def _exists(path: Path) -> bool:
    try:
        os.lstat(path)
        return True
    except (OSError, ValueError):
        return False


def detect() -> list[dict]:
    """Backup and sync tools that look installed or set up on this Mac.

    Each is ``{"name": ..., "kind": "backup" | "sync"}``, sorted backups first,
    then by name. Never raises; anything unreadable counts as not found.
    """
    home = _home()
    app_dirs = (ROOT / "Applications", ROOT / "Applications" / "Utilities", home / "Applications")
    apps = set().union(*(_names(d) for d in app_dirs))
    jobs = {
        n.lower()
        for d in (home / "Library/LaunchAgents", ROOT / "Library/LaunchAgents", ROOT / "Library/LaunchDaemons")
        for n in _names(d)
        if n.lower().endswith(".plist")
    }
    cloud = _names(home / "Library/CloudStorage")

    found: dict[str, str] = {}
    for name, kind, bundles, prefixes, configs in _TOOLS:
        if (
            any(b in apps for b in bundles)
            or any(j.startswith(p) for j in jobs for p in prefixes)
            or any(_exists(home / c) for c in configs)
        ):
            found[name] = kind
    for job in jobs:
        for word in re.split(r"[^a-z0-9]+", job[: -len(".plist")]):
            for start, name in _JOB_WORDS.items():
                if word.startswith(start):
                    found[name] = BACKUP
    for prefix, name in _CLOUD_STORAGE_PREFIXES:
        if any(c.startswith(prefix) for c in cloud):
            found[name] = SYNC
    return sorted(({"name": n, "kind": k} for n, k in found.items()),
                  key=lambda t: (t["kind"] != BACKUP, t["name"].lower()))


def names(tools: list[dict], kind: str) -> list[str]:
    """The names of the tools of one kind, in order."""
    return [t["name"] for t in tools if t.get("kind") == kind]


def join(items: list[str]) -> str:
    """'Arq', 'Arq and Backblaze', 'Arq, Backblaze and Dropbox'."""
    if len(items) <= 1:
        return "".join(items)
    return f"{', '.join(items[:-1])} and {items[-1]}"
