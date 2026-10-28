"""Describe a Linux disk mounted somewhere else, from the files on that disk.

Nothing here asks the running computer anything; every source is read through
the Target so absolute paths and links stay inside the disk.
"""

from __future__ import annotations

import os

from rescue.models import Platform, SystemProfile
from rescue.target import Target

_INSTALLED = "install ok installed"
# A desktop's dpkg status runs to several MB.
DPKG_STATUS_LIMIT = 64 * 1024 * 1024


def _read(target: Target, path: str, limit: int = 1_000_000) -> str:
    try:
        return target.read_text(path, limit)
    except OSError:
        return ""


def _listdir(target: Target, path: str) -> list[str]:
    try:
        return sorted(os.listdir(target.resolve(path)))
    except OSError:
        return []


def _os_release(target: Target) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in _read(target, "/etc/os-release").splitlines():
        key, sep, value = line.partition("=")
        if sep:
            values[key.strip()] = value.strip().strip("\"'")
    return values


def _dpkg_packages(target: Target) -> set[str]:
    names: set[str] = set()
    text = _read(target, "/var/lib/dpkg/status", DPKG_STATUS_LIMIT)
    blocks = text.split("\n\n")
    try:
        too_big = os.path.getsize(target.resolve("/var/lib/dpkg/status")) > DPKG_STATUS_LIMIT
    except OSError:
        too_big = False
    if too_big:
        blocks = blocks[:-1]  # the last record may be cut off
    for block in blocks:
        name = ""
        installed = False
        for line in block.splitlines():
            if line.startswith("Package:"):
                name = line.partition(":")[2].strip()
            elif line.startswith("Status:"):
                installed = line.partition(":")[2].strip().endswith(_INSTALLED)
        if name and installed:
            names.add(name)
    return names


def _snap_names(target: Target) -> set[str]:
    names = set()
    for entry in _listdir(target, "/var/lib/snapd/snaps"):
        if entry.endswith(".snap"):
            names.add(entry[: -len(".snap")].rpartition("_")[0] or entry[: -len(".snap")])
    return names


def _startup_items(target: Target) -> list[str]:
    items: list[str] = []
    for wants in _listdir(target, "/etc/systemd/system"):
        if not wants.endswith(".wants"):
            continue
        directory = f"/etc/systemd/system/{wants}"
        items.extend(f"{directory}/{entry}" for entry in _listdir(target, directory))
    return sorted(items)


def gather_linux_target_profile(target: Target) -> SystemProfile:
    release = _os_release(target)
    software = (
        _dpkg_packages(target)
        | set(_listdir(target, "/var/lib/flatpak/app"))
        | _snap_names(target)
    )
    return SystemProfile(
        platform=Platform.LINUX,
        os_name=release.get("PRETTY_NAME") or "Linux",
        os_version=release.get("VERSION_ID", ""),
        architecture="",
        cpu_model="",
        cpu_cores=0,
        ram_bytes=0,
        disks=[],
        processes=[],
        startup_items=_startup_items(target),
        installed_software=sorted(software),
        hostname=_read(target, "/etc/hostname").strip(),
        target=target,
    )
