"""Bounded filesystem traversal.

Several modules scan user configuration or home directories recursively with no
limit on depth, file count, or time. On a real machine that can wander into huge
or pathological trees and stall a rescue session. :func:`bounded_walk` yields
regular files while enforcing hard limits and stopping cleanly when any is hit.
"""

from __future__ import annotations

import os
import stat
import time
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path


def is_file_nofollow(path: Path | str) -> bool:
    """True if ``path`` is a regular file, without following a final symlink.

    ``Path.is_file(follow_symlinks=False)`` only exists from Python 3.13, but
    this package supports 3.11, where passing that keyword raises TypeError.
    ``os.lstat`` gives the same no-follow semantics on every supported version.
    Returns False rather than raising for a missing or unreadable path, matching
    how ``Path.is_file`` swallows OSError.
    """
    try:
        return stat.S_ISREG(os.lstat(path).st_mode)
    except (OSError, ValueError):
        return False


def is_dir_nofollow(path: Path | str) -> bool:
    """True if ``path`` is a directory, without following a final symlink.

    The no-follow counterpart of :func:`is_file_nofollow`; see its note on why
    ``Path.is_dir(follow_symlinks=False)`` cannot be used here.
    """
    try:
        return stat.S_ISDIR(os.lstat(path).st_mode)
    except (OSError, ValueError):
        return False


@dataclass
class WalkLimits:
    """Hard bounds for a traversal.

    ``max_depth`` is measured from each supplied root: depth 0 visits only the
    files directly inside a root. ``deadline_s`` is a wall-clock budget in
    seconds counted from the start of the walk; a non-positive value stops
    immediately.
    """

    max_depth: int = 6
    max_files: int = 50_000
    max_bytes: int | None = None
    deadline_s: float | None = 30.0
    follow_symlinks: bool = False


def bounded_walk(
    roots: Sequence[Path | str],
    limits: WalkLimits | None = None,
) -> Iterator[Path]:
    """Yield regular files under ``roots`` without exceeding ``limits``.

    Missing or unreadable roots are skipped rather than raising. Traversal stops
    as soon as any limit (file count, byte total, depth, or deadline) is
    reached.
    """
    limits = limits or WalkLimits()
    start = time.monotonic()
    files_seen = 0
    bytes_seen = 0

    def deadline_passed() -> bool:
        if limits.deadline_s is None:
            return False
        return (time.monotonic() - start) >= limits.deadline_s

    for raw_root in roots:
        root = Path(raw_root)
        if not root.is_dir():
            continue
        stack: list[tuple[Path, int]] = [(root, 0)]
        while stack:
            if deadline_passed() or files_seen >= limits.max_files:
                return
            current, depth = stack.pop()
            try:
                entries = list(os.scandir(current))
            except OSError:
                continue
            for entry in entries:
                if deadline_passed() or files_seen >= limits.max_files:
                    return
                try:
                    is_dir = entry.is_dir(follow_symlinks=limits.follow_symlinks)
                    is_file = entry.is_file(follow_symlinks=limits.follow_symlinks)
                except OSError:
                    continue
                if is_dir:
                    if depth < limits.max_depth:
                        stack.append((Path(entry.path), depth + 1))
                elif is_file:
                    files_seen += 1
                    if limits.max_bytes is not None:
                        try:
                            bytes_seen += entry.stat(
                                follow_symlinks=limits.follow_symlinks
                            ).st_size
                        except OSError:
                            pass
                        if bytes_seen > limits.max_bytes:
                            yield Path(entry.path)
                            return
                    yield Path(entry.path)
