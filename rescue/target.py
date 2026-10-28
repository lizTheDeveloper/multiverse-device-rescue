"""A disk mounted somewhere else, read as that disk sees its own paths.

Absolute paths and absolute symlinks on the disk are resolved against its
root, never against the computer doing the checking.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from rescue.models import Platform

MAX_SYMLINK_HOPS = 40


class TargetError(Exception):
    pass


@dataclass(frozen=True)
class Target:
    root: Path
    os: Platform

    def resolve(self, path: str) -> Path:
        """Return the host path for `path` as the target disk sees it.

        Walks component by component, following symlinks inside `root`.
        The final component need not exist.
        """
        pending = path.split("/")
        done: list[str] = []
        hops = 0
        while pending:
            part = pending.pop(0)
            if part in ("", "."):
                continue
            if part == "..":
                if done:
                    done.pop()
                continue
            candidate = self.root.joinpath(*done, part)
            if os.path.islink(candidate):
                hops += 1
                if hops > MAX_SYMLINK_HOPS:
                    raise TargetError(f"Too many symbolic links resolving {path}")
                try:
                    link = os.readlink(candidate)
                except OSError as exc:
                    raise TargetError(f"Cannot read link {part}: {exc}") from exc
                if link.startswith("/"):
                    done = []
                pending = link.split("/") + pending
            else:
                done.append(part)
        return self.root.joinpath(*done)

    def display(self, host_path: Path) -> str:
        """Turn a host path under `root` back into the target's view."""
        try:
            rel = Path(host_path).relative_to(self.root)
        except ValueError as exc:
            raise TargetError(f"{host_path} is not under {self.root}") from exc
        return "/" + "/".join(rel.parts)

    def user_homes(self) -> list[tuple[str, Path]]:
        """(username, home) for root and regular users in the target's passwd."""
        try:
            text = self.resolve("/etc/passwd").read_text(errors="replace")
        except (OSError, TargetError):
            return []
        homes: list[tuple[str, Path]] = []
        for line in text.splitlines():
            fields = line.split(":")
            if len(fields) < 6:
                continue
            name, home = fields[0], fields[5]
            try:
                uid = int(fields[2])
            except ValueError:
                continue
            if uid != 0 and uid < 1000:
                continue
            if not home.startswith("/"):
                continue
            try:
                resolved = self.resolve(home)
            except TargetError:
                continue
            if resolved.is_dir():
                homes.append((name, resolved))
        return homes

    def expand(self, path: str) -> list[Path]:
        """`~/x` gives one path per user home; anything else resolves once."""
        if path.startswith("~/"):
            rest = path[2:]
            return [self._under(home, rest) for _, home in self.user_homes()]
        return [self.resolve(path)]

    def _under(self, home: Path, rest: str) -> Path:
        return self.resolve(self.display(home) + "/" + rest)
