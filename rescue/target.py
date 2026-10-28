"""A disk mounted somewhere else, read as that disk sees its own paths.

Absolute paths and absolute symlinks on the disk are resolved against its
root, never against the computer doing the checking.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from rescue.models import Platform

MAX_SYMLINK_HOPS = 40


class TargetError(OSError):
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
        result = self.root.joinpath(*done)
        root_s = os.path.normpath(str(self.root))
        result_s = os.path.normpath(str(result))
        if os.path.commonpath([root_s, result_s]) != root_s:
            raise TargetError(f"{path} resolved outside {self.root}")
        return result

    def read_text(self, path: str, limit: int = 1_000_000) -> str:
        """Read at most `limit` bytes of a regular file on the target.

        The disk is untrusted: a FIFO or device node at the path would block
        or misbehave, so anything but a regular file is refused.
        """
        host = self.resolve(path)
        try:
            if not stat.S_ISREG(os.stat(host).st_mode):
                raise TargetError(f"{path} is not a regular file")
            fd = os.open(host, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
        except TargetError:
            raise
        except OSError as exc:
            raise TargetError(f"Cannot read {path}: {exc}") from exc
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise TargetError(f"{path} is not a regular file")
            chunks = []
            left = limit
            while left > 0:
                chunk = os.read(fd, left)  # FUSE/NTFS mounts may return short
                if not chunk:
                    break
                chunks.append(chunk)
                left -= len(chunk)
            data = b"".join(chunks)
        except TargetError:
            raise
        except OSError as exc:
            raise TargetError(f"Cannot read {path}: {exc}") from exc
        finally:
            os.close(fd)
        return data.decode("utf-8", errors="replace")

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
            text = self.read_text("/etc/passwd")
        except OSError:
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
            paths = []
            for _, home in self.user_homes():
                try:
                    paths.append(self._under(home, rest))
                except TargetError:
                    continue
            return paths
        return [self.resolve(path)]

    def expand_views(self, path: str) -> list[tuple[str, Path]]:
        """Like `expand`, but pair each host path with the path as the disk shows it.

        The view string is not resolved, so a symlinked `~/.bashrc` is still
        `/home/sam/.bashrc` (what the person would see), while the host path
        is where its contents actually live.
        """
        if path.startswith("~/"):
            rest = path[2:]
            pairs = []
            for _, home in self.user_homes():
                view = self.display(home).rstrip("/") + "/" + rest
                try:
                    pairs.append((view, self.resolve(view)))
                except TargetError:
                    continue
            return pairs
        return [(path, self.resolve(path))]

    def _under(self, home: Path, rest: str) -> Path:
        return self.resolve(self.display(home) + "/" + rest)
