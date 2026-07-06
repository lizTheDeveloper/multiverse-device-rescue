"""Thin, auditable wrapper around the git operations needed to manage a
local clone of the content repository (module data + guide content).
Every git invocation goes through subprocess with list-form arguments --
no shell=True, ever.

Security note: clone() intentionally uses `git clone --no-checkout` and
never trusts git's own HEAD/default-branch pointer as "the current
content". What this engine considers "currently applied" is tracked
through a small local marker file, written only by checkout() -- which
itself is only ever called after signatures have been verified (see
rescue.update.engine). This means a freshly cloned repo starts with
current_commit() == None: nothing is trusted until this code has actually
verified and applied something, no matter what commit the remote repo's
default branch happens to point at.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path


class GitError(Exception):
    """Raised when a git subprocess invocation fails unexpectedly (not
    counting checks -- like git verify-tag -- where a nonzero exit is an
    expected, meaningful outcome the caller wants to inspect itself)."""


@dataclass(frozen=True)
class CommitInfo:
    sha: str
    author: str
    date: str
    subject: str


class ContentRepo:
    """Wraps the git-backed content repository: module data + guide
    content, versioned and distributed as an ordinary git repo."""

    def __init__(self, local_path: Path, remote_url: str):
        self.local_path = Path(local_path)
        self.remote_url = remote_url

    @property
    def _applied_marker_path(self) -> Path:
        return self.local_path / ".git" / "rescue-applied-head"

    def is_cloned(self) -> bool:
        return (self.local_path / ".git").exists()

    def clone(self) -> None:
        self.local_path.parent.mkdir(parents=True, exist_ok=True)
        self._run_git(
            ["clone", "--no-checkout", self.remote_url, str(self.local_path)],
            cwd=self.local_path.parent,
        )

    def fetch(self, remote: str = "origin") -> None:
        self._run_git(["fetch", remote, "--tags", "--force"])

    def fetch_from_bundle(self, bundle_path: Path, remote: str = "origin") -> None:
        bundle_path = Path(bundle_path).resolve()
        self._run_git(
            ["fetch", str(bundle_path), "--tags", f"+refs/heads/*:refs/remotes/{remote}/*"]
        )

    def set_remote_url(self, url: str, remote: str = "origin") -> None:
        self._run_git(["remote", "set-url", remote, url])

    def current_commit(self) -> str | None:
        """The commit this engine has itself verified and checked out --
        NOT necessarily git's own HEAD. None if nothing has been applied
        yet (e.g. immediately after a fresh clone())."""
        marker = self._applied_marker_path
        if not marker.exists():
            return None
        return marker.read_text().strip()

    def remote_commit(self, ref: str = "origin/main") -> str:
        return self._run_git(["rev-parse", ref]).stdout.strip()

    def log_between(self, old_sha: str, new_sha: str) -> list[CommitInfo]:
        sep = "\x1f"
        fmt = f"%H{sep}%an{sep}%ad{sep}%s"
        result = self._run_git(
            [
                "log",
                "--reverse",
                f"--pretty=format:{fmt}",
                "--date=iso-strict",
                f"{old_sha}..{new_sha}",
            ]
        )
        commits = []
        for line in result.stdout.splitlines():
            if not line:
                continue
            sha, author, date, subject = line.split(sep)
            commits.append(CommitInfo(sha=sha, author=author, date=date, subject=subject))
        return commits

    def tags_at_commit(self, commit_sha: str) -> list[str]:
        result = self._run_git(["tag", "--points-at", commit_sha])
        return [line for line in result.stdout.splitlines() if line]

    def checkout(self, ref: str) -> None:
        """Checks out `ref` into the working tree and records it as the
        newly-applied commit. Callers (rescue.update.engine) must only
        call this after verify_commit_approval() has approved `ref`."""
        self._run_git(["checkout", "--detach", ref])
        resolved = self._run_git(["rev-parse", ref]).stdout.strip()
        self._applied_marker_path.write_text(resolved)

    def read_file_at(self, ref: str, rel_path: str) -> bytes:
        """Reads a file's contents straight out of the git object database
        at `ref`, without requiring that ref to be checked out."""
        result = self._run_git(["show", f"{ref}:{rel_path}"])
        return result.stdout.encode("utf-8")

    def verify_tag_raw(self, tag: str) -> subprocess.CompletedProcess:
        """Runs `git verify-tag --raw <tag>` WITHOUT raising on nonzero
        exit -- an invalid/unsigned/untrusted tag is an expected outcome
        the caller (rescue.update.verify) inspects, not a wrapper failure."""
        return self._run_git_allow_failure(["verify-tag", "--raw", tag])

    def _run_git(self, args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
        result = self._run_git_allow_failure(args, cwd=cwd)
        if result.returncode != 0:
            raise GitError(
                f"git {' '.join(args)} failed (exit {result.returncode}): {result.stderr.strip()}"
            )
        return result

    def _run_git_allow_failure(
        self, args: list[str], cwd: Path | None = None
    ) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["git", *args],
            cwd=str(cwd or self.local_path),
            capture_output=True,
            text=True,
        )
