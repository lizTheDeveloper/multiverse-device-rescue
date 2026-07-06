"""Air-gapped update delivery: apply a signed content-repo update carried
in on a `git bundle` file (e.g. via USB) instead of over the network.

A git bundle packages a set of git objects + refs; git can clone directly
from one (`git clone bundle.bundle dest`) or fetch new refs from one into
an existing clone (`git fetch bundle.bundle ...`), exactly as it would
from any other remote. Sideloading therefore reuses ContentRepo and
UpdateEngine completely unchanged -- the only new code here is (a)
validating the bundle file itself before touching it, and (b) landing its
contents in the same refs/remotes/origin/* namespace a networked
`git fetch origin` would use, so UpdateEngine.status() doesn't need to
know or care whether an update arrived over HTTPS or off a USB stick.
"""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from rescue.update.config import ContentRepoConfig
from rescue.update.repo import ContentRepo


class SideloadError(Exception):
    """Raised when a sideloaded bundle file fails git's own integrity
    check, or the file does not exist. Raised before any of the bundle's
    contents are fetched into the content repo clone."""


def verify_bundle_file(bundle_path: Path, repo_cwd: Path | None = None) -> None:
    """Runs `git bundle verify` on the bundle file. That command must run
    inside *some* git repository; if the content repo isn't cloned yet, a
    throwaway empty repo is created in a temp directory purely so the
    command has somewhere to run (a standalone bundle has no prerequisite
    commits to check against, so an empty repo is sufficient; an existing
    clone is used instead when available so incremental bundles are
    checked against real history)."""
    bundle_path = Path(bundle_path).resolve()
    if not bundle_path.is_file():
        raise SideloadError(f"Bundle file not found: {bundle_path}")

    if repo_cwd is not None and (repo_cwd / ".git").exists():
        result = _run_bundle_verify(bundle_path, repo_cwd)
    else:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            init = subprocess.run(
                ["git", "init", "-q"], cwd=tmp_path, capture_output=True, text=True
            )
            if init.returncode != 0:
                raise SideloadError(
                    f"Could not prepare a scratch repo to verify the bundle: {init.stderr.strip()}"
                )
            result = _run_bundle_verify(bundle_path, tmp_path)

    if result.returncode != 0:
        raise SideloadError(f"Bundle failed verification: {result.stderr.strip()}")


def _run_bundle_verify(bundle_path: Path, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "bundle", "verify", str(bundle_path)],
        cwd=str(cwd),
        capture_output=True,
        text=True,
    )


def load_sideload_repo(bundle_path: Path, config: ContentRepoConfig) -> ContentRepo:
    """Verifies a bundle file, then clones (first run) or fetches (later
    runs) the content repo from it. Returns a ContentRepo ready to hand to
    UpdateEngine -- signature verification and apply happen identically to
    the networked path from this point on."""
    bundle_path = Path(bundle_path).resolve()
    repo = ContentRepo(config.local_path, config.remote_url)
    already_cloned = repo.is_cloned()

    verify_bundle_file(bundle_path, repo_cwd=config.local_path if already_cloned else None)

    if not already_cloned:
        ContentRepo(config.local_path, str(bundle_path)).clone()
        repo.set_remote_url(config.remote_url)
    else:
        repo.fetch_from_bundle(bundle_path)

    return repo
