"""Ties ContentRepo (Task 1) and verify_commit_approval (Task 2) together
into the three operations the CLI needs: refresh() (get new git objects),
status() (decide, without changing anything, whether an approved update
is available), and apply() (actually check it out).

This is also exactly what rescue.update.sideload hands its result to --
an air-gapped update populates the same ContentRepo via a bundle instead
of a network fetch, then goes through this identical status()/apply()
pipeline. There is exactly one place signatures are checked and exactly
one place a checkout happens, regardless of transport.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from rescue.security.signers import (
    RevokedSignerStore,
    TrustedSignerSet,
    load_trusted_signers,
    validate_trusted_signers,
)
from rescue.update.config import ContentRepoConfig
from rescue.update.manifest import ContentManifest, ManifestError, validate_content_paths
from rescue.update.repo import CommitInfo, ContentRepo, GitError
from rescue.update.verify import verify_commit_approval


@dataclass
class UpdateResult:
    status: str  # "up_to_date" | "available" | "pending_approval" | "applied"
    #             | "dry_run" | "rolled_back" | "no_previous_version" | "using_bundled"
    old_commit: str | None
    new_commit: str | None
    commits: list[CommitInfo] = field(default_factory=list)
    content_version: str | None = None
    message: str = ""


class UpdateEngine:
    def __init__(
        self,
        config: ContentRepoConfig,
        repo: ContentRepo | None = None,
        trusted_signers: TrustedSignerSet | None = None,
        revoked_signer_ids: set[str] | None = None,
    ):
        self.config = config
        self.repo = repo or ContentRepo(config.local_path, config.remote_url)
        loaded_default_signers = trusted_signers is None
        self.trusted_signers = trusted_signers or load_trusted_signers(config.trusted_signers_path)
        if loaded_default_signers:
            validate_trusted_signers(self.trusted_signers, config.required_approvals)
        if revoked_signer_ids is not None:
            self.revoked_signer_ids = revoked_signer_ids
        else:
            self.revoked_signer_ids = RevokedSignerStore(
                config.revoked_signers_path
            ).revoked_signer_ids()

    def refresh(self) -> None:
        if not self.repo.is_cloned():
            self.repo.clone()
        else:
            self.repo.fetch()

    def status(self, remote_ref: str = "origin/main") -> UpdateResult:
        """Assumes refresh() (or rescue.update.sideload's bundle fetch) has
        already populated the local clone. old_commit is None the very
        first time -- ContentRepo never trusts a fresh clone's working
        tree, so nothing counts as "current" until this engine has
        verified and applied a commit at least once."""
        old_commit = self.repo.current_commit()
        new_commit = self.repo.remote_commit(remote_ref)

        if old_commit == new_commit:
            return UpdateResult(status="up_to_date", old_commit=old_commit, new_commit=new_commit)

        commits = self.repo.log_between(old_commit, new_commit) if old_commit else []

        approval = verify_commit_approval(
            self.repo,
            new_commit,
            self.trusted_signers,
            self.config.required_approvals,
            self.config.tag_prefix,
            self.revoked_signer_ids,
        )
        if not approval.approved:
            return UpdateResult(
                status="pending_approval",
                old_commit=old_commit,
                new_commit=new_commit,
                commits=commits,
                message=(
                    f"New content is available ({new_commit[:12]}) but is not yet approved "
                    f"by enough maintainers ({approval.reason})."
                ),
            )

        content_version = self._peek_content_version(new_commit)
        return UpdateResult(
            status="available",
            old_commit=old_commit,
            new_commit=new_commit,
            commits=commits,
            content_version=content_version,
            message=f"Approved by: {', '.join(approval.approving_signer_ids)}",
        )

    def apply(self, target: UpdateResult, dry_run: bool = False) -> UpdateResult:
        if target.status != "available":
            raise ValueError(f"Cannot apply an update with status={target.status!r}")

        if dry_run:
            return UpdateResult(
                status="dry_run",
                old_commit=target.old_commit,
                new_commit=target.new_commit,
                commits=target.commits,
                content_version=target.content_version,
                message=f"Would update to {target.new_commit[:12]} ({len(target.commits)} commit(s)).",
            )

        self._validate_content_commit(target.new_commit)
        self.repo.checkout(target.new_commit)
        return UpdateResult(
            status="applied",
            old_commit=target.old_commit,
            new_commit=target.new_commit,
            commits=target.commits,
            content_version=target.content_version,
            message=f"Updated to {target.new_commit[:12]} ({len(target.commits)} commit(s)).",
        )

    def rollback(self, dry_run: bool = False) -> UpdateResult:
        """Return to the content version applied before the current one (P0#2).

        Rollback re-verifies maintainer approval rather than trusting that the
        commit was approved when it was first applied. A signer can be revoked
        between then and now, and the whole point of revocation is that content
        that signer approved stops being trusted — including content already on
        the machine. When that happens the honest answer is not to quietly roll
        forward or back but to say so, and point at
        :meth:`use_bundled_content`, which needs no signatures at all because
        it activates the content that shipped inside the installed package.
        """
        current = self.repo.current_commit()
        previous = self.repo.previous_applied_commit()

        if previous is None or previous == current:
            return UpdateResult(
                status="no_previous_version",
                old_commit=current,
                new_commit=None,
                message=(
                    "No previous content version is recorded on this machine, so there is "
                    "nothing to roll back to. `rescue update --use-bundled` returns to the "
                    "content that shipped with the installed package."
                ),
            )

        approval = verify_commit_approval(
            self.repo,
            previous,
            self.trusted_signers,
            self.config.required_approvals,
            self.config.tag_prefix,
            self.revoked_signer_ids,
        )
        if not approval.approved:
            return UpdateResult(
                status="pending_approval",
                old_commit=current,
                new_commit=previous,
                message=(
                    f"The previous content version ({previous[:12]}) is no longer approved "
                    f"({approval.reason}) — most likely a signer has been revoked since it "
                    "was applied. Refusing to roll back to it. Use "
                    "`rescue update --use-bundled` to fall back to the content that shipped "
                    "with the installed package."
                ),
            )

        content_version = self._peek_content_version(previous)
        if dry_run:
            return UpdateResult(
                status="dry_run",
                old_commit=current,
                new_commit=previous,
                content_version=content_version,
                message=f"Would roll back to {previous[:12]}.",
            )

        self._validate_content_commit(previous)
        self.repo.checkout(previous)
        return UpdateResult(
            status="rolled_back",
            old_commit=current,
            new_commit=previous,
            content_version=content_version,
            message=f"Rolled back to {previous[:12]}.",
        )

    def use_bundled_content(self) -> UpdateResult:
        """Deactivate updated content entirely and use what was installed.

        The escape hatch of last resort, and the only one with no dependency on
        git, on signatures, or on anything an update wrote. Nothing is deleted:
        the checkout stays on disk, so a later `rescue update` can reactivate
        content once whatever went wrong is understood.
        """
        current = self.repo.current_commit()
        self.repo.clear_applied_marker()
        return UpdateResult(
            status="using_bundled",
            old_commit=current,
            new_commit=None,
            message=(
                "Updated content is deactivated. The tool will use the modules, profiles "
                "and guides that shipped with the installed package. Nothing was deleted; "
                "`rescue update` can activate downloaded content again."
            ),
        )

    def _peek_content_version(self, commit_sha: str) -> str | None:
        """Best-effort: read manifest.json's content_version straight out
        of the not-yet-checked-out commit, purely for a nicer status
        message. Never raises -- if manifest.json is missing or malformed
        at that commit, we just omit the version."""
        try:
            data = self.repo.read_file_at(commit_sha, "manifest.json")
            return ContentManifest.from_json_bytes(data).content_version
        except (GitError, ManifestError):
            return None

    def _validate_content_commit(self, commit_sha: str) -> None:
        try:
            manifest = ContentManifest.from_json_bytes(
                self.repo.read_file_at(commit_sha, "manifest.json")
            )
            paths = self.repo.list_files_at(commit_sha)
        except GitError as exc:
            raise ManifestError(f"could not inspect content commit {commit_sha}: {exc}") from exc

        if "manifest.json" not in paths:
            raise ManifestError("content commit is missing manifest.json")
        validate_content_paths([path for path in paths if path != "manifest.json"])
        validate_content_paths([f"modules/{path}" for path in manifest.modules])
        validate_content_paths([f"guides/{path}" for path in manifest.guides])
