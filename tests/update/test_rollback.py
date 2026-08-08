"""Tests for one-step content rollback and the bundled-content fallback (P0#2).

The roadmap listed rollback as remaining: recovery was "via git history", which
is not a recovery path for the person this tool is for. These cover both the
happy path and the case that matters more — a previous version that is no
longer trusted must not be silently restored.
"""

from unittest.mock import MagicMock, patch

from rescue.update.config import ContentRepoConfig
from rescue.update.engine import UpdateEngine
from rescue.update.repo import ContentRepo
from rescue.update.verify import ApprovalResult
from rescue.security.signers import TrustedSigner, TrustedSignerSet


def _config(tmp_path):
    return ContentRepoConfig(
        remote_url="https://example.com/content.git",
        local_path=tmp_path / "content",
        trusted_signers_path=tmp_path / "trusted_signers.json",
        revoked_signers_path=tmp_path / "revoked_signers.json",
        required_approvals=2,
    )


def _trusted():
    return TrustedSignerSet(signers=[
        TrustedSigner(signer_id="maintainer-a", key_id="AAAA"),
        TrustedSigner(signer_id="maintainer-b", key_id="BBBB"),
    ])


def _engine(tmp_path, repo):
    return UpdateEngine(_config(tmp_path), repo=repo, trusted_signers=_trusted())


def _approved():
    return ApprovalResult(approved=True, approving_signer_ids=["maintainer-a", "maintainer-b"])


def _rejected(reason="signer revoked"):
    return ApprovalResult(approved=False, approving_signer_ids=[], reason=reason)


# --- ContentRepo marker behaviour -------------------------------------------


def _repo_with_git(tmp_path) -> ContentRepo:
    repo = ContentRepo(tmp_path / "content", "https://example.com/content.git")
    (repo.local_path / ".git").mkdir(parents=True)
    return repo


def test_checkout_records_the_commit_it_replaced(tmp_path):
    repo = _repo_with_git(tmp_path)
    with patch.object(ContentRepo, "_run_git") as run_git:
        run_git.return_value = MagicMock(stdout="old111\n")
        repo.checkout("old111")
        run_git.return_value = MagicMock(stdout="new222\n")
        repo.checkout("new222")

    assert repo.current_commit() == "new222"
    assert repo.previous_applied_commit() == "old111"


def test_first_checkout_records_no_previous_version(tmp_path):
    repo = _repo_with_git(tmp_path)
    with patch.object(ContentRepo, "_run_git") as run_git:
        run_git.return_value = MagicMock(stdout="first1\n")
        repo.checkout("first1")

    assert repo.previous_applied_commit() is None


def test_reapplying_the_same_commit_does_not_lose_the_previous_version(tmp_path):
    """Otherwise a no-op re-apply erases the only record of what was working."""
    repo = _repo_with_git(tmp_path)
    with patch.object(ContentRepo, "_run_git") as run_git:
        run_git.return_value = MagicMock(stdout="old111\n")
        repo.checkout("old111")
        run_git.return_value = MagicMock(stdout="new222\n")
        repo.checkout("new222")
        repo.checkout("new222")

    assert repo.previous_applied_commit() == "old111"


def test_clearing_the_applied_marker_deactivates_content(tmp_path):
    repo = _repo_with_git(tmp_path)
    with patch.object(ContentRepo, "_run_git") as run_git:
        run_git.return_value = MagicMock(stdout="abc123\n")
        repo.checkout("abc123")

    repo.clear_applied_marker()
    assert repo.current_commit() is None
    # Deactivated, not deleted: the previous-version record survives.
    repo.clear_applied_marker()  # idempotent


# --- UpdateEngine.rollback ---------------------------------------------------


def test_rollback_returns_to_the_previous_version(tmp_path):
    repo = MagicMock()
    repo.current_commit.return_value = "new222"
    repo.previous_applied_commit.return_value = "old111"
    engine = _engine(tmp_path, repo)

    with patch("rescue.update.engine.verify_commit_approval", return_value=_approved()), \
         patch.object(UpdateEngine, "_validate_content_commit"), \
         patch.object(UpdateEngine, "_peek_content_version", return_value="2026.07.01"):
        result = engine.rollback()

    assert result.status == "rolled_back"
    assert result.new_commit == "old111"
    repo.checkout.assert_called_once_with("old111")


def test_rollback_dry_run_changes_nothing(tmp_path):
    repo = MagicMock()
    repo.current_commit.return_value = "new222"
    repo.previous_applied_commit.return_value = "old111"
    engine = _engine(tmp_path, repo)

    with patch("rescue.update.engine.verify_commit_approval", return_value=_approved()), \
         patch.object(UpdateEngine, "_peek_content_version", return_value=None):
        result = engine.rollback(dry_run=True)

    assert result.status == "dry_run"
    repo.checkout.assert_not_called()


def test_rollback_with_no_previous_version_says_so(tmp_path):
    repo = MagicMock()
    repo.current_commit.return_value = "only1"
    repo.previous_applied_commit.return_value = None
    engine = _engine(tmp_path, repo)

    result = engine.rollback()

    assert result.status == "no_previous_version"
    assert "--use-bundled" in result.message
    repo.checkout.assert_not_called()


def test_rollback_refuses_a_previous_version_that_is_no_longer_approved(tmp_path):
    """Revocation has to apply to content already on the machine, or it is not
    revocation — it is a note about future downloads."""
    repo = MagicMock()
    repo.current_commit.return_value = "new222"
    repo.previous_applied_commit.return_value = "old111"
    engine = _engine(tmp_path, repo)

    with patch("rescue.update.engine.verify_commit_approval", return_value=_rejected()):
        result = engine.rollback()

    assert result.status == "pending_approval"
    assert "--use-bundled" in result.message
    repo.checkout.assert_not_called()


def test_rollback_validates_the_content_commit_before_checking_it_out(tmp_path):
    repo = MagicMock()
    repo.current_commit.return_value = "new222"
    repo.previous_applied_commit.return_value = "old111"
    engine = _engine(tmp_path, repo)

    with patch("rescue.update.engine.verify_commit_approval", return_value=_approved()), \
         patch.object(UpdateEngine, "_validate_content_commit") as validate, \
         patch.object(UpdateEngine, "_peek_content_version", return_value=None):
        engine.rollback()

    validate.assert_called_once_with("old111")


def test_use_bundled_content_clears_the_marker_without_deleting(tmp_path):
    repo = MagicMock()
    repo.current_commit.return_value = "new222"
    engine = _engine(tmp_path, repo)

    result = engine.use_bundled_content()

    assert result.status == "using_bundled"
    repo.clear_applied_marker.assert_called_once()
    assert "Nothing was deleted" in result.message


def test_use_bundled_content_needs_no_signature_check(tmp_path):
    """The last-resort path must not depend on the trust machinery that may be
    the very thing that has gone wrong."""
    repo = MagicMock()
    repo.current_commit.return_value = "new222"
    engine = _engine(tmp_path, repo)

    with patch("rescue.update.engine.verify_commit_approval") as verify:
        engine.use_bundled_content()

    verify.assert_not_called()
