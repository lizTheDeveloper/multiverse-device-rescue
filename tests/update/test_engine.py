from unittest.mock import MagicMock, patch

import pytest

from rescue.security.signers import TrustedSigner, TrustedSignerSet
from rescue.update.config import ContentRepoConfig
from rescue.update.engine import UpdateEngine, UpdateResult
from rescue.update.repo import CommitInfo
from rescue.update.verify import ApprovalResult


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


def test_refresh_clones_when_not_yet_cloned(tmp_path):
    repo = MagicMock()
    repo.is_cloned.return_value = False
    engine = UpdateEngine(_config(tmp_path), repo=repo, trusted_signers=_trusted())

    engine.refresh()

    repo.clone.assert_called_once()
    repo.fetch.assert_not_called()


def test_refresh_fetches_when_already_cloned(tmp_path):
    repo = MagicMock()
    repo.is_cloned.return_value = True
    engine = UpdateEngine(_config(tmp_path), repo=repo, trusted_signers=_trusted())

    engine.refresh()

    repo.fetch.assert_called_once()
    repo.clone.assert_not_called()


def test_status_up_to_date(tmp_path):
    repo = MagicMock()
    repo.current_commit.return_value = "abc123"
    repo.remote_commit.return_value = "abc123"
    engine = UpdateEngine(_config(tmp_path), repo=repo, trusted_signers=_trusted())

    result = engine.status()

    assert result.status == "up_to_date"
    assert result.old_commit == result.new_commit == "abc123"


def test_status_first_clone_has_no_old_commit(tmp_path):
    repo = MagicMock()
    repo.current_commit.return_value = None
    repo.remote_commit.return_value = "new222"
    repo.tags_at_commit.return_value = []
    engine = UpdateEngine(_config(tmp_path), repo=repo, trusted_signers=_trusted())

    result = engine.status()

    assert result.old_commit is None
    repo.log_between.assert_not_called()


def test_status_pending_approval_when_threshold_not_met(tmp_path):
    repo = MagicMock()
    repo.current_commit.return_value = "old111"
    repo.remote_commit.return_value = "new222"
    repo.log_between.return_value = [
        CommitInfo(sha="new222", author="A", date="d", subject="Add signatures")
    ]

    with patch(
        "rescue.update.engine.verify_commit_approval",
        return_value=ApprovalResult(
            approved=False,
            approving_signer_ids=["maintainer-a"],
            reason="only 1 of required 2 maintainer approvals",
        ),
    ):
        engine = UpdateEngine(_config(tmp_path), repo=repo, trusted_signers=_trusted())
        result = engine.status()

    assert result.status == "pending_approval"
    assert "only 1 of required 2" in result.message
    assert result.commits[0].subject == "Add signatures"


def test_status_available_when_approved(tmp_path):
    repo = MagicMock()
    repo.current_commit.return_value = "old111"
    repo.remote_commit.return_value = "new222"
    repo.log_between.return_value = [
        CommitInfo(sha="new222", author="A", date="d", subject="Add signatures")
    ]
    repo.read_file_at.return_value = (
        b'{"content_version": "2026.07.10-1", "updated_at": "t", "modules": [], "guides": []}'
    )

    with patch(
        "rescue.update.engine.verify_commit_approval",
        return_value=ApprovalResult(
            approved=True, approving_signer_ids=["maintainer-a", "maintainer-b"]
        ),
    ):
        engine = UpdateEngine(_config(tmp_path), repo=repo, trusted_signers=_trusted())
        result = engine.status()

    assert result.status == "available"
    assert result.content_version == "2026.07.10-1"
    assert "maintainer-a" in result.message and "maintainer-b" in result.message


def test_apply_dry_run_does_not_checkout(tmp_path):
    repo = MagicMock()
    engine = UpdateEngine(_config(tmp_path), repo=repo, trusted_signers=_trusted())
    target = UpdateResult(status="available", old_commit="old111", new_commit="new222", commits=[])

    result = engine.apply(target, dry_run=True)

    assert result.status == "dry_run"
    repo.checkout.assert_not_called()


def test_apply_checks_out_target_commit(tmp_path):
    repo = MagicMock()
    engine = UpdateEngine(_config(tmp_path), repo=repo, trusted_signers=_trusted())
    target = UpdateResult(status="available", old_commit="old111", new_commit="new222", commits=[])

    result = engine.apply(target)

    assert result.status == "applied"
    repo.checkout.assert_called_once_with("new222")


def test_apply_raises_if_target_not_available(tmp_path):
    repo = MagicMock()
    engine = UpdateEngine(_config(tmp_path), repo=repo, trusted_signers=_trusted())
    target = UpdateResult(status="pending_approval", old_commit="old111", new_commit="new222", commits=[])

    with pytest.raises(ValueError):
        engine.apply(target)
