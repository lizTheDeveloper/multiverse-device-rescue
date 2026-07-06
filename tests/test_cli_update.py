from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from rescue.cli import main
from rescue.update.engine import UpdateResult
from rescue.update.repo import CommitInfo, GitError


def _engine_with_status(status, apply_status="applied", apply_message="Updated.", **kwargs):
    engine = MagicMock()
    result = UpdateResult(
        status=status,
        old_commit=kwargs.get("old_commit", "old111"),
        new_commit=kwargs.get("new_commit", "new222"),
        commits=kwargs.get("commits", []),
        content_version=kwargs.get("content_version"),
        message=kwargs.get("message", ""),
    )
    engine.status.return_value = result
    engine.apply.return_value = UpdateResult(
        status=apply_status,
        old_commit=result.old_commit,
        new_commit=result.new_commit,
        message=apply_message,
    )
    return engine


def test_update_reports_up_to_date():
    engine = _engine_with_status("up_to_date")
    with patch("rescue.cli.UpdateEngine", return_value=engine), patch("rescue.cli.default_config"):
        result = CliRunner().invoke(main, ["update"])

    assert result.exit_code == 0
    assert "already up to date" in result.output.lower()
    engine.apply.assert_not_called()


def test_update_check_does_not_apply():
    engine = _engine_with_status(
        "available",
        commits=[CommitInfo(sha="new222", author="A", date="d", subject="Add signatures")],
        content_version="2026.07.10-1",
    )
    with patch("rescue.cli.UpdateEngine", return_value=engine), patch("rescue.cli.default_config"):
        result = CliRunner().invoke(main, ["update", "--check"])

    assert result.exit_code == 0
    assert "2026.07.10-1" in result.output
    engine.apply.assert_not_called()


def test_update_dry_run_previews_without_applying():
    engine = _engine_with_status(
        "available", apply_status="dry_run", apply_message="Would update to new222."
    )
    with patch("rescue.cli.UpdateEngine", return_value=engine), patch("rescue.cli.default_config"):
        result = CliRunner().invoke(main, ["update", "--dry-run"])

    assert result.exit_code == 0
    engine.apply.assert_called_once_with(engine.status.return_value, dry_run=True)
    assert "Would update" in result.output


def test_update_yes_applies_without_prompting():
    engine = _engine_with_status("available")
    with patch("rescue.cli.UpdateEngine", return_value=engine), patch("rescue.cli.default_config"):
        result = CliRunner().invoke(main, ["update", "--yes"])

    assert result.exit_code == 0
    engine.apply.assert_called_once_with(engine.status.return_value, dry_run=False)
    assert "Updated." in result.output


def test_update_without_yes_prompts_and_applies_on_confirm():
    engine = _engine_with_status("available")
    with patch("rescue.cli.UpdateEngine", return_value=engine), patch("rescue.cli.default_config"):
        result = CliRunner().invoke(main, ["update"], input="y\n")

    assert result.exit_code == 0
    engine.apply.assert_called_once_with(engine.status.return_value, dry_run=False)


def test_update_without_yes_cancels_on_decline():
    engine = _engine_with_status("available")
    with patch("rescue.cli.UpdateEngine", return_value=engine), patch("rescue.cli.default_config"):
        result = CliRunner().invoke(main, ["update"], input="n\n")

    assert result.exit_code == 0
    engine.apply.assert_not_called()
    assert "cancelled" in result.output.lower()


def test_update_pending_approval_refuses_to_apply():
    engine = _engine_with_status(
        "pending_approval", message="only 1 of required 2 maintainer approvals"
    )
    with patch("rescue.cli.UpdateEngine", return_value=engine), patch("rescue.cli.default_config"):
        result = CliRunner().invoke(main, ["update"])

    assert result.exit_code != 0
    assert "not enough maintainer approvals" in result.output.lower()
    engine.apply.assert_not_called()


def test_update_sideload_uses_bundle_path(tmp_path):
    bundle_path = tmp_path / "content.bundle"
    bundle_path.write_bytes(b"fake bundle bytes")

    engine = _engine_with_status("available")
    fake_repo = MagicMock()

    with patch("rescue.cli.load_sideload_repo", return_value=fake_repo) as mock_load, \
         patch("rescue.cli.UpdateEngine", return_value=engine), \
         patch("rescue.cli.default_config"):
        result = CliRunner().invoke(main, ["update", "--sideload", str(bundle_path), "--yes"])

    assert result.exit_code == 0
    mock_load.assert_called_once()
    engine.apply.assert_called_once()


def test_update_git_error_reports_failure_and_continues():
    with patch("rescue.cli.UpdateEngine") as MockEngine, patch("rescue.cli.default_config"):
        MockEngine.return_value.refresh.side_effect = GitError("network unreachable")
        result = CliRunner().invoke(main, ["update"])

    assert result.exit_code != 0
    assert "update failed" in result.output.lower()


def test_trust_revoke_persists(tmp_path):
    config = MagicMock(revoked_signers_path=tmp_path / "revoked.json")
    with patch("rescue.cli.default_config", return_value=config):
        result = CliRunner().invoke(
            main, ["trust", "revoke", "maintainer-x", "--reason", "compromised laptop"]
        )

    assert result.exit_code == 0
    assert "revoked" in result.output.lower()


def test_trust_list_revoked_empty(tmp_path):
    config = MagicMock(revoked_signers_path=tmp_path / "revoked.json")
    with patch("rescue.cli.default_config", return_value=config):
        result = CliRunner().invoke(main, ["trust", "list-revoked"])

    assert result.exit_code == 0
    assert "no signers revoked" in result.output.lower()
