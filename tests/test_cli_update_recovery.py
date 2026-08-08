"""CLI-level tests for the two update-recovery paths.

The property worth a test of its own: `--use-bundled` must work on a machine
whose trusted-signer configuration is broken or unpopulated. That is precisely
the machine that needs to fall back to the content it was installed with, and
an escape hatch that depends on the thing that failed is not an escape hatch.
"""

from unittest.mock import patch

from click.testing import CliRunner

from rescue.cli import main
from rescue.security.signers import TrustConfigurationError
from rescue.update.config import ContentRepoConfig
from rescue.update.engine import UpdateResult


def _config(tmp_path) -> ContentRepoConfig:
    return ContentRepoConfig(
        remote_url="https://example.com/content.git",
        local_path=tmp_path / "content",
        trusted_signers_path=tmp_path / "trusted_signers.json",
        revoked_signers_path=tmp_path / "revoked_signers.json",
        required_approvals=2,
    )


def test_rollback_and_use_bundled_cannot_be_combined(tmp_path):
    with patch("rescue.cli.default_config", return_value=_config(tmp_path)):
        result = CliRunner().invoke(main, ["update", "--rollback", "--use-bundled"])
    assert result.exit_code == 2
    assert "cannot be combined" in result.output


def test_use_bundled_works_without_a_valid_trust_configuration(tmp_path):
    config = _config(tmp_path)
    (config.local_path / ".git").mkdir(parents=True)
    (config.local_path / ".git" / "rescue-applied-head").write_text("abc123")

    with patch("rescue.cli.default_config", return_value=config), \
         patch("rescue.cli.UpdateEngine", side_effect=TrustConfigurationError("placeholder keys")):
        result = CliRunner().invoke(main, ["update", "--use-bundled"])

    assert result.exit_code == 0
    assert "deactivated" in result.output
    # The marker is gone, so runtime.active_content_root() falls back to bundled.
    assert not (config.local_path / ".git" / "rescue-applied-head").exists()
    # And nothing was deleted.
    assert (config.local_path / ".git").is_dir()


def test_rollback_reports_a_broken_trust_configuration_and_points_at_the_fallback(tmp_path):
    with patch("rescue.cli.default_config", return_value=_config(tmp_path)), \
         patch("rescue.cli.UpdateEngine", side_effect=TrustConfigurationError("placeholder keys")):
        result = CliRunner().invoke(main, ["update", "--rollback"])

    assert result.exit_code == 1
    assert "--use-bundled" in result.output


def test_rollback_exits_non_zero_when_there_is_nothing_to_roll_back_to(tmp_path):
    with patch("rescue.cli.default_config", return_value=_config(tmp_path)), \
         patch("rescue.cli.UpdateEngine") as engine_cls:
        engine_cls.return_value.rollback.return_value = UpdateResult(
            status="no_previous_version",
            old_commit="abc123",
            new_commit=None,
            message="No previous content version is recorded on this machine.",
        )
        result = CliRunner().invoke(main, ["update", "--rollback"])

    assert result.exit_code == 1
    assert "No previous content version" in result.output


def test_successful_rollback_reports_the_version_it_returned_to(tmp_path):
    with patch("rescue.cli.default_config", return_value=_config(tmp_path)), \
         patch("rescue.cli.UpdateEngine") as engine_cls:
        engine_cls.return_value.rollback.return_value = UpdateResult(
            status="rolled_back",
            old_commit="new222",
            new_commit="old111",
            message="Rolled back to old111.",
        )
        result = CliRunner().invoke(main, ["update", "--rollback"])

    assert result.exit_code == 0
    assert "Rolled back to old111." in result.output


def test_rollback_dry_run_is_passed_through(tmp_path):
    with patch("rescue.cli.default_config", return_value=_config(tmp_path)), \
         patch("rescue.cli.UpdateEngine") as engine_cls:
        engine_cls.return_value.rollback.return_value = UpdateResult(
            status="dry_run", old_commit="new222", new_commit="old111",
            message="Would roll back to old111.",
        )
        CliRunner().invoke(main, ["update", "--rollback", "--dry-run"])

    engine_cls.return_value.rollback.assert_called_once_with(dry_run=True)
