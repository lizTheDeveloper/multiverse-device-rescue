import pytest

from rescue.update.config import ContentRepoConfig
from rescue.update.sideload import SideloadError, load_sideload_repo, verify_bundle_file


def _config(tmp_path):
    return ContentRepoConfig(
        remote_url="https://example.com/real-content.git",
        local_path=tmp_path / "content",
        trusted_signers_path=tmp_path / "trusted_signers.json",
        revoked_signers_path=tmp_path / "revoked_signers.json",
    )


def test_verify_bundle_file_raises_when_missing(tmp_path):
    with pytest.raises(SideloadError, match="not found"):
        verify_bundle_file(tmp_path / "does_not_exist.bundle")


def test_verify_bundle_file_accepts_valid_standalone_bundle(tmp_path, make_origin, run_git):
    origin = make_origin()
    bundle_path = tmp_path / "update.bundle"
    run_git(["bundle", "create", str(bundle_path), "--all"], origin)

    verify_bundle_file(bundle_path)  # must not raise


def test_verify_bundle_file_rejects_corrupted_bundle(tmp_path):
    bundle_path = tmp_path / "bad.bundle"
    bundle_path.write_bytes(b"this is not a real git bundle")

    with pytest.raises(SideloadError, match="[Ff]ailed verification"):
        verify_bundle_file(bundle_path)


def test_load_sideload_repo_first_time_clones_and_resets_remote_url(tmp_path, make_origin, run_git):
    origin = make_origin()
    bundle_path = tmp_path / "update.bundle"
    run_git(["bundle", "create", str(bundle_path), "--all"], origin)
    config = _config(tmp_path)

    repo = load_sideload_repo(bundle_path, config)

    assert repo.is_cloned()
    assert repo.remote_commit("origin/main") == run_git(["rev-parse", "HEAD"], origin).strip()
    assert run_git(["remote", "get-url", "origin"], repo.local_path).strip() == config.remote_url


def test_load_sideload_repo_existing_clone_fetches_new_commits(
    tmp_path, make_origin, commit_file, run_git
):
    origin = make_origin()
    config = _config(tmp_path)

    first_bundle = tmp_path / "first.bundle"
    run_git(["bundle", "create", str(first_bundle), "--all"], origin)
    load_sideload_repo(first_bundle, config)

    new_commit = commit_file(
        origin, "modules/bloatware/known_bloatware.json", '{"a": 1}', "Add signatures"
    )
    second_bundle = tmp_path / "second.bundle"
    run_git(["bundle", "create", str(second_bundle), "--all"], origin)

    repo = load_sideload_repo(second_bundle, config)

    assert repo.remote_commit("origin/main") == new_commit
