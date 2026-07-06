import pytest

from rescue.update.repo import CommitInfo, ContentRepo, GitError


def test_is_cloned_false_before_clone(tmp_path):
    repo = ContentRepo(local_path=tmp_path / "content", remote_url="unused")
    assert not repo.is_cloned()


def test_clone_does_not_check_out_any_files_until_explicitly_applied(tmp_path, make_origin):
    """The security-critical property of this whole plan: cloning fetches
    git objects but must never implicitly trust/apply the remote's
    default branch. Nothing is "current" until checkout() says so."""
    origin = make_origin()
    repo = ContentRepo(local_path=tmp_path / "content", remote_url=str(origin))

    repo.clone()

    assert repo.is_cloned()
    assert not (repo.local_path / "manifest.json").exists()
    assert repo.current_commit() is None


def test_fetch_updates_remote_tracking_ref_without_moving_applied_commit(
    tmp_path, make_origin, commit_file
):
    origin = make_origin()
    repo = ContentRepo(local_path=tmp_path / "content", remote_url=str(origin))
    repo.clone()
    initial_commit = repo.remote_commit("origin/main")
    repo.checkout(initial_commit)
    assert repo.current_commit() == initial_commit

    new_commit = commit_file(
        origin, "modules/bloatware/known_bloatware.json", '{"a": 1}', "Add signatures"
    )

    repo.fetch()

    assert repo.current_commit() == initial_commit  # our applied marker is untouched
    assert repo.remote_commit("origin/main") == new_commit


def test_checkout_moves_working_copy_to_ref_and_records_applied_commit(
    tmp_path, make_origin, commit_file
):
    origin = make_origin()
    repo = ContentRepo(local_path=tmp_path / "content", remote_url=str(origin))
    repo.clone()
    new_commit = commit_file(origin, "guides/six_roses/phase1.md", "# Phase 1", "Add guide")
    repo.fetch()

    repo.checkout(new_commit)

    assert repo.current_commit() == new_commit
    assert (repo.local_path / "guides/six_roses/phase1.md").read_text() == "# Phase 1"


def test_log_between_returns_commits_oldest_first(tmp_path, make_origin, commit_file):
    origin = make_origin()
    repo = ContentRepo(local_path=tmp_path / "content", remote_url=str(origin))
    repo.clone()
    old_commit = repo.remote_commit("origin/main")
    mid_commit = commit_file(origin, "modules/a.json", "{}", "Add a")
    new_commit = commit_file(origin, "modules/b.json", "{}", "Add b")
    repo.fetch()

    commits = repo.log_between(old_commit, new_commit)

    assert [c.sha for c in commits] == [mid_commit, new_commit]
    assert all(isinstance(c, CommitInfo) for c in commits)
    assert commits[1].subject == "Add b"


def test_tags_at_commit_returns_tags_pointing_at_commit(tmp_path, make_origin, commit_file, run_git):
    origin = make_origin()
    new_commit = commit_file(origin, "modules/a.json", "{}", "Add a")
    run_git(["tag", "approved/maintainer-a/1", new_commit], origin)
    run_git(["tag", "approved/maintainer-b/1", new_commit], origin)

    repo = ContentRepo(local_path=tmp_path / "content", remote_url=str(origin))
    repo.clone()
    repo.fetch()

    tags = repo.tags_at_commit(new_commit)

    assert sorted(tags) == ["approved/maintainer-a/1", "approved/maintainer-b/1"]


def test_read_file_at_returns_file_contents_at_ref(tmp_path, make_origin, commit_file, run_git):
    origin = make_origin()
    old_commit = run_git(["rev-parse", "HEAD"], origin).strip()
    new_commit = commit_file(
        origin, "manifest.json",
        '{"content_version": "2", "updated_at": "t", "modules": [], "guides": []}',
        "Bump version",
    )

    repo = ContentRepo(local_path=tmp_path / "content", remote_url=str(origin))
    repo.clone()
    repo.fetch()

    assert b'"content_version": "2"' in repo.read_file_at(new_commit, "manifest.json")
    assert b'"content_version": "1"' in repo.read_file_at(old_commit, "manifest.json")


def test_run_git_raises_giterror_on_invalid_ref(tmp_path, make_origin):
    origin = make_origin()
    repo = ContentRepo(local_path=tmp_path / "content", remote_url=str(origin))
    repo.clone()

    with pytest.raises(GitError):
        repo.remote_commit("origin/does-not-exist")


def test_set_remote_url_changes_origin_url(tmp_path, make_origin, run_git):
    origin = make_origin()
    repo = ContentRepo(local_path=tmp_path / "content", remote_url=str(origin))
    repo.clone()

    repo.set_remote_url("https://example.com/real-content.git")

    url = run_git(["remote", "get-url", "origin"], repo.local_path).strip()
    assert url == "https://example.com/real-content.git"


def test_fetch_from_bundle_updates_origin_tracking_ref(tmp_path, make_origin, commit_file, run_git):
    origin = make_origin()
    repo = ContentRepo(local_path=tmp_path / "content", remote_url=str(origin))
    repo.clone()

    new_commit = commit_file(origin, "modules/a.json", "{}", "Add a")
    bundle_path = tmp_path / "update.bundle"
    run_git(["bundle", "create", str(bundle_path), "--all"], origin)

    repo.fetch_from_bundle(bundle_path)

    assert repo.remote_commit("origin/main") == new_commit
