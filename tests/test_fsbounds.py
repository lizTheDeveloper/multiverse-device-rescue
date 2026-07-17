"""Tests for bounded filesystem traversal."""

from rescue.fsbounds import WalkLimits, bounded_walk


def _make_tree(root, depth, files_per_dir=2):
    root.mkdir(parents=True, exist_ok=True)
    for i in range(files_per_dir):
        (root / f"f{i}.txt").write_text("x")
    if depth > 0:
        _make_tree(root / "sub", depth - 1, files_per_dir)


def test_walk_yields_files(tmp_path):
    _make_tree(tmp_path, depth=1)
    files = list(bounded_walk([tmp_path]))
    assert all(f.is_file() for f in files)
    assert len(files) == 4  # 2 at root + 2 in sub


def test_max_depth_limits_recursion(tmp_path):
    _make_tree(tmp_path, depth=3)
    files = list(bounded_walk([tmp_path], WalkLimits(max_depth=0)))
    # depth 0 = only the root directory's own files
    assert len(files) == 2


def test_max_files_stops_early(tmp_path):
    _make_tree(tmp_path, depth=5, files_per_dir=3)
    files = list(bounded_walk([tmp_path], WalkLimits(max_files=4)))
    assert len(files) == 4


def test_deadline_stops_walk(tmp_path):
    _make_tree(tmp_path, depth=3)
    # A deadline already in the past yields nothing.
    limits = WalkLimits(deadline_s=-1.0)
    files = list(bounded_walk([tmp_path], limits))
    assert files == []


def test_missing_root_is_skipped_not_fatal(tmp_path):
    _make_tree(tmp_path / "real", depth=0)
    files = list(bounded_walk([tmp_path / "does_not_exist", tmp_path / "real"]))
    assert len(files) == 2


def test_symlinks_not_followed_by_default(tmp_path):
    _make_tree(tmp_path / "real", depth=0)
    link = tmp_path / "link"
    link.symlink_to(tmp_path / "real")
    files = list(bounded_walk([tmp_path]))
    # Only the real dir's files, not traversed again through the symlink.
    assert len(files) == 2
