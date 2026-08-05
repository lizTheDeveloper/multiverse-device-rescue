import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules

# du -sk reports 1024-byte blocks, so sizes below are expressed in blocks.
BLOCKS_PER_GB = 1024**3 // 1024
SMALL = 1 * BLOCKS_PER_GB  # under both thresholds
BIG_USER = 60 * BLOCKS_PER_GB  # over the 50 GB user-profile threshold
BIG_LIBRARY = 12 * BLOCKS_PER_GB  # over the 10 GB Library threshold
MID_USER = 20 * BLOCKS_PER_GB  # under the user threshold


def _make_profile():
    return SystemProfile(
        platform=Platform.DARWIN,
        os_name="macOS",
        os_version="15.2",
        architecture="arm64",
        cpu_model="Apple M2",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


@pytest.fixture
def tree(tmp_path):
    """A fake /Users tree plus a fake home directory.

    The module walks the real filesystem, so the test supplies a fixture tree
    and points the module's roots at it. Nothing here depends on the host OS —
    these tests must pass on Linux CI as well as macOS.
    """
    users = tmp_path / "Users"
    home = users / "alice"
    for name in ("alice", "bob"):
        (users / name).mkdir(parents=True)
    # Directories the module is expected to skip.
    (users / "Shared").mkdir()
    (users / "Guest").mkdir()
    (users / ".hidden").mkdir()
    # A plain file must not be mistaken for a user profile.
    (users / "notadir").write_text("")
    for sub in ("Library", "Desktop", "Documents", "Downloads"):
        (home / sub).mkdir()
    return {"users": users, "home": home}


def _get_module(tree):
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    mod = next(m for m in modules if m.name == "user_profile_size")
    mod.users_root = tree["users"]
    mod.home_root = tree["home"]
    return mod


def _fake_du(tree, user_blocks=SMALL, library_blocks=SMALL, subdir_blocks=SMALL):
    """Fake `du -sk <path>` that dispatches on the path it is asked about."""
    users_root = tree["users"]

    def fake_run(cmd, **kwargs):
        if not isinstance(cmd, list) or "du" not in cmd[0]:
            return _make_subprocess_result()
        target = Path(cmd[-1])
        if target.name == "Library":
            blocks = library_blocks
        elif target.parent == users_root:
            blocks = user_blocks
        else:
            blocks = subdir_blocks
        return _make_subprocess_result(f"{blocks}\t{target}\n")

    return fake_run


def test_user_profile_size_discovered():
    modules_dir = Path(__file__).parent.parent / "modules"
    mod = next(
        m for m in discover_modules(modules_dir) if m.name == "user_profile_size"
    )
    assert mod.name == "user_profile_size"
    assert mod.category == "performance"
    assert mod.risk_level == RiskLevel.SAFE


def test_user_profile_size_small_dirs(tree):
    """Small directories produce an inventory but no size warnings."""
    mod = _get_module(tree)
    with patch("subprocess.run", side_effect=_fake_du(tree)):
        result = mod.check(_make_profile())

    assert any(f.severity == Severity.INFO for f in result.findings)
    assert not any(f.severity == Severity.WARNING for f in result.findings)
    assert not any(f.data.get("type") == "large_user_dir" for f in result.findings)
    assert not any(f.data.get("type") == "library_bloat" for f in result.findings)


def test_user_profile_size_large_user_warning(tree):
    """A profile over the 50 GB threshold raises a WARNING."""
    mod = _get_module(tree)
    with patch("subprocess.run", side_effect=_fake_du(tree, user_blocks=BIG_USER)):
        result = mod.check(_make_profile())

    assert result.has_issues
    large = [f for f in result.findings if f.data.get("type") == "large_user_dir"]
    assert large
    assert all(f.severity == Severity.WARNING for f in large)
    # Both real user profiles are over the threshold; skipped dirs are not counted.
    assert {f.data["user_name"] for f in large} == {"alice", "bob"}


def test_user_profile_size_large_library_warning(tree):
    """A Library over the 10 GB threshold raises a WARNING."""
    mod = _get_module(tree)
    fake = _fake_du(tree, user_blocks=MID_USER, library_blocks=BIG_LIBRARY)
    with patch("subprocess.run", side_effect=fake):
        result = mod.check(_make_profile())

    assert result.has_issues
    bloat = [f for f in result.findings if f.data.get("type") == "library_bloat"]
    assert bloat
    assert bloat[0].severity == Severity.WARNING
    # The moderate user profiles must not also be flagged.
    assert not any(f.data.get("type") == "large_user_dir" for f in result.findings)


def test_user_profile_size_info_findings(tree):
    """The inventory and per-subdirectory breakdown are both reported."""
    mod = _get_module(tree)
    with patch("subprocess.run", side_effect=_fake_du(tree)):
        result = mod.check(_make_profile())

    summary = next(
        (f for f in result.findings if f.data.get("type") == "user_summary"), None
    )
    assert summary is not None
    assert summary.data["user_count"] == 2
    assert any(f.data.get("type") == "subdir_breakdown" for f in result.findings)


def test_user_profile_size_fix_is_informational(tree):
    """fix() only ever advises; it never reports a system change."""
    mod = _get_module(tree)
    with patch("subprocess.run", side_effect=_fake_du(tree, user_blocks=BIG_USER)):
        check = mod.check(_make_profile())

    with patch("subprocess.run", side_effect=_fake_du(tree)) as run:
        fix = mod.fix(check, Mode.AUTO)

    assert fix.all_succeeded
    assert len(fix.actions) > 0
    # Advisory only: fix() must not shell out to change anything.
    assert run.call_count == 0


def test_user_profile_size_skips_system_dirs(tree):
    """Shared, Guest, dotfiles, and plain files are not counted as profiles."""
    mod = _get_module(tree)
    with patch("subprocess.run", side_effect=_fake_du(tree)):
        result = mod.check(_make_profile())

    summary = next(
        (f for f in result.findings if f.data.get("type") == "user_summary"), None
    )
    assert summary is not None
    assert summary.data["user_count"] == 2
    listed = summary.description
    for skipped in ("Shared", "Guest", ".hidden", "notadir"):
        assert skipped not in listed


def test_user_profile_size_handles_missing_users_root(tmp_path):
    """A machine with no /Users yields no findings rather than an error."""
    modules_dir = Path(__file__).parent.parent / "modules"
    mod = next(
        m for m in discover_modules(modules_dir) if m.name == "user_profile_size"
    )
    mod.users_root = tmp_path / "does_not_exist"
    mod.home_root = tmp_path / "also_missing"
    result = mod.check(_make_profile())
    assert result.findings == []


def test_user_profile_size_survives_du_failure(tree):
    """A failing du is tolerated; sizes fall back to zero."""
    mod = _get_module(tree)
    with patch(
        "subprocess.run", side_effect=lambda *a, **k: _make_subprocess_result(returncode=1)
    ):
        result = mod.check(_make_profile())

    assert not any(f.severity == Severity.WARNING for f in result.findings)
