"""Suite-wide fixtures."""

import os
from pathlib import Path

import pytest

_REALPATH = os.path.realpath  # tests may patch os.path.realpath; the guard must not depend on it


def assert_known_items_isolated(base) -> None:
    """Fail unless the "marked as mine" list the store would use sits under
    pytest's temporary folder, so no test can write the developer's real one."""
    from rescue import known_items

    where = Path(_REALPATH(known_items.default_path()))
    root = Path(_REALPATH(base))
    assert where.is_relative_to(root), (
        f"a test would use the real marked-as-mine list ({where}); keep RESCUE_KNOWN_ITEMS "
        f"under {root} (don't call monkeypatch.undo() or delete it)"
    )


@pytest.fixture(autouse=True)
def _isolated_known_items(tmp_path_factory, monkeypatch):
    """Checks read the person's "marked as mine" list; never the real one."""
    path = tmp_path_factory.mktemp("known-items") / "known_items.json"
    monkeypatch.setenv("RESCUE_KNOWN_ITEMS", str(path))
    base = tmp_path_factory.getbasetemp()
    assert_known_items_isolated(base)
    yield path
    # Runs before monkeypatch's own teardown, so it sees the test's final state.
    assert_known_items_isolated(base)


@pytest.fixture(autouse=True)
def _no_real_app_names(monkeypatch):
    """App names come from the Applications folder; tests never read the real one."""
    from rescue import app_names

    monkeypatch.setattr(app_names, "_index_cache", {})
