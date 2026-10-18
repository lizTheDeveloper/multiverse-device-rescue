"""Suite-wide fixtures."""

import pytest


@pytest.fixture(autouse=True)
def _isolated_known_items(tmp_path_factory, monkeypatch):
    """Checks read the person's "marked as mine" list; never the real one."""
    path = tmp_path_factory.mktemp("known-items") / "known_items.json"
    monkeypatch.setenv("RESCUE_KNOWN_ITEMS", str(path))
    yield path


@pytest.fixture(autouse=True)
def _no_real_app_names(monkeypatch):
    """App names come from the Applications folder; tests never read the real one."""
    from rescue import app_names

    monkeypatch.setattr(app_names, "_index_cache", {})
