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


@pytest.fixture(autouse=True)
def _no_real_downloads(tmp_path_factory, monkeypatch):
    """A scan in a test never fetches anything, and never runs a copy fetched for real."""
    monkeypatch.setenv("RESCUE_NO_DOWNLOADS", "1")
    monkeypatch.setenv("RESCUE_CACHE_DIR", str(tmp_path_factory.mktemp("user-cache")))


@pytest.fixture(autouse=True)
def _not_elevated(monkeypatch):
    """The AI tools check refuses to run with administrator rights, and GitHub's
    Windows runners are administrators. Tests that want an elevated scan set
    ``elevated = True`` on the module instead."""
    import os
    import sys

    if sys.platform == "win32":
        import ctypes

        monkeypatch.setattr(ctypes.windll.shell32, "IsUserAnAdmin", lambda: 0)
    elif hasattr(os, "geteuid") and os.geteuid() == 0:
        monkeypatch.setattr(os, "geteuid", lambda: 1000)
