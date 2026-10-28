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


@pytest.fixture
def linux_disk(tmp_path):
    """A minimal Ubuntu system disk, mounted somewhere else."""
    root = tmp_path / "disk"
    (root / "etc").mkdir(parents=True)
    (root / "etc/os-release").write_text(
        'NAME="Ubuntu"\nPRETTY_NAME="Ubuntu 24.04.1 LTS"\nVERSION_ID="24.04"\n'
    )
    (root / "etc/hostname").write_text("sams-laptop\n")
    (root / "etc/passwd").write_text(
        "root:x:0:0:root:/root:/bin/bash\nsam:x:1000:1000:Sam:/home/sam:/bin/bash\n"
    )
    (root / "root").mkdir()
    (root / "home/sam").mkdir(parents=True)
    (root / "var/lib/dpkg").mkdir(parents=True)
    (root / "var/lib/dpkg/status").write_text(
        "Package: openssh-server\nStatus: install ok installed\nVersion: 1\n\n"
        "Package: oldthing\nStatus: deinstall ok config-files\nVersion: 1\n\n"
    )
    (root / "var/lib/flatpak/app/org.mozilla.firefox").mkdir(parents=True)
    (root / "var/lib/snapd/snaps").mkdir(parents=True)
    (root / "var/lib/snapd/snaps/spotify_75.snap").write_text("")
    (root / "lib/systemd/system").mkdir(parents=True)
    (root / "lib/systemd/system/ssh.service").write_text("[Service]\n")
    wants = root / "etc/systemd/system/multi-user.target.wants"
    wants.mkdir(parents=True)
    (wants / "ssh.service").symlink_to("/lib/systemd/system/ssh.service")
    return root
