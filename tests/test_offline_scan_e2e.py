"""End to end: scan a mounted Linux disk through the real CLI."""

import json
import os

import pytest

from click.testing import CliRunner

from rescue.cli import main
from rescue.known_items import KnownItemsStore, item_identity
from rescue.models import Finding, Severity

# Disk checks read Linux and macOS layouts (symlinks, FIFOs, POSIX modes) and
# only run from those hosts, so these tests do too.
pytestmark = pytest.mark.skipif(os.name != "posix", reason="offline disk checks run on POSIX hosts")


OFFLINE_CAPABLE_EXPECTED = {
    "linux_account_audit",
    "stalkerware_scan",
    "linux_persistence_audit",
    "linux_ssh_hardening",
}


def snapshot_tree(root):
    snap = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in filenames + dirnames:
            p = os.path.join(dirpath, name)
            st = os.lstat(p)
            snap[os.path.relpath(p, root)] = (st.st_size, st.st_mtime_ns)
    return snap


def test_offline_scan_end_to_end(linux_disk, tmp_path, monkeypatch):
    home = tmp_path / "host-home"
    (home / ".rescue").mkdir(parents=True)
    known = home / ".rescue/known_items.json"
    # a real mark on a network proxy that this disk doesn't have: a live scan
    # would retire it, an offline one must leave the list alone
    store = KnownItemsStore(known)
    hit = item_identity(Finding(
        title="Proxy", description="d", severity=Severity.WARNING, category="security",
        code="security.network_proxy.proxy_enabled",
        data={"check": "proxy_enabled", "interface": "Wi-Fi", "proxy_servers": ["HTTP proxy.example:8080"]},
    ))
    assert hit and hit[0] == "network_proxy"
    store.add("network_proxy", hit[1], via="test")
    assert store.load()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("RESCUE_KNOWN_ITEMS", str(known))
    before = known.read_bytes()

    # a hostile disk: /etc/shadow points at the checking computer's shadow
    (linux_disk / "etc/shadow").symlink_to("/etc/shadow")
    (linux_disk / "etc/ssh").mkdir()
    (linux_disk / "etc/ssh/sshd_config").write_text("PermitRootLogin yes\n")
    snapshot_before = snapshot_tree(linux_disk)

    r = CliRunner().invoke(
        main,
        ["scan", "--json", "--no-downloads", "--target-root", str(linux_disk), "--target-os", "linux"],
    )
    assert r.exit_code == 0, r.stderr
    doc = json.loads(r.stdout)
    assert "read_only" in doc["target"]  # a tmp dir is writable, so only the key is checked
    mods = {m["name"]: m for m in doc["modules"]}
    for name in OFFLINE_CAPABLE_EXPECTED:
        assert mods[name]["supported"] is True, name
    assert mods["linux_ssh_hardening"]["not_checked"] == ["whether SSH was running"]
    assert all(
        m["supported"] is False for n, m in mods.items() if n not in OFFLINE_CAPABLE_EXPECTED
    )
    assert known.read_bytes() == before
    assert not [
        f for m in doc["modules"] for f in m["findings"] if f["title"].startswith("No longer marked")
    ]
    assert snapshot_tree(linux_disk) == snapshot_before
