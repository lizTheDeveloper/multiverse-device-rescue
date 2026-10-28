"""End to end: scan a mounted Linux disk through the real CLI."""

import json
import os

from click.testing import CliRunner

from rescue.cli import main

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
    known.write_text('{"version": 1, "items": []}')
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
    assert snapshot_tree(linux_disk) == snapshot_before
