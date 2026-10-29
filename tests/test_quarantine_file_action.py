"""quarantine_file: validation, the quarantine/restore round trip, the scan offer, the CLI.

Everything runs in a temporary HOME. No real file outside it is touched.
"""

import hashlib
import json
import os
import stat
import sys

import pytest
from click.testing import CliRunner

from rescue.actions import quarantine_file as qf
from rescue.app_fixes import load_app_actions, validate_app_actions
from rescue.cli import main
from rescue.models import CheckResult, Finding, Severity
from rescue.serialize import checks_to_json

ACTIONS = load_app_actions()

# POSIX semantics (uid, mode bits, symlinks); Windows uses Defender's own quarantine.
pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="quarantine needs POSIX uid/mode semantics")


class _Mod:
    def __init__(self, name):
        self.name = name
        self.category = "security"


@pytest.fixture
def env(tmp_path, monkeypatch):
    home = tmp_path / "home"
    downloads = home / "Downloads"
    downloads.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_DATA_HOME", str(home / ".local" / "share"))
    return type("Env", (), {"home": home, "downloads": downloads})


def _bad_file(env, name="Installer.command", body=b"#!/bin/sh\necho pretend-malware\n"):
    p = env.downloads / name
    p.write_bytes(body)
    os.chmod(p, 0o755)
    return p


def _sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def test_quarantine_moves_strips_execute_and_records_a_manifest(env):
    f = _bad_file(env)
    digest = _sha(f)
    doc = qf.quarantine(str(f))
    assert doc["status"] == "fixed" and doc["applied"] and doc["verified"]
    assert not f.exists()
    qid = doc["quarantine_id"]
    assert qf.QUARANTINE_ID.match(qid) and qid.endswith(digest[:16])
    held = qf.quarantine_dir() / f"{qid}.quarantined"
    assert held.is_file()
    assert stat.S_IMODE(os.stat(held).st_mode) == 0o400, "read-only, never runnable"
    entry = json.loads((qf.quarantine_dir() / f"{qid}.json").read_text())
    assert entry["original_path"] == str(f.resolve())
    assert entry["sha256"] == digest
    assert entry["mode"] == 0o755
    assert entry["quarantined_at"]
    assert stat.S_IMODE(os.stat(qf.quarantine_dir()).st_mode) == 0o700
    assert doc["how_to_undo"] == qf.UNDO_STEPS


def test_restore_puts_it_back_with_its_permissions(env):
    f = _bad_file(env)
    digest = _sha(f)
    qid = qf.quarantine(str(f))["quarantine_id"]
    doc = qf.restore(qid)
    assert doc["status"] == "restored" and doc["applied"] and doc["verified"]
    assert f.is_file() and _sha(f) == digest
    assert stat.S_IMODE(os.stat(f).st_mode) == 0o755
    assert not (qf.quarantine_dir() / f"{qid}.quarantined").exists()
    assert json.loads((qf.quarantine_dir() / f"{qid}.json").read_text())["restored_at"]
    # Only once.
    assert qf.restore(qid)["status"] == "refused"


def test_restore_drops_setuid_bits(env):
    f = _bad_file(env)
    qid = qf.quarantine(str(f))["quarantine_id"]
    manifest = qf.quarantine_dir() / f"{qid}.json"
    entry = json.loads(manifest.read_text())
    entry["mode"] = 0o4755
    manifest.write_text(json.dumps(entry))
    qf.restore(qid)
    assert stat.S_IMODE(os.stat(f).st_mode) == 0o755


def test_restore_refuses_a_changed_file_and_an_occupied_place(env):
    f = _bad_file(env)
    qid = qf.quarantine(str(f))["quarantine_id"]
    f.write_text("something new in its place")
    doc = qf.restore(qid)
    assert doc["error"] == "exists" and f.read_text() == "something new in its place"
    f.unlink()
    held = qf.quarantine_dir() / f"{qid}.quarantined"
    os.chmod(held, 0o600)
    held.write_bytes(b"swapped")
    assert qf.restore(qid)["error"] == "tampered"
    assert not f.exists()


def test_restore_rebuilds_the_held_file_name_from_the_id(env):
    f = _bad_file(env)
    qid = qf.quarantine(str(f))["quarantine_id"]
    manifest = qf.quarantine_dir() / f"{qid}.json"
    entry = json.loads(manifest.read_text())
    entry["original_path"] = "/etc/evil"
    manifest.write_text(json.dumps(entry))
    doc = qf.restore(qid)
    assert doc["status"] == "refused" and "system folder" in doc["message"]


def test_bad_undo_ids_are_refused(env):
    for bad in ("", "../../etc/passwd", "20260101T000000Z-com.label", None, 7):
        assert qf.restore(bad)["error"] == "not_allowed"


def test_refuses_symlinks_system_files_and_other_owners(env, monkeypatch):
    real = _bad_file(env)
    link = env.downloads / "link.command"
    link.symlink_to(real)
    assert "symbolic link" in qf.quarantine(str(link))["message"]
    assert real.exists()

    with monkeypatch.context() as m:
        m.setattr(qf.file_scan, "is_protected", lambda p, platform=None: True)
        doc = qf.quarantine(str(real))
    assert doc["error"] == "not_allowed" and "never moves system files" in doc["message"]
    assert real.exists()

    with monkeypatch.context() as m:
        m.setattr(qf, "_uid", lambda: os.getuid() + 1)
        doc = qf.quarantine(str(real))
    assert "belongs to another account" in doc["message"]
    assert real.exists()


def test_refuses_relative_paths_folders_and_the_quarantine_itself(env):
    assert "full file path" in qf.quarantine("Downloads/x")["message"]
    assert "ordinary file" in qf.quarantine(str(env.downloads))["message"]
    f = _bad_file(env)
    qid = qf.quarantine(str(f))["quarantine_id"]
    held = qf.quarantine_dir() / f"{qid}.quarantined"
    assert "already in Reclaim City's quarantine" in qf.quarantine(str(held))["message"]


def test_system_paths_are_protected():
    for p in ("/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder", "/usr/bin/python3", "/bin/ls"):
        assert qf.file_scan.is_system_path(p, "darwin")
    assert not qf.file_scan.is_system_path("/usr/local/bin/thing", "darwin")
    assert qf.file_scan.is_system_path("/usr/lib/x.so", "linux")
    assert qf.file_scan.is_system_path("C:\\Windows\\System32\\x.dll", "win32")


def test_second_card_for_the_same_file_has_nothing_to_do(env):
    f = _bad_file(env)
    qid = qf.quarantine(str(f))["quarantine_id"]
    again = qf.quarantine(str(f))
    assert again["status"] == "nothing_to_fix" and again["quarantine_id"] == qid
    gone = qf.quarantine(str(env.downloads / "never-existed.command"))
    assert gone["status"] == "nothing_to_fix" and "already gone" in gone["message"]


def test_list_items_shows_only_what_is_still_held(env):
    a = qf.quarantine(str(_bad_file(env, "a.command")))["quarantine_id"]
    b = qf.quarantine(str(_bad_file(env, "b.command", b"#!/bin/sh\necho b\n")))["quarantine_id"]
    qf.restore(a)
    assert [i["id"] for i in qf.list_items()] == [b]


def test_unsupported_on_windows(monkeypatch, env):
    monkeypatch.setattr(qf, "_supported", lambda: False)
    doc = qf.quarantine(str(_bad_file(env)))
    assert doc["status"] == "unsupported" and "Protection history" in doc["message"]
    assert qf.exit_code(doc) == 3


# --- the scan offer -------------------------------------------------------------


def _match(f, code="security.malware_file_scan.malware_match", **data):
    return Finding(
        title="A file matched Apple's malware rules", description="d", severity=Severity.CRITICAL,
        category="security", code=code, data={"path": str(f), "sha256": "a" * 64, **data},
    )


def test_the_allowlist_entry_is_valid():
    assert "quarantine_file" in ACTIONS
    assert validate_app_actions(ACTIONS) == []
    assert ACTIONS["quarantine_file"]["severities"] == ["critical"]


def test_a_critical_match_is_offered_quarantine(env):
    f = _bad_file(env)
    out = json.loads(checks_to_json([(_Mod("malware_file_scan"), CheckResult("malware_file_scan", [_match(f)]))],
                                    "darwin", app_actions=ACTIONS))
    fx = out["modules"][0]["findings"][0]["fixable"]
    assert fx["action"] == "quarantine_file" and fx["target"] == str(f)
    assert "Installer.command" in fx["will_change"] and "Nothing is deleted" in fx["will_change"]
    assert "safety_note" not in fx


def test_monitoring_match_carries_the_safety_note(env):
    f = _bad_file(env)
    finding = _match(f, code="security.malware_file_scan.monitoring_match", monitoring_name="FlexiSPY")
    out = json.loads(checks_to_json([(_Mod("malware_file_scan"), CheckResult("malware_file_scan", [finding]))],
                                    "darwin", app_actions=ACTIONS))
    fx = out["modules"][0]["findings"][0]["fixable"]
    assert "removing it can alert them" in fx["safety_note"]


def test_no_offer_for_other_modules_warnings_or_missing_files(env):
    f = _bad_file(env)
    for mod, finding in (
        ("stalkerware_scan", _match(f)),
        ("malware_file_scan", Finding("t", "d", Severity.WARNING, "security", data={"path": str(f)})),
        ("malware_file_scan", _match(env.downloads / "gone.command")),
    ):
        out = json.loads(checks_to_json([(_Mod(mod), CheckResult(mod, [finding]))], "darwin", app_actions=ACTIONS))
        assert "fixable" not in out["modules"][0]["findings"][0]


# --- the CLI ----------------------------------------------------------------------


def test_cli_quarantine_list_and_undo(env):
    f = _bad_file(env)
    runner = CliRunner()
    refused = runner.invoke(main, ["fix", "--action", "quarantine_file", "--target", str(f), "--json"])
    assert refused.exit_code == 2 and f.exists()
    res = runner.invoke(main, ["fix", "--action", "quarantine_file", "--target", str(f), "--json", "--i-understand"])
    assert res.exit_code == 0, res.output
    qid = json.loads(res.output)["quarantine_id"]
    listed = runner.invoke(main, ["quarantine", "list", "--json"])
    assert [i["id"] for i in json.loads(listed.output)["items"]] == [qid]
    back = runner.invoke(main, ["undo", "--quarantine-id", qid, "--json"])
    assert back.exit_code == 0 and json.loads(back.output)["action"] == "undo_quarantine_file"
    assert f.exists()


def test_cli_lookup_prints_the_hash_and_the_url_and_uploads_nothing(env):
    f = _bad_file(env)
    res = CliRunner().invoke(main, ["lookup-file", str(f), "--json"])
    assert res.exit_code == 0
    doc = json.loads(res.output)
    assert doc["sha256"] == _sha(f)
    assert doc["virustotal_url"] == f"https://www.virustotal.com/gui/file/{_sha(f)}"
    assert doc["uploaded"] is False and "paying customers" in doc["upload_warning"]
    text = CliRunner().invoke(main, ["lookup-file", str(f)]).output
    assert "Nothing was uploaded" in text and "Never upload anything private" in text
    missing = CliRunner().invoke(main, ["lookup-file", str(env.downloads / "nope")])
    assert missing.exit_code != 0


# --- links swapped in mid-way never redirect a move or a chmod ------------------------


def test_restore_refuses_a_folder_that_became_a_shortcut(env, tmp_path):
    f = _bad_file(env)
    qid = qf.quarantine(str(f))["quarantine_id"]
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    env.downloads.rmdir()
    env.downloads.symlink_to(elsewhere)
    doc = qf.restore(qid)
    assert doc["status"] == "refused" and "shortcut" in doc["message"]
    assert not (elsewhere / f.name).exists()
    assert (qf.quarantine_dir() / f"{qid}.quarantined").exists()


def test_restore_refuses_folders_that_are_not_yours_or_open_to_everyone(env, monkeypatch):
    f = _bad_file(env)
    qid = qf.quarantine(str(f))["quarantine_id"]
    with monkeypatch.context() as m:
        m.setattr(qf, "_uid", lambda: os.getuid() + 1)
        doc = qf.restore(qid)
    assert doc["status"] == "refused" and "belongs to another account" in doc["message"]
    os.chmod(env.downloads, 0o777)
    doc = qf.restore(qid)
    assert doc["status"] == "refused" and "Anyone can change" in doc["message"]
    assert not f.exists()
    os.chmod(env.downloads, 0o1777)  # sticky: others can't remove or replace your files
    assert qf.restore(qid)["status"] == "restored"
    os.chmod(env.downloads, 0o755)


def test_a_link_swapped_in_after_the_move_never_gets_the_chmod(env, monkeypatch, tmp_path):
    victim = tmp_path / "victim.txt"
    victim.write_text("someone else's file")
    os.chmod(victim, 0o644)
    f = _bad_file(env)
    qid = qf.quarantine(str(f))["quarantine_id"]

    def link_then_swap(src, dst, *, src_dir_fd=None, dst_dir_fd=None, follow_symlinks=True):
        os.symlink(str(victim), dst, dir_fd=dst_dir_fd)

    monkeypatch.setattr(qf.os, "link", link_then_swap)
    doc = qf.restore(qid)
    assert doc["status"] == "failed"
    assert stat.S_IMODE(os.stat(victim).st_mode) == 0o644, "the chmod never followed the link"
    assert (qf.quarantine_dir() / f"{qid}.quarantined").exists()


def test_quarantine_never_follows_a_link_swapped_in_for_the_file(env, monkeypatch, tmp_path):
    real = _bad_file(env)
    link = env.downloads / "swapped.command"
    link.symlink_to(real)
    monkeypatch.setattr(qf, "validate", lambda p: {"path": str(link), "stat": os.lstat(real)})
    doc = qf.quarantine(str(link))
    assert doc["status"] == "refused" and "shortcut" in doc["message"]
    assert real.exists() and link.is_symlink()
    assert stat.S_IMODE(os.stat(real).st_mode) == 0o755


def test_quarantine_refuses_a_file_changed_after_the_check(env, monkeypatch):
    f = _bad_file(env)
    before = os.lstat(f)
    f.write_bytes(b"#!/bin/sh\necho changed, and longer than before\n")
    monkeypatch.setattr(qf, "validate", lambda p: {"path": str(f), "stat": before})
    doc = qf.quarantine(str(f))
    assert doc["status"] == "refused" and "changed" in doc["message"]
    assert f.exists()


def test_control_characters_in_a_recorded_path_are_refused(env):
    f = _bad_file(env)
    qid = qf.quarantine(str(f))["quarantine_id"]
    manifest = qf.quarantine_dir() / f"{qid}.json"
    entry = json.loads(manifest.read_text())
    entry["original_path"] = str(env.downloads / "a\nb")
    manifest.write_text(json.dumps(entry))
    assert "damaged" in qf.restore(qid)["message"]
