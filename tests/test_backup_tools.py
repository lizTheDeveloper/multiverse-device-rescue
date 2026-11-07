"""Other backup tools (rescue.backup_tools) and what the Time Machine checks say about them.

Each test builds a fake Mac: a root with Applications and Library folders and
a home folder, pointed at by backup_tools.ROOT / HOME.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue import backup_tools
from rescue.models import Platform, Severity, SystemProfile
from rescue.registry import discover_modules

MODULES = {m.name: m for m in discover_modules(Path(__file__).parent.parent / "modules")}


@pytest.fixture
def mac(tmp_path, monkeypatch):
    root = tmp_path / "root"
    home = tmp_path / "home"
    for d in (root / "Applications", root / "Library/LaunchDaemons", root / "Library/LaunchAgents",
              home / "Library/LaunchAgents", home / "Library/CloudStorage"):
        d.mkdir(parents=True)
    monkeypatch.setattr(backup_tools, "ROOT", root)
    monkeypatch.setattr(backup_tools, "HOME", home)
    return root, home


def _app(folder: Path, name: str):
    (folder / name / "Contents").mkdir(parents=True)


def _profile():
    return SystemProfile(platform=Platform.DARWIN, os_name="macOS", os_version="15.2",
                         architecture="arm64", cpu_model="Apple M2", cpu_cores=8, ram_bytes=16 * 1024**3)


def _result(stdout="", stderr="", returncode=0):
    r = MagicMock()
    r.stdout, r.stderr, r.returncode = stdout, stderr, returncode
    return r


def _no_time_machine(cmd, **kwargs):
    if cmd[0] == "tmutil" and "destinationinfo" in cmd:
        return _result(stdout="tmutil: No destinations configured.\n")
    if cmd[0] == "defaults" and "ExcludeByPath" not in cmd:
        return _result(stdout="{\n    PreferencesVersion = 6;\n}\n")
    return _result(returncode=1)


def _time_machine_set_up(cmd, **kwargs):
    if cmd[0] == "tmutil" and "destinationinfo" in cmd:
        return _result(stdout="Name          : Backup Disk\nKind          : Local\nMount Point   : /Volumes/Backup\nID            : 1234\n")
    if cmd[0] == "tmutil" and "latestbackup" in cmd:
        return _result(stdout="/Volumes/Backup/Backups.backupdb/Mac/2026-10-27-101010\n")
    if cmd[0] == "tmutil" and "status" in cmd:
        return _result(stdout="AutoBackup = 1;")
    return _result(returncode=1)


def _check(name, fake):
    with patch("subprocess.run", side_effect=fake):
        return MODULES[name].check(_profile())


# --- the detector ---------------------------------------------------------------


def test_nothing_installed_finds_nothing(mac):
    assert backup_tools.detect() == []


def test_backup_apps_in_both_applications_folders(mac):
    root, home = mac
    _app(root / "Applications", "Arq.app")
    _app(home / "Applications", "Carbon Copy Cloner.app")
    assert backup_tools.detect() == [
        {"name": "Arq", "kind": "backup"},
        {"name": "Carbon Copy Cloner", "kind": "backup"},
    ]


def test_launchd_job_of_a_backup_service(mac):
    root, _ = mac
    (root / "Library/LaunchDaemons/com.backblaze.bzserv.plist").write_bytes(b"")
    assert backup_tools.detect() == [{"name": "Backblaze", "kind": "backup"}]


def test_scheduled_command_line_backup(mac):
    _, home = mac
    (home / "Library/LaunchAgents/com.me.restic-nightly.plist").write_bytes(b"")
    (home / "Library/LaunchAgents/homebrew.mxcl.borgmatic.plist").write_bytes(b"")
    # A word that merely contains a tool's name is not that tool.
    (home / "Library/LaunchAgents/com.cyborg.updater.plist").write_bytes(b"")
    assert backup_tools.names(backup_tools.detect(), backup_tools.BACKUP) == ["borg", "restic"]


def test_command_line_tool_config(mac):
    _, home = mac
    (home / ".config/rclone").mkdir(parents=True)
    (home / ".config/rclone/rclone.conf").write_text("[remote]\n")
    assert backup_tools.detect() == [{"name": "rclone", "kind": "backup"}]


def test_sync_tools_are_sync_not_backup(mac):
    root, home = mac
    _app(root / "Applications", "Dropbox.app")
    (home / "Library/CloudStorage/OneDrive-Personal").mkdir()
    (home / "Library/Mobile Documents/com~apple~CloudDocs").mkdir(parents=True)
    tools = backup_tools.detect()
    assert backup_tools.names(tools, backup_tools.BACKUP) == []
    assert backup_tools.names(tools, backup_tools.SYNC) == ["Dropbox", "iCloud Drive", "OneDrive"]


def test_results_are_names_only(mac):
    root, home = mac
    _app(root / "Applications", "Arq.app")
    (home / "Library/CloudStorage/Dropbox").mkdir()
    for tool in backup_tools.detect():
        assert set(tool) == {"name", "kind"}
        assert "/" not in tool["name"]


def test_unreadable_folders_count_as_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(backup_tools, "ROOT", tmp_path / "missing")
    monkeypatch.setattr(backup_tools, "HOME", tmp_path / "missing-home")
    assert backup_tools.detect() == []


def test_join():
    assert backup_tools.join([]) == ""
    assert backup_tools.join(["Arq"]) == "Arq"
    assert backup_tools.join(["Arq", "Dropbox"]) == "Arq and Dropbox"
    assert backup_tools.join(["Arq", "Backblaze", "Dropbox"]) == "Arq, Backblaze and Dropbox"


# --- what the checks say ----------------------------------------------------------


def test_arq_installed_is_info_naming_it(mac):
    root, _ = mac
    _app(root / "Applications", "Arq.app")
    findings = _check("time_machine_check", _no_time_machine).findings
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.INFO
    assert f.code == "integrity.time_machine_check.other_backup_tool"
    assert "Time Machine isn't set up. Arq is installed, which may be how you back up." in f.description
    assert f.data["backup_tools"] == ["Arq"]
    assert f.data["sync_tools"] == []


def test_backup_and_sync_says_sync_is_not_backup(mac):
    root, home = mac
    _app(root / "Applications", "Backblaze.app")
    (home / "Library/CloudStorage/Dropbox").mkdir()
    f = _check("time_machine_check", _no_time_machine).findings[0]
    assert f.severity == Severity.INFO
    assert "Dropbox is here too, but that is sync, not a backup." in f.description
    assert f.data == {"check": "other_backup_tool", "backup_tools": ["Backblaze"], "sync_tools": ["Dropbox"]}


def test_sync_only_is_a_warning(mac):
    root, home = mac
    _app(root / "Applications", "Dropbox.app")
    (home / "Library/Mobile Documents/com~apple~CloudDocs").mkdir(parents=True)
    findings = _check("time_machine_check", _no_time_machine).findings
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.WARNING
    assert f.code == "integrity.time_machine_check.sync_only"
    assert "Sync isn't a backup: deleting a file deletes it everywhere" in f.description
    assert f.data["sync_tools"] == ["Dropbox", "iCloud Drive"]


def test_nothing_at_all_stays_critical(mac):
    findings = _check("time_machine_check", _no_time_machine).findings
    assert [(f.severity, f.code) for f in findings] == [
        (Severity.CRITICAL, "integrity.time_machine_check.no_backup"),
    ]


def test_time_machine_set_up_ignores_other_tools(mac):
    root, _ = mac
    _app(root / "Applications", "Arq.app")
    findings = _check("time_machine_check", _time_machine_set_up).findings
    codes = {f.code for f in findings}
    assert not codes & set(MODULES["time_machine_check"].emits_codes)
    assert not any(f.severity == Severity.CRITICAL for f in findings)


@pytest.mark.parametrize("layout", ["nothing", "arq", "sync"])
def test_only_one_check_reports_no_backup(mac, layout):
    """Without Time Machine, only time_machine_check says anything above info."""
    root, home = mac
    if layout == "arq":
        _app(root / "Applications", "Arq.app")
    elif layout == "sync":
        (home / "Library/CloudStorage/Dropbox").mkdir()
    for name in ("time_machine_health", "backup_status"):
        findings = _check(name, _no_time_machine).findings
        assert findings and all(f.severity == Severity.INFO for f in findings), name
    headline = [f for f in _check("time_machine_check", _no_time_machine).findings
                if f.severity != Severity.INFO]
    assert len(headline) == (0 if layout == "arq" else 1)


# --- "I back up another way" (rescue.known_items backup_elsewhere) -----------------


def _scan_with_marks(fake):
    from rescue.orchestrator import _apply_item_marks

    findings = list(_check("time_machine_check", fake).findings)
    _apply_item_marks("time_machine_check", findings, None)
    return findings


def test_sync_only_can_be_answered_and_the_answer_retires(mac):
    from rescue.known_items import KnownItemsStore, item_identity, item_markable

    root, home = mac
    (home / "Library/CloudStorage/Dropbox").mkdir()
    f = _check("time_machine_check", _no_time_machine).findings[0]
    offer = item_markable(f, "time_machine_check")
    assert offer["kind"] == "backup_elsewhere"
    assert offer["monitoring"] is False
    assert "Dropbox" in offer["will_change"]
    kind, identity = item_identity(f)
    KnownItemsStore().add(kind, identity, via="test")

    marked = _scan_with_marks(_no_time_machine)
    assert len(marked) == 1
    assert marked[0].severity == Severity.INFO
    assert marked[0].data["marked_by_user"] is True
    assert marked[0].description.startswith("On ")
    assert "you said you back up this Mac another way" in marked[0].description

    # A backup app turns up: the warning is gone, so is the answer.
    _app(root / "Applications", "Arq.app")
    after = _scan_with_marks(_no_time_machine)
    assert KnownItemsStore().load() == []
    retired = [x for x in after if x.data.get("check") == "known_item_retired"]
    assert len(retired) == 1 and "a backup app was found" in retired[0].description


def test_no_backup_at_all_is_never_offered(mac):
    from rescue.known_items import item_markable

    f = _check("time_machine_check", _no_time_machine).findings[0]
    assert f.severity == Severity.CRITICAL
    assert item_markable(f, "time_machine_check") is None
