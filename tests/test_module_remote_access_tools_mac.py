"""remote_access_tools on macOS: the evidence for each tool (synthetic files only)."""

import dataclasses
import importlib.util
import json
import os
import plistlib
import sys
from datetime import date, datetime
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.command import CommandResult
from rescue.models import Platform, ProcessInfo, SystemProfile

ROOT = Path(__file__).parent.parent
_spec = importlib.util.spec_from_file_location(
    "rescue_modules.remote_access_tools_mac_test", ROOT / "modules/security/remote_access_tools/__init__.py")
MOD = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(MOD)
EV = MOD._ev


def _profile(platform=Platform.DARWIN, processes=()):
    return SystemProfile(platform=platform, os_name="macOS", os_version="15.0", architecture="arm64",
                         cpu_model="test", cpu_cores=8, ram_bytes=8 * 1024**3,
                         processes=[ProcessInfo(pid=100 + i, name=n, cpu_percent=0.0, memory_bytes=0, command=n)
                                    for i, n in enumerate(processes)])


def _cmd(stdout="", returncode=0):
    return CommandResult(args=[], returncode=returncode, stdout=stdout, stderr="", timed_out=False,
                         error=None, duration_s=0.0, truncated=False)


def _module(tmp_path):
    m = MOD.Module()
    home = tmp_path / "home"
    (home / "Downloads").mkdir(parents=True)
    (home / "Applications").mkdir()
    apps = tmp_path / "Applications"
    apps.mkdir()
    daemons = tmp_path / "LaunchDaemons"
    daemons.mkdir()
    agents = tmp_path / "LaunchAgents"
    agents.mkdir()
    m.HOME = home
    m.MAC_APP_DIRS = [apps, home / "Applications", home / "Downloads"]
    m.MAC_LAUNCHD_DIRS = [daemons, agents]
    m.now = lambda: datetime(2026, 3, 12, 12, 0, 0)
    m.kernel_path = staticmethod(lambda pid: None)  # no real process is ever read
    return m, apps, daemons


def _app(directory, name, bundle_id=None):
    app = directory / name
    (app / "Contents").mkdir(parents=True)
    if bundle_id:
        with open(app / "Contents" / "Info.plist", "wb") as fh:
            plistlib.dump({"CFBundleIdentifier": bundle_id}, fh)
    return app


def _plist(directory, label):
    with open(directory / f"{label}.plist", "wb") as fh:
        plistlib.dump({"Label": label, "ProgramArguments": ["/bin/true"]}, fh)


def _no_mdls(args, **kw):
    return _cmd("(null)")


def _sightings(m, profile=None, mdls=_no_mdls):
    with patch.object(MOD, "run", side_effect=mdls):
        return {s.tool.id: s for s in m._mac_sightings(profile or _profile())}


def test_finds_app_and_date_added(tmp_path):
    m, apps, _ = _module(tmp_path)
    app = _app(apps, "AnyDesk.app")
    seen = []

    def mdls(args, **kw):
        seen.append(args)
        return _cmd("2026-03-03 10:00:00 +0000")

    s = _sightings(m, mdls=mdls)["anydesk"]
    assert s.path == str(app)
    assert s.added_on == date(2026, 3, 3)
    assert seen[0][:4] == ["mdls", "-raw", "-name", "kMDItemDateAdded"]


def test_finds_renamed_app_by_bundle_id(tmp_path):
    m, apps, _ = _module(tmp_path)
    _app(apps, "Helper.app", bundle_id="com.philandro.anydesk")
    assert "anydesk" in _sightings(m)


def test_falls_back_to_birth_time_when_mdls_fails(tmp_path):
    m, apps, _ = _module(tmp_path)
    app = _app(apps, "AnyDesk.app")
    s = _sightings(m, mdls=lambda args, **kw: _cmd("", returncode=1))["anydesk"]
    birth = getattr(os.stat(app), "st_birthtime", None)
    if birth is None:
        assert s.added_on is None
    else:
        assert s.added_on == datetime.fromtimestamp(birth).date()


def test_launchd_plist_means_unattended(tmp_path):
    m, apps, daemons = _module(tmp_path)
    _app(apps, "AnyDesk.app")
    _plist(daemons, "com.philandro.anydesk.service")
    s = _sightings(m)["anydesk"]
    assert s.lets_in_unattended is True
    assert s.unattended_via == "com.philandro.anydesk.service"


def test_launchd_plist_alone_is_a_sighting(tmp_path):
    m, _, daemons = _module(tmp_path)
    _plist(daemons, "com.teamviewer.teamviewer_service")
    s = _sightings(m)["teamviewer"]
    assert s.lets_in_unattended is True
    assert s.path == str(daemons / "com.teamviewer.teamviewer_service.plist")


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root can read anything")
def test_no_launchd_item_is_false_only_when_dirs_were_readable(tmp_path):
    m, apps, daemons = _module(tmp_path)
    _app(apps, "AnyDesk.app")
    assert _sightings(m)["anydesk"].lets_in_unattended is False
    os.chmod(daemons, 0)
    try:
        s = _sightings(m)["anydesk"]
    finally:
        os.chmod(daemons, 0o755)
    assert s.lets_in_unattended is None
    assert s.unattended_via is None


def test_missing_launchd_dir_is_readable(tmp_path):
    m, apps, _ = _module(tmp_path)
    m.MAC_LAUNCHD_DIRS = list(m.MAC_LAUNCHD_DIRS) + [tmp_path / "nope"]
    _app(apps, "AnyDesk.app")
    assert _sightings(m)["anydesk"].lets_in_unattended is False


def _kernel(m, paths):
    """The kernel's executable path for each pid (proc_pidpath); a missing pid can't be read."""
    m.kernel_path = staticmethod(lambda pid: paths.get(pid))


def test_running_now_from_profile_processes(tmp_path):
    m, apps, _ = _module(tmp_path)
    _app(apps, "AnyDesk.app")
    _app(apps, "RustDesk.app")
    _kernel(m, {100: "/Applications/AnyDesk.app/Contents/MacOS/AnyDesk",
                101: "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder"})
    got = _sightings(m, _profile(processes=["AnyDesk", "Finder"]))
    assert got["anydesk"].running_now is True
    assert got["rustdesk"].running_now is False


def test_running_is_read_from_the_kernels_path_not_the_command_line(tmp_path):
    # ps aux's command line is argv: "Splashtop Streamer" reads as "Splashtop",
    # and a process can call itself anything. The kernel's path is the program.
    m, apps, _ = _module(tmp_path)
    _app(apps, "Splashtop Streamer.app")
    _app(apps, "AnyDesk.app")
    _kernel(m, {100: "/Applications/Splashtop Streamer.app/Contents/MacOS/Splashtop Streamer",
                101: "/Applications/AnyDesk.app/Contents/MacOS/AnyDesk"})
    got = _sightings(m, _profile(processes=["Splashtop", "launchd"]))
    assert got["splashtop"].running_now is True
    assert got["anydesk"].running_now is True


def test_not_running_only_when_every_process_could_be_read(tmp_path):
    m, apps, _ = _module(tmp_path)
    _app(apps, "AnyDesk.app")
    _kernel(m, {100: "/usr/libexec/logd"})  # pid 101's program can't be read (deleted, or no access)
    assert _sightings(m, _profile(processes=["logd", "helper"]))["anydesk"].running_now is None
    # A process that has exited since the list was taken is no process at all.
    _kernel(m, {100: "/usr/libexec/logd", 101: MOD.PROCESS_GONE})
    assert _sightings(m, _profile(processes=["logd", "helper"]))["anydesk"].running_now is False


def test_a_command_line_match_still_counts(tmp_path):
    m, apps, _ = _module(tmp_path)
    _app(apps, "AnyDesk.app")
    _kernel(m, {})
    assert _sightings(m, _profile(processes=["AnyDesk"]))["anydesk"].running_now is True


def test_the_kernel_path_reader_is_real_and_safe():
    if sys.platform == "darwin":
        mine = MOD.Module.kernel_path(os.getpid())
        assert isinstance(mine, str) and mine.startswith("/") and os.path.exists(mine)
    assert MOD.Module.kernel_path(-1) in (None, MOD.PROCESS_GONE)
    assert MOD.Module.kernel_path("junk") is None


def test_running_unknown_without_a_process_list(tmp_path):
    m, apps, _ = _module(tmp_path)
    _app(apps, "AnyDesk.app")
    assert _sightings(m, _profile(processes=()))["anydesk"].running_now is None


def test_running_process_alone_is_a_sighting(tmp_path):
    m, _, _ = _module(tmp_path)
    s = _sightings(m, _profile(processes=["TeamViewer"]))["teamviewer"]
    assert s.running_now is True and s.path is None


def _tv_line(day, peer="Some Peer", rid="111222333"):
    return f"{rid}\t{peer}\t{day} 10:00:00\t{day} 10:30:00\tlocaluser\tRemoteControl\t{{00000000-0000-0000-0000-000000000000}}\n"


def test_teamviewer_incoming_dates_and_count():
    text = "".join(_tv_line(d) for d in ["01-03-2026", "05-03-2026", "12-03-2026", "07-03-2026"])
    dates, count = EV.parse_teamviewer_incoming(text)
    assert count == 4
    assert max(dates) == date(2026, 3, 12)


def test_teamviewer_odd_lines_are_skipped():
    text = _tv_line("12-03-2026") + "garbage line\n" + "a\tb\t2026-03-12 10:00:00\n" + "a\tb\t31-02-2026 10:00:00\n"
    dates, count = EV.parse_teamviewer_incoming(text)
    assert (dates, count) == ([date(2026, 3, 12)], 1)


def test_anydesk_trace_counts_incoming_only():
    text = (
        "Incoming    2026-03-10, 09:00    User    123456789    123456789\n"
        "Outgoing    2026-03-11, 09:00    User    987654321    987654321\n"
        "Incoming    2026-03-12, 09:00    REJECTED    123456789    123456789\n"
        "Incoming    no date here\n"
    )
    dates, count = EV.parse_anydesk_trace(text)
    assert count == 2
    assert max(dates) == date(2026, 3, 12)


def test_logs_feed_the_sighting(tmp_path):
    m, apps, _ = _module(tmp_path)
    _app(apps, "AnyDesk.app")
    (m.HOME / ".anydesk").mkdir()
    (m.HOME / ".anydesk" / "connection_trace.txt").write_text(
        "Incoming    2026-03-10, 09:00    User    123456789    123456789\n"
        "Incoming    2026-03-12, 09:00    User    123456789    123456789\n")
    s = _sightings(m)["anydesk"]
    assert s.last_incoming == date(2026, 3, 12)
    assert s.incoming_count == 2


def test_log_missing_is_none_not_zero(tmp_path):
    m, apps, _ = _module(tmp_path)
    _app(apps, "AnyDesk.app")
    s = _sightings(m)["anydesk"]
    assert s.last_incoming is None and s.incoming_count is None


def test_tool_without_a_log_is_none(tmp_path):
    m, apps, _ = _module(tmp_path)
    _app(apps, "RustDesk.app")
    s = _sightings(m)["rustdesk"]
    assert s.last_incoming is None and s.incoming_count is None


HOSTILE_PEER = "<img src=x onerror=1>"
HOSTILE_ID = "987654321"


def test_log_values_never_leave_the_parser(tmp_path):
    m, apps, _ = _module(tmp_path)
    m.MAC_LAUNCHD_DIRS = []
    _app(apps, "TeamViewer.app")
    _app(apps, "AnyDesk.app")
    (m.HOME / ".anydesk").mkdir()
    (m.HOME / ".anydesk" / "connection_trace.txt").write_text(
        f"Incoming    2026-03-12, 09:00    {HOSTILE_PEER}    {HOSTILE_ID}    {HOSTILE_ID}\n")
    with patch.object(MOD, "run", side_effect=_no_mdls):
        result = m.check(_profile())
        sightings = m._mac_sightings(_profile())
    blob = json.dumps([f.data for f in result.findings], default=str)
    blob += json.dumps([f.title + f.description for f in result.findings])
    blob += json.dumps([{k: v for k, v in dataclasses.asdict(s).items() if k != "tool"} for s in sightings],
                       default=str)
    assert HOSTILE_PEER not in blob and "onerror" not in blob
    assert HOSTILE_ID not in blob


def test_huge_log_reads_only_the_tail(tmp_path):
    path = tmp_path / "connection_trace.txt"
    old = "Incoming    2020-01-01, 09:00    User    1    1\n"
    new = "Incoming    2026-03-12, 09:00    User    1    1\n"
    with open(path, "w") as fh:
        fh.write(old * (2 * 1024 * 1024 // len(old)))
        fh.write(new * (1024 * 1024 // len(new) + 10))
    assert path.stat().st_size > 3 * 1024 * 1024 - 4096
    text = EV.read_tail(path)
    assert text is not None and len(text.encode()) <= 1_048_576
    dates, count = EV.parse_anydesk_trace(text)
    assert dates and min(dates) == date(2026, 3, 12)
    assert count < 1_048_576 // len(new) + 1


def test_binary_log_gives_none_not_zero(tmp_path):
    path = tmp_path / "connection_trace.txt"
    path.write_bytes(b"\x00\xff\xfe" + os.urandom(4096))
    assert EV.read_tail(path) is None
    assert EV.read_log(path, "anydesk_trace") is None


def test_log_that_is_a_folder_or_symlink_is_none(tmp_path):
    (tmp_path / "dir").mkdir()
    assert EV.read_tail(tmp_path / "dir") is None
    target = tmp_path / "real.txt"
    target.write_text("Incoming    2026-03-12\n")
    (tmp_path / "link.txt").symlink_to(target)
    assert EV.read_tail(tmp_path / "link.txt") is None
    assert EV.read_tail(tmp_path / "missing.txt") is None


def test_app_in_downloads_without_service_is_one_off(tmp_path):
    m, apps, daemons = _module(tmp_path)
    _app(m.HOME / "Downloads", "AnyDesk.app")
    _app(m.HOME / "Downloads", "TeamViewer.app")
    _plist(daemons, "com.teamviewer.teamviewer_service")
    _app(apps, "RustDesk.app")
    got = _sightings(m)
    assert got["anydesk"].one_off is True
    assert got["teamviewer"].one_off is False
    assert got["rustdesk"].one_off is False


def test_installed_copy_wins_over_downloads(tmp_path):
    m, apps, _ = _module(tmp_path)
    _app(m.HOME / "Downloads", "AnyDesk.app")
    installed = _app(apps, "AnyDesk.app")
    s = _sightings(m)["anydesk"]
    assert s.path == str(installed) and s.one_off is False


def test_quick_assist_is_never_a_mac_sighting(tmp_path):
    m, _, _ = _module(tmp_path)
    assert "quick_assist" not in _sightings(m, _profile(processes=["QuickAssist.exe"]))


def test_budget_exhausted_leaves_rest_none(tmp_path):
    m, apps, daemons = _module(tmp_path)
    _app(apps, "AnyDesk.app")
    _plist(daemons, "com.philandro.anydesk.service")
    (m.HOME / ".anydesk").mkdir()
    (m.HOME / ".anydesk" / "connection_trace.txt").write_text("Incoming    2026-03-12, 09:00    U    1    1\n")
    m._deadline = 0.0
    m.clock = lambda: 10_000.0
    calls = []
    s = _sightings(m, mdls=lambda args, **kw: calls.append(args) or _cmd("2026-03-03 10:00:00 +0000"))["anydesk"]
    assert calls == []
    assert s.added_on is None
    assert s.lets_in_unattended is None
    assert s.last_incoming is None and s.incoming_count is None


def test_module_metadata():
    m = MOD.Module()
    assert m.name == "remote_access_tools"
    assert m.category == "security"
    assert set(m.platforms) == {Platform.DARWIN, Platform.WIN32}
    assert MOD.EVIDENCE_BUDGET_SECONDS == 20.0


def test_apples_parsecd_is_not_parsec(tmp_path):
    # Apple's CoreParsec runs "parsecd"; Parsec, the remote-desktop app, runs "Parsec".
    m, _, _ = _module(tmp_path)
    profile = _profile()
    profile.processes = [ProcessInfo(pid=1, name="parsecd", cpu_percent=0.0, memory_bytes=0,
                                     command="/System/Library/PrivateFrameworks/CoreParsec.framework/parsecd")]
    assert "parsec" not in _sightings(m, profile)
    profile.processes.append(ProcessInfo(pid=3, name="Parsec", cpu_percent=0.0, memory_bytes=0,
                                         command="/Applications/Parsec.app/Contents/MacOS/Parsec"))
    assert _sightings(m, profile)["parsec"].running_now is True


def test_a_system_looking_command_line_does_not_hide_a_tool(tmp_path):
    # argv is set by the process itself, so it never decides anything.
    m, _, _ = _module(tmp_path)
    profile = _profile()
    profile.processes = [ProcessInfo(pid=1, name="AnyDesk", cpu_percent=0.0, memory_bytes=0,
                                     command="/System/Library/CoreServices/AnyDesk")]
    assert _sightings(m, profile)["anydesk"].running_now is True


# ---------------- what couldn't be read is never a clean result ----------------

def _mac_check(m, profile):
    with patch.object(MOD, "run", side_effect=_no_mdls):
        return m.check(profile)


def _readable(m):
    _kernel(m, {100: "/usr/libexec/logd"})
    return _profile(processes=["logd"])


def test_mac_check_is_complete_when_everything_was_read(tmp_path):
    m, _, _ = _module(tmp_path)
    assert _mac_check(m, _readable(m)).complete is True


def test_mac_check_is_incomplete_when_a_folder_cannot_be_read(tmp_path):
    not_a_folder = tmp_path / "file"
    not_a_folder.write_text("x")
    for attr in ("MAC_APP_DIRS", "MAC_LAUNCHD_DIRS"):
        m, _, _ = _module(tmp_path / attr)
        setattr(m, attr, list(getattr(m, attr)) + [not_a_folder])
        result = _mac_check(m, _readable(m))
        assert result.supported and result.error is None
        assert result.complete is False, attr


def test_mac_check_is_incomplete_without_a_process_list_or_budget(tmp_path):
    m, _, _ = _module(tmp_path / "a")
    assert _mac_check(m, _profile()).complete is False
    m, _, _ = _module(tmp_path / "b")
    profile = _readable(m)
    with patch.object(MOD, "EVIDENCE_BUDGET_SECONDS", -1.0):  # spent as soon as check() starts it
        assert _mac_check(m, profile).complete is False


def test_mac_check_is_incomplete_when_a_folder_is_cut_short(tmp_path):
    m, _, _ = _module(tmp_path)
    for i in range(3):
        (m.HOME / "Downloads" / f"file{i}.txt").write_text("x")
    with patch.object(MOD, "MAX_DIR_ENTRIES", 3):
        assert _mac_check(m, _readable(m)).complete is False
    assert _mac_check(m, _readable(m)).complete is True
