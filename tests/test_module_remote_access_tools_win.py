"""remote_access_tools on Windows: the evidence for each tool (mocked registry, synthetic files)."""

import importlib.util
import sys
from datetime import date, datetime
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.command import CommandResult
from rescue.models import Platform, ProcessInfo, SystemProfile

ROOT = Path(__file__).parent.parent
_spec = importlib.util.spec_from_file_location(
    "rescue_modules.remote_access_tools_win_test", ROOT / "modules/security/remote_access_tools/__init__.py")
MOD = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(MOD)

HKLM = r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall"
HKLM32 = r"HKEY_LOCAL_MACHINE\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
SERVICES = r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services"


def _profile(processes=()):
    return SystemProfile(platform=Platform.WIN32, os_name="Windows 11", os_version="10.0.22631",
                         architecture="AMD64", cpu_model="test", cpu_cores=8, ram_bytes=8 * 1024**3,
                         processes=[ProcessInfo(pid=200 + i, name=n, cpu_percent=0.0, memory_bytes=0, command=c)
                                    for i, (n, c) in enumerate(processes)])


def _cmd(stdout="", returncode=0):
    return CommandResult(args=[], returncode=returncode, stdout=stdout, stderr="", timed_out=False,
                         error=None, duration_s=0.0, truncated=False)


def _uninstall_block(key, sub, display, location="", install_date=""):
    lines = [f"{key}\\{sub}", f"    DisplayName    REG_SZ    {display}"]
    if location:
        lines.append(f"    InstallLocation    REG_SZ    {location}")
    if install_date:
        lines.append(f"    InstallDate    REG_SZ    {install_date}")
    lines.append("    Publisher    REG_SZ    Example Publisher")
    return "\r\n".join(lines) + "\r\n\r\n"


def _services_output(services):
    out = []
    for name, start in services.items():
        out.append(f"{SERVICES}\\{name}\r\n    Start    REG_DWORD    0x{start:x}\r\n\r\n")
    out.append(f"{SERVICES}\\{next(iter(services), 'x')}\\Parameters\r\n    Start    REG_DWORD    0x2\r\n\r\n"
               if services else "")
    out.append(f"End of search: {len(services)} match(es) found.\r\n")
    return "".join(out)


def _fake_reg(uninstall=None, uninstall32="", hkcu="", services=None, fail=()):
    """A fake `rescue.command.run` for reg query. `fail` lists the keys whose query fails."""

    def run(args, **kw):
        assert args[0] == "reg" and args[1] == "query"
        key = args[2]
        if any(key.lower().startswith(f.lower()) for f in fail):
            return _cmd("", returncode=1)
        if key.lower().endswith(r"system\currentcontrolset\services"):
            return _cmd(_services_output(services or {}))
        if "wow6432node" in key.lower():
            return _cmd(uninstall32)
        if key.upper().startswith("HKCU"):
            return _cmd(hkcu)
        return _cmd(uninstall or "")

    return run


def _module(tmp_path):
    m = MOD.Module()
    m.HOME = tmp_path / "home"
    (m.HOME / "Downloads").mkdir(parents=True)
    m.ENV = {"ProgramFiles": str(tmp_path / "pf"), "ProgramFiles(x86)": str(tmp_path / "pf86"),
             "ProgramData": str(tmp_path / "pd"), "AppData": str(tmp_path / "ad")}
    m.now = lambda: datetime(2026, 3, 12, 12, 0, 0)
    return m


def _sightings(m, fake, profile=None):
    with patch.object(MOD, "run", side_effect=fake):
        return {s.tool.id: s for s in m._win_sightings(profile or _profile())}


def test_uninstall_entry_and_date(tmp_path):
    m = _module(tmp_path)
    fake = _fake_reg(uninstall=_uninstall_block(HKLM, "AnyDesk", "AnyDesk", r"C:\Program Files (x86)\AnyDesk",
                                                 "20260303"))
    with patch.object(MOD, "run", side_effect=fake):
        entries = m._win_uninstall_entries()
    assert {"display_name": "AnyDesk", "install_location": r"C:\Program Files (x86)\AnyDesk",
            "install_date": "20260303"} in entries
    s = _sightings(m, fake)["anydesk"]
    assert s.added_on == date(2026, 3, 3)
    assert s.path == r"C:\Program Files (x86)\AnyDesk"


def test_uninstall_entries_from_all_three_keys(tmp_path):
    m = _module(tmp_path)
    fake = _fake_reg(uninstall=_uninstall_block(HKLM, "A", "Parsec"),
                     uninstall32=_uninstall_block(HKLM32, "B", "TeamViewer 15"),
                     hkcu=_uninstall_block("HKEY_CURRENT_USER\\x", "C", "RustDesk"))
    got = _sightings(m, fake)
    assert {"parsec", "teamviewer", "rustdesk"} <= set(got)


def test_display_name_must_match_the_pattern(tmp_path):
    m = _module(tmp_path)
    fake = _fake_reg(uninstall=_uninstall_block(HKLM, "A", "Not AnyDesk Related Tool")
                     + _uninstall_block(HKLM, "B", "LogMeIn Hamachi"))
    got = _sightings(m, fake)
    assert "anydesk" not in got and "logmein" not in got


def test_install_date_missing_uses_folder_creation_time(tmp_path):
    m = _module(tmp_path)
    folder = tmp_path / "AnyDesk"
    folder.mkdir()
    fake = _fake_reg(uninstall=_uninstall_block(HKLM, "AnyDesk", "AnyDesk", str(folder)))
    s = _sightings(m, fake)["anydesk"]
    created = MOD._created_on(folder)
    assert s.added_on == created
    bad = _fake_reg(uninstall=_uninstall_block(HKLM, "AnyDesk", "AnyDesk", str(folder), "2026-03-03"))
    assert _sightings(m, bad)["anydesk"].added_on == created


def test_auto_start_service_is_unattended(tmp_path):
    m = _module(tmp_path)
    fake = _fake_reg(uninstall=_uninstall_block(HKLM, "AnyDesk", "AnyDesk"),
                     services={"AnyDesk": 2, "Spooler": 2})
    s = _sightings(m, fake)["anydesk"]
    assert s.lets_in_unattended is True and s.unattended_via == "AnyDesk"
    with patch.object(MOD, "run", side_effect=fake):
        assert m._win_services()["AnyDesk"] == "automatic"


def test_manual_service_is_not_unattended(tmp_path):
    m = _module(tmp_path)
    fake = _fake_reg(uninstall=_uninstall_block(HKLM, "AnyDesk", "AnyDesk"), services={"AnyDesk": 3})
    s = _sightings(m, fake)["anydesk"]
    assert s.lets_in_unattended is False and s.unattended_via is None


def test_service_alone_is_a_sighting(tmp_path):
    m = _module(tmp_path)
    fake = _fake_reg(services={"ScreenConnect Client (0123456789abcdef)": 2})
    s = _sightings(m, fake)["screenconnect"]
    assert s.lets_in_unattended is True
    assert s.unattended_via == "ScreenConnect Client (0123456789abcdef)"


def test_registry_unreadable_is_none_not_false(tmp_path):
    m = _module(tmp_path)
    fake = _fake_reg(fail=("HKLM",))
    with patch.object(MOD, "run", side_effect=fake):
        assert m._win_uninstall_entries() is None
        assert m._win_services() is None
    s = _sightings(m, fake, _profile([("AnyDesk.exe", r"C:\Users\x\AnyDesk.exe")]))["anydesk"]
    assert s.lets_in_unattended is None
    assert s.added_on is None
    assert s.one_off is False


def test_quick_assist_only_when_running(tmp_path):
    m = _module(tmp_path)
    fake = _fake_reg(uninstall=_uninstall_block(HKLM, "QA", "Quick Assist"))
    assert "quick_assist" not in _sightings(m, fake)
    assert "quick_assist" not in _sightings(m, fake, _profile([("explorer.exe", "explorer.exe")]))
    s = _sightings(m, fake, _profile([("QuickAssist.exe", r"C:\Windows\System32\QuickAssist.exe")]))["quick_assist"]
    assert s.running_now is True


def test_running_from_downloads_is_one_off(tmp_path):
    m = _module(tmp_path)
    exe = m.HOME / "Downloads" / "AnyDesk.exe"
    exe.write_bytes(b"MZ")
    fake = _fake_reg(services={"Spooler": 2})
    s = _sightings(m, fake, _profile([("AnyDesk.exe", str(exe))]))["anydesk"]
    assert s.running_now is True
    assert s.one_off is True
    assert s.path == str(exe)


def test_download_alone_is_a_sighting(tmp_path):
    m = _module(tmp_path)
    (m.HOME / "Downloads" / "TeamViewerQS.exe").write_bytes(b"MZ")
    s = _sightings(m, _fake_reg(), _profile([("explorer.exe", "explorer.exe")]))["teamviewer"]
    assert s.one_off is True and s.running_now is False


def test_teamviewer_log_on_windows(tmp_path):
    m = _module(tmp_path)
    log = tmp_path / "pf86" / "TeamViewer"
    log.mkdir(parents=True)
    (log / "Connections_incoming.txt").write_text(
        "111\tPeer\t03-03-2026 10:00:00\t03-03-2026 11:00:00\tuser\tRemoteControl\t{0}\n"
        "111\tPeer\t11-03-2026 10:00:00\t11-03-2026 11:00:00\tuser\tRemoteControl\t{0}\n")
    fake = _fake_reg(uninstall32=_uninstall_block(HKLM32, "TeamViewer", "TeamViewer"))
    s = _sightings(m, fake)["teamviewer"]
    assert s.last_incoming == date(2026, 3, 11) and s.incoming_count == 2


def test_check_on_windows_uses_windows_evidence(tmp_path):
    m = _module(tmp_path)
    fake = _fake_reg(uninstall=_uninstall_block(HKLM, "AnyDesk", "AnyDesk"))
    with patch.object(MOD, "run", side_effect=fake):
        result = m.check(_profile([("explorer.exe", "explorer.exe")]))
    assert result.supported and result.error is None
    assert any(f.data.get("tool_id") == "anydesk" for f in result.findings)


# ---------------- never a network or device path ----------------

def test_local_path_rules():
    lp = MOD._local_path
    assert lp(r"C:\Program Files\AnyDesk", True) == r"C:\Program Files\AnyDesk"
    for bad in (r"\\evil\share\AnyDesk", "//evil/share", r"\\?\C:\x", r"\\.\PhysicalDrive0", r"\\?\UNC\evil\s",
                "C:relative", "AnyDesk", "C:\\a\0b", "", None, "/tmp/x"):
        assert lp(bad, True) is None, bad


def _windows_host(m):
    m.WINDOWS_HOST = True
    return m


def test_unc_install_location_is_never_touched(tmp_path):
    m = _windows_host(_module(tmp_path))
    m.HOME = Path("C:/Users/x")  # not a folder here; Downloads is simply empty
    fake = _fake_reg(uninstall=_uninstall_block(HKLM, "AnyDesk", "AnyDesk", r"\\evil\share\AnyDesk"))
    stats, ids = [], []
    real_stat = MOD.os.stat
    with patch.object(MOD.os, "stat", side_effect=lambda p, *a, **k: stats.append(str(p)) or real_stat(p, *a, **k)), \
            patch("rescue.attribution.identify", side_effect=lambda *a, **k: ids.append(a)):
        got = _sightings(m, fake)
        findings = m._findings(list(got.values()), "win32")
    s = got["anydesk"]
    assert s.path is None and s.added_on is None
    assert not [p for p in stats if "evil" in p]
    assert ids == []
    assert all(f.data.get("path") is None for f in findings if f.data.get("tool_id") == "anydesk")
    assert "evil" not in repr([f.data for f in findings])


def test_device_path_install_location_is_rejected(tmp_path):
    m = _windows_host(_module(tmp_path))
    m.HOME = Path("C:/Users/x")
    fake = _fake_reg(uninstall=_uninstall_block(HKLM, "AnyDesk", "AnyDesk", r"\\?\C:\x"))
    with patch.object(MOD, "_created_on", side_effect=AssertionError("stat on a device path")):
        s = _sightings(m, fake)["anydesk"]
    assert s.path is None and s.added_on is None


def test_local_install_location_is_used(tmp_path):
    m = _windows_host(_module(tmp_path))
    m.HOME = Path("C:/Users/x")
    fake = _fake_reg(uninstall=_uninstall_block(HKLM, "AnyDesk", "AnyDesk", r"C:\Program Files\AnyDesk", "20260303"))
    s = _sightings(m, fake)["anydesk"]
    assert s.path == r"C:\Program Files\AnyDesk" and s.added_on == date(2026, 3, 3)


def test_unc_process_path_is_ignored(tmp_path):
    m = _windows_host(_module(tmp_path))
    m.HOME = Path("C:/Users/x")
    with patch.object(MOD, "_created_on", side_effect=AssertionError("stat on a network path")):
        s = _sightings(m, _fake_reg(), _profile([("AnyDesk.exe", r"\\evil\share\AnyDesk.exe")]))["anydesk"]
    assert s.running_now is True and s.path is None and s.added_on is None


def test_env_pointing_at_a_share_means_the_log_is_not_read(tmp_path):
    m = _windows_host(_module(tmp_path))
    m.HOME = Path("C:/Users/x")
    m.ENV = {"ProgramData": r"\\evil\share", "AppData": r"\\evil\share2"}
    fake = _fake_reg(uninstall=_uninstall_block(HKLM, "AnyDesk", "AnyDesk", r"C:\Program Files\AnyDesk"))
    with patch.object(MOD._ev, "read_log", side_effect=AssertionError("read a log on a share")):
        s = _sightings(m, fake)["anydesk"]
    assert s.last_incoming is None and s.incoming_count is None


def test_unc_downloads_folder_is_not_listed(tmp_path):
    m = _windows_host(_module(tmp_path))
    m.HOME = Path(r"\\evil\home")
    with patch.object(MOD, "_bounded_listing", side_effect=AssertionError("listed a share")):
        assert m._win_downloads() == {}
