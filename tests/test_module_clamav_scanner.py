"""clamav_scanner: the "is it installed" checks, and the opt-in ClamAV file scan.

Every command goes through a fake runner, and every file lives in a temporary
folder. No ClamAV is run and nothing is downloaded.
"""

import os
import sys
import time
from pathlib import Path

import pytest

from rescue import file_scan
from rescue.command import CommandResult
from rescue.models import Mode, Platform, RiskLevel, Severity, SystemProfile
from rescue.registry import discover_modules

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX paths in the fake ClamAV layout")


def _profile(platform=Platform.DARWIN):
    return SystemProfile(platform=platform, os_name="x", os_version="1", architecture="arm64",
                         cpu_model="M2", cpu_cores=8, ram_bytes=16 * 1024**3)


def _res(code=0, out="", err="", timed_out=False):
    return CommandResult(args=[], returncode=None if timed_out else code, stdout=out, stderr=err,
                         timed_out=timed_out, error="timed out" if timed_out else None, duration_s=0, truncated=False)


# The ClamAV folders every test module looks in (the db fixture fills it); empty = none.
_DB_DIRS: list[str] = []


def _module(**attrs):
    mod = next(m for m in discover_modules(Path(__file__).parent.parent / "modules") if m.name == "clamav_scanner")
    mod.db_dirs = _DB_DIRS
    for k, v in attrs.items():
        setattr(mod, k, v)
    return mod


class FakeClam:
    """clamscan/freshclam/sigtool/pgrep, answered from a table; every call is recorded."""

    def __init__(self, scan=None, fresh=None, daemon=True):
        self.calls = []
        self.scan = scan or _res(0)
        self.fresh = fresh
        self.daemon = daemon

    def __call__(self, args, timeout=None):
        self.calls.append(list(args))
        prog = os.path.basename(args[0])
        if args[1:] == ["--version"]:
            return _res(0, "ClamAV 1.4.1/27450/Mon Oct 20 08:00:00 2026\n")
        if prog == "sigtool":
            return _res(0, "Version: 62\n")
        if prog == "pgrep":
            return _res(0 if self.daemon else 1, "123\n" if self.daemon else "")
        if prog == "freshclam":
            return self.fresh(args) if self.fresh else _res(1)
        if prog == "clamscan":
            return self.scan
        raise AssertionError(args)


def _which(installed):
    return lambda name: f"/usr/local/bin/{os.path.basename(name)}" if os.path.basename(name) in installed else None


@pytest.fixture
def db(tmp_path):
    """A ClamAV virus list folder, `age` days old; modules made by _module() look only there."""
    folder = tmp_path / "clamdb"
    folder.mkdir()

    def make(age):
        for name in ("main.cvd", "daily.cvd"):
            p = folder / name
            p.write_bytes(b"cvd")
            t = time.time() - age * 86400
            os.utime(p, (t, t))
        return str(folder)

    _DB_DIRS[:] = [str(folder)]
    yield make
    _DB_DIRS[:] = []


@pytest.fixture
def targets(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / "Downloads").mkdir(parents=True)
    monkeypatch.setattr(file_scan, "app_programs", lambda h: [])
    monkeypatch.setattr(file_scan, "job_programs", lambda h: [])
    monkeypatch.setattr(file_scan, "places", lambda platform, h: [("downloads", h / "Downloads", 4)])
    bad = home / "Downloads" / "invoice.zip"
    bad.write_bytes(b"PK\x03\x04 pretend archive")
    (home / "Downloads" / "letter.pdf").write_bytes(b"%PDF")
    return type("T", (), {"home": home, "bad": bad})


# --- is it installed --------------------------------------------------------------


def test_metadata():
    mod = _module()
    assert mod.category == "security" and mod.risk_level == RiskLevel.SAFE
    assert set(mod.platforms) == {Platform.DARWIN, Platform.LINUX, Platform.WIN32}


@pytest.mark.parametrize("platform, words", [
    (Platform.DARWIN, ".pkg file"), (Platform.WIN32, ".msi file"), (Platform.LINUX, "apt install clamav"),
])
def test_not_installed_is_information_with_a_route_for_everyone(platform, words):
    res = _module(which=_which(set()), runner=FakeClam()).check(_profile(platform))
    assert [f.code for f in res.findings] == ["security.clamav_scanner.clamav_not_installed"]
    f = res.findings[0]
    assert f.severity == Severity.INFO
    assert words in f.description
    assert ("clamav.net/downloads" in f.description) == (platform != Platform.LINUX)


def test_not_installed_and_a_deep_scan_was_asked_for_says_it_did_not_run():
    mod = _module(which=_which(set()), runner=FakeClam())
    mod.configure({"scan_files": True})
    codes = [f.data.get("reason") for f in mod.check(_profile()).findings]
    assert "not_installed" in codes


def test_healthy_install_offers_the_deep_scan(db):
    db(2)
    res = _module(which=_which({"clamscan", "freshclam", "sigtool"}), runner=FakeClam()).check(_profile())
    codes = {f.code.rsplit(".", 1)[1] for f in res.findings}
    assert {"clamav_version", "clamav_definitions", "clamd_running", "deep_scan_available"} <= codes
    assert all(f.severity == Severity.INFO for f in res.findings)
    offer = next(f for f in res.findings if f.code.endswith("deep_scan_available"))
    assert "115 MB" in offer.description


def test_old_list_and_no_updater_are_warnings(db):
    db(45)
    res = _module(which=_which({"clamscan"}), runner=FakeClam(daemon=False)).check(_profile())
    by = {f.code.rsplit(".", 1)[1]: f for f in res.findings}
    assert by["clamav_outdated_definitions"].severity == Severity.WARNING
    assert by["freshclam_not_installed"].severity == Severity.WARNING
    assert by["clamd_not_running"].severity == Severity.INFO


def test_fix_is_guidance_only_and_not_homebrew_only():
    mod = _module(which=_which(set()), runner=FakeClam())
    fix = mod.fix(mod.check(_profile()), Mode.MANUAL)
    assert fix.all_succeeded and fix.actions[0].title == "Install ClamAV"
    assert "clamav.net/downloads" in fix.actions[0].description


# --- the deep scan ----------------------------------------------------------------


def _deep(**attrs):
    mod = _module(**attrs)
    mod.configure({"scan_files": True})
    return mod


def test_deep_scan_reports_a_virus_with_its_fingerprint(db, targets, tmp_path):
    db(1)
    clam = FakeClam(scan=_res(1, f"{targets.bad}: Win.Trojan.Agent-123 FOUND\n"))
    mod = _deep(which=_which({"clamscan", "freshclam"}), runner=clam, home=targets.home, cache_dir=tmp_path / "c")
    res = mod.check(_profile())
    hit = next(f for f in res.findings if f.code == "security.clamav_scanner.virus_found")
    assert hit.severity == Severity.CRITICAL
    assert hit.data["path"] == str(targets.bad) and hit.data["signature"] == "Win.Trojan.Agent-123"
    assert hit.data["virustotal_url"].endswith(hit.data["sha256"])
    scan = next(c for c in clam.calls if os.path.basename(c[0]) == "clamscan" and "--file-list" in c)
    assert "--infected" in scan and scan[scan.index("--database") + 1].endswith("clamdb")
    assert mod.check_timeout and mod.check_timeout > mod.scan_timeout


def test_deep_scan_monitoring_hit_carries_the_warning(db, targets, tmp_path):
    db(1)
    clam = FakeClam(scan=_res(1, f"{targets.bad}: Osx.Spyware.FlexiSpy-1 FOUND\n"))
    res = _deep(which=_which({"clamscan"}), runner=clam, home=targets.home, cache_dir=tmp_path / "c").check(_profile())
    hit = next(f for f in res.findings if f.code == "security.clamav_scanner.monitoring_found")
    assert "removing it can alert them" in hit.description


def test_deep_scan_clean_and_timed_out(db, targets, tmp_path):
    db(1)
    clean = _deep(which=_which({"clamscan"}), runner=FakeClam(), home=targets.home, cache_dir=tmp_path / "c")
    f = next(f for f in clean.check(_profile()).findings if f.code.endswith("scan_clean"))
    assert f.data["files_scanned"] == 2 and "ruling one out" in f.description
    late = _deep(which=_which({"clamscan"}), runner=FakeClam(scan=_res(timed_out=True)), home=targets.home,
                 cache_dir=tmp_path / "c")
    f = next(f for f in late.check(_profile()).findings if f.code.endswith("scan_incomplete"))
    assert "isn't a clean result" in f.description


@pytest.mark.parametrize("setup, reason", [
    ({"env": True}, "downloads_off"),
    ({"config": True}, "kept_offline"),
    ({"elevated": True}, "elevated"),
    ({"offline": True}, "offline"),
    ({"no_freshclam": True}, "no_freshclam"),
    ({}, "fetch_failed"),
])
def test_an_old_list_that_cannot_be_refreshed_is_not_a_scan(db, targets, tmp_path, monkeypatch, setup, reason):
    db(40)
    monkeypatch.delenv("RESCUE_NO_DOWNLOADS", raising=False)
    if setup.get("env"):
        monkeypatch.setenv("RESCUE_NO_DOWNLOADS", "1")
    installed = {"clamscan"} if setup.get("no_freshclam") else {"clamscan", "freshclam"}
    clam = FakeClam()
    mod = _module(which=_which(installed), runner=clam, home=targets.home, cache_dir=tmp_path / "c",
                  elevated=bool(setup.get("elevated")), mirror_resolves=lambda: not setup.get("offline"))
    mod.configure({"scan_files": True, **({"downloads": False} if setup.get("config") else {})})
    res = mod.check(_profile())
    could_not = [f for f in res.findings if f.code == "security.clamav_scanner.could_not_scan"]
    assert [f.data["reason"] for f in could_not] == [reason]
    assert not any(os.path.basename(c[0]) == "clamscan" and "--file-list" in c for c in clam.calls)


def test_a_fresh_list_is_downloaded_into_the_cache_once_allowed(db, targets, tmp_path, monkeypatch):
    db(40)
    monkeypatch.delenv("RESCUE_NO_DOWNLOADS", raising=False)
    cache = tmp_path / "cache"

    def fetch(args):
        for name in ("main.cvd", "daily.cvd"):
            (cache / name).write_bytes(b"cvd")
        return _res(0)

    clam = FakeClam(fresh=fetch)
    mod = _deep(which=_which({"clamscan", "freshclam"}), runner=clam, home=targets.home, cache_dir=cache,
                elevated=False, mirror_resolves=lambda: True)
    res = mod.check(_profile())
    fresh = next(c for c in clam.calls if os.path.basename(c[0]) == "freshclam")
    assert f"--datadir={cache}" in fresh
    assert "DatabaseMirror database.clamav.net" in (cache / "freshclam.conf").read_text()
    clean = next(f for f in res.findings if f.code.endswith("scan_clean"))
    assert clean.data["database_fetched"] is True and clean.data["database_dir"] == str(cache)


def test_emitted_codes_are_declared():
    declared = set(_module().emits_codes)
    assert all(c.startswith("security.clamav_scanner.") for c in declared)
    assert {"security.clamav_scanner.virus_found", "security.clamav_scanner.could_not_scan"} <= declared
