"""knockknock_scan: KnockKnock's command-line scan, from a verified copy, turned into leads.

KnockKnock, codesign, curl and ditto are never really run here: a fake runner
stands in for rescue.command.run and records every call. The fixture is a
real KnockKnock 4.1.0 scan, trimmed and with the names changed. The live test
at the bottom downloads and runs the real tool, and only when RESCUE_LIVE_KK=1.
"""

import functools
import hashlib
import io
import json
import os
import sys
import zipfile
from pathlib import Path

import pytest

from rescue.command import CommandResult
from rescue.models import Platform, Severity, SystemProfile
from rescue.registry import discover_modules

ROOT = Path(__file__).parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "knockknock" / "whosthere-mac.json"
CODE = "security.knockknock_scan."


def _profile():
    return SystemProfile(
        platform=Platform.DARWIN, os_name="macOS", os_version="26.3", architecture="arm64",
        cpu_model="Apple M2", cpu_cores=8, ram_bytes=16 * 1024**3,
    )


def _result(args, rc=0, out="", err="", timed_out=False):
    return CommandResult(
        args=list(args), returncode=None if timed_out else rc, stdout=out, stderr=err,
        timed_out=timed_out, error="timed out" if timed_out else None,
        duration_s=0.1, truncated=False,
    )


@functools.lru_cache(maxsize=None)
def _code_module():
    # Discovery imports the file afresh each time; patch and use one copy.
    mod = next(m for m in discover_modules(ROOT / "modules") if m.name == "knockknock_scan")
    return sys.modules[type(mod).__module__]


def _fake_app(where: Path) -> Path:
    app = where / "KnockKnock.app"
    exe = app / "Contents" / "MacOS" / "KnockKnock"
    exe.parent.mkdir(parents=True, exist_ok=True)
    exe.write_text("#!/bin/false\n")
    return app


def _app_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("KnockKnock.app/Contents/MacOS/KnockKnock", "#!/bin/false\n")
        z.writestr("KnockKnock.app/Contents/Info.plist", "<plist/>")
    return buf.getvalue()


class FakeRunner:
    """Answers codesign, curl, ditto and KnockKnock the way the real tools do."""

    def __init__(self, scan=None, verify=None, zip_bytes=None):
        self.scan = scan or (lambda args: _result(args, 0, FIXTURE.read_text()))
        # verify(app_path, call_number) -> bool
        self.verify = verify or (lambda app, n: True)
        self.zip_bytes = zip_bytes
        self.calls = []
        self.verifies = 0

    def __call__(self, args, *, timeout=20.0, env=None, cwd=None, **kw):
        args = [str(a) for a in args]
        self.calls.append({"args": args, "timeout": timeout, "env": env})
        prog = Path(args[0]).name
        if prog == "codesign":
            self.verifies += 1
            return _result(args, 0 if self.verify(args[-1], self.verifies) else 3)
        if prog == "curl":
            if self.zip_bytes is None:
                return _result(args, 6, err="curl: (6) Could not resolve host")
            Path(args[args.index("--output") + 1]).write_bytes(self.zip_bytes)
            return _result(args)
        if prog == "ditto":
            with zipfile.ZipFile(args[-2]) as z:
                z.extractall(args[-1])
            return _result(args)
        if prog == "KnockKnock":
            return self.scan(args)
        raise AssertionError(f"unexpected command {args}")

    def ran(self, name):
        return [c for c in self.calls if Path(c["args"][0]).name == name]


@pytest.fixture
def setup(tmp_path, monkeypatch):
    code = _code_module()
    monkeypatch.setenv("RESCUE_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.delenv("RESCUE_NO_DOWNLOADS", raising=False)

    def make(runner=None, installed=True, run_scan=True, **attrs):
        runner = runner or FakeRunner()
        monkeypatch.setattr(code, "run", runner)
        mod = code.Module()
        mod.configure({"run_scan": run_scan})
        mod.elevated = False
        mod.host_resolves = lambda: True
        apps = tmp_path / "Applications"
        mod.installed_apps = (str(_fake_app(apps)),) if installed else (str(apps / "KnockKnock.app"),)
        for k, v in attrs.items():
            setattr(mod, k, v)
        return mod, runner

    return make


def _by_code(result, tail):
    return [f for f in result.findings if f.code == CODE + tail]


# --- off by default ---------------------------------------------------------------


def test_a_plain_checkup_runs_nothing_and_says_so(setup):
    mod, runner = setup(run_scan=False)
    result = mod.check(_profile())
    assert runner.calls == []
    [f] = result.findings
    assert f.code == CODE + "not_run" and f.severity == Severity.INFO
    assert "nothing was checked" in f.description
    assert "deep_startup_check" in f.description


def test_turning_it_on_gives_the_orchestrator_room_for_the_scan(setup):
    mod, _ = setup()
    assert mod.check_timeout and mod.check_timeout > mod.scan_timeout
    off = _code_module().Module()
    off.configure({})
    assert off.check_timeout is None


# --- running a verified copy ------------------------------------------------------


def test_the_scan_is_read_only_and_never_asks_virustotal(setup):
    mod, runner = setup()
    mod.check(_profile())
    [scan] = runner.ran("KnockKnock")
    assert scan["args"][1:] == ["-whosthere", "-skipVT"]
    assert "-key" not in scan["args"] and "-apple" not in scan["args"]
    # Its signature is checked right before and right after the run.
    verifies = runner.ran("codesign")
    assert len(verifies) == 2
    req = next(a for a in verifies[0]["args"] if a.startswith("-R="))
    assert 'certificate leaf[subject.OU] = "VBG97UB4TA"' in req
    assert 'identifier "com.objective-see.KnockKnock"' in req and "notarized" in req
    assert runner.ran("curl") == []


def test_unsigned_and_ad_hoc_programs_are_leads_and_macos_own_are_left_out(setup, monkeypatch):
    mod, _ = setup()
    monkeypatch.setenv("HOME", "/Users/alex")  # the fixture's home folder
    result = mod.check(_profile())
    unsigned = {f.data["name"]: f for f in _by_code(result, "unsigned_autostart")}
    # MailHog and postgres from Homebrew (ad-hoc signed), and a script.
    assert set(unsigned) == {"MailHog", "postgres", "autonomous-agent.sh"}
    assert unsigned["MailHog"].data["signature"] == "ad_hoc"
    assert "Homebrew" in unsigned["MailHog"].description
    assert unsigned["autonomous-agent.sh"].data["signature"] == "unsigned"
    for f in unsigned.values():
        assert f.severity == Severity.WARNING
        # The program and its settings file are named, so "Who made it?" can look.
        assert f.data["path"].startswith("/") and f.data["plist"].endswith(".plist")
        assert "~/Library/LaunchAgents/" in f.description
    # cupsd is on the sealed system volume: macOS's own even though it couldn't be read.
    [unreadable] = _by_code(result, "unreadable_autostart")
    assert unreadable.data["name"] == "com.docker.socket"
    names = {f.data.get("name") for f in result.findings}
    assert "cupsd" not in names and "bash" not in names


def test_the_same_item_listed_twice_is_one_lead(setup):
    mod, _ = setup()
    result = mod.check(_profile())
    [mailhog] = [f for f in result.findings if f.data.get("name") == "MailHog"]
    assert mailhog.data["knockknock_groups"] == ["Background Managed Tasks", "Launch Items"]
    # Described by the launch item, the place a person can find it.
    assert "a launch agent or daemon" in mailhog.description


def test_signed_items_are_one_inventory_note_with_the_noise_counted(setup):
    mod, _ = setup()
    result = mod.check(_profile())
    [inv] = _by_code(result, "signed_inventory")
    assert inv.severity == Severity.INFO
    names = {i["name"] for i in inv.data["items"]}
    assert {"Dropbox", "Loom", "usbserial", "ChmodBPF"} <= names
    assert inv.data["covered_elsewhere"] == 3  # a cron job, a browser extension, .zshrc
    assert inv.data["duplicates"] >= 5
    # bash for two launch agents, and cupsd on the sealed volume
    assert inv.data["apple_run_count"] == 3
    assert inv.data["lead_count"] == 4
    assert inv.data["knockknock_source"] == "installed"
    assert "Signed doesn't mean safe" in inv.description


def _scan_with(items: dict):
    return lambda args: _result(args, 0, json.dumps(items))


def test_anything_in_a_rarely_used_place_is_a_lead_and_unsigned_injection_is_critical(setup):
    items = {
        "Library Inserts": [{"name": "libhook.dylib", "path": "/Users/Shared/libhook.dylib",
                             "plist": "/Library/LaunchAgents/com.x.plist", "hashes": "unknown",
                             "signature(s)": {"signatureStatus": -67062}}],
        "Authorization Plugins": [{"name": "Okta", "path": "/Library/Security/SecurityAgentPlugins/Okta.bundle",
                                   "plist": "n/a", "signature(s)": {
                                       "signatureStatus": 0, "signatureSigner": 3, "notarized": True,
                                       "signatureAuthorities": ["Developer ID Application: Okta, Inc. (B7F62B65BN)"]}}],
    }
    mod, _ = setup(FakeRunner(scan=_scan_with(items)))
    result = mod.check(_profile())
    rare = {f.data["name"]: f for f in _by_code(result, "rare_autostart_place")}
    assert rare["libhook.dylib"].severity == Severity.CRITICAL
    assert rare["Okta"].severity == Severity.WARNING
    assert "Okta, Inc." in rare["Okta"].description
    for f in rare.values():
        assert "alert them" in f.description  # the monitoring safety note


def test_a_signature_that_doesnt_check_out_is_its_own_lead(setup):
    items = {"Login Items": [{"name": "Helper", "path": "/Applications/H.app/Contents/MacOS/H",
                              "plist": "n/a", "signature(s)": {"signatureStatus": -67061}}]}
    mod, _ = setup(FakeRunner(scan=_scan_with(items)))
    [f] = _by_code(mod.check(_profile()), "broken_signature")
    assert f.severity == Severity.WARNING and "plist" not in f.data


def test_leads_are_capped_and_the_rest_counted(setup):
    code = _code_module()
    items = {"Launch Items": [
        {"name": f"t{i}", "path": f"/Users/alex/bin/t{i}", "plist": f"/Users/alex/Library/LaunchAgents/t{i}.plist",
         "signature(s)": {"signatureStatus": -67062}} for i in range(code.MAX_LEADS + 5)]}
    mod, _ = setup(FakeRunner(scan=_scan_with(items)))
    result = mod.check(_profile())
    assert len(_by_code(result, "unsigned_autostart")) == code.MAX_LEADS
    [inv] = _by_code(result, "signed_inventory")
    assert inv.data["not_listed_leads"] == 5 and "5 more" in inv.description


@pytest.mark.parametrize("item,state", [
    ({"signature(s)": {"signatureStatus": 0, "signatureSigner": 1}}, "apple"),
    ({"signature(s)": {"signatureStatus": 0, "signatureSigner": 2, "signatureIdentifier": "com.apple.iWork.Pages"}}, "apple"),
    ({"signature(s)": {"signatureStatus": 0, "signatureSigner": 2, "signatureIdentifier": "com.vendor.app"}}, "signed"),
    ({"signature(s)": {"signatureStatus": 0, "signatureSigner": 3}}, "signed"),
    ({"signature(s)": {"signatureStatus": 0, "signatureSigner": 4}}, "ad_hoc"),
    ({"signature(s)": {"signatureStatus": -67062}}, "unsigned"),
    ({"signature(s)": {"signatureStatus": -67061}}, "broken"),
    ({"signature(s)": {"signatureStatus": 100013}}, "unreadable"),
    ({"signature(s)": "unknown"}, "unreadable"),
    ({"command": "* * * * * x", "file": "/private/var/at/tabs/alex"}, "none"),
])
def test_signature_states(item, state):
    assert _code_module().signature_state(item) == state


# --- couldn't run: never "clean" ------------------------------------------------


def _couldnt(result):
    [f] = result.findings
    assert f.code == CODE + "could_not_check" and f.severity == Severity.INFO
    assert "doesn't mean everything is fine" in f.description
    return f


def test_never_runs_with_administrator_rights(setup):
    mod, runner = setup(elevated=True)
    assert _couldnt(mod.check(_profile())).data["reason"] == "elevated"
    assert runner.calls == []


def test_no_full_disk_access_says_how_to_give_it(setup):
    err = "ERROR: KnockKnock (Terminal) requires Full Disk Access.\nPlease grant Full Disk Access..."
    mod, _ = setup(FakeRunner(scan=lambda a: _result(a, 1, "", err)))
    f = _couldnt(mod.check(_profile()))
    assert f.data["reason"] == "no_full_disk_access"
    assert "Privacy & Security > Full Disk Access" in f.description


@pytest.mark.parametrize("scan,reason", [
    (lambda a: _result(a, timed_out=True), "timed_out"),
    (lambda a: _result(a, 0, "not json"), "bad_output"),
    (lambda a: _result(a, 0, '{"ERROR" : "failed to covert output to JSON"}'), "bad_output"),
    (lambda a: _result(a, 2, "", "Segmentation fault"), "tool_failed"),
])
def test_a_scan_that_didnt_finish_is_reported_as_such(setup, scan, reason):
    mod, _ = setup(FakeRunner(scan=scan))
    assert _couldnt(mod.check(_profile())).data["reason"] == reason


def test_an_installed_copy_not_signed_by_objective_see_is_never_run(setup, monkeypatch):
    monkeypatch.setenv("RESCUE_NO_DOWNLOADS", "1")
    mod, runner = setup(FakeRunner(verify=lambda app, n: False))
    f = _couldnt(mod.check(_profile()))
    assert f.data == {"reason": "downloads_off", "installed_but_wrong": True}
    assert "isn't signed by Objective-See" in f.description
    assert runner.ran("KnockKnock") == []


def test_a_profile_kept_offline_never_downloads(setup):
    mod, runner = setup(installed=False)
    mod.configure({"run_scan": True, "downloads": False})
    assert _couldnt(mod.check(_profile())).data["reason"] == "kept_offline"
    assert runner.ran("curl") == []


def test_no_internet_skips_the_download_at_once(setup):
    mod, runner = setup(installed=False, host_resolves=lambda: False)
    assert _couldnt(mod.check(_profile())).data["reason"] == "offline"
    assert runner.ran("curl") == []


# --- the one-time download --------------------------------------------------------


def test_first_run_downloads_the_pinned_release_checks_it_and_keeps_it(setup, monkeypatch, tmp_path):
    code = _code_module()
    blob = _app_zip()
    monkeypatch.setattr(code, "KK_ZIP_SHA256", hashlib.sha256(blob).hexdigest())
    mod, runner = setup(FakeRunner(zip_bytes=blob), installed=False)
    result = mod.check(_profile())
    [curl] = runner.ran("curl")
    assert code.KK_URL in curl["args"] and "=https" in curl["args"]
    saved = tmp_path / "cache" / "ReclaimCity" / f"knockknock-{code.KK_VERSION}" / "KnockKnock.app"
    assert (saved / "Contents" / "MacOS" / "KnockKnock").is_file()
    [inv] = _by_code(result, "signed_inventory")
    assert inv.data["knockknock_source"] == "downloaded"
    # No leftovers beside the saved copy.
    assert sorted(p.name for p in saved.parent.parent.iterdir()) == [saved.parent.name]
    # The next checkup reuses it.
    mod.check(_profile())
    assert len(runner.ran("curl")) == 1


def test_a_download_that_isnt_the_published_file_is_thrown_away(setup, tmp_path):
    mod, runner = setup(FakeRunner(zip_bytes=_app_zip()), installed=False)
    assert _couldnt(mod.check(_profile())).data["reason"] == "download_mismatch"
    assert runner.ran("ditto") == [] and runner.ran("KnockKnock") == []
    assert list((tmp_path / "cache" / "ReclaimCity").iterdir()) == []


def test_a_download_whose_signature_fails_is_never_run_or_kept(setup, monkeypatch, tmp_path):
    code = _code_module()
    blob = _app_zip()
    monkeypatch.setattr(code, "KK_ZIP_SHA256", hashlib.sha256(blob).hexdigest())
    mod, runner = setup(FakeRunner(zip_bytes=blob, verify=lambda app, n: False), installed=False)
    assert _couldnt(mod.check(_profile())).data["reason"] == "signature_mismatch"
    assert runner.ran("KnockKnock") == []
    assert list((tmp_path / "cache" / "ReclaimCity").iterdir()) == []


def test_a_zip_with_paths_outside_the_app_is_refused(setup, monkeypatch):
    code = _code_module()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("KnockKnock.app/Contents/MacOS/KnockKnock", "x")
        z.writestr("../evil", "x")
    blob = buf.getvalue()
    monkeypatch.setattr(code, "KK_ZIP_SHA256", hashlib.sha256(blob).hexdigest())
    mod, runner = setup(FakeRunner(zip_bytes=blob), installed=False)
    assert _couldnt(mod.check(_profile())).data["reason"] == "download_mismatch"
    assert runner.ran("ditto") == []


def test_a_signature_that_stops_checking_out_during_the_run_discards_everything(setup, monkeypatch, tmp_path):
    code = _code_module()
    blob = _app_zip()
    monkeypatch.setattr(code, "KK_ZIP_SHA256", hashlib.sha256(blob).hexdigest())
    # Check 1 (where it will run from, before the run) passes; 2 (after the run) fails.
    mod, _ = setup(FakeRunner(zip_bytes=blob, verify=lambda app, n: n < 2), installed=False)
    [f] = mod.check(_profile()).findings
    assert f.code == CODE + "changed_during_run" and f.severity == Severity.WARNING
    assert not (tmp_path / "cache" / "ReclaimCity" / f"knockknock-{code.KK_VERSION}").exists()


# --- the real thing --------------------------------------------------------------


@pytest.mark.skipif(os.environ.get("RESCUE_LIVE_KK") != "1" or sys.platform != "darwin",
                    reason="set RESCUE_LIVE_KK=1 on a Mac to download and run the real KnockKnock")
def test_live_download_and_scan(tmp_path, monkeypatch):
    monkeypatch.setenv("RESCUE_CACHE_DIR", str(tmp_path))
    mod = _code_module().Module()
    mod.configure({"run_scan": True})
    mod.installed_apps = ()
    result = mod.check(_profile())
    codes = {f.code for f in result.findings}
    assert CODE + "signed_inventory" in codes or CODE + "could_not_check" in codes
