"""Check names, error kinds, tidy titles, severity caps and the extra evidence
fields in ``rescue scan --json`` (UX audit 1: P2-14, P2-15, P2-16, P2-27,
P2-30, P1-11, P1-12)."""

import json
from pathlib import Path

import pytest

from rescue.check_names import CHECK_NAMES, check_name, error_kind
from rescue.models import CheckResult, Finding, Severity
from rescue.registry import discover_modules
from rescue.serialize import checks_to_json, module_entry
from rescue.severity_policy import CAPPABLE, cap_severity
from rescue.wording import plain_day, tidy

MODULES_DIR = Path(__file__).resolve().parent.parent / "modules"
ALL = discover_modules(MODULES_DIR)


class Mod:
    def __init__(self, name, category="security"):
        self.name = name
        self.category = category


def f(title="t", severity=Severity.WARNING, data=None, description="d", code=None):
    return Finding(title=title, description=description, severity=severity, category="security",
                   data=data or {}, code=code)


# ---- check names (P2-15) ----

def test_every_module_has_a_name_for_people():
    names = {m.name for m in ALL}
    assert names, "modules were discovered"
    missing = sorted(names - set(CHECK_NAMES))
    assert not missing, f"add these to rescue/check_names.py: {missing}"
    stale = sorted(set(CHECK_NAMES) - names)
    assert not stale, f"no such module: {stale}"


@pytest.mark.parametrize("name", sorted(CHECK_NAMES))
def test_a_name_is_words_not_an_id(name):
    words = CHECK_NAMES[name]
    assert words[0].isupper() or words.startswith(("iCloud", "iPhone", "macOS")), words
    assert "_" not in words
    assert len(words) <= 60


def test_unknown_module_gets_words_never_the_id():
    assert check_name("brand_new_check") == "Brand new check"
    assert check_name("") == "A check"
    assert check_name("code_signature_audit") == "App signatures"


def test_error_kinds():
    assert error_kind(None) is None
    assert error_kind("This check took too long ... (timed out after 60.0s)") == "timeout"
    assert error_kind("PermissionError: [Errno 1] Operation not permitted: '/Library/LaunchDaemons'") == "permission"
    assert error_kind("skipped: session time budget exhausted") == "skipped"
    assert error_kind("KeyError: 'x'") == "error"
    assert error_kind(None, supported=False) == "unsupported"
    assert error_kind(None, complete=False) == "unfinished"


def test_module_entry_carries_check_name_and_error_kind():
    e = module_entry(Mod("code_signature_audit"), CheckResult(module_name="code_signature_audit",
                     error="PermissionError: [Errno 1] Operation not permitted"))
    assert e["check_name"] == "App signatures"
    assert e["error_kind"] == "permission"
    ok = module_entry(Mod("disk_space", "performance"), CheckResult(module_name="disk_space"))
    assert ok["check_name"] == "Disk space" and ok["error_kind"] is None


def test_plan_and_progress_lines_carry_check_name(capsys):
    from rescue import cli

    cli._emit_plan([Mod("smcreset_guide", "integrity")])
    cli._emit_progress("start", 60, 196, Mod("smcreset_guide", "integrity"), None)
    lines = [json.loads(x) for x in capsys.readouterr().err.splitlines()]
    assert lines[0]["plan"]["modules"][0]["check_name"] == "Power controller reset guide"
    assert lines[1]["progress"]["check_name"] == "Power controller reset guide"


# ---- tidy titles (P2-14) ----

@pytest.mark.parametrize("raw, want", [
    ("Keyboard access: 1 app(s)", "Keyboard access: 1 app"),
    ("Keyboard access: 2 app(s) with familiar names", "Keyboard access: 2 apps with familiar names"),
    ("1 new persistence item(s) since 2026-10-10T18:44:55+00:00", "1 new persistence item since 10 Oct 2026"),
    ("4 new listening port(s) since 2026-10-10T18:44:55+00:00", "4 new listening ports since 10 Oct 2026"),
    ("1 app(s) have been granted access", "1 app has been granted access"),
    ("3 app(s) have been granted access", "3 apps have been granted access"),
    ("Your Mac crashed 1 times in the last 30 days", "Your Mac crashed once in the last 30 days"),
    ("crashed 50 times", "crashed 50 times"),
    ("Proxy server(s) configured on en0", "Proxy servers configured on en0"),
    ("Bad RAM detected (1 error(s))", "Bad RAM detected (1 error)"),
    ("1 32-bit app(s) installed", "1 32-bit app installed"),
    ("Spyware scanner not installed (2 backup(s) found)", "Spyware scanner not installed (2 backups found)"),
    ("1,200 file(s)", "1,200 files"),
    ("2 box(s)", "2 boxes"),
    ("no change here", "no change here"),
])
def test_tidy(raw, want):
    assert tidy(raw) == want


def test_tidy_leaves_non_strings_and_dates_alone():
    assert tidy(None) is None
    assert tidy("") == ""
    assert plain_day("2026-01-02T00:00:00Z") == "2 Jan 2026"
    assert tidy("on 2026-10-13 11:16:42") == "on 2026-10-13 11:16:42"  # a plain date stays as written


def test_scan_json_titles_and_descriptions_are_tidy_and_data_is_not():
    when = "2026-10-10T18:44:55+00:00"
    finding = f(title=f"1 new persistence item(s) since {when}", description="1 app(s) have it",
                data={"baseline_captured_at": when})
    doc = json.loads(checks_to_json([(Mod("security_baseline_diff"), CheckResult("security_baseline_diff", [finding]))], "darwin"))
    out = doc["modules"][0]["findings"][0]
    assert out["title"] == "1 new persistence item since 10 Oct 2026"
    assert out["description"] == "1 app has it"
    assert out["data"]["baseline_captured_at"] == when
    assert "(s)" in finding.title, "the finding itself is unchanged"


def test_no_module_title_says_website_names_are_for_one():
    src = (MODULES_DIR / "security" / "hosts_file_check" / "__init__.py").read_text()
    assert "1 website name is being redirected" in src
    font = (MODULES_DIR / "integrity" / "font_issues" / "__init__.py").read_text()
    assert "more than one place ({len(duplicates)})" not in font


# ---- dedupe (P2-14) ----

def test_identical_findings_in_one_check_become_one_with_repeats():
    same = lambda: f(title="Login item: Amical", severity=Severity.INFO, data={"item_name": "Amical"})  # noqa: E731
    other = f(title="Login item: Zoom", severity=Severity.INFO, data={"item_name": "Zoom"})
    e = module_entry(Mod("login_items", "bloatware"), CheckResult("login_items", [same(), other, same(), same()]))
    titles = [x["title"] for x in e["findings"]]
    assert titles == ["Login item: Amical", "Login item: Zoom"]
    assert e["findings"][0]["repeats"] == 3
    assert "repeats" not in e["findings"][1]


def test_findings_that_differ_in_data_are_kept_apart():
    a = f(title="Script downloads and runs code: setup.sh", data={"path": "/a/setup.sh"})
    b = f(title="Script downloads and runs code: setup.sh", data={"path": "/b/setup.sh"})
    e = module_entry(Mod("ai_worm_filesystem"), CheckResult("ai_worm_filesystem", [a, b]))
    assert len(e["findings"]) == 2


# ---- makers verified (P1-11) ----

def _with_makers(entries, apps):
    finding = f(title="Keyboard access: 2 app(s) with familiar names", severity=Severity.INFO,
                data={"check": "claimed_vendor_input_monitoring", "apps": apps},
                code="security.keylogger_indicators.suspicious_input_monitoring")
    e = module_entry(Mod("keylogger_indicators"), CheckResult("keylogger_indicators", [finding]),
                     made_by={id(finding): entries})
    return e["findings"][0]


def test_makers_verified_only_when_every_app_has_a_verified_maker():
    ms = {"subject": "com.microsoft.VSCode", "name": "Microsoft Corporation", "verified": True, "how": "Developer ID signature"}
    valve = {"subject": "com.valvesoftware.steam", "name": "Valve", "verified": True, "how": "Developer ID signature"}
    apps = ["com.microsoft.VSCode", "com.valvesoftware.steam"]
    assert _with_makers([ms, valve], apps)["makers_verified"] is True
    assert _with_makers([ms], apps)["makers_verified"] is False
    assert _with_makers([ms, {**valve, "verified": False}], apps)["makers_verified"] is False
    plain = module_entry(Mod("x"), CheckResult("x", [f()]))["findings"][0]
    assert "makers_verified" not in plain, "no makers looked up, nothing claimed"


# ---- severity (P2-30) ----

def _cat(module):
    return {"resource_hog_identifier": "performance"}.get(module, "integrity")


@pytest.mark.parametrize("module, check_key", sorted(CAPPABLE, key=str))
def test_each_named_finding_is_capped_to_a_warning(module, check_key):
    data = {} if check_key is None else {"check": check_key}
    finding = Finding(title="t", description="d", severity=Severity.CRITICAL, category=_cat(module), data=data)
    check = CheckResult(module, [finding, f(severity=Severity.INFO)])
    cap_severity(Mod(module, _cat(module)), check)
    assert [x.severity for x in check.findings] == [Severity.WARNING, Severity.INFO]


def test_process_scanner_cryptominer_and_scareware_stay_critical():
    for kind in ("cryptominer", "scareware"):
        finding = Finding(title="x", description="d", severity=Severity.CRITICAL, category="bloatware",
                          data={"name": "x", "bloatware_category": kind})
        check = CheckResult("process_scanner", [finding])
        cap_severity(Mod("process_scanner", "bloatware"), check)
        assert check.findings[0].severity == Severity.CRITICAL, kind


def test_a_named_finding_that_names_harm_stays_critical():
    finding = Finding(title="xmrig is using a lot of power", description="d", severity=Severity.CRITICAL,
                      category="performance", data={"name": "xmrig", "command": "/tmp/xmrig --donate-level 1"})
    check = CheckResult("resource_hog_identifier", [finding])
    cap_severity(Mod("resource_hog_identifier", "performance"), check)
    assert check.findings[0].severity == Severity.CRITICAL


def test_unnamed_findings_and_security_checks_keep_their_severity():
    for mod, data in ((Mod("startup_auditor", "bloatware"), {}),
                      (Mod("time_machine_check", "integrity"), {"check": "tm_unknown"}),
                      (Mod("code_signature_audit", "security"), {"check": "tampered_binary"}),
                      (Mod("disk_smart_check", "integrity"), {})):
        check = CheckResult(mod.name, [f(severity=Severity.CRITICAL, data=data)])
        cap_severity(mod, check)
        assert check.findings[0].severity == Severity.CRITICAL, mod.name
    # A security-category finding is never capped, even from a named module.
    sec = Finding(title="t", description="d", severity=Severity.CRITICAL, category="security", data={})
    check = CheckResult("resource_hog_identifier", [sec])
    cap_severity(Mod("resource_hog_identifier", "performance"), check)
    assert check.findings[0].severity == Severity.CRITICAL


def test_capped_modules_exist():
    names = {m.name for m in ALL}
    assert {m for m, _ in CAPPABLE} <= names


def test_orchestrator_applies_the_cap():
    src = (Path(__file__).resolve().parent.parent / "rescue" / "orchestrator.py").read_text()
    assert "cap_severity(mod, check)" in src
    cli = (Path(__file__).resolve().parent.parent / "rescue" / "cli.py").read_text()
    assert "cap_severity(mod, check)" in cli


# ---- held wording (P2-27) and undo text (P2-16) ----

def test_monitoring_finding_does_not_point_at_steps_that_are_not_shown():
    src = (MODULES_DIR / "security" / "stalkerware_scan" / "__init__.py").read_text()
    assert "steps below" not in src


def test_mark_undo_keeps_the_command_line_apart():
    from rescue import known_items

    assert all("rescue known" not in s for s in known_items.MARK_HOW_TO_UNDO)
    assert known_items.MARK_HOW_TO_UNDO_CLI.startswith("rescue known remove <id>")


# ---- evidence (P1-12) ----

def test_ssh_keys_finding_names_its_file(tmp_path):
    from rescue.registry import discover_modules as dm

    mod = next(m for m in dm(MODULES_DIR) if m.name == "session_revocation_scan")
    data = mod._authorized_keys_data(0)
    assert data["file"] == "~/.ssh/authorized_keys" or data["file"] == str(mod.authorized_keys_path)
