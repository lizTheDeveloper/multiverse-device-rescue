"""keylogger_indicators reads each Input Monitoring grant's code requirement.

Synthetic TCC rows and csreq output only: the real TCC.db is never queried
(every command goes through the module's mocked runner).
"""

import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.attribution import REQUIREMENT_HOW, maker_for_signer, requirement_made_by
from rescue.command import CommandResult
from rescue.models import CheckResult, Severity
from rescue.registry import discover_modules
from rescue.serialize import checks_to_json

MAGIC = "FADE0C00"


def _mod():
    modules = discover_modules(Path(__file__).parent.parent / "modules")
    return next(m for m in modules if m.name == "keylogger_indicators")


def _devid(ident, team):
    return (f'identifier "{ident}" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] '
            f"/* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and "
            f"certificate leaf[subject.OU] = {team}")


def _result(args, rc=0, stdout=""):
    return CommandResult(args=list(args), returncode=rc, stdout=stdout, stderr="", timed_out=False,
                         error=None, duration_s=0.0, truncated=False)


def _runner(rows, requirements, *, csreq_rc=0, sqlite_rc=0, seen=None):
    """rows: [(client, client_type, blob_id or None)]; requirements: blob_id -> text.

    Each blob is the csreq magic plus the blob id, so the fake csreq can tell
    which requirement text to print for it.
    """
    def hexrow(client, ctype, blob_id):
        blob = "" if blob_id is None else MAGIC + blob_id.encode().hex().upper()
        return f"{client.encode().hex().upper()}|{ctype}|{blob}"

    user_rows = "\n".join(hexrow(*r) for r in rows) + "\n"

    def fake(args, timeout=None, input=None, **kw):
        if seen is not None:
            seen.append((list(args), timeout, input))
        assert timeout is not None and timeout <= 5, "every command has a short time budget"
        if args[0] == "sqlite3":
            # Only the user database answers; the system one is unreadable (no Full Disk Access).
            if "/Library/Application Support/com.apple.TCC/TCC.db" == args[1]:
                return _result(args, rc=1)
            return _result(args, rc=sqlite_rc, stdout=user_rows if "hex(client)" in args[2] else "")
        if args[0] == "/usr/bin/csreq":
            assert args[1:] == ["-r", "-", "-t"]
            assert isinstance(input, bytes) and input.startswith(bytes.fromhex(MAGIC))
            blob_id = input[4:].decode()
            return _result(args, rc=csreq_rc, stdout=requirements.get(blob_id, "") + "\n")
        raise AssertionError(f"unexpected command {args}")

    return fake


def _check(rows, requirements, **kw):
    mod = _mod()
    with patch.object(sys.modules[type(mod).__module__], "run", side_effect=_runner(rows, requirements, **kw)), \
            patch.object(mod, "_check_cgeventtap_usage", return_value=[]):
        return mod, mod.check(None)


def _by_check(result, check):
    return [f for f in result.findings if f.data.get("check") == check]


VSC, STEAM = "com.microsoft.VSCode", "com.valvesoftware.steam"
MS, VALVE = "UBF8T346G9", "MXGJJ98X76"


def test_familiar_apps_whose_requirement_pins_the_expected_team_are_verified():
    _, result = _check([(VSC, 0, "a"), (STEAM, 0, "b")], {"a": _devid(VSC, MS), "b": _devid(STEAM, VALVE)})
    (f,) = _by_check(result, "claimed_vendor_input_monitoring")
    assert f.severity == Severity.INFO
    assert f.data["apps"] == [VSC, STEAM]
    assert f.data["verified_apps"] == [
        {"bundle_id": VSC, "team_id": MS, "maker": "Microsoft Corporation", "verified_by": "macos_code_requirement",
         "runs_other_programs": True},
        {"bundle_id": STEAM, "team_id": VALVE, "maker": "Valve Corporation (Steam)", "verified_by": "macos_code_requirement"},
    ]
    assert "confirmed by macOS" in f.title
    assert not [x for x in result.findings if x.severity != Severity.INFO]


def test_familiar_name_signed_by_another_team_is_a_warning_with_the_removal_warning():
    _, result = _check([("com.microsoft.Keyboard", 0, "a"), (VSC, 0, "b")],
                       {"a": _devid("com.microsoft.Keyboard", "EVILTEAM99"), "b": _devid(VSC, MS)})
    (bad,) = _by_check(result, "familiar_name_other_signer")
    assert bad.severity == Severity.WARNING
    assert bad.code == "security.keylogger_indicators.suspicious_input_monitoring"
    assert bad.data["apps"] == ["com.microsoft.Keyboard"]
    assert bad.data["signers"] == [{"bundle_id": "com.microsoft.Keyboard", "team_id": "EVILTEAM99", "maker": None}]
    assert "removing it can alert them" in bad.description
    assert "1-800-799-7233" in bad.description and "START to 88788" in bad.description
    assert "EVILTEAM99" in bad.description
    (good,) = _by_check(result, "claimed_vendor_input_monitoring")
    assert good.data["apps"] == [VSC]


def test_familiar_name_signed_by_another_known_company_is_also_an_impostor():
    _, result = _check([("com.google.Chrome", 0, "a")], {"a": _devid("com.google.Chrome", MS)})
    (bad,) = _by_check(result, "familiar_name_other_signer")
    assert bad.data["signers"][0]["maker"] == "Microsoft Corporation"


@pytest.mark.parametrize("rows,reqs,kw", [
    ([(VSC, 0, None)], {}, {}),  # no csreq in the row
    ([(VSC, 0, "a")], {"a": "garbage"}, {}),  # unparseable
    ([(VSC, 0, "a")], {"a": _devid(VSC, MS) + " or anchor trusted"}, {}),  # hostile
    ([(VSC, 0, "a")], {"a": _devid("com.microsoft.Other", MS)}, {}),  # wrong identifier
    ([(VSC, 0, "a")], {"a": _devid(VSC, MS)}, {"csreq_rc": 1}),  # csreq failed
    ([(VSC, 1, "a")], {"a": _devid(VSC, MS)}, {}),  # a path-type row
    ([(VSC, 0, "a"), (VSC, 0, None)], {"a": _devid(VSC, MS)}, {}),  # a second row we can't read
    ([("com.sublimetext.3", 0, "a")], {"a": _devid("com.sublimetext.3", "ABCDE12345")}, {}),  # no expected team known
    ([("com.logitech.Options", 0, "a")], {"a": _devid("com.logitech.Options", MS)}, {}),  # prefix with no known team
])
def test_anything_unproven_stays_unverified_info_as_before(rows, reqs, kw):
    _, result = _check(rows, reqs, **kw)
    (f,) = _by_check(result, "claimed_vendor_input_monitoring")
    assert f.severity == Severity.INFO
    assert "verified_apps" not in f.data
    assert "not verified" in f.description.lower()
    assert not _by_check(result, "familiar_name_other_signer")


def test_apple_anchor_counts_as_apple():
    _, result = _check([("com.apple.Terminal", 0, "a")], {"a": 'identifier "com.apple.Terminal" and anchor apple'})
    (f,) = _by_check(result, "claimed_vendor_input_monitoring")
    assert f.data["verified_apps"][0]["maker"] == "Apple"
    assert f.data["verified_apps"][0]["team_id"] == "apple"


def test_unfamiliar_apps_are_still_warned_about_even_when_signed():
    _, result = _check([("com.example.keys", 0, "a")], {"a": _devid("com.example.keys", MS)})
    (f,) = _by_check(result, "suspicious_input_monitoring")
    assert f.severity == Severity.WARNING
    assert "removing it can alert them" in f.description


def test_commands_are_bounded_and_the_csreq_calls_capped():
    mod = _mod()
    kmod = sys.modules[type(mod).__module__]
    seen = []
    rows = [(f"com.microsoft.App{i}", 0, f"r{i}") for i in range(kmod.CSREQ_MAX_CALLS + 5)]
    reqs = {f"r{i}": _devid(f"com.microsoft.App{i}", MS) for i in range(len(rows))}
    with patch.object(kmod, "run", side_effect=_runner(rows, reqs, seen=seen)), \
            patch.object(mod, "_check_cgeventtap_usage", return_value=[]):
        result = mod.check(None)
    csreq_calls = [s for s in seen if s[0][0] == "/usr/bin/csreq"]
    assert len(csreq_calls) == kmod.CSREQ_MAX_CALLS
    verified, unread = sorted(_by_check(result, "claimed_vendor_input_monitoring"), key=lambda f: "verified_apps" in f.data, reverse=True)
    assert len(verified.data["verified_apps"]) == kmod.CSREQ_MAX_CALLS
    assert len(unread.data["apps"]) == 5 and "verified_apps" not in unread.data


def test_oversized_or_wrong_magic_blobs_never_reach_csreq():
    mod = _mod()
    kmod = sys.modules[type(mod).__module__]
    with patch.object(kmod, "run", side_effect=AssertionError("must not run")):
        assert mod._requirement_text(b"\x00\x01") is None
        assert mod._requirement_text(bytes.fromhex(MAGIC) + b"x" * 5000) is None
        assert mod._requirement_text(b"") is None


def test_old_schema_falls_back_to_names_only():
    mod = _mod()
    kmod = sys.modules[type(mod).__module__]

    def fake(args, timeout=None, input=None, **kw):
        if args[0] == "sqlite3" and "hex(client)" in args[2]:
            return _result(args, rc=1)
        if args[0] == "sqlite3":
            return _result(args, stdout=f"{VSC}\n")
        raise AssertionError(args)

    with patch.object(kmod, "run", side_effect=fake), patch.object(mod, "_check_cgeventtap_usage", return_value=[]):
        result = mod.check(None)
    (f,) = _by_check(result, "claimed_vendor_input_monitoring")
    assert "verified_apps" not in f.data


def test_parse_rows_skips_malformed_lines():
    kmod = sys.modules[type(_mod()).__module__]
    good = f"{VSC.encode().hex()}|0|{MAGIC}"
    rows = kmod._parse_rows("\n".join([good, "zz|0|", "abc", "|0|", f"{VSC.encode().hex()}|x|"]))
    assert rows == [(VSC, 0, bytes.fromhex(MAGIC)), (VSC, None, b"")]


def test_familiar_signer_teams_are_all_in_the_maker_table():
    kmod = sys.modules[type(_mod()).__module__]
    for _prefix, signers in kmod.FAMILIAR_SIGNERS:
        for s in signers:
            assert maker_for_signer(s), s


# ---- serialized: the verified evidence becomes verified makers ----

def _serialize(rows, reqs, made_by=None):
    mod, result = _check(rows, reqs)
    if made_by is None:
        made_by = {}
    doc = json.loads(checks_to_json([(mod, result)], "darwin", made_by=made_by))
    return doc["modules"][0]["findings"]


def test_serialized_verified_finding_has_verified_makers_from_the_requirement():
    findings = _serialize([(VSC, 0, "a"), (STEAM, 0, "b")], {"a": _devid(VSC, MS), "b": _devid(STEAM, VALVE)})
    (f,) = [x for x in findings if x["data"].get("check") == "claimed_vendor_input_monitoring"]
    assert f["makers_verified"] is True
    by = {m["subject"]: m for m in f["made_by"]}
    assert by[VSC]["verified"] is True and by[VSC]["how"] == REQUIREMENT_HOW
    assert by[VSC]["name"] == "Microsoft Corporation"
    assert by[VSC]["what"].startswith("Visual Studio Code")
    assert by[STEAM]["what"].startswith("Steam")


def test_serialized_requirement_entry_replaces_a_named_only_lookup():
    mod, result = _check([(VSC, 0, "a")], {"a": _devid(VSC, MS)})
    (f,) = [x for x in result.findings if x.data.get("check") == "claimed_vendor_input_monitoring"]
    named = {"subject": VSC, "name": "Someone", "verified": True, "how": "Developer ID signature"}
    doc = json.loads(checks_to_json([(mod, result)], "darwin", made_by={id(f): [named]}))
    (out,) = [x for x in doc["modules"][0]["findings"] if x["data"].get("check") == "claimed_vendor_input_monitoring"]
    assert out["made_by"] == [requirement_made_by(VSC, MS).to_dict(VSC)]
    assert out["makers_verified"] is True


def test_serialized_unverified_and_no_attribution_stay_as_before():
    findings = _serialize([(VSC, 0, None)], {})
    (f,) = [x for x in findings if x["data"].get("check") == "claimed_vendor_input_monitoring"]
    assert "made_by" not in f or f.get("makers_verified") is not True
    mod, result = _check([(VSC, 0, "a")], {"a": _devid(VSC, MS)})
    doc = json.loads(checks_to_json([(mod, result)], "darwin"))  # attribution off
    (f,) = [x for x in doc["modules"][0]["findings"] if x["data"].get("check") == "claimed_vendor_input_monitoring"]
    assert "made_by" not in f


def test_verified_apps_from_another_module_or_forged_entries_are_ignored():
    from rescue.models import Finding

    class Other:
        name = "app_permissions"
        category = "security"

    forged = Finding(title="x", description="y", severity=Severity.INFO, category="security",
                     code="security.keylogger_indicators.suspicious_input_monitoring",
                     data={"check": "claimed_vendor_input_monitoring", "apps": [VSC],
                           "verified_apps": [{"bundle_id": VSC, "team_id": MS, "maker": "M",
                                              "verified_by": "macos_code_requirement"}]})
    doc = json.loads(checks_to_json([(Other(), CheckResult("app_permissions", [forged]))], "darwin", made_by={}))
    assert "made_by" not in doc["modules"][0]["findings"][0]
    mod = _mod()
    for bad in ({"bundle_id": VSC, "team_id": "NOTINTABLE", "verified_by": "macos_code_requirement"},
                {"bundle_id": VSC, "team_id": MS, "verified_by": "name"},
                {"bundle_id": "com.other.App", "team_id": MS, "verified_by": "macos_code_requirement"}):
        f = Finding(title="x", description="y", severity=Severity.INFO, category="security",
                    code="security.keylogger_indicators.suspicious_input_monitoring",
                    data={"check": "claimed_vendor_input_monitoring", "apps": [VSC], "verified_apps": [bad]})
        doc = json.loads(checks_to_json([(mod, CheckResult(mod.name, [f]))], "darwin", made_by={}))
        assert doc["modules"][0]["findings"][0].get("makers_verified") is not True, bad


def test_the_suite_never_reads_a_real_tcc_database():
    import subprocess

    with pytest.raises(AssertionError, match="real TCC database"):
        subprocess.run(["sqlite3", "/Library/Application Support/com.apple.TCC/TCC.db", "select 1"])


def test_requirement_makers_and_apple_anchor_agree_with_attribution():
    from rescue import attribution
    from rescue.code_requirement import APPLE

    assert APPLE == attribution._APPLE_ANCHOR
    assert maker_for_signer(APPLE) == "Apple"
    assert maker_for_signer("NOTATEAMID") is None and maker_for_signer("ZZZZZZZZZZ") is None
    assert requirement_made_by("com.microsoft.VSCode", "ZZZZZZZZZZ") is None
    assert requirement_made_by('com.x" or', MS) is None
    made = requirement_made_by(VSC, MS)
    assert made.verified and made.how == REQUIREMENT_HOW
    assert attribution.describe(made).startswith("Visual Studio Code")
    # A Team ID is not enough for a description: the identifier must match too.
    assert attribution.describe(requirement_made_by("com.microsoft.Other", MS)) == ""


def test_verified_apps_that_start_other_programs_say_those_programs_share_the_access():
    # A terminal or code editor's grant covers whatever it runs (a script typed
    # into it can read keys too), so confirming the maker isn't the whole story.
    _, result = _check([(VSC, 0, "a"), ("com.apple.Terminal", 0, "b"), (STEAM, 0, "c")],
                       {"a": _devid(VSC, MS), "b": 'identifier "com.apple.Terminal" and anchor apple',
                        "c": _devid(STEAM, VALVE)})
    (f,) = _by_check(result, "claimed_vendor_input_monitoring")
    hosts = {v["bundle_id"]: v.get("runs_other_programs", False) for v in f.data["verified_apps"]}
    assert hosts == {VSC: True, "com.apple.Terminal": True, STEAM: False}
    assert "Programs started from" in f.description
    assert "com.apple.Terminal" in f.description.split("Programs started from")[1]
    assert STEAM not in f.description.split("Programs started from")[1]
