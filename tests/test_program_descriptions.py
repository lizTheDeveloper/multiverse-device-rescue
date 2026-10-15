"""Tests for the "what it is" line (rescue/program_descriptions.json).

A description is attached only when the signing Identifier AND the verified
Team ID (or Apple's anchor) match an entry, never by name or path.
"""
import json
import re
from pathlib import Path
from types import SimpleNamespace

import rescue.attribution as attribution
from rescue.attribution import Attributor, MadeBy, describe, parse_codesign
from rescue.models import CheckResult, Finding, Severity
from rescue.serialize import checks_to_json
from tests.test_attribution import APPLE_LS, KEYNOTE, UNSIGNED, _plist, mac, verify_run

LOOM = """Executable=/Applications/Loom.app/Contents/MacOS/Loom
Identifier=com.loom.desktop
Format=app bundle with Mach-O universal (x86_64 arm64)
Authority=Developer ID Application: Loom, Inc (QGD2ZPXZZG)
Authority=Developer ID Certification Authority
Authority=Apple Root CA
TeamIdentifier=QGD2ZPXZZG
"""
KEYSTONE_AGENT = """Identifier=com.google.Keystone.Agent
Authority=Developer ID Application: Google LLC (EQHXZ8M8AV)
Authority=Developer ID Certification Authority
TeamIdentifier=EQHXZ8M8AV
"""
TERMINAL = APPLE_LS.replace("Identifier=com.apple.ls", "Identifier=com.apple.Terminal")
DEV = dict(verified=True, how="Developer ID signature")


def _identify(dv, ok=True, calls=None, path="/Applications/Loom.app"):
    return Attributor("darwin", run=verify_run(dv, ok, calls)).identify(path, exists=lambda p: True)


def _verify_args(calls):
    return " ".join(next(c for c in calls if "--verify" in c))


def test_verified_identifier_and_team_get_a_description():
    d = _identify(LOOM).to_dict("com.loom.desktop")
    assert d["verified"] is True and d["name"] == "Loom, Inc"
    assert d["what"] == "Loom: records your screen and camera to make video messages you can share with a link."


def test_verify_requirement_pins_the_identifier_the_description_is_keyed_on():
    calls = []
    _identify(LOOM, calls=calls)
    req = _verify_args(calls)
    assert 'identifier "com.loom.desktop" and anchor apple generic' in req
    assert '"QGD2ZPXZZG"' in req


def test_same_identifier_with_another_team_gets_no_description():
    other = LOOM.replace("Loom, Inc (QGD2ZPXZZG)", "Look Alike Ltd (ABCDE12345)").replace(
        "TeamIdentifier=QGD2ZPXZZG", "TeamIdentifier=ABCDE12345")
    m = _identify(other)
    assert m.verified is True  # a real signature, just not Loom's
    assert "what" not in m.to_dict("x")


def test_same_identifier_with_missing_team_gets_no_description():
    m = MadeBy("Loom, Inc", identifier="com.loom.desktop", **DEV)
    assert describe(m) == ""
    assert "what" not in m.to_dict("x")


def test_unverified_signature_gets_no_description():
    m = _identify(LOOM, ok=False)
    assert m.verified is False and "what" not in m.to_dict("x")
    forged = MadeBy("Loom, Inc", False, "Developer ID signature", team="QGD2ZPXZZG",
                    identifier="com.loom.desktop")
    assert describe(forged) == ""


def test_unsigned_and_homebrew_get_no_description():
    assert "what" not in parse_codesign(UNSIGNED).to_dict("x")
    assert "what" not in mac({}).identify("homebrew.mxcl.evil").to_dict("homebrew.mxcl.evil")


def test_name_or_path_alone_never_selects_a_description():
    m = MadeBy("Google LLC", team="EQHXZ8M8AV", identifier="com.example.notchrome", **DEV)
    assert "what" not in m.to_dict("/Applications/Google Chrome.app")


def test_extra_instructions_drop_the_description(tmp_path):
    path = _plist(tmp_path, {"ProgramArguments": ["/Applications/Loom.app/Contents/MacOS/Loom", "--x"]})
    made = Attributor("darwin", run=verify_run(LOOM, True))._identify_plist(path, lambda p: True)
    assert made.verified is False and "what" not in made.to_dict(path)


def test_prefix_entry_covers_helpers_of_the_same_team():
    m = _identify(KEYSTONE_AGENT, path="/x/GoogleSoftwareUpdateAgent.app")
    assert m.verified is True
    assert m.to_dict("x")["what"].startswith("Google Software Update: ")


def test_prefix_entry_needs_a_dot_boundary_and_the_same_team():
    assert describe(MadeBy("G", team="EQHXZ8M8AV", identifier="com.google.Keystone", **DEV))
    assert describe(MadeBy("G", team="EQHXZ8M8AV", identifier="com.google.KeystoneEvil", **DEV)) == ""
    assert describe(MadeBy("G", team="ABCDE12345", identifier="com.google.Keystone.Agent", **DEV)) == ""


def test_exact_entry_is_not_a_prefix():
    assert describe(MadeBy("L", team="QGD2ZPXZZG", identifier="com.loom.desktop.helper", **DEV)) == ""


def test_apple_system_program_is_described_by_anchor_and_identifier():
    m = _identify(TERMINAL, path="/System/Applications/Utilities/Terminal.app")
    assert m.how == "Apple system file"
    assert m.to_dict("x")["what"].startswith("Terminal: ")
    assert "what" not in _identify(TERMINAL, ok=False).to_dict("x")
    calls = []
    _identify(TERMINAL, calls=calls)
    assert 'identifier "com.apple.Terminal" and anchor apple' in _verify_args(calls)


def test_apple_team_entries_need_apples_own_signature():
    # An "apple" entry is never matched by a Developer ID signature, whatever its team.
    assert describe(MadeBy("x", team="ABCDE12345", identifier="com.apple.Terminal", **DEV)) == ""


def test_apple_app_store_app_is_described_but_not_a_third_party_one():
    pages = KEYNOTE.replace("com.apple.iWork.Keynote", "com.apple.iWork.Pages")
    assert _identify(pages).to_dict("x")["what"].startswith("Pages: ")
    third = MadeBy("x", True, "Mac App Store signature", team="4CBU3JHV97",
                   identifier="com.daisydiskapp.DaisyDisk")
    assert describe(third) == ""


def test_windows_and_linux_entries_never_get_descriptions():
    assert describe(MadeBy("Google LLC", True, "Authenticode signature")) == ""
    assert describe(MadeBy("Ubuntu package x", True, "system package")) == ""


def test_identifier_that_cannot_be_pinned_is_dropped():
    odd = LOOM.replace("Identifier=com.loom.desktop", 'Identifier=com.loom.desktop"or"1')
    calls = []
    m = _identify(odd, calls=calls)
    assert m.identifier == "" and "what" not in m.to_dict("x")
    assert "identifier" not in _verify_args(calls)


def test_description_table_is_well_formed():
    raw = json.loads((Path(attribution.__file__).parent / "program_descriptions.json").read_text("utf-8"))
    assert raw["_comment"]
    seen = set()
    for p in raw["programs"]:
        assert set(p) <= {"identifier", "team_id", "name", "what", "match"}, p
        assert p["team_id"] == "apple" or attribution._TEAM_ID_RE.match(p["team_id"]), p
        assert attribution._IDENTIFIER_RE.match(p["identifier"]), p
        assert p.get("match", "exact") in ("exact", "prefix"), p
        assert p["what"].endswith(".") and len(p["what"]) <= 240, p
        assert not re.search(r"\b(safe|harmless|legitimate|nothing to worry)\b", p["what"], re.I), p
        key = (p["identifier"], p["team_id"])
        assert key not in seen, p
        seen.add(key)
    exact, prefix = attribution._load_descriptions()
    assert len(exact) + len(prefix) == len(raw["programs"])


def test_remote_access_entries_say_what_they_allow():
    exact, _ = attribution._load_descriptions()
    for ident in ("com.apple.RemoteDesktopAgent", "com.apple.screensharing.daemon"):
        assert "see and control this Mac from elsewhere" in exact[(ident, "apple")]
    assert "log in to this Mac over the network" in exact[("com.apple.sshd", "apple")]


def test_checks_to_json_carries_what_but_no_internals():
    f = Finding(title="t", description="d", severity=Severity.INFO, category="security",
                data={"bundle_id": "com.loom.desktop"})
    entry = MadeBy("Loom, Inc", team="QGD2ZPXZZG", identifier="com.loom.desktop", **DEV).to_dict("com.loom.desktop")
    doc = json.loads(checks_to_json([(SimpleNamespace(name="m"), CheckResult(module_name="m", findings=[f]))],
                                    "darwin", made_by={id(f): [entry]}))
    mb = doc["modules"][0]["findings"][0]["made_by"][0]
    assert mb["what"].startswith("Loom: ")
    assert not {"team", "identifier", "runner"} & set(mb)


def test_unmatched_entries_have_no_what_key():
    d = MadeBy("Some Shop", team="ABCDE12345", identifier="com.some.thing", **DEV).to_dict("x")
    assert "what" not in d
