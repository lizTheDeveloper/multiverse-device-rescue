"""rescue.macos_profiles: reading `profiles` output. All output here is synthetic."""

import json
import plistlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.macos_profiles import (
    is_known_mdm,
    parse_enrollment,
    parse_profiles_text,
    parse_profiles_xml,
    parse_system_profile_count,
    untrusted_profiles,
)

KNOWN = json.loads(
    (Path(__file__).parent.parent / "modules/security/mdm_enrollment/data/known_mdm.json").read_text()
)


def _lines(level, idx, **attrs):
    return "".join(f"{level}[{idx}] attribute: {k}: {v}\n" for k, v in attrs.items())


# --- enrollment -------------------------------------------------------------


def test_enrollment_yes_and_user_approved():
    assert parse_enrollment("Enrolled via DEP: No\nMDM enrollment: Yes\n")["mdm"] is True
    e = parse_enrollment("Enrolled via DEP: Yes\nMDM enrollment: Yes (User Approved)\nMDM server: https://x.example/mdm\n")
    assert e["mdm"] is True and e["dep"] is True
    assert e["server"] == "https://x.example/mdm"


def test_enrollment_no():
    e = parse_enrollment("Enrolled via DEP: No\nMDM enrollment: No\n")
    assert e["mdm"] is False and e["dep"] is False


def test_dep_yes_is_not_mdm_enrollment():
    assert parse_enrollment("Enrolled via DEP: Yes\nMDM enrollment: No\n")["mdm"] is False


def test_enrollment_unreadable_is_none():
    for out in ["", None, "Enrolled: Yes\n", "MDM enrollment: perhaps\n", "garbage"]:
        assert parse_enrollment(out)["mdm"] is None, out


def test_enrollment_conflicting_lines_is_none():
    assert parse_enrollment("MDM enrollment: Yes\nMDM enrollment: No\n")["mdm"] is None


# --- system profile count -----------------------------------------------------


def test_system_profile_count():
    assert parse_system_profile_count("There are no configuration profiles installed on this system\n") == 0
    assert parse_system_profile_count("There are 3 configuration profiles installed on this system\n") == 3
    assert parse_system_profile_count("There is 1 configuration profile installed on this system\n") == 1
    assert parse_system_profile_count("") is None
    assert parse_system_profile_count("something else") is None


# --- text listing -----------------------------------------------------------------


def test_text_blocks_split_on_index_and_never_carry_fields():
    out = (
        _lines("_computerlevel", 1, name="Wi-Fi", profileIdentifier="com.example.wifi")
        + _lines("_computerlevel", 2, name="Example MDM", organization="Jamf", source="MDM")
    )
    profiles = parse_profiles_text(out)
    assert [p["name"] for p in profiles] == ["Wi-Fi", "Example MDM"]
    assert profiles[0]["organization"] is None
    assert profiles[0]["installed_by_mdm"] is None
    assert profiles[1]["organization"] == "Jamf"
    assert profiles[1]["installed_by_mdm"] is True


def test_text_organization_before_name_stays_in_its_block():
    out = _lines("_computerlevel", 1, name="First") + _lines("_computerlevel", 2, organization="Jamf", name="Second")
    a, b = parse_profiles_text(out)
    assert (a["name"], a["organization"]) == ("First", None)
    assert (b["name"], b["organization"]) == ("Second", "Jamf")


def test_text_user_level_and_computer_level_are_separate_blocks():
    out = _lines("_computerlevel", 1, name="A", organization="Jamf") + _lines("tester", 1, name="B")
    a, b = parse_profiles_text(out)
    assert a["level"] == "_computerlevel" and b["level"] == "tester"
    assert b["organization"] is None


def test_text_noise_lines_are_ignored_and_none_installed_is_empty():
    assert parse_profiles_text(
        "profiles: verbose mode ON\nThere are no configuration profiles installed for user 'tester'\n"
    ) == []


def test_text_unrecognised_output_is_none():
    # No `level[N] attribute:` lines and no "no profiles" sentence: we can't tell what's there.
    assert parse_profiles_text("Name: Example MDM\nOrganization: Jamf\n") is None
    assert parse_profiles_text("") is None
    assert parse_profiles_text(None) is None


def test_text_manual_source_is_not_mdm():
    (p,) = parse_profiles_text(_lines("_computerlevel", 1, name="X", organization="Jamf", source="Manual"))
    assert p["installed_by_mdm"] is False


def test_text_conflicting_values_in_a_block_are_ambiguous():
    out = "_computerlevel[1] attribute: name: X\n_computerlevel[1] attribute: organization: Jamf\n" \
          "_computerlevel[1] attribute: organization: Someone Else\n"
    (p,) = parse_profiles_text(out)
    assert p["ambiguous"] is True


# --- XML listing ------------------------------------------------------------------


def _xml(obj):
    return plistlib.dumps(obj).decode()


def test_xml_profiles():
    out = _xml({"_computerlevel": [
        {"ProfileDisplayName": "Example MDM", "ProfileIdentifier": "com.example.mdm", "ProfileOrganization": "Kandji"},
        {"ProfileIdentifier": "com.example.wifi"},
    ]})
    a, b = parse_profiles_xml(out)
    assert (a["name"], a["organization"], a["level"]) == ("Example MDM", "Kandji", "_computerlevel")
    assert (b["name"], b["organization"]) == ("com.example.wifi", None)


def test_xml_empty_dict_is_no_profiles():
    assert parse_profiles_xml(_xml({})) == []


def test_xml_bad_or_odd_shape_is_none():
    assert parse_profiles_xml("not xml") is None
    assert parse_profiles_xml("") is None
    assert parse_profiles_xml(_xml(["a"])) is None
    assert parse_profiles_xml(_xml({"_computerlevel": "nope"})) is None


# --- known / trust ------------------------------------------------------------------


def test_known_list_has_no_generic_one_word_names():
    assert "Fleet" not in KNOWN
    assert "Fleet Device Management" in KNOWN
    assert "VMware Workspace ONE" in KNOWN
    assert not is_known_mdm("Fleet Street Bakery", KNOWN)
    assert is_known_mdm("Jamf Software", KNOWN)


def _p(name, org=None, by_mdm=None):
    return {"name": name, "organization": org, "installed_by_mdm": by_mdm, "ambiguous": False}


def test_trust_needs_enrollment():
    ps = [_p("A", "Jamf")]
    assert untrusted_profiles(ps, enrolled=True, known=KNOWN) == []
    assert untrusted_profiles(ps, enrolled=False, known=KNOWN) == ps
    assert untrusted_profiles(ps, enrolled=None, known=KNOWN) == ps


def test_trust_needs_mdm_source_when_the_output_gives_sources():
    manual = [_p("A", "Jamf", by_mdm=False)]
    assert untrusted_profiles(manual, enrolled=True, known=KNOWN) == manual
    mixed = [_p("A", "Jamf", by_mdm=True), _p("B", "Jamf")]
    # Some profiles say where they came from: one that doesn't is not known.
    assert [p["name"] for p in untrusted_profiles(mixed, enrolled=True, known=KNOWN)] == ["B"]


def test_ambiguous_profile_is_never_trusted():
    p = _p("A", "Jamf")
    p["ambiguous"] = True
    assert untrusted_profiles([p], enrolled=True, known=KNOWN) == [p]
