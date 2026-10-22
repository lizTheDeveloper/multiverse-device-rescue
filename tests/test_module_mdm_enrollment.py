"""mdm_enrollment. All `profiles` output here is synthetic."""

import json
import plistlib
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.command import CommandResult
from rescue.models import Mode, Platform, RiskLevel, Severity, SystemProfile
from rescue.registry import discover_modules

NOT_ENROLLED = "Enrolled via DEP: No\nMDM enrollment: No\n"
ENROLLED = "Enrolled via DEP: Yes\nMDM enrollment: Yes (User Approved)\n"
NO_PROFILES_STATUS = "There are no configuration profiles installed on this system\n"
NO_PROFILES_LIST = "profiles: verbose mode ON\nThere are no configuration profiles installed for user 'tester'\n"
FAIL = object()
TIMEOUT = object()


def _make_profile():
    return SystemProfile(
        platform=Platform.DARWIN,
        os_name="macOS",
        os_version="15.2",
        architecture="arm64",
        cpu_model="Apple M2",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "mdm_enrollment")


def _res(args, out):
    if out is TIMEOUT:
        return CommandResult(list(args), None, "", "", True, None, 10.0, False)
    if out is FAIL:
        return CommandResult(list(args), 1, "", "profiles: error", False, None, 0.01, False)
    return CommandResult(list(args), 0, out, "", False, None, 0.01, False)


def _lines(idx, level="_computerlevel", **attrs):
    return "".join(f"{level}[{idx}] attribute: {k}: {v}\n" for k, v in attrs.items())


def _run(mod, enrollment=NOT_ENROLLED, status=NO_PROFILES_STATUS, xml=FAIL, listing=NO_PROFILES_LIST, calls=None):
    """Run check() with `profiles` answering from the arguments (synthetic output)."""
    answers = {
        ("status", "-type", "enrollment"): enrollment,
        ("status",): status,
        ("show", "-output", "stdout-xml"): xml,
        ("list", "-verbose"): listing,
    }

    def fake(args, **kwargs):
        if calls is not None:
            calls.append((list(args), kwargs))
        if args[0] != "/usr/bin/profiles":
            return CommandResult(list(args), None, "", "", False, "No such file or directory", 0.0, False)
        return _res(args, answers.get(tuple(args[1:]), FAIL))

    with patch.object(sys.modules[type(mod).__module__], "run", side_effect=fake):
        return mod.check(_make_profile())


def _finding(result, check):
    return next((f for f in result.findings if f.data.get("check") == check), None)


def test_mdm_enrollment_discovered():
    mod = _get_module()
    assert mod.name == "mdm_enrollment"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.DARWIN in mod.platforms


def test_mdm_enrollment_no_mdm():
    result = _run(_get_module())
    assert _finding(result, "no_mdm").severity == Severity.INFO
    assert result.complete


def test_mdm_enrollment_mdm_enrolled():
    result = _run(_get_module(), enrollment=ENROLLED)
    assert _finding(result, "mdm_enrolled").severity == Severity.WARNING
    assert _finding(result, "no_mdm") is None


def test_dep_only_is_still_reported_as_managed():
    result = _run(_get_module(), enrollment="Enrolled via DEP: Yes\nMDM enrollment: No\n")
    assert _finding(result, "mdm_enrolled") is not None
    assert _finding(result, "no_mdm") is None


def test_mdm_enrollment_supervised():
    result = _run(_get_module(), enrollment=ENROLLED, status="Supervised: Yes\n" + NO_PROFILES_STATUS)
    assert _finding(result, "supervised").severity == Severity.WARNING


def test_mdm_enrollment_multiple_profiles():
    listing = (
        _lines(1, name="VPN Configuration", profileIdentifier="com.company.vpn")
        + _lines(2, name="Email Configuration", profileIdentifier="com.company.email")
        + _lines(3, name="Security Settings", profileIdentifier="com.company.security")
    )
    f = _finding(_run(_get_module(), listing=listing), "profiles_installed")
    assert f.data.get("count") == 3
    assert f.severity == Severity.WARNING
    assert f.data["unknown_profiles"] == ["VPN Configuration", "Email Configuration", "Security Settings"]


def test_mdm_enrollment_profiles_list_fails():
    """The listing can't be read: enrollment is still reported, but the result isn't complete."""
    result = _run(_get_module(), listing=FAIL)
    assert _finding(result, "no_mdm") is not None
    assert result.complete is False


def test_mdm_enrollment_fix_is_informational():
    mod = _get_module()
    check = _run(mod, enrollment=ENROLLED)
    fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert len(fix.actions) > 0
    for action in fix.actions:
        assert action.success is True


def test_mdm_enrollment_no_mdm_fix():
    mod = _get_module()
    fix = mod.fix(_run(mod), Mode.MANUAL)
    assert fix.all_succeeded
    assert any("no mdm" in a.title.lower() for a in fix.actions)


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.mdm_enrollment.") for c in declared)


# --- a profile is trusted only with evidence its author can't write -------------------


def test_hand_installed_jamf_profile_on_a_mac_not_enrolled_is_a_warning():
    listing = _lines(1, name="Totally Legit IT", organization="Jamf")
    f = _finding(_run(_get_module(), enrollment=NOT_ENROLLED, listing=listing), "profiles_installed")
    assert f.severity == Severity.WARNING
    assert f.data["unknown_profiles"] == ["Totally Legit IT"]


def test_jamf_profile_from_a_manual_source_on_an_enrolled_mac_is_a_warning():
    listing = _lines(1, name="Totally Legit IT", organization="Jamf", source="Manual")
    f = _finding(_run(_get_module(), enrollment=ENROLLED, listing=listing), "profiles_installed")
    assert f.severity == Severity.WARNING
    assert f.data["unknown_profiles"] == ["Totally Legit IT"]


def test_only_the_second_profile_has_an_organization():
    listing = _lines(1, name="Wi-Fi") + _lines(2, name="Example Corp MDM", organization="Jamf")
    f = _finding(_run(_get_module(), enrollment=ENROLLED, listing=listing), "profiles_installed")
    assert f.severity == Severity.WARNING
    assert f.data["unknown_profiles"] == ["Wi-Fi"]
    assert f.data["profiles"][0]["organization"] is None
    assert f.data["profiles"][1]["organization"] == "Jamf"


def test_known_mdm_installed_profile_on_an_enrolled_mac_is_info():
    listing = _lines(1, name="Example Corp MDM", organization="Kandji", profileIdentifier="com.example.mdm")
    f = _finding(_run(_get_module(), enrollment=ENROLLED, listing=listing), "profiles_installed")
    assert f.severity == Severity.INFO
    assert f.data["unknown_profiles"] == []
    with_source = _lines(1, name="Example Corp MDM", organization="Kandji", source="MDM")
    f = _finding(_run(_get_module(), enrollment=ENROLLED, listing=with_source), "profiles_installed")
    assert f.severity == Severity.INFO


def test_structured_output_is_preferred():
    xml = plistlib.dumps({"_computerlevel": [
        {"ProfileDisplayName": "Example Corp MDM", "ProfileIdentifier": "com.example.mdm",
         "ProfileOrganization": "Mosyle"},
    ]}).decode()
    # The text listing disagrees; the XML wins.
    f = _finding(_run(_get_module(), enrollment=ENROLLED, xml=xml, listing=FAIL), "profiles_installed")
    assert f.severity == Severity.INFO
    assert f.data["profiles"][0]["name"] == "Example Corp MDM"


def test_malformed_listing_is_never_info():
    result = _run(_get_module(), enrollment=ENROLLED, listing="Name: Example Corp MDM\nOrganization: Jamf\n")
    f = _finding(result, "profiles_installed")
    assert f is None or f.severity == Severity.WARNING
    assert result.complete is False


def test_ambiguous_enrollment_is_not_trusted():
    listing = _lines(1, name="Example Corp MDM", organization="Jamf")
    result = _run(_get_module(), enrollment="MDM enrollment: maybe\n", listing=listing)
    assert _finding(result, "profiles_installed").severity == Severity.WARNING
    assert _finding(result, "no_mdm") is None
    assert result.complete is False


def test_enrollment_timeout_is_not_healthy():
    listing = _lines(1, name="Example Corp MDM", organization="Jamf")
    result = _run(_get_module(), enrollment=TIMEOUT, listing=listing)
    assert _finding(result, "no_mdm") is None
    assert _finding(result, "profiles_installed").severity == Severity.WARNING
    assert result.complete is False


def test_every_command_timing_out_is_unsupported():
    result = _run(_get_module(), enrollment=TIMEOUT, status=TIMEOUT, xml=TIMEOUT, listing=TIMEOUT)
    assert result.supported is False
    assert result.findings == []


def test_profiles_the_listing_cannot_see_are_not_healthy():
    """`profiles status` counts system-wide; without an administrator the listing may show fewer."""
    result = _run(_get_module(), status="There are 2 configuration profiles installed on this system\n")
    f = _finding(result, "profiles_installed")
    assert f is not None and f.severity == Severity.WARNING
    assert f.data["unreadable_count"] == 2
    assert result.complete is False


def test_never_uses_sudo_and_always_has_a_timeout():
    calls = []
    _run(_get_module(), calls=calls)
    assert calls
    for args, kwargs in calls:
        assert "sudo" not in args
        assert 0 < kwargs.get("timeout", 0) <= 30


def test_known_mdm_list_matches_the_check_modules_copy():
    root = Path(__file__).parent.parent / "modules" / "security"
    a = (root / "mdm_enrollment" / "data" / "known_mdm.json").read_text()
    b = (root / "mdm_enrollment_check" / "data" / "known_mdm.json").read_text()
    assert a == b
    names = json.loads(a)
    for want in ["Jamf", "Kandji", "Mosyle", "Microsoft Intune", "Addigy", "JumpCloud",
                 "VMware Workspace ONE", "Hexnode", "SimpleMDM", "Fleet Device Management",
                 "Apple Business Manager", "Apple School Manager"]:
        assert want in names
    # One-word names that are also ordinary words or other companies' names don't belong.
    for generic in ["Fleet", "Workspace ONE", "Intune", "Apple", "Microsoft"]:
        assert generic not in names
