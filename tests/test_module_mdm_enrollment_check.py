"""mdm_enrollment_check. All `profiles` output here is synthetic."""

import plistlib
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.command import CommandResult
from rescue.models import Mode, RiskLevel, Severity, SystemProfile, Platform
from rescue.registry import discover_modules

NOT_ENROLLED = "Enrolled via DEP: No\nMDM enrollment: No\n"
NO_PROFILES_STATUS = "There are no configuration profiles installed on this system\n"
NO_PROFILES_LIST = "There are no configuration profiles installed for user 'tester'\n"
FAIL = object()
TIMEOUT = object()


def _enrolled(server):
    return f"Enrolled via DEP: Yes\nMDM enrollment: Yes (User Approved)\nMDM server: {server}\n"


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
    return next(m for m in modules if m.name == "mdm_enrollment_check")


def _res(args, out):
    if out is TIMEOUT:
        return CommandResult(list(args), None, "", "", True, None, 10.0, False)
    if out is FAIL:
        return CommandResult(list(args), 1, "", "profiles: error", False, None, 0.01, False)
    return CommandResult(list(args), 0, out, "", False, None, 0.01, False)


def _lines(idx, level="_computerlevel", **attrs):
    return "".join(f"{level}[{idx}] attribute: {k}: {v}\n" for k, v in attrs.items())


def _run(mod, enrollment=NOT_ENROLLED, status=NO_PROFILES_STATUS, xml=FAIL, listing=NO_PROFILES_LIST,
         bootstrap="profiles: Bootstrap Token supported on server: NO\n", calls=None):
    answers = {
        ("status", "-type", "enrollment"): enrollment,
        ("status",): status,
        ("status", "-type", "bootstraptoken"): bootstrap,
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


JAMF_LISTING = (
    _lines(1, name="Company Mobile Device Management", organization="Jamf", source="MDM")
    + _lines(2, name="Company Security Settings", organization="Jamf Pro", source="MDM")
)


def test_mdm_enrollment_check_discovered():
    mod = _get_module()
    assert mod.name == "mdm_enrollment_check"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE


def test_mdm_enrollment_check_no_mdm():
    result = _run(_get_module())
    assert not result.has_issues
    assert result.supported and result.complete


def test_mdm_enrollment_check_mdm_enrolled_jamf():
    result = _run(_get_module(), enrollment=_enrolled("https://mycompany.jamfcloud.com"), listing=JAMF_LISTING)
    mdm_finding = _finding(result, "mdm_enrollment")
    assert mdm_finding.severity == Severity.INFO
    assert "jamfcloud" in mdm_finding.description.lower()


def test_mdm_enrollment_check_with_restrictions():
    listing = (
        _lines(1, name="Company Mobile Device Management")
        + _lines(2, name="Parental Controls Profile")
        + _lines(3, name="App Restrictions")
        + _lines(4, name="Managed Settings")
    )
    result = _run(_get_module(), enrollment=_enrolled("https://mycompany.kandji.io"), listing=listing)
    assert _finding(result, "mdm_enrollment") is not None
    assert _finding(result, "restrictions_profiles").severity == Severity.WARNING


def test_mdm_enrollment_check_all_profiles_listed():
    result = _run(_get_module(), enrollment=_enrolled("https://mycompany.jamfcloud.com"), listing=JAMF_LISTING)
    f = _finding(result, "all_profiles")
    assert f.severity == Severity.INFO
    assert f.data["profiles"] == ["Company Mobile Device Management", "Company Security Settings"]


def test_mdm_enrollment_check_profiles_command_fails():
    """Nothing could be read: unsupported, never an empty (healthy) result."""
    result = _run(_get_module(), enrollment=FAIL, status=FAIL, bootstrap=FAIL, xml=FAIL, listing=FAIL)
    assert result.supported is False
    assert result.findings == []


def test_mdm_enrollment_check_mdm_no_dep():
    listing = _lines(1, name="MDM Enrollment Profile")
    result = _run(_get_module(), enrollment=_enrolled("https://mycompany.mosyle.com"), listing=listing)
    assert _finding(result, "mdm_enrollment") is not None
    assert _finding(result, "dep_status") is None


def test_mdm_enrollment_check_fix_is_informational():
    mod = _get_module()
    check = _run(mod, enrollment=_enrolled("https://mycompany.jamfcloud.com"), listing=JAMF_LISTING)
    fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert len(fix.actions) > 0
    assert all(a.risk_level == RiskLevel.SAFE for a in fix.actions)


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.mdm_enrollment_check.") for c in declared)


# --- a profile is trusted only with evidence its author can't write -------------------


def test_hand_installed_jamf_profile_on_a_mac_not_enrolled_is_a_warning():
    listing = _lines(1, name="Totally Legit IT", organization="Jamf")
    f = _finding(_run(_get_module(), listing=listing), "all_profiles")
    assert f.severity == Severity.WARNING
    assert f.data["unknown_profiles"] == ["Totally Legit IT"]


def test_jamf_profile_from_a_manual_source_on_an_enrolled_mac_is_a_warning():
    listing = _lines(1, name="Totally Legit IT", organization="Jamf", source="Manual")
    f = _finding(_run(_get_module(), enrollment=_enrolled("https://x.example"), listing=listing), "all_profiles")
    assert f.severity == Severity.WARNING


def test_an_organization_never_moves_to_another_profile():
    """Only the second profile names an organization: the first stays unknown."""
    listing = _lines(1, name="Wi-Fi") + _lines(2, organization="Jamf", name="Example Corp MDM", source="MDM")
    f = _finding(_run(_get_module(), enrollment=_enrolled("https://x.example"), listing=listing), "all_profiles")
    assert f.severity == Severity.WARNING
    assert f.data["unknown_profiles"] == ["Wi-Fi"]
    assert f.data["organizations"] == {"Wi-Fi": None, "Example Corp MDM": "Jamf"}


def test_known_mdm_installed_profile_on_an_enrolled_mac_is_info():
    xml = plistlib.dumps({"_computerlevel": [
        {"ProfileDisplayName": "Example Corp MDM", "ProfileIdentifier": "com.example.mdm",
         "ProfileOrganization": "Microsoft Intune", "ProfileInstallSource": "MDM"},
    ]}).decode()
    f = _finding(_run(_get_module(), enrollment=_enrolled("https://x.example"), xml=xml, listing=FAIL),
                 "all_profiles")
    assert f.severity == Severity.INFO
    assert f.data["unknown_profiles"] == []


def test_a_known_organization_alone_is_not_enough_on_an_enrolled_mac():
    xml = plistlib.dumps({"_computerlevel": [
        {"ProfileDisplayName": "Example Corp MDM", "ProfileIdentifier": "com.example.mdm",
         "ProfileOrganization": "Microsoft Intune"},
    ]}).decode()
    f = _finding(_run(_get_module(), enrollment=_enrolled("https://x.example"), xml=xml, listing=FAIL),
                 "all_profiles")
    assert f.severity == Severity.WARNING
    assert f.data["unknown_profiles"] == ["Example Corp MDM"]


def test_fleet_street_is_not_fleet_device_management():
    listing = _lines(1, name="Bakery Wi-Fi", organization="Fleet Street Bakery")
    f = _finding(_run(_get_module(), enrollment=_enrolled("https://x.example"), listing=listing), "all_profiles")
    assert f.severity == Severity.WARNING


def test_malformed_listing_is_never_info():
    result = _run(_get_module(), enrollment=_enrolled("https://x.example"),
                  listing="attribute: name\nvalue: Example Corp MDM\nattribute: organization\nvalue: Jamf\n")
    f = _finding(result, "all_profiles")
    assert f is None or f.severity == Severity.WARNING
    assert result.complete is False


def test_enrollment_timeout_is_not_healthy():
    listing = _lines(1, name="Example Corp MDM", organization="Jamf")
    result = _run(_get_module(), enrollment=TIMEOUT, listing=listing)
    assert _finding(result, "all_profiles").severity == Severity.WARNING
    assert result.complete is False


def test_listing_timeout_is_not_healthy():
    result = _run(_get_module(), xml=TIMEOUT, listing=TIMEOUT)
    assert result.complete is False or result.supported is False


def test_profiles_the_listing_cannot_see_are_not_healthy():
    result = _run(_get_module(), status="There are 3 configuration profiles installed on this system\n")
    f = _finding(result, "all_profiles")
    assert f is not None and f.severity == Severity.WARNING
    assert f.data["unreadable_count"] == 3
    assert result.complete is False


def test_never_uses_sudo_and_always_has_a_timeout():
    calls = []
    _run(_get_module(), calls=calls)
    assert calls
    for args, kwargs in calls:
        assert "sudo" not in args
        assert 0 < kwargs.get("timeout", 0) <= 30
