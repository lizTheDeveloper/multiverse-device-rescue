import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


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


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_no_mdm():
    """Personal device with no MDM enrollment"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "profiles status -type enrollment" in cmd_str:
            return _make_subprocess_result(
                "Enrolled: No\nDEP Capable: No\n"
            )
        elif "profiles status" in cmd_str:
            return _make_subprocess_result(
                "Supervised: No\nDEP Capable: No\n"
            )
        elif "profiles list -verbose" in cmd_str:
            return _make_subprocess_result("")
        return _make_subprocess_result()
    return fake_run


def _fake_run_mdm_enrolled():
    """Device with MDM enrollment"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "profiles status -type enrollment" in cmd_str:
            return _make_subprocess_result(
                "Enrolled: Yes\nDEP Capable: Yes\n"
            )
        elif "profiles status" in cmd_str:
            return _make_subprocess_result(
                "Supervised: No\nDEP Capable: Yes\nEnrolled: Yes\n"
            )
        elif "profiles list -verbose" in cmd_str:
            return _make_subprocess_result(
                "Configuration Profile:\n"
                "Name: Company MDM Enrollment\n"
                "ProfileIdentifier: com.company.mdm.enrollment\n"
                "Source: MDM\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_supervised():
    """Device that is supervised"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "profiles status -type enrollment" in cmd_str:
            return _make_subprocess_result(
                "Enrolled: Yes\nDEP Capable: Yes\nSupervised: Yes\n"
            )
        elif "profiles status" in cmd_str:
            return _make_subprocess_result(
                "Supervised: Yes\nDEP Capable: Yes\nEnrolled: Yes\n"
            )
        elif "profiles list -verbose" in cmd_str:
            return _make_subprocess_result(
                "Configuration Profile:\n"
                "Name: Device Supervision\n"
                "ProfileIdentifier: com.company.supervision\n"
                "Source: MDM\n"
                "\n"
                "Configuration Profile:\n"
                "Name: Company WiFi Settings\n"
                "ProfileIdentifier: com.company.wifi\n"
                "Source: MDM\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_multiple_profiles():
    """Device with multiple configuration profiles"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "profiles status -type enrollment" in cmd_str:
            return _make_subprocess_result(
                "Enrolled: No\nDEP Capable: No\n"
            )
        elif "profiles status" in cmd_str:
            return _make_subprocess_result(
                "Supervised: No\nDEP Capable: No\n"
            )
        elif "profiles list -verbose" in cmd_str:
            return _make_subprocess_result(
                "Configuration Profile:\n"
                "Name: VPN Configuration\n"
                "ProfileIdentifier: com.company.vpn\n"
                "Source: Manual\n"
                "\n"
                "Configuration Profile:\n"
                "Name: Email Configuration\n"
                "ProfileIdentifier: com.company.email\n"
                "Source: Manual\n"
                "\n"
                "Configuration Profile:\n"
                "Name: Security Settings\n"
                "ProfileIdentifier: com.company.security\n"
                "Source: Manual\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_profiles_list_fails():
    """profiles list command fails"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "profiles status -type enrollment" in cmd_str:
            return _make_subprocess_result(
                "Enrolled: No\nDEP Capable: No\n"
            )
        elif "profiles status" in cmd_str:
            return _make_subprocess_result(
                "Supervised: No\nDEP Capable: No\n"
            )
        elif "profiles list -verbose" in cmd_str:
            return _make_subprocess_result(returncode=1)
        return _make_subprocess_result()
    return fake_run


def test_mdm_enrollment_discovered():
    mod = _get_module()
    assert mod.name == "mdm_enrollment"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.DARWIN in mod.platforms


def test_mdm_enrollment_no_mdm():
    """Test personal device with no MDM enrollment"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_mdm()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "no_mdm" for f in result.findings)
    assert any(f.severity == Severity.INFO for f in result.findings)


def test_mdm_enrollment_mdm_enrolled():
    """Test device with MDM enrollment"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_mdm_enrolled()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "mdm_enrolled" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_mdm_enrollment_supervised():
    """Test device that is supervised"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_supervised()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "supervised" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_mdm_enrollment_multiple_profiles():
    """Test device with multiple configuration profiles"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_multiple_profiles()):
        result = mod.check(_make_profile())
    assert result.has_issues
    profiles_finding = next(
        (f for f in result.findings if f.data.get("check") == "profiles_installed"),
        None,
    )
    assert profiles_finding is not None
    assert profiles_finding.data.get("count") == 3
    # Added by hand, with no organization from a known device-management service: a warning (plan 2026-10-22 Task 8).
    assert profiles_finding.severity == Severity.WARNING
    assert profiles_finding.data["unknown_profiles"] == ["VPN Configuration", "Email Configuration", "Security Settings"]


def test_mdm_enrollment_profiles_list_fails():
    """Test when profiles list command fails gracefully"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_profiles_list_fails()):
        result = mod.check(_make_profile())
    # Should still report no_mdm info, just without profiles list
    assert result.has_issues
    assert any(f.data.get("check") == "no_mdm" for f in result.findings)


def test_mdm_enrollment_fix_is_informational():
    """Test that fix() returns informational actions"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_mdm_enrolled()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action
    assert len(fix.actions) > 0
    # All actions should succeed
    for action in fix.actions:
        assert action.success is True


def test_mdm_enrollment_no_mdm_fix():
    """Test fix action for no_mdm case"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_mdm()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert any("no mdm" in a.title.lower() for a in fix.actions)


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.mdm_enrollment.") for c in declared)


def _fake_run_profiles(listing):
    """Not enrolled, not supervised; `profiles list -verbose` prints `listing` (synthetic)."""
    def fake_run(cmd, **kwargs):
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else cmd
        if "profiles status -type enrollment" in cmd_str:
            return _make_subprocess_result("Enrolled: No\nDEP Capable: No\n")
        if "profiles status" in cmd_str:
            return _make_subprocess_result("Supervised: No\nDEP Capable: No\n")
        if "profiles list -verbose" in cmd_str:
            return _make_subprocess_result(listing)
        return _make_subprocess_result()
    return fake_run


def _profiles_finding(listing):
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_profiles(listing)):
        result = mod.check(_make_profile())
    return next(f for f in result.findings if f.data.get("check") == "profiles_installed")


def test_unknown_mdm_org_is_a_warning_jamf_is_info():
    jamf = _profiles_finding(
        "Configuration Profile:\n"
        "Name: Example Corp MDM\n"
        "ProfileIdentifier: com.example.mdm\n"
        "Organization: Jamf\n"
        "Source: MDM\n"
    )
    assert jamf.severity == Severity.INFO
    assert jamf.data["unknown_profiles"] == []
    odd = _profiles_finding(
        "Configuration Profile:\n"
        "Name: Example Corp MDM\n"
        "Organization: Jamf\n"
        "Source: MDM\n"
        "\n"
        "Configuration Profile:\n"
        "Name: Helper Settings\n"
        "Organization: Example Helper Ltd\n"
        "Source: Manual\n"
    )
    assert odd.severity == Severity.WARNING
    assert odd.data["unknown_profiles"] == ["Helper Settings"]
    assert "Helper Settings" in odd.description


def test_a_profile_with_no_organization_is_not_known():
    """Missing evidence never reads as safe: no organization line means it isn't a known one."""
    f = _profiles_finding("Configuration Profile:\nName: Wi-Fi\nSource: Manual\n")
    assert f.severity == Severity.WARNING
    assert f.data["unknown_profiles"] == ["Wi-Fi"]


def test_real_profiles_prefix_is_read():
    """`profiles list -verbose` prefixes each line with the level and `attribute:`."""
    f = _profiles_finding(
        "_computerlevel[1] attribute: name: Example Corp MDM\n"
        "_computerlevel[1] attribute: organization: Kandji\n"
    )
    assert f.data["profiles"][0]["name"] == "Example Corp MDM"
    assert f.data["profiles"][0]["organization"] == "Kandji"
    assert f.severity == Severity.INFO


def test_known_mdm_list_matches_the_check_modules_copy():
    root = Path(__file__).parent.parent / "modules" / "security"
    a = (root / "mdm_enrollment" / "data" / "known_mdm.json").read_text()
    b = (root / "mdm_enrollment_check" / "data" / "known_mdm.json").read_text()
    assert a == b
    import json
    names = json.loads(a)
    for want in ["Jamf", "Kandji", "Mosyle", "Microsoft Intune", "Addigy", "JumpCloud", "Workspace ONE",
                 "Hexnode", "SimpleMDM", "Fleet", "Apple Business Manager", "Apple School Manager"]:
        assert want in names
