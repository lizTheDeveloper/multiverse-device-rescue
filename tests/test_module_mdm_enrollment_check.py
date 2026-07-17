import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules

# Pre-load module so we can patch it
_modules_dir = Path(__file__).parent.parent / "modules"
_all_modules = discover_modules(_modules_dir)
_mdm_module_obj = next(m for m in _all_modules if m.name == "mdm_enrollment_check")
_mdm_sys_module = sys.modules.get("rescue_modules.mdm_enrollment_check")


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


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_no_mdm():
    """Device is not enrolled in MDM"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "profiles" in cmd_str and "enrollment" in cmd_str:
            return _make_subprocess_result(
                "MDM enrollment: No\n"
            )
        elif "profiles" in cmd_str and "bootstraptoken" in cmd_str:
            return _make_subprocess_result(
                "Bootstrap Token: No\n"
            )
        elif "profiles" in cmd_str and "list" in cmd_str:
            return _make_subprocess_result("")
        return _make_subprocess_result()
    return fake_run


def _fake_run_mdm_enrolled_jamf():
    """Device enrolled in Jamf MDM"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "profiles" in cmd_str and "enrollment" in cmd_str:
            return _make_subprocess_result(
                "MDM enrollment: Yes\n"
                "MDM Enrollment Server: https://mycompany.jamfcloud.com\n"
            )
        elif "profiles" in cmd_str and "bootstraptoken" in cmd_str:
            return _make_subprocess_result(
                "Bootstrap Token: Yes\n"
            )
        elif "profiles" in cmd_str and "list" in cmd_str:
            return _make_subprocess_result(
                "attribute: name\n"
                "value: Company Mobile Device Management\n"
                "attribute: name\n"
                "value: Company Security Settings\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_mdm_with_restrictions():
    """Device with MDM enrollment and restriction profiles"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "profiles" in cmd_str and "enrollment" in cmd_str:
            return _make_subprocess_result(
                "MDM enrollment: Yes\n"
                "MDM Enrollment Server: https://mycompany.kandji.io\n"
            )
        elif "profiles" in cmd_str and "bootstraptoken" in cmd_str:
            return _make_subprocess_result(
                "Bootstrap Token: Yes\n"
            )
        elif "profiles" in cmd_str and "list" in cmd_str:
            return _make_subprocess_result(
                "attribute: name\n"
                "value: Company Mobile Device Management\n"
                "attribute: name\n"
                "value: Parental Controls Profile\n"
                "attribute: name\n"
                "value: App Restrictions\n"
                "attribute: name\n"
                "value: Managed Settings\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_profiles_command_fails():
    """profiles command returns error"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "profiles" in cmd_str:
            return _make_subprocess_result(stderr="Command failed", returncode=1)
        return _make_subprocess_result()
    return fake_run


def _fake_run_mdm_no_dep():
    """Device enrolled in MDM but no DEP"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "profiles" in cmd_str and "enrollment" in cmd_str:
            return _make_subprocess_result(
                "MDM enrollment: Yes\n"
                "MDM Enrollment Server: https://mycompany.mosyle.com\n"
            )
        elif "profiles" in cmd_str and "bootstraptoken" in cmd_str:
            return _make_subprocess_result(
                "Bootstrap Token: No\n"
            )
        elif "profiles" in cmd_str and "list" in cmd_str:
            return _make_subprocess_result(
                "attribute: name\n"
                "value: MDM Enrollment Profile\n"
            )
        return _make_subprocess_result()
    return fake_run


def test_mdm_enrollment_check_discovered():
    mod = _get_module()
    assert mod.name == "mdm_enrollment_check"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE


def test_mdm_enrollment_check_no_mdm():
    """Device not enrolled in MDM"""
    mod = _get_module()
    with patch.object(_mdm_sys_module.subprocess, "run", side_effect=_fake_run_no_mdm()):
        result = mod.check(_make_profile())
    assert not result.has_issues


def test_mdm_enrollment_check_mdm_enrolled_jamf():
    """Device enrolled in Jamf MDM"""
    mod = _get_module()
    with patch.object(_mdm_sys_module.subprocess, "run", side_effect=_fake_run_mdm_enrolled_jamf()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "mdm_enrollment" for f in result.findings)
    mdm_finding = next(f for f in result.findings if f.data.get("check") == "mdm_enrollment")
    assert mdm_finding.severity == Severity.INFO
    assert "jamfcloud" in mdm_finding.description.lower()


def test_mdm_enrollment_check_with_restrictions():
    """Device with MDM enrollment and restriction profiles"""
    mod = _get_module()
    with patch.object(_mdm_sys_module.subprocess, "run", side_effect=_fake_run_mdm_with_restrictions()):
        result = mod.check(_make_profile())
    assert result.has_issues

    # Should have MDM enrollment finding
    assert any(f.data.get("check") == "mdm_enrollment" for f in result.findings)

    # Should have restrictions finding
    assert any(f.data.get("check") == "restrictions_profiles" for f in result.findings)
    restrictions_finding = next(
        f for f in result.findings if f.data.get("check") == "restrictions_profiles"
    )
    assert restrictions_finding.severity == Severity.WARNING


def test_mdm_enrollment_check_all_profiles_listed():
    """All installed profiles are listed"""
    mod = _get_module()
    with patch.object(_mdm_sys_module.subprocess, "run", side_effect=_fake_run_mdm_enrolled_jamf()):
        result = mod.check(_make_profile())

    # Should have all_profiles finding
    assert any(f.data.get("check") == "all_profiles" for f in result.findings)
    profiles_finding = next(f for f in result.findings if f.data.get("check") == "all_profiles")
    assert profiles_finding.severity == Severity.INFO


def test_mdm_enrollment_check_profiles_command_fails():
    """Handle gracefully when profiles command fails"""
    mod = _get_module()
    with patch.object(_mdm_sys_module.subprocess, "run", side_effect=_fake_run_profiles_command_fails()):
        result = mod.check(_make_profile())
    # Should handle gracefully with no issues or minimal findings
    # (MDM enrollment check will fail, so no findings)
    assert not result.has_issues or len(result.findings) == 0


def test_mdm_enrollment_check_mdm_no_dep():
    """Device enrolled in MDM but no DEP"""
    mod = _get_module()
    with patch.object(_mdm_sys_module.subprocess, "run", side_effect=_fake_run_mdm_no_dep()):
        result = mod.check(_make_profile())

    # Should have MDM enrollment finding
    assert any(f.data.get("check") == "mdm_enrollment" for f in result.findings)

    # Should NOT have DEP finding
    assert not any(f.data.get("check") == "dep_status" for f in result.findings)


def test_mdm_enrollment_check_fix_is_informational():
    """fix() is informational and always succeeds"""
    mod = _get_module()
    with patch.object(_mdm_sys_module.subprocess, "run", side_effect=_fake_run_mdm_enrolled_jamf()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have actions for the findings
    assert len(fix.actions) > 0
    # All actions should be SAFE risk level
    assert all(a.risk_level == RiskLevel.SAFE for a in fix.actions)
