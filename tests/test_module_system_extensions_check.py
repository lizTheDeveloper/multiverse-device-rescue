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
    return next(m for m in modules if m.name == "system_extensions_check")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_with_active_endpoint_security():
    """System with active endpoint security extension (CrowdStrike)"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "systemextensionsctl" in cmd_str:
            output = """UUID                                    BUNDLE_ID                           STATE                  CATEGORY
5A3F1C2D-4E8B-4F2C-A1B3-C4D5E6F7A8B9 com.crowdstrike.falconxf enabled com.apple.system-extension.endpoint-security
6B4G2D3E-5F9C-5G3D-B2C4-D5E6F7A8B9C0 com.example.networkext enabled com.apple.system-extension.network-extension
"""
            return _make_subprocess_result(stdout=output)
        return _make_subprocess_result()

    return fake_run


def _fake_run_with_waiting_endpoint_security():
    """System with endpoint security extension awaiting user approval"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "systemextensionsctl" in cmd_str:
            output = """UUID                                    BUNDLE_ID                           STATE                  CATEGORY
5A3F1C2D-4E8B-4F2C-A1B3-C4D5E6F7A8B9 com.sentinelone.sentinel waiting com.apple.system-extension.endpoint-security
"""
            return _make_subprocess_result(stdout=output)
        return _make_subprocess_result()

    return fake_run


def _fake_run_with_terminated_extensions():
    """System with terminated extensions"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "systemextensionsctl" in cmd_str:
            output = """UUID                                    BUNDLE_ID                           STATE                  CATEGORY
5A3F1C2D-4E8B-4F2C-A1B3-C4D5E6F7A8B9 com.vmware.carbonblack terminated com.apple.system-extension.endpoint-security
6B4G2D3E-5F9C-5G3D-B2C4-D5E6F7A8B9C0 com.example.driver enabled com.apple.system-extension.driver
"""
            return _make_subprocess_result(stdout=output)
        return _make_subprocess_result()

    return fake_run


def _fake_run_no_extensions():
    """System with no extensions"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "systemextensionsctl" in cmd_str:
            output = """UUID                                    BUNDLE_ID                           STATE                  CATEGORY
"""
            return _make_subprocess_result(stdout=output)
        return _make_subprocess_result()

    return fake_run


def _fake_run_command_not_found():
    """System where systemextensionsctl is not available"""
    def fake_run(cmd, **kwargs):
        raise OSError("Command not found")

    return fake_run


def _fake_run_no_endpoint_security():
    """System with only network and driver extensions (no endpoint security)"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "systemextensionsctl" in cmd_str:
            output = """UUID                                    BUNDLE_ID                           STATE                  CATEGORY
5A3F1C2D-4E8B-4F2C-A1B3-C4D5E6F7A8B9 com.example.networkext enabled com.apple.system-extension.network-extension
6B4G2D3E-5F9C-5G3D-B2C4-D5E6F7A8B9C0 com.example.driver enabled com.apple.system-extension.driver
"""
            return _make_subprocess_result(stdout=output)
        return _make_subprocess_result()

    return fake_run


def test_system_extensions_check_discovered():
    """Module is properly discovered and has correct metadata"""
    mod = _get_module()
    assert mod.name == "system_extensions_check"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.DARWIN in mod.platforms


def test_system_extensions_check_active_endpoint_security():
    """System with active endpoint security extension"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_with_active_endpoint_security()):
        result = mod.check(_make_profile())

    # Should have findings (informational about extensions list)
    assert result.has_issues

    # Should report extensions list
    assert any(f.data.get("check") == "extensions_list" for f in result.findings)

    # Should identify CrowdStrike as a known product
    ext_list_finding = next(
        f for f in result.findings if f.data.get("check") == "extensions_list"
    )
    assert "CrowdStrike Falcon" in ext_list_finding.data.get("known_security_products", [])

    # Should NOT have warnings
    assert not any(f.severity == Severity.WARNING for f in result.findings)


def test_system_extensions_check_waiting_endpoint_security():
    """System with endpoint security extension awaiting approval (WARNING)"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_with_waiting_endpoint_security()):
        result = mod.check(_make_profile())

    # Should have findings
    assert result.has_issues

    # Should have warning about waiting endpoint security
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) > 0
    assert any(
        f.data.get("check") == "waiting_endpoint_security" for f in warning_findings
    )

    # Warning should mention the extension waiting state
    waiting_finding = next(
        f
        for f in warning_findings
        if f.data.get("check") == "waiting_endpoint_security"
    )
    assert "sentinel" in waiting_finding.description.lower()
    assert "approval" in waiting_finding.description.lower()


def test_system_extensions_check_terminated_extensions():
    """System with terminated extensions (WARNING)"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_with_terminated_extensions()):
        result = mod.check(_make_profile())

    # Should have findings
    assert result.has_issues

    # Should have warning about terminated extensions
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) > 0
    assert any(
        f.data.get("check") == "terminated_extensions" for f in warning_findings
    )

    # Warning should mention Carbon Black
    terminated_finding = next(
        f for f in warning_findings if f.data.get("check") == "terminated_extensions"
    )
    assert "terminated" in terminated_finding.description.lower()


def test_system_extensions_check_no_extensions():
    """System with no extensions"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_extensions()):
        result = mod.check(_make_profile())

    # Should have findings
    assert result.has_issues

    # Should report no extensions
    assert any(f.data.get("check") == "no_extensions" for f in result.findings)


def test_system_extensions_check_command_not_found():
    """System where systemextensionsctl is not available"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_command_not_found()):
        result = mod.check(_make_profile())

    # Should have findings
    assert result.has_issues

    # Should report unable to list
    assert any(f.data.get("check") == "unable_to_list" for f in result.findings)


def test_system_extensions_check_no_endpoint_security():
    """System with only network/driver extensions (no endpoint security) (WARNING)"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_endpoint_security()):
        result = mod.check(_make_profile())

    # Should have findings
    assert result.has_issues

    # Should have warning about no endpoint security
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) > 0
    assert any(f.data.get("check") == "no_endpoint_security" for f in warning_findings)


def test_system_extensions_check_fix_is_informational():
    """fix() should always succeed with informational messages"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_with_waiting_endpoint_security()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    # fix() should always succeed
    assert fix.all_succeeded

    # Should have actions for any warnings
    warnings = [f for f in check.findings if f.severity == Severity.WARNING]
    if warnings:
        assert len(fix.actions) > 0


def test_system_extensions_check_fix_active_extensions():
    """fix() with active extensions should provide management guidance"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_with_active_endpoint_security()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    # fix() should always succeed
    assert fix.all_succeeded

    # Should have at least one action (extensions overview)
    assert len(fix.actions) > 0


def test_system_extensions_check_parsing():
    """Test the parsing function with various formats"""
    from modules.integrity.system_extensions_check import _parse_systemextensionsctl

    output = """UUID                                    BUNDLE_ID                           STATE                  CATEGORY
5A3F1C2D-4E8B-4F2C-A1B3-C4D5E6F7A8B9 com.crowdstrike.falconxf enabled com.apple.system-extension.endpoint-security
6B4G2D3E-5F9C-5G3D-B2C4-D5E6F7A8B9C0 com.example.network waiting com.apple.system-extension.network-extension
"""

    extensions = _parse_systemextensionsctl(output)

    assert len(extensions) == 2
    assert extensions[0]["bundle_id"] == "com.crowdstrike.falconxf"
    assert extensions[0]["state"] == "activated_enabled"
    assert (
        extensions[0]["category"]
        == "com.apple.system-extension.endpoint-security"
    )
    assert extensions[1]["state"] == "activated_waiting_for_user"


def test_system_extensions_check_known_products():
    """Test the known security products identification"""
    from modules.integrity.system_extensions_check import (
        _identify_known_security_products,
    )

    extensions = [
        {
            "name": "CrowdStrike Falcon",
            "bundle_id": "com.crowdstrike.falconxf",
            "state": "activated_enabled",
        },
        {
            "name": "Microsoft Defender",
            "bundle_id": "com.microsoft.wdav",
            "state": "activated_enabled",
        },
        {
            "name": "SentinelOne",
            "bundle_id": "com.sentinelone.sentinel",
            "state": "activated_enabled",
        },
    ]

    products = _identify_known_security_products(extensions)

    assert "CrowdStrike Falcon" in products
    assert "Microsoft Defender" in products
    assert "SentinelOne Singularity" in products
