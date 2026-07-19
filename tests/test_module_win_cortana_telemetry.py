import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


# Registry query output templates
OPTIMIZED_PRIVACY = {
    "AllowTelemetry": None,  # Not set = Default (Basic)
    "AllowCortana": "0",  # Disabled
    "Enabled": "0",  # Advertising ID disabled
    "EnableActivityFeed": "0",  # Activity History disabled
    "Value": "Deny",  # Location services disabled
}

FULL_TELEMETRY = {
    "AllowTelemetry": "3",  # Full telemetry
    "AllowCortana": "1",  # Enabled
    "Enabled": "1",  # Advertising ID enabled
    "EnableActivityFeed": "1",  # Activity History enabled
    "Value": "Allow",  # Location services enabled
}

ENHANCED_TELEMETRY = {
    "AllowTelemetry": "2",  # Enhanced telemetry
    "AllowCortana": "0",  # Disabled
    "Enabled": "0",  # Advertising ID disabled
    "EnableActivityFeed": "0",  # Activity History disabled
    "Value": "Deny",  # Location services disabled
}

CORTANA_ONLY = {
    "AllowTelemetry": None,  # Not set = Default (Basic)
    "AllowCortana": "1",  # Enabled
    "Enabled": "0",  # Advertising ID disabled
    "EnableActivityFeed": "0",  # Activity History disabled
    "Value": "Deny",  # Location services disabled
}

ADVERTISING_ONLY = {
    "AllowTelemetry": None,  # Not set = Default (Basic)
    "AllowCortana": "0",  # Disabled
    "Enabled": "1",  # Advertising ID enabled
    "EnableActivityFeed": "0",  # Activity History disabled
    "Value": "Deny",  # Location services disabled
}

REG_NOT_FOUND = "The system was unable to find the specified registry key or value.\r\n"

REG_QUERY_TEMPLATES = {
    "AllowTelemetry": r"""
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection
    AllowTelemetry    REG_DWORD    {value}
""",
    "AllowCortana": r"""
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search
    AllowCortana    REG_DWORD    {value}
""",
    "Enabled": r"""
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo
    Enabled    REG_DWORD    {value}
""",
    "EnableActivityFeed": r"""
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System
    EnableActivityFeed    REG_DWORD    {value}
""",
    "Value": r"""
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location
    Value    REG_SZ    {value}
""",
}


def _make_profile():
    return SystemProfile(
        platform=Platform.WIN32,
        os_name="Windows 11",
        os_version="10.0.22621",
        architecture="AMD64",
        cpu_model="Intel(R) Core(TM) i7-9700K",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "win_cortana_telemetry")


def _fake_reg_run(config_dict):
    """Factory function that returns a mock subprocess.run for registry queries."""

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        if len(cmd) >= 3 and cmd[0] == "reg" and cmd[1] == "query":
            # This is a reg query command
            value_name = cmd[4] if len(cmd) > 4 else None
            if value_name:
                # Get the value from the config dictionary
                if value_name in config_dict:
                    value = config_dict[value_name]
                    if value is None:
                        # Simulate value not found
                        result.returncode = 1
                        result.stderr = REG_NOT_FOUND
                    else:
                        # Generate output using the template
                        if value_name in REG_QUERY_TEMPLATES:
                            # Format the hex value for DWORD (needs 0x prefix)
                            if value_name in ["AllowTelemetry", "AllowCortana", "Enabled", "EnableActivityFeed"]:
                                hex_value = f"0x{value}"
                                template = REG_QUERY_TEMPLATES[value_name]
                                result.stdout = template.format(value=hex_value)
                            else:
                                # REG_SZ value (no hex conversion)
                                template = REG_QUERY_TEMPLATES[value_name]
                                result.stdout = template.format(value=value)
                else:
                    result.returncode = 1
                    result.stderr = REG_NOT_FOUND
            else:
                result.returncode = 1
                result.stderr = REG_NOT_FOUND
        return result

    return fake_run


def test_win_cortana_telemetry_discovered():
    mod = _get_module()
    assert mod.name == "win_cortana_telemetry"
    assert mod.category == "security"
    assert Platform.WIN32 in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_win_cortana_telemetry_optimized_privacy():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_reg_run(OPTIMIZED_PRIVACY)):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert len(result.findings) == 1
    assert result.findings[0].severity == Severity.INFO
    assert "optimized" in result.findings[0].title.lower()


def test_win_cortana_telemetry_full_telemetry():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_reg_run(FULL_TELEMETRY)):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have warnings for telemetry and advertising ID
    assert any(f.severity == Severity.WARNING for f in result.findings)
    assert any(f.data.get("check") == "telemetry_level" for f in result.findings)
    assert any(f.data.get("check") == "advertising_id" for f in result.findings)


def test_win_cortana_telemetry_enhanced_telemetry():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_reg_run(ENHANCED_TELEMETRY)):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have warning for enhanced telemetry
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warnings) > 0
    assert any(f.data.get("check") == "telemetry_level" for f in warnings)


def test_win_cortana_telemetry_cortana_enabled():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_reg_run(CORTANA_ONLY)):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have info about Cortana
    assert any(f.data.get("check") == "cortana_enabled" for f in result.findings)
    assert any(f.severity == Severity.INFO for f in result.findings)


def test_win_cortana_telemetry_advertising_id_enabled():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_reg_run(ADVERTISING_ONLY)):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have warning for advertising ID
    assert any(f.data.get("check") == "advertising_id" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_win_cortana_telemetry_multiple_issues():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_reg_run(FULL_TELEMETRY)):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Full telemetry has multiple issues
    assert len(result.findings) >= 2
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warnings) >= 2  # At least telemetry and advertising ID


def test_win_cortana_telemetry_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_reg_run(FULL_TELEMETRY)):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have actions for each finding
    assert len(fix.actions) >= 2


def test_win_cortana_telemetry_fix_no_actions_for_optimized():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_reg_run(OPTIMIZED_PRIVACY)):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # Optimized privacy means only one INFO finding, no fix actions
    assert len(fix.actions) == 0


def test_win_cortana_telemetry_fix_provides_guidance():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_reg_run(ADVERTISING_ONLY)):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # Should have at least one action with guidance
    assert len(fix.actions) > 0
    assert all(a.description for a in fix.actions)
    assert any("Settings" in a.description for a in fix.actions)


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.win_cortana_telemetry.") for c in declared)
