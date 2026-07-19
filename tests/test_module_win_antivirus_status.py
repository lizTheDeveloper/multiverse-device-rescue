import json
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


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
    return next(m for m in modules if m.name == "win_antivirus_status")


def _fake_run(av_products_data=None, defender_data=None):
    """Factory for subprocess.run mock that returns antivirus product data."""

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        cmd_str = " ".join(cmd)

        if "AntiVirusProduct" in cmd_str:
            if av_products_data is not None:
                result.stdout = json.dumps(av_products_data)
            else:
                result.stdout = ""
        elif "AntivirusSignatureLastUpdated" in cmd_str:
            if defender_data is not None:
                result.stdout = json.dumps(defender_data)
            else:
                result.stdout = ""
        else:
            # Fix commands (Set-MpPreference, Update-MpSignature)
            result.returncode = 0
            result.stderr = ""

        return result

    return fake_run


# Sample healthy antivirus configuration
HEALTHY_AV = {
    "displayName": "Windows Defender",
    "productState": 0x1000100,  # Bit 8 set for real-time protection enabled
    "pathToSignedReportingExe": "C:\\Program Files\\Windows Defender\\MSASCui.exe",
}

DEFENDER_HEALTHY = {
    "AntivirusSignatureLastUpdated": "2026-07-06T10:30:00Z"
}


def test_win_antivirus_status_discovered():
    mod = _get_module()
    assert mod.name == "win_antivirus_status"
    assert mod.category == "security"
    assert Platform.WIN32 in mod.platforms
    assert mod.risk_level == RiskLevel.MODERATE


def test_win_antivirus_status_healthy():
    """Test healthy AV configuration with registered product."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(HEALTHY_AV, DEFENDER_HEALTHY)):
        result = mod.check(_make_profile())
    # Should only have INFO finding about registered products
    assert result.has_issues
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert len(info_findings) == 1
    assert "registered antivirus products" in info_findings[0].title.lower()


def test_win_antivirus_status_no_av_product():
    """Test CRITICAL when no AV product is registered."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run([])):
        result = mod.check(_make_profile())
    assert result.has_issues
    critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert len(critical) >= 1
    assert any("no antivirus" in f.title.lower() for f in critical)
    assert any(f.data.get("check") == "no_av_product" for f in critical)


def test_win_antivirus_status_empty_response():
    """Test CRITICAL when AV query returns empty/null."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(None)):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.severity == Severity.CRITICAL for f in result.findings)


def test_win_antivirus_status_realtime_disabled():
    """Test CRITICAL when real-time protection is disabled."""
    mod = _get_module()
    av_product = dict(HEALTHY_AV, productState=0x0000000)  # Real-time disabled
    with patch("subprocess.run", side_effect=_fake_run(av_product, DEFENDER_HEALTHY)):
        result = mod.check(_make_profile())
    assert result.has_issues
    critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert len(critical) >= 1
    assert any("real-time protection" in f.title.lower() for f in critical)


def test_win_antivirus_status_multiple_products():
    """Test WARNING when multiple AV products are registered."""
    mod = _get_module()
    av_products = [HEALTHY_AV, dict(HEALTHY_AV, displayName="Norton 360")]
    with patch(
        "subprocess.run", side_effect=_fake_run(av_products, DEFENDER_HEALTHY)
    ):
        result = mod.check(_make_profile())
    assert result.has_issues
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert any("antivirus products are registered" in f.title.lower() for f in warnings)


def test_win_antivirus_status_subprocess_error():
    """Test graceful handling when subprocess fails."""
    mod = _get_module()

    def bad_run(cmd, **kwargs):
        raise OSError("PowerShell not available")

    with patch("subprocess.run", side_effect=bad_run):
        result = mod.check(_make_profile())
    # Should treat as no AV products found
    assert result.has_issues
    assert any(f.severity == Severity.CRITICAL for f in result.findings)


def test_win_antivirus_status_json_parse_error():
    """Test graceful handling when JSON parsing fails."""
    mod = _get_module()

    def bad_json_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stdout = "Not valid JSON {{"
        result.stderr = ""
        return result

    with patch("subprocess.run", side_effect=bad_json_run):
        result = mod.check(_make_profile())
    # Should treat as no AV products found
    assert result.has_issues
    assert any(f.severity == Severity.CRITICAL for f in result.findings)


def test_win_antivirus_status_fix_suggests_enable_realtime():
    """Test that fix provides guidance for enabling real-time protection."""
    mod = _get_module()
    av_product = dict(HEALTHY_AV, productState=0x0000000)  # Real-time disabled

    with patch("subprocess.run", side_effect=_fake_run(av_product, DEFENDER_HEALTHY)):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    # Should have action for enabling real-time protection
    realtime_actions = [
        a for a in fix.actions if "real-time" in a.title.lower()
    ]
    assert len(realtime_actions) >= 1
    assert realtime_actions[0].success  # PowerShell mock returns success


def test_win_antivirus_status_fix_handles_admin_error():
    """Test that fix handles permission errors gracefully."""
    mod = _get_module()
    av_product = dict(HEALTHY_AV, productState=0x0000000)

    def permission_error_run(cmd, **kwargs):
        result = MagicMock()
        cmd_str = " ".join(cmd)
        # Return product info for check phase
        if "AntiVirusProduct" in cmd_str:
            result.returncode = 0
            result.stdout = json.dumps(av_product)
            result.stderr = ""
        # Return error for fix commands
        else:
            result.returncode = 1
            result.stderr = "Access is denied."
            result.stdout = ""
        return result

    with patch("subprocess.run", side_effect=permission_error_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    assert not fix.all_succeeded
    assert any("Access is denied" in str(a.error) for a in fix.actions if a.error)


def test_win_antivirus_status_fix_no_action_for_no_av():
    """Test that fix handles missing AV product gracefully."""
    mod = _get_module()

    with patch("subprocess.run", side_effect=_fake_run([])):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    # Should have action indicating manual installation needed
    no_av_actions = [a for a in fix.actions if "install" in a.description.lower()]
    assert len(no_av_actions) >= 1
    assert not no_av_actions[0].success
    assert "install" in no_av_actions[0].description.lower()


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.win_antivirus_status.") for c in declared)
