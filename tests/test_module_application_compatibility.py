import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


def _make_profile(architecture="arm64"):
    return SystemProfile(
        platform=Platform.DARWIN,
        os_name="macOS",
        os_version="15.2",
        architecture=architecture,
        cpu_model="Apple M2",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "application_compatibility")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_no_apps():
    """Unable to retrieve application data"""
    def fake_run(cmd, **kwargs):
        return _make_subprocess_result(stdout="", returncode=1)
    return fake_run


def _fake_run_only_modern_apps():
    """Only modern 64-bit and universal apps (no issues)"""
    def fake_run(cmd, **kwargs):
        stdout = """Applications:
    Finder:
      Kind: Universal
      Version: 1.1
      Last Modified: 1/15/2025, 10:30:45 AM

    Safari:
      Kind: Apple Silicon
      Version: 18.2
      Last Modified: 1/14/2025, 2:15:30 PM

    Chrome:
      Kind: Intel
      Version: 132.0.6834.159
      Last Modified: 1/10/2025, 5:20:15 AM
"""
        return _make_subprocess_result(stdout=stdout)
    return fake_run


def _fake_run_with_32bit_apps():
    """Mix of modern and 32-bit applications"""
    def fake_run(cmd, **kwargs):
        stdout = """Applications:
    Finder:
      Kind: Universal
      Version: 1.1
      Last Modified: 1/15/2025, 10:30:45 AM

    OldApp:
      Kind: Intel (32-bit)
      Version: 2.5
      Last Modified: 3/10/2020, 8:45:20 AM

    LegacyTool:
      Kind: Intel (32-bit)
      Version: 1.0
      Last Modified: 2/28/2018, 1:15:30 PM
"""
        return _make_subprocess_result(stdout=stdout)
    return fake_run


def _fake_run_intel_apps_no_rosetta():
    """Intel apps on Apple Silicon, no Rosetta installed"""
    def fake_run(cmd, **kwargs):
        # Check if this is the Rosetta check
        if "arch" in cmd:
            return _make_subprocess_result(returncode=1)  # Rosetta not installed
        # System profiler call
        stdout = """Applications:
    Safari:
      Kind: Apple Silicon
      Version: 18.2
      Last Modified: 1/14/2025, 2:15:30 PM

    IntelApp:
      Kind: Intel
      Version: 3.0
      Last Modified: 12/20/2024, 3:45:10 PM

    AdobeApp:
      Kind: Intel
      Version: 24.6
      Last Modified: 1/5/2025, 10:15:45 AM
"""
        return _make_subprocess_result(stdout=stdout)
    return fake_run


def _fake_run_intel_apps_with_rosetta():
    """Intel apps on Apple Silicon, Rosetta is installed"""
    def fake_run(cmd, **kwargs):
        # Check if this is the Rosetta check
        if "arch" in cmd:
            return _make_subprocess_result(returncode=0)  # Rosetta installed
        # System profiler call
        stdout = """Applications:
    Safari:
      Kind: Apple Silicon
      Version: 18.2
      Last Modified: 1/14/2025, 2:15:30 PM

    IntelApp:
      Kind: Intel
      Version: 3.0
      Last Modified: 12/20/2024, 3:45:10 PM
"""
        return _make_subprocess_result(stdout=stdout)
    return fake_run


def _fake_run_with_outdated_apps():
    """Apps including some not updated in >2 years"""
    def fake_run(cmd, **kwargs):
        if "arch" in cmd:
            return _make_subprocess_result(returncode=0)
        stdout = """Applications:
    RecentApp:
      Kind: Universal
      Version: 2.0
      Last Modified: 1/10/2025, 2:30:15 PM

    OutdatedApp:
      Kind: Intel
      Version: 1.5
      Last Modified: 6/15/2022, 9:45:30 AM

    VeryOldApp:
      Kind: Universal
      Version: 3.2
      Last Modified: 3/1/2021, 11:20:45 AM
"""
        return _make_subprocess_result(stdout=stdout)
    return fake_run


def _fake_run_mixed_architectures():
    """Good mix of different architectures for breakdown"""
    def fake_run(cmd, **kwargs):
        if "arch" in cmd:
            return _make_subprocess_result(returncode=0)
        stdout = """Applications:
    Universal1:
      Kind: Universal
      Version: 1.0
      Last Modified: 1/10/2025, 2:30:15 PM

    Universal2:
      Kind: Universal
      Version: 2.0
      Last Modified: 1/11/2025, 3:45:20 PM

    AppleSilicon1:
      Kind: Apple Silicon
      Version: 1.0
      Last Modified: 1/9/2025, 10:15:30 AM

    Intel1:
      Kind: Intel
      Version: 2.0
      Last Modified: 1/8/2025, 4:20:10 PM

    Bit32:
      Kind: Intel (32-bit)
      Version: 1.0
      Last Modified: 3/1/2019, 2:30:15 PM
"""
        return _make_subprocess_result(stdout=stdout)
    return fake_run


def test_application_compatibility_discovered():
    """Module should be discoverable with correct properties"""
    mod = _get_module()
    assert mod.name == "application_compatibility"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.DARWIN in mod.platforms


def test_application_compatibility_no_apps():
    """Unable to retrieve app data should produce INFO finding"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_apps()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert len(result.findings) >= 1
    assert any(f.data.get("check") == "unable_to_retrieve" for f in result.findings)


def test_application_compatibility_only_modern_apps():
    """Only modern apps should still produce architecture breakdown"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_only_modern_apps()):
        result = mod.check(_make_profile())
    # Should have at least architecture breakdown
    assert result.has_issues
    assert any(f.data.get("check") == "architecture_breakdown" for f in result.findings)


def test_application_compatibility_detects_32bit_apps():
    """32-bit apps should produce WARNING finding"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_with_32bit_apps()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have finding for 32-bit apps
    bit32_findings = [f for f in result.findings if f.data.get("check") == "32bit_apps"]
    assert len(bit32_findings) == 1
    assert bit32_findings[0].severity == Severity.WARNING
    # Should list the 32-bit apps
    apps = bit32_findings[0].data.get("apps", [])
    assert "OldApp" in apps
    assert "LegacyTool" in apps


def test_application_compatibility_intel_without_rosetta():
    """Intel apps on Apple Silicon without Rosetta should produce WARNING"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_intel_apps_no_rosetta()):
        result = mod.check(_make_profile(architecture="arm64"))
    assert result.has_issues
    # Should have finding for Intel without Rosetta
    intel_findings = [f for f in result.findings if f.data.get("check") == "intel_without_rosetta"]
    assert len(intel_findings) == 1
    assert intel_findings[0].severity == Severity.WARNING
    # Should mention specific Intel apps
    apps = intel_findings[0].data.get("apps", [])
    assert "IntelApp" in apps
    assert "AdobeApp" in apps


def test_application_compatibility_intel_with_rosetta():
    """Intel apps on Apple Silicon with Rosetta should produce INFO"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_intel_apps_with_rosetta()):
        result = mod.check(_make_profile(architecture="arm64"))
    assert result.has_issues
    # Should have finding for Intel with Rosetta (INFO)
    intel_findings = [f for f in result.findings if f.data.get("check") == "intel_with_rosetta"]
    assert len(intel_findings) == 1
    assert intel_findings[0].severity == Severity.INFO


def test_application_compatibility_intel_on_x86():
    """Intel apps on Intel Mac should not flag Rosetta issues"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_intel_apps_with_rosetta()):
        result = mod.check(_make_profile(architecture="x86_64"))
    # Should not have Rosetta-related findings
    rosetta_findings = [f for f in result.findings
                       if "rosetta" in f.data.get("check", "").lower()]
    assert len(rosetta_findings) == 0


def test_application_compatibility_detects_outdated_apps():
    """Apps not updated in >2 years should produce INFO finding"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_with_outdated_apps()):
        result = mod.check(_make_profile(architecture="arm64"))
    assert result.has_issues
    # Should have finding for outdated apps
    outdated_findings = [f for f in result.findings if f.data.get("check") == "outdated_apps"]
    assert len(outdated_findings) == 1
    assert outdated_findings[0].severity == Severity.INFO


def test_application_compatibility_architecture_breakdown():
    """Should always provide architecture breakdown"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_mixed_architectures()):
        result = mod.check(_make_profile(architecture="arm64"))
    assert result.has_issues
    # Should have architecture breakdown
    breakdown_findings = [f for f in result.findings if f.data.get("check") == "architecture_breakdown"]
    assert len(breakdown_findings) == 1
    breakdown = breakdown_findings[0].data
    assert breakdown.get("total") == 5
    assert breakdown.get("universal") == 2
    assert breakdown.get("apple_silicon") == 1
    assert breakdown.get("intel") == 1
    assert breakdown.get("32bit") == 1


def test_application_compatibility_fix_is_informational():
    """fix() should return informational actions, never modify system"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_with_32bit_apps()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed
    assert fix.all_succeeded
    # Should have actions
    assert len(fix.actions) > 0
    # All actions should be SAFE risk level (informational)
    assert all(a.risk_level == RiskLevel.SAFE for a in fix.actions)
    # All actions should mark success=True
    assert all(a.success for a in fix.actions)


def test_application_compatibility_fix_creates_actions_per_finding():
    """Should create one action per finding"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_with_32bit_apps()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # Should have one action per finding
    assert len(fix.actions) == len(check.findings)


def test_application_compatibility_32bit_action_has_guidance():
    """Fix for 32-bit apps should provide remediation guidance"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_with_32bit_apps()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # Find action for 32-bit apps
    bit32_actions = [a for a in fix.actions if "32-bit" in a.title]
    assert len(bit32_actions) > 0
    action = bit32_actions[0]
    # Should mention action to address (download, update, replace, remove, etc.)
    description = action.description.lower()
    assert any(word in description for word in ["download", "update", "replace", "remove", "uninstall"])


def test_application_compatibility_rosetta_action_has_guidance():
    """Fix for missing Rosetta should provide installation guidance"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_intel_apps_no_rosetta()):
        check = mod.check(_make_profile(architecture="arm64"))
        fix = mod.fix(check, Mode.MANUAL)
    # Find action for Rosetta
    rosetta_actions = [a for a in fix.actions if "rosetta" in a.title.lower()]
    # Should have at least one Rosetta-related action
    assert len(rosetta_actions) > 0
    action = rosetta_actions[0]
    # Should mention installation steps
    description = action.description.lower()
    assert "install" in description or "softwareupdate" in description
