import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


def _make_profile_intel():
    return SystemProfile(
        platform=Platform.DARWIN,
        os_name="macOS",
        os_version="14.2",
        architecture="x86_64",
        cpu_model="Intel Core i7",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _make_profile_apple_silicon():
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
    return next(m for m in modules if m.name == "smcreset_guide")


def _fake_run_intel_macbook_pro():
    """Mock subprocess for Intel MacBook Pro (2018)."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = str(cmd)

        if "sysctl" in cmd_str and "hw.model" in cmd_str:
            result.stdout = "hw.model: MacBookPro15,1\n"
        elif "system_profiler" in cmd_str and "SPHardwareDataType" in cmd_str:
            result.stdout = """Hardware Overview:
      Model Name: MacBook Pro
      Model Identifier: MacBookPro15,1
      Processor Name: Intel Core i7
"""
        elif "powermetrics" in cmd_str:
            result.stdout = """
CPU Power: 1234 mW
Fan 0 speed: 2000 rpm
Fan 1 speed: 2100 rpm
"""
        elif "system_profiler" in cmd_str and "SPPowerDataType" in cmd_str:
            result.stdout = """Power Information:
      Battery Information:
      Charging: Yes
      Connected: Yes
      Battery Installed: Yes
"""
        elif "system_profiler" in cmd_str and "SPDisplaysDataType" in cmd_str:
            result.stdout = """Displays:
      Display 1:
      Resolution: 2560 x 1600
"""
        return result

    return fake_run


def _fake_run_apple_silicon_macbook_air():
    """Mock subprocess for Apple Silicon MacBook Air."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = str(cmd)

        if "sysctl" in cmd_str and "hw.model" in cmd_str:
            result.stdout = "hw.model: MacBookAir13,2\n"
        elif "system_profiler" in cmd_str and "SPHardwareDataType" in cmd_str:
            result.stdout = """Hardware Overview:
      Model Name: MacBook Air
      Model Identifier: MacBookAir13,2
      Processor Name: Apple M1
"""
        elif "powermetrics" in cmd_str:
            result.stdout = """
CPU Power: 500 mW
Fan 0 speed: 1000 rpm
"""
        elif "system_profiler" in cmd_str and "SPPowerDataType" in cmd_str:
            result.stdout = """Power Information:
      Battery Information:
      Charging: Yes
      Connected: Yes
      Battery Installed: Yes
"""
        elif "system_profiler" in cmd_str and "SPDisplaysDataType" in cmd_str:
            result.stdout = """Displays:
      Display 1:
      Resolution: 2560 x 1600
"""
        return result

    return fake_run


def _fake_run_mac_mini_high_fans():
    """Mock subprocess for Mac mini with high fan speed."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = str(cmd)

        if "sysctl" in cmd_str and "hw.model" in cmd_str:
            result.stdout = "hw.model: Macmini9,1\n"
        elif "system_profiler" in cmd_str and "SPHardwareDataType" in cmd_str:
            result.stdout = """Hardware Overview:
      Model Name: Mac mini
      Model Identifier: Macmini9,1
      Processor Name: Apple M1
"""
        elif "powermetrics" in cmd_str:
            # High fan speed
            result.stdout = """
CPU Power: 800 mW
Fan 0 speed: 6500 rpm
"""
        elif "system_profiler" in cmd_str and "SPPowerDataType" in cmd_str:
            result.stdout = """Power Information:
      AC Adapter Information:
      Connected: Yes
      Wattage: 100
"""
        elif "system_profiler" in cmd_str and "SPDisplaysDataType" in cmd_str:
            result.stdout = """Displays:
      Display 1:
      Resolution: 3840 x 2160
"""
        return result

    return fake_run


def _fake_run_imac_no_charging():
    """Mock subprocess for iMac with battery not charging."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = str(cmd)

        if "sysctl" in cmd_str and "hw.model" in cmd_str:
            result.stdout = "hw.model: iMac21,1\n"
        elif "system_profiler" in cmd_str and "SPHardwareDataType" in cmd_str:
            result.stdout = """Hardware Overview:
      Model Name: iMac
      Model Identifier: iMac21,1
      Processor Name: Apple M1
"""
        elif "powermetrics" in cmd_str:
            result.stdout = """
CPU Power: 600 mW
Fan 0 speed: 1200 rpm
"""
        elif "system_profiler" in cmd_str and "SPPowerDataType" in cmd_str:
            # Charging: No even though connected
            result.stdout = """Power Information:
      Battery Information:
      Charging: No
      Connected: Yes
      Battery Installed: Yes
"""
        elif "system_profiler" in cmd_str and "SPDisplaysDataType" in cmd_str:
            result.stdout = """Displays:
      Display 1:
      Resolution: 5120 x 2880
"""
        return result

    return fake_run


def test_smcreset_guide_discovered():
    mod = _get_module()
    assert mod.name == "smcreset_guide"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE


def test_smcreset_guide_intel_macbook_pro():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_intel_macbook_pro()):
        result = mod.check(_make_profile_intel())
    assert result.has_issues
    # Should have at least model_info finding
    assert any(f.data.get("check") == "model_info" for f in result.findings)
    model_finding = next(f for f in result.findings if f.data.get("check") == "model_info")
    assert not model_finding.data.get("is_apple_silicon")
    assert "MacBookPro15,1" in model_finding.data.get("model", "")


def test_smcreset_guide_apple_silicon_macbook_air():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_apple_silicon_macbook_air()):
        result = mod.check(_make_profile_apple_silicon())
    assert result.has_issues
    model_finding = next(f for f in result.findings if f.data.get("check") == "model_info")
    assert model_finding.data.get("is_apple_silicon")


def test_smcreset_guide_high_fan_speed_symptom():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_mac_mini_high_fans()):
        result = mod.check(_make_profile_apple_silicon())
    assert result.has_issues
    symptom_finding = next(
        (f for f in result.findings if f.data.get("check") == "symptoms"),
        None
    )
    assert symptom_finding is not None
    assert "fans running at high speed" in symptom_finding.data.get("symptoms", [])


def test_smcreset_guide_battery_not_charging_symptom():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_imac_no_charging()):
        result = mod.check(_make_profile_apple_silicon())
    assert result.has_issues
    symptom_finding = next(
        (f for f in result.findings if f.data.get("check") == "symptoms"),
        None
    )
    assert symptom_finding is not None
    assert "battery not charging despite AC power" in symptom_finding.data.get("symptoms", [])


def test_smcreset_guide_fix_intel_macbook():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_intel_macbook_pro()):
        check = mod.check(_make_profile_intel())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert len(fix.actions) > 0
    # Should have SMC reset instructions for Intel
    assert any("SMC Reset" in a.title or "SMC Reset Instructions" in a.title for a in fix.actions)
    assert all(a.success for a in fix.actions)


def test_smcreset_guide_fix_apple_silicon():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_apple_silicon_macbook_air()):
        check = mod.check(_make_profile_apple_silicon())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    # Should explain Apple Silicon doesn't have SMC reset
    assert any("Apple Silicon" in a.title or "Apple Silicon" in a.description for a in fix.actions)
    assert all(a.success for a in fix.actions)


def test_smcreset_guide_fix_intel_has_nvram_guidance():
    """Intel Macs should get both SMC and NVRAM guidance."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_intel_macbook_pro()):
        check = mod.check(_make_profile_intel())
        fix = mod.fix(check, Mode.MANUAL)
    # Should have SMC and NVRAM reset actions
    has_smc = any("SMC Reset" in a.title for a in fix.actions)
    has_nvram = any("NVRAM" in a.title for a in fix.actions)
    assert has_smc
    assert has_nvram


def test_smcreset_guide_fix_with_symptoms():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_mac_mini_high_fans()):
        check = mod.check(_make_profile_apple_silicon())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    # Should have symptom guidance
    assert any("symptom" in a.title.lower() for a in fix.actions)


def test_smcreset_guide_model_detection():
    """Test that model information is correctly detected."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_intel_macbook_pro()):
        result = mod.check(_make_profile_intel())
    model_finding = next(f for f in result.findings if f.data.get("check") == "model_info")
    assert model_finding.severity == Severity.INFO
    assert "MacBook Pro" in model_finding.description


def test_smcreset_guide_apple_silicon_architecture_detection():
    """Test that Apple Silicon is detected from profile."""
    mod = _get_module()
    # Use a profile with arm64 architecture
    profile = SystemProfile(
        platform=Platform.DARWIN,
        os_name="macOS",
        os_version="15.2",
        architecture="arm64",
        cpu_model="Apple M3",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )
    with patch("subprocess.run", side_effect=_fake_run_apple_silicon_macbook_air()):
        result = mod.check(profile)
    model_finding = next(f for f in result.findings if f.data.get("check") == "model_info")
    assert model_finding.data.get("is_apple_silicon") is True
