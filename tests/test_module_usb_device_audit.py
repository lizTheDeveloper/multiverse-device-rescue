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
    return next(m for m in modules if m.name == "usb_device_audit")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_no_devices():
    """No USB devices connected"""
    def fake_run(cmd, **kwargs):
        return _make_subprocess_result(
            stdout="USB:\n  Root Hub:\n"
        )
    return fake_run


def _fake_run_single_device():
    """Single USB device (mouse)"""
    def fake_run(cmd, **kwargs):
        return _make_subprocess_result(
            stdout="""USB:
  Root Hub:
    Logitech USB Optical Mouse:
      Product ID: 0xc077
      Vendor ID: 0x046d (Logitech, Inc.)
      Version: 12.00
      Serial Number: 123ABC456
      Speed: Up to 1.5 Mb/sec
      Manufacturer: Logitech
      Location ID: 0x14100000 / 1
      Current Available (mA): 96
      Current Required (mA): 100
      Extra Operating Current (mA): 0
"""
        )
    return fake_run


def _fake_run_multiple_devices():
    """Multiple USB devices including storage and hub"""
    def fake_run(cmd, **kwargs):
        return _make_subprocess_result(
            stdout="""USB:
  Root Hub:
    Logitech USB Optical Mouse:
      Product ID: 0xc077
      Vendor ID: 0x046d (Logitech, Inc.)
      Version: 12.00
      Serial Number: MOUSE001
      Speed: Up to 1.5 Mb/sec
      Manufacturer: Logitech
      Location ID: 0x14100000 / 1
      Current Available (mA): 96
      Current Required (mA): 100
    Sandisk Ultra Flash Drive:
      Product ID: 0x1666
      Vendor ID: 0x0781 (SanDisk Corp.)
      Version: 1.00
      Serial Number: 0A1B2C3D4E5F
      Speed: Up to 480 Mb/sec
      Mass Storage:
        Location ID: 0x14200000 / 2
        Removable Media:
          Capacity: 128.0 GB
          Removable Media:
            UNTITLED:
              Mount Point: /Volumes/UNTITLED
    USB 2.0 Hub:
      Product ID: 0x2514
      Vendor ID: 0x0424 (Microchip Technology Inc.)
      Version: 0.00
      Serial Number: HUBSERIAL001
      Speed: Up to 480 Mb/sec
      Hub: Yes
      Location ID: 0x14300000 / 3
      Current Available (mA): 500
      Current Required (mA): 100
"""
        )
    return fake_run


def _fake_run_unknown_vendor():
    """Device with no vendor information"""
    def fake_run(cmd, **kwargs):
        return _make_subprocess_result(
            stdout="""USB:
  Root Hub:
    Unknown USB Device:
      Product ID: 0xFFFF
      Version: 1.00
      Serial Number: UNKNOWN001
      Speed: Up to 480 Mb/sec
      Location ID: 0x14100000 / 1
      Current Available (mA): 500
      Current Required (mA): 100
"""
        )
    return fake_run


def _fake_run_multiple_hubs():
    """Multiple USB hubs (daisy-chaining)"""
    def fake_run(cmd, **kwargs):
        return _make_subprocess_result(
            stdout="""USB:
  Root Hub:
    USB 2.0 Hub 1:
      Product ID: 0x2514
      Vendor ID: 0x0424 (Microchip Technology Inc.)
      Version: 0.00
      Serial Number: HUB001
      Speed: Up to 480 Mb/sec
      Hub: Yes
      Location ID: 0x14300000 / 3
      Current Available (mA): 500
      Current Required (mA): 100
    USB 2.0 Hub 2:
      Product ID: 0x2514
      Vendor ID: 0x0424 (Microchip Technology Inc.)
      Version: 0.00
      Serial Number: HUB002
      Speed: Up to 480 Mb/sec
      Hub: Yes
      Location ID: 0x14400000 / 4
      Current Available (mA): 500
      Current Required (mA): 100
"""
        )
    return fake_run


def test_usb_device_audit_discovered():
    mod = _get_module()
    assert mod.name == "usb_device_audit"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE


def test_usb_device_audit_no_devices():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_devices()):
        result = mod.check(_make_profile())
    assert not result.has_issues


def test_usb_device_audit_single_device():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_single_device()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "usb_devices" for f in result.findings)
    assert any(f.data.get("device_count") == 1 for f in result.findings)


def test_usb_device_audit_multiple_devices():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_multiple_devices()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should detect devices, storage, and hub
    assert any(f.data.get("check") == "usb_devices" for f in result.findings)
    assert any(f.data.get("check") == "storage_devices" for f in result.findings)
    assert any(f.data.get("check") == "usb_hubs" for f in result.findings)


def test_usb_device_audit_unknown_vendor():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_unknown_vendor()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "no_vendor_devices" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_usb_device_audit_multiple_hubs():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_multiple_hubs()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "usb_hubs" for f in result.findings)
    # Should detect 2 hubs
    hub_findings = [f for f in result.findings if f.data.get("check") == "usb_hubs"]
    assert len(hub_findings) > 0
    assert hub_findings[0].data.get("hub_count") == 2


def test_usb_device_audit_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_multiple_devices()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action per finding
    assert len(fix.actions) >= len(check.findings)


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.usb_device_audit.") for c in declared)
