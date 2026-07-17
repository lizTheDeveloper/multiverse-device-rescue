import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


def _make_profile_intel():
    """Create an Intel Mac profile."""
    return SystemProfile(
        platform=Platform.DARWIN,
        os_name="macOS",
        os_version="13.5",
        architecture="x86_64",
        cpu_model="Intel Core i7",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _make_profile_apple_silicon():
    """Create an Apple Silicon Mac profile."""
    return SystemProfile(
        platform=Platform.DARWIN,
        os_name="macOS",
        os_version="14.1",
        architecture="arm64",
        cpu_model="Apple M2 Pro",
        cpu_cores=10,
        ram_bytes=16 * 1024**3,
    )


def _make_profile_t2():
    """Create a T2 Mac profile."""
    return SystemProfile(
        platform=Platform.DARWIN,
        os_name="macOS",
        os_version="13.0",
        architecture="x86_64",
        cpu_model="Intel Core i9 with T2",
        cpu_cores=8,
        ram_bytes=32 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "recovery_partition_check")


def _fake_run_intel_with_recovery():
    """Mock subprocess for Intel Mac with healthy recovery partition."""

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        if "diskutil" in cmd or (isinstance(cmd, list) and "diskutil" in cmd[0]):
            result.stdout = """DISK0
   #:                       TYPE NAME                    SIZE       IDENTIFIER
   0:      GUID_partition_scheme                        *500.1 GB   disk0
   1:                        EFI EFI                     209.7 MB   disk0s1
   2:       Apple_APFS Container Macintosh HD           *499.7 GB   disk0s2
   3:   Apple_Boot Recovery HD                          650.0 MB   disk0s3
"""
        return result

    return fake_run


def _fake_run_intel_without_recovery():
    """Mock subprocess for Intel Mac without recovery partition."""

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        if "diskutil" in cmd or (isinstance(cmd, list) and "diskutil" in cmd[0]):
            result.stdout = """DISK0
   #:                       TYPE NAME                    SIZE       IDENTIFIER
   0:      GUID_partition_scheme                        *500.1 GB   disk0
   1:                        EFI EFI                     209.7 MB   disk0s1
   2:       Apple_APFS Container Macintosh HD           *499.7 GB   disk0s2
"""
        return result

    return fake_run


def _fake_run_intel_small_recovery():
    """Mock subprocess for Intel Mac with small recovery partition."""

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        if "diskutil" in cmd or (isinstance(cmd, list) and "diskutil" in cmd[0]):
            result.stdout = """DISK0
   #:                       TYPE NAME                    SIZE       IDENTIFIER
   0:      GUID_partition_scheme                        *500.1 GB   disk0
   1:                        EFI EFI                     209.7 MB   disk0s1
   2:       Apple_APFS Container Macintosh HD           *499.7 GB   disk0s2
   3:   Apple_Boot Recovery HD                          350.0 MB   disk0s3
"""
        return result

    return fake_run


def _fake_run_apfs_recovery():
    """Mock subprocess for Mac with APFS Recovery container."""

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        if "diskutil" in cmd or (isinstance(cmd, list) and "diskutil" in cmd[0]):
            result.stdout = """DISK0
   #:                       TYPE NAME                    SIZE       IDENTIFIER
   0:      GUID_partition_scheme                        *500.1 GB   disk0
   1:                        EFI EFI                     209.7 MB   disk0s1
   2:       Apple_APFS Container Macintosh HD           *470.0 GB   disk0s2
   3:       Apple_APFS Container Recovery               29.5 GB    disk0s3
   4:   APFS Recovery                                   5.4 GB     disk0s4
"""
        return result

    return fake_run


def test_recovery_partition_discovered():
    mod = _get_module()
    assert mod.name == "recovery_partition_check"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.DARWIN in mod.platforms


def test_intel_with_recovery_healthy():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_intel_with_recovery()):
        result = mod.check(_make_profile_intel())
    assert result.has_issues
    assert any(f.data.get("check") == "recovery_partition_healthy" for f in result.findings)
    assert any(f.severity == Severity.INFO for f in result.findings)
    assert any("650" in f.description for f in result.findings)


def test_intel_without_recovery_critical():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_intel_without_recovery()):
        result = mod.check(_make_profile_intel())
    assert result.has_issues
    assert any(f.data.get("check") == "no_recovery_partition" for f in result.findings)
    assert any(f.severity == Severity.CRITICAL for f in result.findings)


def test_intel_small_recovery_warning():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_intel_small_recovery()):
        result = mod.check(_make_profile_intel())
    assert result.has_issues
    assert any(f.data.get("check") == "small_recovery_partition" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)
    assert any("350" in f.description for f in result.findings)


def test_apple_silicon_without_recovery_info():
    """Apple Silicon without traditional recovery partition should just report firmware recovery."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_intel_without_recovery()):
        result = mod.check(_make_profile_apple_silicon())
    assert result.has_issues
    # Should report apple_silicon_recovery, not no_recovery_partition
    assert any(f.data.get("check") == "apple_silicon_recovery" for f in result.findings)
    assert all(f.severity == Severity.INFO for f in result.findings)


def test_apple_silicon_with_recovery_info():
    """Apple Silicon with recovery partition should report both."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_intel_with_recovery()):
        result = mod.check(_make_profile_apple_silicon())
    assert result.has_issues
    assert any(f.data.get("check") == "recovery_partition_healthy" for f in result.findings)
    assert any(f.data.get("check") == "apple_silicon_detected" for f in result.findings)


def test_apfs_recovery_container():
    """Test parsing APFS Recovery containers."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_apfs_recovery()):
        result = mod.check(_make_profile_intel())
    assert result.has_issues
    # Should find APFS Recovery
    assert any("recovery" in f.title.lower() for f in result.findings)


def test_fix_no_recovery_partition():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_intel_without_recovery()):
        check = mod.check(_make_profile_intel())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert len(fix.actions) > 0
    assert any("missing" in a.title.lower() for a in fix.actions)
    assert any("Internet Recovery" in a.description for a in fix.actions)


def test_fix_small_recovery():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_intel_small_recovery()):
        check = mod.check(_make_profile_intel())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert len(fix.actions) > 0
    assert any("undersized" in a.title.lower() for a in fix.actions)


def test_fix_healthy_recovery():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_intel_with_recovery()):
        check = mod.check(_make_profile_intel())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert any("healthy" in a.title.lower() for a in fix.actions)


def test_fix_apple_silicon_recovery():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_intel_without_recovery()):
        check = mod.check(_make_profile_apple_silicon())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert any("firmware" in a.title.lower() or "Apple Silicon" in a.description for a in fix.actions)
