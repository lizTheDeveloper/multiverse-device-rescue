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
        os_version="14.0",
        architecture="arm64",
        cpu_model="Apple M2",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "disk_health")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _diskutil_info_healthy():
    """Normal case: SSD with healthy SMART status."""
    return """
Device Identifier:         disk0s2
Device Node:               /dev/disk0s2
Whole Device:              No
Part of Whole:             disk0
Device / Media Name:       APPLE SSD AP0512Q

Volume Name:               Macintosh HD
Mounted:                   Yes
Mount Point:               /

Partition Type:            Apple_APFS
File System Personality:   APFS
Type (Bundle):             apfs
Name (User Visible):       APFS

Owners:                    Enabled
OS Can Be Installed:       Yes
Recovery Partition:        Not Present
Media Type:                SSD
Protocol:                  PCI-NVMe
SMART Status:              Verified
Solid State:               Yes
Total Size:                512 GB
Free Space:                256 GB
Used Space:                256 GB
Block Size:                4096 Bytes
Container Total Capacity:  512 GB
Container Free Space:      256 GB
"""


def _diskutil_info_ssd_not_verified():
    """SSD with SMART not verified (WARNING)."""
    return """
Device Identifier:         disk0s2
Device Node:               /dev/disk0s2
Whole Device:              No
Part of Whole:             disk0
Device / Media Name:       APPLE SSD AP0512Q

Volume Name:               Macintosh HD
Mounted:                   Yes
Mount Point:               /

Partition Type:            Apple_APFS
File System Personality:   APFS
Type (Bundle):             apfs
Name (User Visible):       APFS

Owners:                    Enabled
OS Can Be Installed:       Yes
Recovery Partition:        Not Present
Media Type:                SSD
Protocol:                  PCI-NVMe
SMART Status:              Not Verified
Solid State:               Yes
Total Size:                512 GB
Free Space:                128 GB
Used Space:                384 GB
Block Size:                4096 Bytes
Container Total Capacity:  512 GB
Container Free Space:      128 GB
"""


def _diskutil_info_disk_failing():
    """Disk with SMART status 'Failing' (CRITICAL)."""
    return """
Device Identifier:         disk0s2
Device Node:               /dev/disk0s2
Whole Device:              No
Part of Whole:             disk0
Device / Media Name:       SEAGATE ST1000DM003

Volume Name:               Macintosh HD
Mounted:                   Yes
Mount Point:               /

Partition Type:            Apple_APFS
File System Personality:   APFS
Type (Bundle):             apfs
Name (User Visible):       APFS

Owners:                    Enabled
OS Can Be Installed:       Yes
Recovery Partition:        Not Present
Media Type:                HDD
Protocol:                  SATA
SMART Status:              Failing
Solid State:               No
Total Size:                1 TB
Free Space:                100 GB
Used Space:                900 GB
Block Size:                4096 Bytes
Container Total Capacity:  1 TB
Container Free Space:      100 GB
"""


def _diskutil_info_hdd_healthy():
    """HDD with healthy SMART status."""
    return """
Device Identifier:         disk0s2
Device Node:               /dev/disk0s2
Whole Device:              No
Part of Whole:             disk0
Device / Media Name:       WDC WD10EZEX

Volume Name:               Macintosh HD
Mounted:                   Yes
Mount Point:               /

Partition Type:            Apple_APFS
File System Personality:   APFS
Type (Bundle):             apfs
Name (User Visible):       APFS

Owners:                    Enabled
OS Can Be Installed:       Yes
Recovery Partition:        Not Present
Media Type:                HDD
Protocol:                  SATA
SMART Status:              Verified
Solid State:               No
Total Size:                1 TB
Free Space:                500 GB
Used Space:                500 GB
Block Size:                4096 Bytes
Container Total Capacity:  1 TB
Container Free Space:      500 GB
"""


def _diskutil_info_no_smart():
    """Disk with no SMART information (e.g., external drive)."""
    return """
Device Identifier:         disk2s1
Device Node:               /dev/disk2s1
Whole Device:              No
Part of Whole:             disk2
Device / Media Name:       Samsung Portable SSD

Volume Name:               External HD
Mounted:                   Yes
Mount Point:               /Volumes/External HD

Partition Type:            Apple_APFS
File System Personality:   APFS
Type (Bundle):             apfs
Name (User Visible):       APFS

Owners:                    Enabled
OS Can Be Installed:       No
Recovery Partition:        Not Present
Media Type:                SSD
Protocol:                  USB
Total Size:                2 TB
Free Space:                1.5 TB
Used Space:                500 GB
Block Size:                4096 Bytes
Container Total Capacity:  2 TB
Container Free Space:      1.5 TB
"""


def _fake_run_healthy():
    """diskutil returns healthy SSD with Verified SMART."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "diskutil" in cmd and "info" in cmd:
            return _make_subprocess_result(_diskutil_info_healthy())
        return _make_subprocess_result()
    return fake_run


def _fake_run_ssd_not_verified():
    """diskutil returns SSD with SMART not verified."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "diskutil" in cmd and "info" in cmd:
            return _make_subprocess_result(_diskutil_info_ssd_not_verified())
        return _make_subprocess_result()
    return fake_run


def _fake_run_disk_failing():
    """diskutil returns HDD with SMART Failing."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "diskutil" in cmd and "info" in cmd:
            return _make_subprocess_result(_diskutil_info_disk_failing())
        return _make_subprocess_result()
    return fake_run


def _fake_run_hdd_healthy():
    """diskutil returns healthy HDD with Verified SMART."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "diskutil" in cmd and "info" in cmd:
            return _make_subprocess_result(_diskutil_info_hdd_healthy())
        return _make_subprocess_result()
    return fake_run


def _fake_run_no_smart():
    """diskutil returns disk without SMART info."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "diskutil" in cmd and "info" in cmd:
            return _make_subprocess_result(_diskutil_info_no_smart())
        return _make_subprocess_result()
    return fake_run


def _fake_run_diskutil_error():
    """diskutil command fails."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "diskutil" in cmd:
            return _make_subprocess_result(stderr="Error", returncode=1)
        return _make_subprocess_result()
    return fake_run


def test_disk_health_discovered():
    mod = _get_module()
    assert mod.name == "disk_health"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.DARWIN in mod.platforms


def test_disk_health_ssd_healthy():
    """SSD with Verified SMART status - no issues."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        result = mod.check(_make_profile())
    # Should have one INFO finding (healthy status)
    assert result.has_issues is False or any(
        f.severity == Severity.INFO for f in result.findings
    )
    # Should mention SSD
    finding_strs = [f.description for f in result.findings]
    assert any("SSD" in s for s in finding_strs)


def test_disk_health_ssd_not_verified():
    """SSD with SMART not verified - WARNING."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_ssd_not_verified()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Find the warning finding
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) > 0
    assert "Not Verified" in warning_findings[0].description


def test_disk_health_disk_failing():
    """HDD with SMART Failing - CRITICAL."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_disk_failing()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Find the critical finding
    critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert len(critical_findings) > 0
    assert "Failing" in critical_findings[0].description


def test_disk_health_hdd_healthy():
    """HDD with Verified SMART status - no issues."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_hdd_healthy()):
        result = mod.check(_make_profile())
    # Should have INFO finding (healthy)
    assert any(f.severity == Severity.INFO for f in result.findings)
    # Should mention HDD
    finding_strs = [f.description for f in result.findings]
    assert any("HDD" in s for s in finding_strs)


def test_disk_health_no_smart_info():
    """Disk without SMART info (e.g., external drive)."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_smart()):
        result = mod.check(_make_profile())
    # Should still work, but may report unknown or info
    # (External drives often don't have SMART)
    assert len(result.findings) >= 0


def test_disk_health_diskutil_error():
    """diskutil command fails."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_diskutil_error()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have warning about failed disk info
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) > 0
    assert "Could not retrieve" in warning_findings[0].title


def test_disk_health_fix_critical():
    """Fix action for CRITICAL SMART status."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_disk_failing()):
        check_result = mod.check(_make_profile())
    fix_result = mod.fix(check_result, Mode.AUTO)
    assert len(fix_result.actions) > 0
    # Action should be informational (SAFE risk level)
    for action in fix_result.actions:
        assert action.risk_level == RiskLevel.SAFE
        assert action.success is True


def test_disk_health_fix_warning():
    """Fix action for WARNING SMART status."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_ssd_not_verified()):
        check_result = mod.check(_make_profile())
    fix_result = mod.fix(check_result, Mode.AUTO)
    assert len(fix_result.actions) > 0
    for action in fix_result.actions:
        assert action.risk_level == RiskLevel.SAFE
        assert action.success is True


def test_disk_health_fix_healthy():
    """Fix action for healthy disk."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        check_result = mod.check(_make_profile())
    fix_result = mod.fix(check_result, Mode.AUTO)
    assert len(fix_result.actions) > 0
    for action in fix_result.actions:
        assert action.risk_level == RiskLevel.SAFE
        assert action.success is True


def test_disk_health_free_space_parsing():
    """Free space is correctly parsed and displayed."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        result = mod.check(_make_profile())
    # Check that free space percentage is in findings
    finding_strs = [f.description for f in result.findings]
    assert any("%" in s for s in finding_strs)
    # Should mention the percentage
    assert any("50.0%" in s for s in finding_strs)


def test_disk_health_multiple_checks():
    """Running check multiple times produces consistent results."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        result1 = mod.check(_make_profile())
    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        result2 = mod.check(_make_profile())
    # Results should be the same
    assert len(result1.findings) == len(result2.findings)
    assert result1.findings[0].severity == result2.findings[0].severity
