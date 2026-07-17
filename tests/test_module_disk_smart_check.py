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
    return next(m for m in modules if m.name == "disk_smart_check")


def _fake_run_healthy_disk():
    """Mock subprocess for healthy disk."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""

        if "diskutil" in cmd and "info" in cmd:
            result.stdout = """Device Identifier: disk0s1
Device Node: /dev/disk0s1
Whole Device: No
Part of Whole: disk0
Device / Media Name: Samsung 970 EVO 512GB
Volume Name: Macintosh HD
Mounted: Yes
Mount Point: /
Partition Type: Apple_APFS
File System Type: apfs
Owners: Disabled
OS Can Be Installed: Yes
Recovery Disk: disk0s3
Media Type: SSD
Protocol: NVMe
SMART Status: Verified
Disk Size: 512.1 GB
Device Block Size: 4096 Bytes
"""
        elif "system_profiler" in cmd and "SPStorageDataType" in cmd:
            result.stdout = """Storage:
    NVMe:
        Model: Samsung 970 EVO 512GB
        S.M.A.R.T. Status: Verified
        Wear Level: 15%
"""
        elif "system_profiler" in cmd and "SPNVMeDataType" in cmd:
            result.stdout = ""
        elif "df" in cmd:
            result.stdout = """Filesystem     1B-blocks       Used  Available Use% Mounted on
/dev/disk0s1 549453078528 387637080064 161816498464  71% /"""
        elif "diskutil" in cmd and "apfs" in cmd:
            result.stdout = """APFS Container Reference:                 disk1
Name:                                     Container
Metadata Block Size:                      4096
Container Total Capacity:                 512.1 GB
Container Available Capacity:              161.8 GB
Container Used Capacity:                  350.3 GB
Physical Store /dev/disk0s2 (internal):
    SMART Status:                          Verified
"""
        return result
    return fake_run


def _fake_run_failing_disk():
    """Mock subprocess for disk with failing SMART status."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""

        if "diskutil" in cmd and "info" in cmd:
            result.stdout = """Device Identifier: disk0s1
Device Node: /dev/disk0s1
Device / Media Name: Seagate Barracuda 2TB
Mounted: Yes
Mount Point: /
Partition Type: Apple_APFS
SMART Status: Failing
Disk Size: 2.0 TB
Solid State: No
"""
        elif "system_profiler" in cmd and "SPStorageDataType" in cmd:
            result.stdout = """Storage:
    SATA/HDD:
        Model: Seagate Barracuda 2TB
        S.M.A.R.T. Status: Failing
"""
        elif "df" in cmd:
            result.stdout = """Filesystem     1B-blocks       Used  Available Use% Mounted on
/dev/disk0s1 2199023255552 1919100108800 279923146752  13% /"""
        elif "diskutil" in cmd and "apfs" in cmd:
            result.stdout = ""
        return result
    return fake_run


def _fake_run_low_disk_space():
    """Mock subprocess for disk with low space."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""

        if "diskutil" in cmd and "info" in cmd:
            result.stdout = """Device Identifier: disk0s1
Device / Media Name: Apple SSD 256GB
SMART Status: Verified
Disk Size: 256.1 GB
Solid State: Yes
"""
        elif "system_profiler" in cmd:
            result.stdout = ""
        elif "df" in cmd:
            result.stdout = """Filesystem     1B-blocks       Used  Available Use% Mounted on
/dev/disk0s1 274877906944 257437777920 17440129024   6% /"""
        elif "diskutil" in cmd and "apfs" in cmd:
            result.stdout = ""
        return result
    return fake_run


def _fake_run_ssd_high_wear():
    """Mock subprocess for SSD with high wear level."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""

        if "diskutil" in cmd and "info" in cmd:
            result.stdout = """Device / Media Name: Intel 860 QVO 512GB
SMART Status: Verified
Disk Size: 512.1 GB
Solid State: Yes
"""
        elif "system_profiler" in cmd and "SPStorageDataType" in cmd:
            result.stdout = """Storage:
    SSD:
        Model: Intel 860 QVO 512GB
        S.M.A.R.T. Status: Verified
        Wear Level: 85%
"""
        elif "df" in cmd:
            result.stdout = """Filesystem     1B-blocks       Used  Available Use% Mounted on
/dev/disk0s1 549453078528 460000000000 89453078528  16% /"""
        elif "diskutil" in cmd and "apfs" in cmd:
            result.stdout = ""
        return result
    return fake_run


def test_disk_smart_check_discovered():
    mod = _get_module()
    assert mod.name == "disk_smart_check"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE


def test_disk_smart_check_healthy():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy_disk()):
        result = mod.check(_make_profile())

    # Should have findings (SMART healthy + wear level info)
    assert result.has_issues
    # Should have SMART healthy info
    assert any(f.data.get("check") == "smart_healthy" for f in result.findings)
    assert any(f.severity == Severity.INFO for f in result.findings)


def test_disk_smart_check_failing():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_failing_disk()):
        result = mod.check(_make_profile())

    assert result.has_issues
    assert any(f.data.get("check") == "smart_failing" for f in result.findings)
    assert any(f.severity == Severity.CRITICAL for f in result.findings)


def test_disk_smart_check_low_disk_space():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_low_disk_space()):
        result = mod.check(_make_profile())

    assert result.has_issues
    # Should flag low disk space
    assert any(f.data.get("check") == "low_disk_space" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_disk_smart_check_ssd_high_wear():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_ssd_high_wear()):
        result = mod.check(_make_profile())

    assert result.has_issues
    # Should flag high wear level
    assert any(f.data.get("check") == "ssd_wear" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_disk_smart_check_fix_critical():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_failing_disk()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    assert fix.all_succeeded
    assert len(fix.actions) > 0
    # All actions should be informational
    assert all(a.success for a in fix.actions)


def test_disk_smart_check_fix_healthy():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy_disk()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    assert fix.all_succeeded
    assert len(fix.actions) > 0
    assert all(a.success for a in fix.actions)


def test_disk_smart_check_fix_low_space():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_low_disk_space()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    assert fix.all_succeeded
    assert any("Free up disk space" in a.title for a in fix.actions)
