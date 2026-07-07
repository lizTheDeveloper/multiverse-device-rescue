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
    return next(m for m in modules if m.name == "smart_status")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _diskutil_ssd_verified():
    """Normal case: SSD with Verified SMART status."""
    return """
Device Identifier:         disk0s2
Device Node:               /dev/disk0s2
Whole Device:              No
Device / Media Name:       APPLE SSD AP0512Q
SMART Status:              Verified
Solid State:               Yes
Total Size:                512 GB
Free Space:                256 GB
"""


def _diskutil_ssd_not_verified():
    """SSD with SMART not verified."""
    return """
Device Identifier:         disk0s2
Device Node:               /dev/disk0s2
Whole Device:              No
Device / Media Name:       APPLE SSD AP0512Q
SMART Status:              Not Verified
Solid State:               Yes
Total Size:                512 GB
Free Space:                128 GB
"""


def _diskutil_hdd_failing():
    """HDD with SMART status Failing."""
    return """
Device Identifier:         disk0s2
Device Node:               /dev/disk0s2
Whole Device:              No
Device / Media Name:       SEAGATE ST1000DM003
SMART Status:              Failing
Solid State:               No
Total Size:                1 TB
Free Space:                100 GB
"""


def _diskutil_hdd_verified():
    """HDD with Verified SMART status."""
    return """
Device Identifier:         disk0s2
Device Node:               /dev/disk0s2
Whole Device:              No
Device / Media Name:       WDC WD10EZEX
SMART Status:              Verified
Solid State:               No
Total Size:                1 TB
Free Space:                500 GB
"""


def _system_profiler_storage_verified():
    """system_profiler SPStorageDataType with verified SMART."""
    return """
Storage:

    NVMe:

    Capacity: 512 GB
    Manufacturer: Apple
    Model: Apple SSD AP0512Q
    Serial Number: ABC123
    Firmware Version: 123A2
    S.M.A.R.T. Status: Verified
"""


def _system_profiler_storage_failing():
    """system_profiler SPStorageDataType with failing SMART."""
    return """
Storage:

    SATA:

    Capacity: 1 TB
    Manufacturer: Seagate
    Device Name: SEAGATE ST1000DM003
    S.M.A.R.T. Status: Failing
"""


def _system_profiler_nvme_good():
    """system_profiler SPNVMeDataType with good health."""
    return """
NVMe:

    Model: Apple SSD AP1024Q
    Serial Number: XYZ789
    Health: Good
    Capacity: 1 TB
"""


def _fake_run_diskutil_ssd_verified():
    """diskutil returns verified SSD."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "diskutil" in cmd and "info" in cmd:
            return _make_subprocess_result(_diskutil_ssd_verified())
        return _make_subprocess_result()
    return fake_run


def _fake_run_diskutil_ssd_not_verified():
    """diskutil returns SSD with SMART not verified."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "diskutil" in cmd and "info" in cmd:
            return _make_subprocess_result(_diskutil_ssd_not_verified())
        return _make_subprocess_result()
    return fake_run


def _fake_run_diskutil_hdd_failing():
    """diskutil returns HDD with SMART Failing."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "diskutil" in cmd and "info" in cmd:
            return _make_subprocess_result(_diskutil_hdd_failing())
        return _make_subprocess_result()
    return fake_run


def _fake_run_diskutil_error():
    """diskutil command fails and system_profiler also fails."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and cmd[0] in ["diskutil", "system_profiler"]:
            return _make_subprocess_result(stderr="Error", returncode=1)
        return _make_subprocess_result()
    return fake_run


def _fake_run_storage_profiler_verified():
    """diskutil fails, but system_profiler SPStorageDataType works."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "diskutil" in cmd:
            return _make_subprocess_result(stderr="Error", returncode=1)
        if isinstance(cmd, list) and "system_profiler" in cmd and "SPStorageDataType" in cmd:
            return _make_subprocess_result(_system_profiler_storage_verified())
        return _make_subprocess_result()
    return fake_run


def _fake_run_nvme_profiler_good():
    """diskutil and storage fail, but NVMe profiler works."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "diskutil" in cmd:
            return _make_subprocess_result(stderr="Error", returncode=1)
        if isinstance(cmd, list) and "system_profiler" in cmd and "SPStorageDataType" in cmd:
            return _make_subprocess_result(stderr="Error", returncode=1)
        if isinstance(cmd, list) and "system_profiler" in cmd and "SPNVMeDataType" in cmd:
            return _make_subprocess_result(_system_profiler_nvme_good())
        return _make_subprocess_result()
    return fake_run


def test_smart_status_discovered():
    mod = _get_module()
    assert mod.name == "smart_status"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.DARWIN in mod.platforms


def test_smart_status_diskutil_ssd_verified():
    """SSD with Verified SMART status via diskutil."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_diskutil_ssd_verified()):
        result = mod.check(_make_profile())
    # Should have one finding with INFO severity
    assert len(result.findings) > 0
    assert result.findings[0].severity == Severity.INFO
    assert "Verified" in result.findings[0].description
    assert "APPLE SSD AP0512Q" in result.findings[0].description
    assert "SSD" in result.findings[0].description


def test_smart_status_diskutil_ssd_not_verified():
    """SSD with SMART not verified via diskutil."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_diskutil_ssd_not_verified()):
        result = mod.check(_make_profile())
    assert len(result.findings) > 0
    assert result.findings[0].severity == Severity.WARNING
    assert "Not Verified" in result.findings[0].description


def test_smart_status_diskutil_hdd_failing():
    """HDD with SMART Failing via diskutil."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_diskutil_hdd_failing()):
        result = mod.check(_make_profile())
    assert len(result.findings) > 0
    assert result.findings[0].severity == Severity.CRITICAL
    assert "Failing" in result.findings[0].description
    assert "SEAGATE" in result.findings[0].description
    assert "HDD" in result.findings[0].description


def test_smart_status_fallback_storage_profiler():
    """Falls back to system_profiler SPStorageDataType when diskutil fails."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_storage_profiler_verified()):
        result = mod.check(_make_profile())
    assert len(result.findings) > 0
    assert result.findings[0].severity == Severity.INFO
    assert "Verified" in result.findings[0].description


def test_smart_status_fallback_nvme_profiler():
    """Falls back to system_profiler SPNVMeDataType when diskutil and storage fail."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_nvme_profiler_good()):
        result = mod.check(_make_profile())
    assert len(result.findings) > 0
    assert result.findings[0].severity == Severity.INFO
    assert "NVMe" in result.findings[0].description


def test_smart_status_all_sources_fail():
    """All sources fail to provide SMART status."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_diskutil_error()):
        result = mod.check(_make_profile())
    assert len(result.findings) > 0
    assert result.findings[0].severity == Severity.WARNING
    assert "Could not retrieve" in result.findings[0].title


def test_smart_status_fix_critical():
    """Fix action for CRITICAL SMART status (Failing)."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_diskutil_hdd_failing()):
        check_result = mod.check(_make_profile())
    fix_result = mod.fix(check_result, Mode.AUTO)
    assert len(fix_result.actions) > 0
    assert fix_result.actions[0].risk_level == RiskLevel.SAFE
    assert fix_result.actions[0].success is True
    assert "CRITICAL" in fix_result.actions[0].title
    assert "Back up" in fix_result.actions[0].description


def test_smart_status_fix_warning():
    """Fix action for WARNING SMART status (Not Verified)."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_diskutil_ssd_not_verified()):
        check_result = mod.check(_make_profile())
    fix_result = mod.fix(check_result, Mode.AUTO)
    assert len(fix_result.actions) > 0
    assert fix_result.actions[0].risk_level == RiskLevel.SAFE
    assert fix_result.actions[0].success is True
    assert "not verified" in fix_result.actions[0].title.lower() or "Not Verified" in fix_result.actions[0].description


def test_smart_status_fix_healthy():
    """Fix action for healthy disk (Verified)."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_diskutil_ssd_verified()):
        check_result = mod.check(_make_profile())
    fix_result = mod.fix(check_result, Mode.AUTO)
    assert len(fix_result.actions) > 0
    assert fix_result.actions[0].risk_level == RiskLevel.SAFE
    assert fix_result.actions[0].success is True
    assert "health" in fix_result.actions[0].description.lower()


def test_smart_status_multiple_checks():
    """Running check multiple times produces consistent results."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_diskutil_ssd_verified()):
        result1 = mod.check(_make_profile())
    with patch("subprocess.run", side_effect=_fake_run_diskutil_ssd_verified()):
        result2 = mod.check(_make_profile())
    assert len(result1.findings) == len(result2.findings)
    assert result1.findings[0].severity == result2.findings[0].severity
