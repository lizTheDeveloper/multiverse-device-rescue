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


def _make_laptop_profile():
    return SystemProfile(
        platform=Platform.DARWIN,
        os_name="macOS",
        os_version="15.2",
        architecture="arm64",
        cpu_model="Apple M3 Pro",
        cpu_cores=12,
        ram_bytes=32 * 1024**3,
    )


def _make_imac_profile():
    return SystemProfile(
        platform=Platform.DARWIN,
        os_name="macOS",
        os_version="15.2",
        architecture="arm64",
        cpu_model="iMac M4",
        cpu_cores=10,
        ram_bytes=24 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "filesystem_health_check")


def _fake_run_apfs_healthy():
    """Mock subprocess for healthy APFS filesystem."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""

        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "diskutil info" in cmd_str:
            result.stdout = """
   Device Identifier:         disk3s1
   Device Node:               /dev/disk3s1
   Whole Device:              No
   Part of Whole:             disk3
   Device / Media Name:       Macintosh HD
   Volume Name:               Macintosh HD
   Mounted:                   Yes
   Mount Point:               /
   Encrypted:                 Yes
   FileVault:                 Yes
   Type (Bundle Code):        apfs
   File System Personality:   APFS
   Type (Overall):            apfs
   Name (User Visible):       APFS
   Owners:                    Enabled
   OS Can Be Installed:       Yes
   Removable Media:           No
   Virtual:                   No
   Key Size:                  256-bit
   UUID:                      ABC12345-1234-1234-1234-123456789ABC
   Allocation Block Size:     4096
   Block Count:               488280320
   Free Blocks:               244140160
   Sector Size:               4096
   Media Type:                SSD
   Protocol:                  SATA
   SMART Status:              Verified
"""
        elif "diskutil apfs list" in cmd_str:
            result.stdout = """
APFS Containers (1 found)
|
+-- Container disk2
    ├─ APFS Volume disk2s1 - Macintosh HD
    ├─ APFS Volume disk2s2 - Preboot
    ├─ APFS Volume disk2s3 - Recovery
    ├─ APFS Volume disk2s4 - VM
    ├─ Snapshot 20240801-120000 /System/Volumes/Data@com.apple.TimeMachine.2024-08-01-120000
    ├─ Snapshot 20240725-120000 /System/Volumes/Data@com.apple.TimeMachine.2024-07-25-120000
    └─ Snapshot 20240718-120000 /System/Volumes/Data@com.apple.TimeMachine.2024-07-18-120000
"""
        elif "diskutil verifyVolume" in cmd_str:
            result.stdout = "Verifying storage system"
            result.stderr = "The volume /dev/disk3s1 appears to be OK."
        elif "df -i" in cmd_str:
            result.stdout = """Filesystem   512-blocks      Used Available Capacity iused  ifree %iused  Mounted on
/dev/disk3s1 976560640 488280320 488280320   50%  1000000 5000000   16%   /
"""
        return result
    return fake_run


def _fake_run_hfs_plus():
    """Mock subprocess for HFS+ filesystem."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""

        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "diskutil info" in cmd_str:
            result.stdout = """
   Device Identifier:         disk2s2
   Whole Device:              No
   Device / Media Name:       Macintosh HD
   Mount Point:               /
   Encrypted:                 No
   FileVault:                 No
   Type (Bundle Code):        hfs
   File System Personality:   Journaled HFS+
   Type (Overall):            hfs
"""
        elif "diskutil apfs list" in cmd_str:
            result.stdout = ""
        elif "diskutil verifyVolume" in cmd_str:
            result.stdout = "Verifying storage system"
            result.stderr = "The volume /dev/disk2s2 appears to be OK."
        elif "df -i" in cmd_str:
            result.stdout = """Filesystem   512-blocks      Used Available Capacity iused  ifree %iused  Mounted on
/dev/disk2s2 976560640 488280320 488280320   50%  1000000 5000000   16%   /
"""
        return result
    return fake_run


def _fake_run_unencrypted_filesystem():
    """Mock subprocess for unencrypted filesystem."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""

        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "diskutil info" in cmd_str:
            result.stdout = """
   Type (Bundle Code):        apfs
   File System Personality:   APFS
   Encrypted:                 No
   Mount Point:               /
"""
        elif "diskutil apfs list" in cmd_str:
            result.stdout = "APFS Containers (1 found)\n+-- Container disk3\n"
        elif "diskutil verifyVolume" in cmd_str:
            result.stdout = "Verifying storage system"
            result.stderr = "The volume appears to be OK."
        elif "df -i" in cmd_str:
            result.stdout = """Filesystem   512-blocks      Used Available Capacity iused  ifree %iused  Mounted on
/dev/disk3s1 976560640 488280320 488280320   50%  1000000 5000000   16%   /
"""
        return result
    return fake_run


def _fake_run_many_snapshots():
    """Mock subprocess for filesystem with many snapshots."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""

        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "diskutil info" in cmd_str:
            result.stdout = """
   Type (Bundle Code):        apfs
   Encrypted:                 Yes
   Mount Point:               /
"""
        elif "diskutil apfs list" in cmd_str:
            # Create output with 60 snapshots
            snapshot_lines = "\n".join([f"    ├─ Snapshot {i} @snapshot{i}" for i in range(60)])
            result.stdout = f"""APFS Containers (1 found)
|
+-- Container disk2
{snapshot_lines}
"""
        elif "diskutil verifyVolume" in cmd_str:
            result.stdout = "Verifying storage system"
            result.stderr = "The volume appears to be OK."
        elif "df -i" in cmd_str:
            result.stdout = """Filesystem   512-blocks      Used Available Capacity iused  ifree %iused  Mounted on
/dev/disk3s1 976560640 488280320 488280320   50%  1000000 5000000   16%   /
"""
        return result
    return fake_run


def _fake_run_corrupted_filesystem():
    """Mock subprocess for corrupted filesystem."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""

        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "diskutil info" in cmd_str:
            result.stdout = """
   Type (Bundle Code):        apfs
   Encrypted:                 Yes
   Mount Point:               /
"""
        elif "diskutil apfs list" in cmd_str:
            result.stdout = "APFS Containers (1 found)\n"
        elif "diskutil verifyVolume" in cmd_str:
            result.stdout = "Verifying storage system"
            result.stderr = "The volume /dev/disk3s1 appears to be corrupt. Error: CRC mismatch detected."
        elif "df -i" in cmd_str:
            result.stdout = """Filesystem   512-blocks      Used Available Capacity iused  ifree %iused  Mounted on
/dev/disk3s1 976560640 488280320 488280320   50%  1000000 5000000   16%   /
"""
        return result
    return fake_run


def _fake_run_high_inode_usage():
    """Mock subprocess for high inode usage."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""

        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "diskutil info" in cmd_str:
            result.stdout = """
   Type (Bundle Code):        apfs
   Encrypted:                 Yes
   Mount Point:               /
"""
        elif "diskutil apfs list" in cmd_str:
            result.stdout = "APFS Containers (1 found)\n"
        elif "diskutil verifyVolume" in cmd_str:
            result.stdout = "Verifying storage system"
            result.stderr = "The volume appears to be OK."
        elif "df -i" in cmd_str:
            # 90% inode usage
            result.stdout = """Filesystem   512-blocks      Used Available Capacity iused  ifree %iused  Mounted on
/dev/disk3s1 976560640 488280320 488280320   50%  9000000 1000000   90%   /
"""
        return result
    return fake_run


def test_filesystem_health_check_discovered():
    mod = _get_module()
    assert mod.name == "filesystem_health_check"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.DARWIN in mod.platforms


def test_filesystem_health_check_apfs_healthy():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_apfs_healthy()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have filesystem type info
    assert any(f.data.get("check") == "filesystem_type" for f in result.findings)
    # Should have encryption info
    assert any(f.data.get("check") == "encryption_status" for f in result.findings)
    # Should have verification ok
    assert any(f.data.get("check") == "fs_verification_ok" for f in result.findings)


def test_filesystem_health_check_hfs_plus():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_hfs_plus()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should detect HFS+ and flag warning
    assert any(f.data.get("check") == "hfs_plus_detection" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings if f.data.get("check") == "hfs_plus_detection")


def test_filesystem_health_check_unencrypted_laptop():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_unencrypted_filesystem()):
        result = mod.check(_make_laptop_profile())
    assert result.has_issues
    # Should flag unencrypted laptop warning
    assert any(f.data.get("check") == "unencrypted_laptop" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings if f.data.get("check") == "unencrypted_laptop")


def test_filesystem_health_check_imac_unencrypted():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_unencrypted_filesystem()):
        result = mod.check(_make_imac_profile())
    # Should not flag unencrypted warning for desktop (iMac)
    assert not any(f.data.get("check") == "unencrypted_laptop" for f in result.findings)


def test_filesystem_health_check_many_snapshots():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_many_snapshots()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should detect excessive snapshots
    assert any(f.data.get("check") == "apfs_snapshot_count" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings if f.data.get("check") == "apfs_snapshot_count")


def test_filesystem_health_check_corrupted():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_corrupted_filesystem()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should detect filesystem error
    assert any(f.data.get("check") == "fs_verification_error" for f in result.findings)
    assert any(f.severity == Severity.CRITICAL for f in result.findings if f.data.get("check") == "fs_verification_error")


def test_filesystem_health_check_high_inode_usage():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_high_inode_usage()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should detect high inode usage
    assert any(f.data.get("check") == "inode_low" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings if f.data.get("check") == "inode_low")


def test_filesystem_health_check_fix_hfs_plus():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_hfs_plus()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    # Should have actions for HFS+ warning
    assert any("HFS+" in a.description or "upgrade" in a.description.lower() for a in fix.actions)


def test_filesystem_health_check_fix_unencrypted():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_unencrypted_filesystem()):
        check = mod.check(_make_laptop_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    # Should have actions for unencrypted laptop
    assert any("FileVault" in a.description for a in fix.actions)


def test_filesystem_health_check_fix_snapshots():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_many_snapshots()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    # Should have actions for snapshot management
    assert any("snapshot" in a.description.lower() for a in fix.actions)


def test_filesystem_health_check_fix_corrupted():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_corrupted_filesystem()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    # Should have actions for filesystem repair
    assert any("First Aid" in a.description or "Recovery" in a.description for a in fix.actions)


def test_filesystem_health_check_fix_inode_usage():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_high_inode_usage()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    # Should have actions for inode usage
    assert any("inode" in a.description.lower() for a in fix.actions)
