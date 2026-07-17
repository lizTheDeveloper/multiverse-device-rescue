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
    return next(m for m in modules if m.name == "disk_utility_firstaid")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_healthy():
    """Normal case: filesystem is healthy"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "diskutil info" in cmd_str:
            return _make_subprocess_result(
                """
   Device Identifier:        disk3s1
   Device Node:              /dev/disk3s1
   Whole Device:             No
   Part of Whole:            disk3
   Device / Media Name:      Macintosh HD
   Volume Name:              Macintosh HD
   Mounted:                  Yes
   Mount Point:              /
   Partition Type:           41504653-0000-11AA-AA11-00306543ECAC
   File System Personality:  APFS
   Type (Bundle):            apfs
   """
            )
        elif "diskutil verifyVolume" in cmd_str:
            return _make_subprocess_result(
                """Started file system verification on disk3s1 (Macintosh HD)
Verifying file system
Volume could not be unmounted
Using live mode
Performing fsck_apfs -n -l -x /dev/rdisk3s1
Checking the container superblock
Checking the checkpoint with transaction ID 57010650
Checking the space manager
The volume /dev/rdisk3s1 with UUID 28174D5B-9301-4315-B024-6165EAFFD6D1 appears to be OK
File system check exit code is 0
Finished file system verification on disk3s1 (Macintosh HD)
"""
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_filesystem_errors():
    """Filesystem has errors"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "diskutil info" in cmd_str:
            return _make_subprocess_result(
                """
   Device Identifier:        disk3s1
   Device Node:              /dev/disk3s1
   File System Personality:  APFS
   Type (Bundle):            apfs
"""
            )
        elif "diskutil verifyVolume" in cmd_str:
            return _make_subprocess_result(
                """Started file system verification on disk3s1 (Macintosh HD)
Verifying file system
Performing fsck_apfs -n -l -x /dev/rdisk3s1
ERROR: Filesystem check failed with error code 1
Checking the container superblock: ERROR - Invalid superblock
File system check exit code is 1
Finished file system verification on disk3s1 (Macintosh HD)
"""
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_filesystem_needs_repair():
    """Filesystem needs repair"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "diskutil info" in cmd_str:
            return _make_subprocess_result(
                """
   Device Identifier:        disk3s1
   File System Personality:  HFS+
   Type (Bundle):            hfs
"""
            )
        elif "diskutil verifyVolume" in cmd_str:
            return _make_subprocess_result(
                """Started file system verification on disk3s1 (Macintosh HD)
Verifying file system
Running repair procedure
Volume needs repair
Repairing filesystem
File system check exit code is 0
Finished file system verification on disk3s1 (Macintosh HD)
"""
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_diskutil_info_fails():
    """diskutil info command fails"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "diskutil info" in cmd_str:
            return _make_subprocess_result(returncode=1, stderr="Error")
        elif "diskutil verifyVolume" in cmd_str:
            return _make_subprocess_result(
                "Started file system verification\nappears to be OK\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_diskutil_verify_fails():
    """diskutil verifyVolume command fails"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "diskutil info" in cmd_str:
            return _make_subprocess_result(
                """
   Device Identifier:        disk3s1
   File System Personality:  APFS
   Type (Bundle):            apfs
"""
            )
        elif "diskutil verifyVolume" in cmd_str:
            return _make_subprocess_result(returncode=1, stderr="Error")
        return _make_subprocess_result()
    return fake_run


def test_disk_utility_firstaid_discovered():
    mod = _get_module()
    assert mod.name == "disk_utility_firstaid"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE


def test_disk_utility_firstaid_healthy():
    """Test with healthy filesystem"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.severity == Severity.INFO for f in result.findings)
    assert any(f.data.get("check") == "fs_healthy" for f in result.findings)


def test_disk_utility_firstaid_apfs_filesystem():
    """Test APFS filesystem type is reported"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        result = mod.check(_make_profile())
    assert any("APFS" in f.data.get("filesystem", "") for f in result.findings)


def test_disk_utility_firstaid_filesystem_errors():
    """Test with filesystem errors"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_filesystem_errors()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.severity == Severity.CRITICAL for f in result.findings)
    assert any(f.data.get("check") == "fs_errors" for f in result.findings)


def test_disk_utility_firstaid_hfs_filesystem():
    """Test HFS+ filesystem type is reported"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_filesystem_needs_repair()):
        result = mod.check(_make_profile())
    assert any("HFS+" in f.data.get("filesystem", "") for f in result.findings)


def test_disk_utility_firstaid_filesystem_needs_repair():
    """Test with filesystem that needs repair"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_filesystem_needs_repair()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.severity == Severity.WARNING for f in result.findings)
    assert any(f.data.get("check") == "fs_needs_repair" for f in result.findings)


def test_disk_utility_firstaid_diskutil_info_fails():
    """Test when diskutil info fails"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_diskutil_info_fails()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.severity == Severity.WARNING for f in result.findings)
    assert any(f.data.get("check") == "fs_type_failed" for f in result.findings)


def test_disk_utility_firstaid_diskutil_verify_fails():
    """Test when diskutil verifyVolume fails"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_diskutil_verify_fails()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.severity == Severity.WARNING for f in result.findings)
    assert any(f.data.get("check") == "verify_failed" for f in result.findings)


def test_disk_utility_firstaid_fix_is_informational():
    """Test that fix() always succeeds with informational messages"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_filesystem_errors()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action
    assert len(fix.actions) > 0


def test_disk_utility_firstaid_fix_provides_recovery_instructions():
    """Test that fix() provides Recovery Mode instructions"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_filesystem_errors()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    # Should mention Recovery Mode in the actions
    assert any(
        "Recovery Mode" in action.description for action in fix.actions
    )


def test_disk_utility_firstaid_fix_healthy():
    """Test fix() for healthy filesystem"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert len(fix.actions) > 0
