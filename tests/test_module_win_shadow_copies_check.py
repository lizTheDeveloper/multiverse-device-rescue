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
    return next(m for m in modules if m.name == "win_shadow_copies_check")


def _make_run_result(
    vss_running=True,
    restore_enabled=True,
    shadow_output=None,
    storage_output=None,
    expect_clean=False,
):
    """Create a fake subprocess.run that returns appropriate results.

    Args:
        vss_running: Whether VSS service is running. Takes precedence over expect_clean.
        restore_enabled: Whether System Restore is enabled. Takes precedence over expect_clean.
        shadow_output: Output from 'vssadmin list shadows'.
        storage_output: Output from 'vssadmin list shadowstorage'.
        expect_clean: If True, use default healthy configurations.
    """

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        # sc query VSS command
        if "sc" in cmd_str and "query" in cmd_str and "VSS" in cmd_str:
            if vss_running:
                result.stdout = (
                    "SERVICE_NAME: VSS\n"
                    "        TYPE               : 10  WIN32_OWN_PROCESS\n"
                    "        STATE              : 4  RUNNING\n"
                    "        WIN32_EXIT_CODE    : 0  (0x0)\n"
                    "        SERVICE_EXIT_CODE  : 0  (0x0)\n"
                    "        CHECKPOINT         : 0x0\n"
                    "        WAIT_HINT          : 0x0\n"
                )
            else:
                result.returncode = 1
                result.stdout = (
                    "SERVICE_NAME: VSS\n"
                    "        TYPE               : 10  WIN32_OWN_PROCESS\n"
                    "        STATE              : 1  STOPPED\n"
                    "        WIN32_EXIT_CODE    : 0  (0x0)\n"
                    "        SERVICE_EXIT_CODE  : 0  (0x0)\n"
                )

        # reg query for System Restore
        elif "reg" in cmd_str and "RPSessionInterval" in cmd_str:
            if restore_enabled:
                result.stdout = (
                    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore\n"
                    "    RPSessionInterval    REG_DWORD    0x18\n"
                )
            else:
                result.returncode = 1
                result.stdout = "ERROR: The system was unable to find the specified registry key or value."

        # vssadmin list shadowstorage command (check BEFORE shadows since shadowstorage contains "shadows")
        elif "vssadmin" in cmd_str and "list" in cmd_str and "shadowstorage" in cmd_str:
            if storage_output is not None:
                result.stdout = storage_output
            elif expect_clean:
                result.stdout = (
                    "vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool\n"
                    "(C) Copyright 2001-2021 Microsoft Corporation. All rights reserved.\n\n"
                    "Volume shadow copy storage association(s)\n"
                    "   For volume: (C:)\\n"
                    "   Shadow Copy Storage volume: (C:)\n"
                    "   Used Shadow Copy Storage space: 5.50 GB out of 100.00 GB (5%)\n"
                    "   Allocated Shadow Copy Storage space: 100.00 GB\n"
                    "   Maximum Shadow Copy Storage space: 100.00 GB\n"
                )
            else:
                result.stdout = (
                    "vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool\n"
                    "(C) Copyright 2001-2021 Microsoft Corporation. All rights reserved.\n\n"
                    "Volume shadow copy storage association(s)\n"
                    "   For volume: (C:)\\n"
                    "   Shadow Copy Storage volume: (C:)\n"
                    "   Used Shadow Copy Storage space: 2.75 GB out of 50.00 GB (5%)\n"
                    "   Allocated Shadow Copy Storage space: 50.00 GB\n"
                    "   Maximum Shadow Copy Storage space: 50.00 GB\n"
                )

        # vssadmin list shadows command
        elif "vssadmin" in cmd_str and "list" in cmd_str and "shadows" in cmd_str:
            if shadow_output is not None:
                result.stdout = shadow_output
            elif expect_clean:
                result.stdout = (
                    "vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool\n"
                    "(C) Copyright 2001-2021 Microsoft Corporation. All rights reserved.\n\n"
                    "Number of shadow copies on this system: 0\n"
                )
            else:
                result.stdout = (
                    "vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool\n"
                    "(C) Copyright 2001-2021 Microsoft Corporation. All rights reserved.\n\n"
                    "Number of shadow copies on this system: 3\n\n"
                    "Shadow Copy ID: {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}\n"
                    "   Shadow Copy Volume: \\\\?\\Volume{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}\\\n"
                    "   Original Volume: C:\\\n"
                    "   Shadow Copy Device: \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\\n"
                    "   Originating Machine: MYCOMPUTER\n"
                    "   Service Machine: MYCOMPUTER\n"
                    "   Creation time: 2024-07-08T10:30:15Z\n"
                    "   Shadow Copy Volume Name: \\\\?\\Volume{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}\\\n"
                    "   Contained 1 snapshots.\n\n"
                    "Shadow Copy ID: {yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy}\n"
                    "   Shadow Copy Volume: \\\\?\\Volume{yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy}\\\n"
                    "   Original Volume: C:\\\n"
                    "   Shadow Copy Device: \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy2\\\n"
                    "   Originating Machine: MYCOMPUTER\n"
                    "   Service Machine: MYCOMPUTER\n"
                    "   Creation time: 2024-07-07T10:30:15Z\n"
                    "   Shadow Copy Volume Name: \\\\?\\Volume{yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy}\\\n"
                    "   Contained 1 snapshots.\n\n"
                    "Shadow Copy ID: {zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz}\n"
                    "   Shadow Copy Volume: \\\\?\\Volume{zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz}\\\n"
                    "   Original Volume: C:\\\n"
                    "   Shadow Copy Device: \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy3\\\n"
                    "   Originating Machine: MYCOMPUTER\n"
                    "   Service Machine: MYCOMPUTER\n"
                    "   Creation time: 2024-07-06T10:30:15Z\n"
                    "   Shadow Copy Volume Name: \\\\?\\Volume{zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz}\\\n"
                    "   Contained 1 snapshots.\n"
                )

        return result

    return fake_run


def test_win_shadow_copies_check_discovered():
    mod = _get_module()
    assert mod.name == "win_shadow_copies_check"
    assert mod.category == "integrity"
    assert Platform.WIN32 in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_win_shadow_copies_check_all_pass():
    """Test when all VSS checks pass (healthy system)."""
    mod = _get_module()
    fake_run = _make_run_result(expect_clean=True)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    # Should have at least one INFO finding
    assert result.has_issues
    assert any(f.severity == Severity.INFO for f in result.findings)


def test_win_shadow_copies_check_vss_disabled():
    """Test detection of disabled VSS service."""
    mod = _get_module()
    fake_run = _make_run_result(vss_running=False, expect_clean=True)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "vss_disabled" for f in result.findings)
    critical = [f for f in result.findings if f.data.get("check") == "vss_disabled"]
    assert critical[0].severity == Severity.CRITICAL


def test_win_shadow_copies_check_restore_disabled():
    """Test detection of disabled System Restore."""
    mod = _get_module()
    fake_run = _make_run_result(restore_enabled=False)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "restore_disabled" for f in result.findings)
    warning = [f for f in result.findings if f.data.get("check") == "restore_disabled"]
    assert warning[0].severity == Severity.WARNING


def test_win_shadow_copies_check_no_recovery():
    """Test critical finding when both VSS and System Restore disabled, no shadow copies."""
    mod = _get_module()
    fake_run = _make_run_result(
        vss_running=False,
        restore_enabled=False,
        shadow_output=(
            "vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool\n"
            "Number of shadow copies on this system: 0\n"
        ),
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "no_recovery_capability" for f in result.findings)
    critical = [f for f in result.findings if f.data.get("check") == "no_recovery_capability"]
    assert critical[0].severity == Severity.CRITICAL


def test_win_shadow_copies_check_shadow_copies_exist():
    """Test reporting when shadow copies exist."""
    mod = _get_module()
    fake_run = _make_run_result(expect_clean=True)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    restore_points = [f for f in result.findings if "restore point" in f.title.lower()]
    assert len(restore_points) > 0


def test_win_shadow_copies_check_small_storage():
    """Test detection of very small storage allocation."""
    mod = _get_module()
    small_storage = (
        "vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool\n"
        "Volume shadow copy storage association(s)\n"
        "   For volume: (C:)\\n"
        "   Shadow Copy Storage volume: (C:)\n"
        "   Used Shadow Copy Storage space: 0.25 GB out of 2.00 GB (2%)\n"
        "   Allocated Shadow Copy Storage space: 2.00 GB\n"
        "   Maximum Shadow Copy Storage space: 2.00 GB\n"
    )
    fake_run = _make_run_result(storage_output=small_storage)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "small_storage_allocation" for f in result.findings)
    warning = [f for f in result.findings if f.data.get("check") == "small_storage_allocation"]
    assert warning[0].severity == Severity.WARNING
    assert warning[0].data.get("percent_allocated") == 2


def test_win_shadow_copies_check_fix_vss_disabled():
    """Test fix recommendation for disabled VSS."""
    mod = _get_module()
    fake_run = _make_run_result(vss_running=False, expect_clean=True)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    assert any("VSS" in a.title or "Volume Shadow Copy" in a.title for a in fix.actions)


def test_win_shadow_copies_check_fix_restore_disabled():
    """Test fix recommendation for disabled System Restore."""
    mod = _get_module()
    fake_run = _make_run_result(restore_enabled=False)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    assert any("System Restore" in a.title for a in fix.actions)


def test_win_shadow_copies_check_fix_small_storage():
    """Test fix recommendation for small storage allocation."""
    mod = _get_module()
    small_storage = (
        "vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool\n"
        "Volume shadow copy storage association(s)\n"
        "   For volume: (C:)\\n"
        "   Shadow Copy Storage volume: (C:)\n"
        "   Used Shadow Copy Storage space: 0.10 GB out of 1.00 GB (1%)\n"
        "   Allocated Shadow Copy Storage space: 1.00 GB\n"
        "   Maximum Shadow Copy Storage space: 1.00 GB\n"
    )
    fake_run = _make_run_result(storage_output=small_storage)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    storage_actions = [a for a in fix.actions if "storage" in a.title.lower()]
    assert len(storage_actions) > 0


def test_win_shadow_copies_check_multiple_issues():
    """Test when multiple issues are detected."""
    mod = _get_module()
    fake_run = _make_run_result(
        vss_running=False,
        restore_enabled=False,
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    checks = [f.data.get("check") for f in result.findings]
    assert "vss_disabled" in checks
    assert "restore_disabled" in checks


def test_win_shadow_copies_check_handles_subprocess_error():
    """Test graceful handling of subprocess errors."""
    mod = _get_module()

    def error_run(cmd, **kwargs):
        raise OSError("Command failed")

    with patch("subprocess.run", side_effect=error_run):
        result = mod.check(_make_profile())
    # Should still complete without crashing
    assert isinstance(result.findings, list)


def test_win_shadow_copies_check_empty_shadow_output():
    """Test handling of empty vssadmin output."""
    mod = _get_module()
    fake_run = _make_run_result(
        shadow_output="vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool\n"
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    # Should handle gracefully
    assert isinstance(result.findings, list)
