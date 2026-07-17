import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


def _make_profile():
    return SystemProfile(
        platform=Platform.WIN32,
        os_name="Windows 10",
        os_version="10.0.19045",
        architecture="AMD64",
        cpu_model="Intel(R) Core(TM) i7-9700K",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "win_startup_repair")


def _make_run_result(
    boot_config=None,
    recovery_sequence=None,
    boot_manager=None,
    boot_degradation=None,
    expect_clean=False,
):
    """Create a fake subprocess.run that returns appropriate boot config results."""

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        # bcdedit /enum {current}
        if "bcdedit" in cmd_str and "{current}" in cmd_str:
            if boot_config:
                result.stdout = boot_config
            elif expect_clean:
                result.stdout = (
                    "Windows Boot Loader\n"
                    "identifier              {default}\n"
                    "device                  partition=C:\n"
                    "timeout                 30\n"
                )
            else:
                result.stdout = (
                    "Windows Boot Loader\n"
                    "identifier              {default}\n"
                    "device                  partition=C:\n"
                    "timeout                 30\n"
                )

        # bcdedit /enum {recoverysequence}
        elif "bcdedit" in cmd_str and "{recoverysequence}" in cmd_str:
            if recovery_sequence is not None:
                result.stdout = recovery_sequence
                result.returncode = 0 if recovery_sequence else 1
            elif not expect_clean:
                result.returncode = 1
                result.stderr = "No such entry"
            else:
                result.stdout = (
                    "Windows Recovery Environment\n"
                    "identifier              {recovery}\n"
                )

        # bcdedit /enum {bootmgr}
        elif "bcdedit" in cmd_str and "{bootmgr}" in cmd_str:
            if boot_manager:
                result.stdout = boot_manager
            elif expect_clean:
                result.stdout = (
                    "Windows Boot Manager\n"
                    "identifier              {bootmgr}\n"
                    "timeout                 30\n"
                )
            else:
                result.stdout = (
                    "Windows Boot Manager\n"
                    "identifier              {bootmgr}\n"
                    "timeout                 30\n"
                )

        # bcdedit /enum (all entries)
        elif "bcdedit" in cmd_str and "/enum" in cmd_str:
            if expect_clean:
                result.stdout = (
                    "Windows Boot Manager\n"
                    "identifier              {bootmgr}\n\n"
                    "Windows Boot Loader\n"
                    "identifier              {default}\n"
                )
            else:
                result.stdout = (
                    "Windows Boot Manager\n"
                    "identifier              {bootmgr}\n\n"
                    "Windows Boot Loader\n"
                    "identifier              {default}\n"
                    "description             Windows 10\n"
                    "device                  partition=C:\n"
                )

        # PowerShell Get-WinEvent for boot degradation
        elif "powershell" in cmd_str and "Diagnostics-Performance" in cmd_str:
            if boot_degradation is not None:
                result.stdout = boot_degradation
            elif expect_clean:
                result.stdout = "Count : 0\n"
            else:
                result.stdout = "Count : 0\n"

        return result

    return fake_run


def test_win_startup_repair_discovered():
    mod = _get_module()
    assert mod.name == "win_startup_repair"
    assert mod.category == "integrity"
    assert Platform.WIN32 in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_win_startup_repair_clean_boot():
    """Test when boot configuration is clean."""
    mod = _get_module()
    fake_run = _make_run_result(expect_clean=True)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    # Should have INFO finding about boot status
    assert result.has_issues
    assert any(f.data.get("check") == "boot_status" for f in result.findings)
    assert any(f.severity == Severity.INFO for f in result.findings)


def test_win_startup_repair_recovery_missing():
    """Test detection of missing recovery sequence."""
    mod = _get_module()
    fake_run = _make_run_result(recovery_sequence=None, expect_clean=False)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "recovery_missing" for f in result.findings)
    recovery_finding = [f for f in result.findings if f.data.get("check") == "recovery_missing"]
    assert recovery_finding[0].severity == Severity.WARNING


def test_win_startup_repair_recovery_available():
    """Test when recovery sequence is available."""
    mod = _get_module()
    recovery_output = (
        "Windows Recovery Environment\n"
        "identifier              {recovery}\n"
        "device                  ramdisk=[boot]\\Recovery\\x.sys\n"
    )
    fake_run = _make_run_result(recovery_sequence=recovery_output)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    # Should not have recovery_missing finding
    assert not any(f.data.get("check") == "recovery_missing" for f in result.findings)


def test_win_startup_repair_multiple_boot_entries():
    """Test detection of multiple boot entries."""
    mod = _get_module()

    def custom_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""

        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        if "bcdedit" in cmd_str and "/enum" in cmd_str and "{" not in cmd_str:
            # Return multiple boot entries
            result.stdout = (
                "Windows Boot Manager\n"
                "identifier              {bootmgr}\n\n"
                "Windows Boot Loader\n"
                "identifier              {default}\n"
                "description             Windows 10\n"
                "device                  partition=C:\n\n"
                "Windows Boot Loader\n"
                "identifier              {ubuntu}\n"
                "description             Ubuntu 20.04\n"
                "device                  partition=D:\n"
            )
        elif "bcdedit" in cmd_str and "{current}" in cmd_str:
            result.stdout = (
                "Windows Boot Loader\n"
                "identifier              {default}\n"
                "device                  partition=C:\n"
            )
        elif "bcdedit" in cmd_str and "{recoverysequence}" in cmd_str:
            result.returncode = 0
            result.stdout = "Windows Recovery Environment\n"
        elif "bcdedit" in cmd_str and "{bootmgr}" in cmd_str:
            result.stdout = "Windows Boot Manager\n"
        elif "powershell" in cmd_str:
            result.stdout = "Count : 0\n"
        else:
            result.stdout = ""

        return result

    with patch("subprocess.run", side_effect=custom_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "multiple_boot_entries" for f in result.findings)
    multi_boot = [f for f in result.findings if f.data.get("check") == "multiple_boot_entries"]
    assert multi_boot[0].severity == Severity.INFO


def test_win_startup_repair_boot_degradation():
    """Test detection of boot degradation events."""
    mod = _get_module()
    fake_run = _make_run_result(boot_degradation="Count : 3\n")
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "boot_degradation" for f in result.findings)
    degradation = [f for f in result.findings if f.data.get("check") == "boot_degradation"]
    assert degradation[0].severity == Severity.WARNING
    assert degradation[0].data.get("event_count") == 3


def test_win_startup_repair_unusual_entries():
    """Test detection of unusual boot entries."""
    mod = _get_module()

    def custom_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""

        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        if "bcdedit" in cmd_str and "/enum" in cmd_str and "{" not in cmd_str:
            # Return boot config with unusual entries
            result.stdout = (
                "Windows Boot Manager\n"
                "identifier              {bootmgr}\n\n"
                "Windows Boot Loader\n"
                "identifier              {default}\n"
                "description             Windows 10\n"
                "device                  partition=C:\n"
                "debug                   Yes\n"
                "debugtype               Serial\n"
            )
        elif "bcdedit" in cmd_str and "{current}" in cmd_str:
            result.stdout = (
                "Windows Boot Loader\n"
                "identifier              {default}\n"
                "device                  partition=C:\n"
            )
        elif "bcdedit" in cmd_str and "{recoverysequence}" in cmd_str:
            result.returncode = 0
            result.stdout = "Windows Recovery Environment\n"
        elif "bcdedit" in cmd_str and "{bootmgr}" in cmd_str:
            result.stdout = "Windows Boot Manager\n"
        elif "powershell" in cmd_str:
            result.stdout = "Count : 0\n"
        else:
            result.stdout = ""

        return result

    with patch("subprocess.run", side_effect=custom_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "unusual_entries" for f in result.findings)
    unusual = [f for f in result.findings if f.data.get("check") == "unusual_entries"]
    assert unusual[0].severity == Severity.WARNING


def test_win_startup_repair_boot_config_failed():
    """Test when bcdedit command fails."""
    mod = _get_module()

    def error_run(cmd, **kwargs):
        raise OSError("Command failed")

    with patch("subprocess.run", side_effect=error_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "boot_config_failed" for f in result.findings)
    failed = [f for f in result.findings if f.data.get("check") == "boot_config_failed"]
    assert failed[0].severity == Severity.WARNING


def test_win_startup_repair_fix_recovery_missing():
    """Test fix recommendation for missing recovery."""
    mod = _get_module()
    fake_run = _make_run_result(recovery_sequence=None, expect_clean=False)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    assert any("recovery" in a.title.lower() for a in fix.actions)


def test_win_startup_repair_fix_boot_degradation():
    """Test fix recommendation for boot degradation."""
    mod = _get_module()
    fake_run = _make_run_result(boot_degradation="Count : 5\n")
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    degradation_action = [a for a in fix.actions if "boot" in a.title.lower()]
    assert len(degradation_action) > 0
    assert degradation_action[0].success


def test_win_startup_repair_fix_multiple_entries():
    """Test fix recommendation for multiple boot entries."""
    mod = _get_module()

    def custom_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""

        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        if "bcdedit" in cmd_str and "/enum" in cmd_str and "{" not in cmd_str:
            result.stdout = (
                "Windows Boot Manager\n"
                "identifier              {bootmgr}\n\n"
                "Windows Boot Loader\n"
                "identifier              {default}\n"
                "description             Windows 10\n\n"
                "Windows Boot Loader\n"
                "identifier              {ubuntu}\n"
                "description             Ubuntu\n"
            )
        elif "bcdedit" in cmd_str:
            result.stdout = "Windows Boot Manager\nidentifier {bootmgr}\n"
        elif "powershell" in cmd_str:
            result.stdout = "Count : 0\n"
        else:
            result.stdout = ""

        return result

    with patch("subprocess.run", side_effect=custom_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    multi_action = [a for a in fix.actions if "multiple" in a.title.lower()]
    assert len(multi_action) > 0


def test_win_startup_repair_multiple_issues():
    """Test when multiple issues are detected."""
    mod = _get_module()

    def custom_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""

        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        if "bcdedit" in cmd_str and "{recoverysequence}" in cmd_str:
            result.returncode = 1
            result.stderr = "No such entry"
        elif "bcdedit" in cmd_str and "/enum" in cmd_str and "{" not in cmd_str:
            result.stdout = (
                "Windows Boot Manager\n"
                "identifier              {bootmgr}\n\n"
                "Windows Boot Loader\n"
                "identifier              {default}\n"
                "debug                   Yes\n\n"
                "Windows Boot Loader\n"
                "identifier              {backup}\n"
            )
        elif "bcdedit" in cmd_str:
            result.stdout = "Windows Boot Manager\nidentifier {bootmgr}\n"
        elif "powershell" in cmd_str and "Diagnostics-Performance" in cmd_str:
            result.stdout = "Count : 2\n"
        else:
            result.stdout = ""

        return result

    with patch("subprocess.run", side_effect=custom_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    checks = [f.data.get("check") for f in result.findings]
    # Should have multiple issues
    assert len(checks) > 1
    # Should not be just the boot_status info
    assert any(check != "boot_status" for check in checks)
