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
    return next(m for m in modules if m.name == "win_boot_config_check")


def _make_run_result(
    bcdedit_enum_output=None,
    bcdedit_current_output=None,
    bcdedit_bootmgr_output=None,
    secure_boot_enabled=True,
    reagentc_output=None,
    registry_fast_startup=False,
    clean_boot_time=None,
    expect_clean=False,
):
    """Create a fake subprocess.run that returns appropriate results."""

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        # bcdedit /enum
        if "bcdedit" in cmd_str and "/enum" in cmd_str:
            if "{current}" in cmd_str:
                # bcdedit /enum {current}
                if bcdedit_current_output is not None:
                    result.stdout = bcdedit_current_output
                else:
                    result.stdout = (
                        "Windows Boot Loader\n"
                        "identifier              {default}\n"
                        "path                    \\Windows\\system32\\winload.efi\n"
                    )
            elif "{bootmgr}" in cmd_str:
                # bcdedit /enum {bootmgr}
                if bcdedit_bootmgr_output is not None:
                    result.stdout = bcdedit_bootmgr_output
                else:
                    result.stdout = (
                        "Windows Boot Manager\n"
                        "identifier              {bootmgr}\n"
                        "timeout                 30\n"
                    )
            else:
                # bcdedit /enum (all entries)
                if bcdedit_enum_output is not None:
                    result.stdout = bcdedit_enum_output
                else:
                    result.stdout = (
                        "Windows Boot Manager\n"
                        "identifier              {bootmgr}\n"
                        "description             Windows Boot Manager\n"
                        "\n"
                        "Windows Boot Loader\n"
                        "identifier              {default}\n"
                        "description             Windows 11\n"
                    )

        # Secure Boot
        elif "powershell" in cmd_str and "Confirm-SecureBootUEFI" in cmd_str:
            if secure_boot_enabled:
                result.stdout = "True\n"
            else:
                result.returncode = 1
                result.stderr = "Not UEFI system\n"

        # reagentc /info
        elif "reagentc" in cmd_str and "/info" in cmd_str:
            if reagentc_output is not None:
                result.stdout = reagentc_output
                result.returncode = 0 if "Enabled" in reagentc_output else 1
            else:
                if expect_clean:
                    result.stdout = (
                        "REAGENT.XML Information\n"
                        "Windows RE Status         Enabled\n"
                    )
                    result.returncode = 0
                else:
                    result.returncode = 1

        # Fast Startup (reg query)
        elif "reg" in cmd_str and "query" in cmd_str:
            if registry_fast_startup:
                result.stdout = (
                    "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power\n"
                    "    HiberbootEnabled    REG_DWORD    0x1\n"
                )
            else:
                result.stdout = (
                    "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power\n"
                    "    HiberbootEnabled    REG_DWORD    0x0\n"
                )

        # Clean boot time (PowerShell Get-WinEvent)
        elif "powershell" in cmd_str and "Get-WinEvent" in cmd_str:
            if clean_boot_time:
                result.stdout = clean_boot_time + "\n"
            else:
                result.stdout = "2026-07-08 14:30:45\n"

        return result

    return fake_run


def test_win_boot_config_check_discovered():
    mod = _get_module()
    assert mod.name == "win_boot_config_check"
    assert mod.category == "integrity"
    assert Platform.WIN32 in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_win_boot_config_check_all_pass():
    """Test when all boot config checks pass."""
    mod = _get_module()
    fake_run = _make_run_result(expect_clean=True)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    # Should have findings for boot type, secure boot, timeout, etc.
    assert result.has_issues
    checks = [f.data.get("check") for f in result.findings]
    assert "boot_type_info" in checks
    assert "secure_boot_enabled" in checks
    assert "boot_timeout_info" in checks


def test_win_boot_config_check_secure_boot_disabled():
    """Test detection of disabled Secure Boot."""
    mod = _get_module()
    fake_run = _make_run_result(secure_boot_enabled=False)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "secure_boot_disabled" for f in result.findings)
    critical = [f for f in result.findings if f.data.get("check") == "secure_boot_disabled"]
    assert critical[0].severity == Severity.WARNING


def test_win_boot_config_check_secure_boot_enabled():
    """Test when Secure Boot is enabled."""
    mod = _get_module()
    fake_run = _make_run_result(secure_boot_enabled=True)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    # Should have INFO finding for secure boot enabled
    assert any(f.data.get("check") == "secure_boot_enabled" for f in result.findings)
    info = [f for f in result.findings if f.data.get("check") == "secure_boot_enabled"]
    assert info[0].severity == Severity.INFO


def test_win_boot_config_check_boot_type_uefi():
    """Test detection of UEFI boot type."""
    mod = _get_module()
    uefi_output = (
        "Windows Boot Loader\n"
        "identifier              {default}\n"
        "path                    \\Windows\\system32\\winload.efi\n"
    )
    fake_run = _make_run_result(bcdedit_current_output=uefi_output)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert any(f.data.get("check") == "boot_type_info" for f in result.findings)
    boot_type = [f for f in result.findings if f.data.get("check") == "boot_type_info"]
    assert boot_type[0].data["boot_type"] == "UEFI"


def test_win_boot_config_check_boot_type_legacy():
    """Test detection of Legacy BIOS boot type."""
    mod = _get_module()
    legacy_output = (
        "Windows Boot Loader\n"
        "identifier              {default}\n"
        "path                    \\Windows\\system32\\winload.exe\n"
    )
    fake_run = _make_run_result(bcdedit_current_output=legacy_output)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert any(f.data.get("check") == "boot_type_info" for f in result.findings)
    boot_type = [f for f in result.findings if f.data.get("check") == "boot_type_info"]
    assert boot_type[0].data["boot_type"] == "Legacy BIOS"


def test_win_boot_config_check_boot_timeout_zero():
    """Test detection of boot timeout set to 0."""
    mod = _get_module()
    bootmgr_output = (
        "Windows Boot Manager\n"
        "identifier              {bootmgr}\n"
        "timeout                 0\n"
    )
    fake_run = _make_run_result(bcdedit_bootmgr_output=bootmgr_output)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert any(f.data.get("check") == "boot_timeout_zero" for f in result.findings)
    timeout_zero = [f for f in result.findings if f.data.get("check") == "boot_timeout_zero"]
    assert timeout_zero[0].severity == Severity.WARNING


def test_win_boot_config_check_boot_timeout_normal():
    """Test normal boot timeout."""
    mod = _get_module()
    bootmgr_output = (
        "Windows Boot Manager\n"
        "identifier              {bootmgr}\n"
        "timeout                 30\n"
    )
    fake_run = _make_run_result(bcdedit_bootmgr_output=bootmgr_output)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert any(f.data.get("check") == "boot_timeout_info" for f in result.findings)
    info = [f for f in result.findings if f.data.get("check") == "boot_timeout_info"]
    assert info[0].data["timeout"] == 30


def test_win_boot_config_check_multiple_boot_entries():
    """Test detection of multiple boot entries."""
    mod = _get_module()
    multi_boot_output = (
        "Windows Boot Manager\n"
        "identifier              {bootmgr}\n"
        "description             Windows Boot Manager\n"
        "\n"
        "Windows Boot Loader\n"
        "identifier              {default}\n"
        "description             Windows 11\n"
        "\n"
        "Windows Boot Loader\n"
        "identifier              {other}\n"
        "description             Windows 10\n"
    )
    fake_run = _make_run_result(bcdedit_enum_output=multi_boot_output)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert any(f.data.get("check") == "multiple_boot_entries" for f in result.findings)
    multi = [f for f in result.findings if f.data.get("check") == "multiple_boot_entries"]
    assert multi[0].data["entry_count"] >= 2


def test_win_boot_config_check_windows_re_enabled():
    """Test when Windows RE is enabled."""
    mod = _get_module()
    reagentc_output = (
        "REAGENT.XML Information\n"
        "Windows RE Status         Enabled\n"
        "Windows RE Location       \\Device\\HarddiskVolume1\\Recovery\n"
    )
    fake_run = _make_run_result(reagentc_output=reagentc_output)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert any(f.data.get("check") == "windows_re_enabled" for f in result.findings)
    re_enabled = [f for f in result.findings if f.data.get("check") == "windows_re_enabled"]
    assert re_enabled[0].severity == Severity.INFO


def test_win_boot_config_check_windows_re_disabled():
    """Test when Windows RE is disabled."""
    mod = _get_module()
    reagentc_output = (
        "REAGENT.XML Information\n"
        "Windows RE Status         Disabled\n"
    )
    fake_run = _make_run_result(reagentc_output=reagentc_output)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert any(f.data.get("check") == "windows_re_disabled" for f in result.findings)
    re_disabled = [f for f in result.findings if f.data.get("check") == "windows_re_disabled"]
    assert re_disabled[0].severity == Severity.WARNING


def test_win_boot_config_check_fast_startup_enabled():
    """Test when Fast Startup is enabled."""
    mod = _get_module()
    fake_run = _make_run_result(registry_fast_startup=True)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert any(f.data.get("check") == "fast_startup_enabled" for f in result.findings)
    fast = [f for f in result.findings if f.data.get("check") == "fast_startup_enabled"]
    assert fast[0].severity == Severity.WARNING


def test_win_boot_config_check_fast_startup_disabled():
    """Test when Fast Startup is disabled."""
    mod = _get_module()
    fake_run = _make_run_result(registry_fast_startup=False)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert any(f.data.get("check") == "fast_startup_disabled" for f in result.findings)
    fast = [f for f in result.findings if f.data.get("check") == "fast_startup_disabled"]
    assert fast[0].severity == Severity.INFO


def test_win_boot_config_check_clean_boot():
    """Test clean boot detection."""
    mod = _get_module()
    fake_run = _make_run_result(clean_boot_time="2026-07-08 14:30:45")
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert any(f.data.get("check") == "clean_boot_info" for f in result.findings)
    clean = [f for f in result.findings if f.data.get("check") == "clean_boot_info"]
    assert "14:30:45" in clean[0].data["time"]


def test_win_boot_config_check_bcdedit_failed():
    """Test graceful handling when bcdedit fails."""
    mod = _get_module()

    def error_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 1
        result.stderr = "Access denied"
        result.stdout = ""
        return result

    with patch("subprocess.run", side_effect=error_run):
        result = mod.check(_make_profile())
    assert any(f.data.get("check") == "bcdedit_failed" for f in result.findings)
    failed = [f for f in result.findings if f.data.get("check") == "bcdedit_failed"]
    assert failed[0].severity == Severity.WARNING


def test_win_boot_config_check_multiple_issues():
    """Test when multiple issues are detected."""
    mod = _get_module()
    bootmgr_output = (
        "Windows Boot Manager\n"
        "identifier              {bootmgr}\n"
        "timeout                 0\n"
    )
    fake_run = _make_run_result(
        secure_boot_enabled=False,
        bcdedit_bootmgr_output=bootmgr_output,
        registry_fast_startup=True,
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    checks = [f.data.get("check") for f in result.findings]
    assert "secure_boot_disabled" in checks
    assert "boot_timeout_zero" in checks
    assert "fast_startup_enabled" in checks


def test_win_boot_config_check_fix_secure_boot_disabled():
    """Test fix recommendation for disabled Secure Boot."""
    mod = _get_module()
    fake_run = _make_run_result(secure_boot_enabled=False)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    secure_boot_action = [a for a in fix.actions if "secure" in a.title.lower()]
    assert len(secure_boot_action) > 0


def test_win_boot_config_check_fix_boot_timeout_zero():
    """Test fix recommendation for boot timeout zero."""
    mod = _get_module()
    bootmgr_output = (
        "Windows Boot Manager\n"
        "identifier              {bootmgr}\n"
        "timeout                 0\n"
    )
    fake_run = _make_run_result(bcdedit_bootmgr_output=bootmgr_output)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    timeout_action = [a for a in fix.actions if "timeout" in a.title.lower()]
    assert len(timeout_action) > 0


def test_win_boot_config_check_fix_windows_re_disabled():
    """Test fix recommendation for disabled Windows RE."""
    mod = _get_module()
    reagentc_output = (
        "REAGENT.XML Information\n"
        "Windows RE Status         Disabled\n"
    )
    fake_run = _make_run_result(reagentc_output=reagentc_output)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    re_action = [a for a in fix.actions if "recovery" in a.title.lower()]
    assert len(re_action) > 0


def test_win_boot_config_check_fix_fast_startup_enabled():
    """Test fix recommendation for enabled Fast Startup."""
    mod = _get_module()
    fake_run = _make_run_result(registry_fast_startup=True)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    fast_action = [a for a in fix.actions if "fast startup" in a.title.lower()]
    assert len(fast_action) > 0


def test_win_boot_config_check_handles_subprocess_error():
    """Test graceful handling of subprocess errors."""
    mod = _get_module()

    def error_run(cmd, **kwargs):
        raise OSError("Command failed")

    with patch("subprocess.run", side_effect=error_run):
        result = mod.check(_make_profile())
    # Should still complete without crashing
    assert isinstance(result.findings, list)
