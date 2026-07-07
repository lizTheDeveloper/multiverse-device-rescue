import json
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
    return next(m for m in modules if m.name == "win_rootkit_check")


def _make_run_result(
    drivers=None,
    ads_files=None,
    secure_boot=None,
    ps_services=None,
    sc_services_output=None,
    bcdedit_output=None,
    expect_clean=False,
):
    """Create a fake subprocess.run that returns appropriate results.

    Args:
        expect_clean: If True, mock returns clean/empty results for all commands by default.
    """

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        # driverquery command for unsigned drivers
        if "driverquery" in cmd_str:
            if drivers:
                result.stdout = json.dumps(drivers)
            else:
                result.stdout = "[]"

        # PowerShell commands
        elif "powershell" in cmd_str:
            # Get-Service check
            if "Get-Service" in cmd_str and "Select-Object -ExpandProperty Name" in cmd_str:
                if ps_services is not None:
                    result.stdout = json.dumps(ps_services)
                else:
                    result.stdout = "[]"
            # Get-Item for Alternate Data Streams
            elif "Get-Item" in cmd_str and "Stream" in cmd_str:
                if ads_files is not None:
                    result.stdout = json.dumps(ads_files)
                else:
                    result.stdout = "[]"
            # Secure Boot check
            elif "Confirm-SecureBootUEFI" in cmd_str:
                if secure_boot == "enabled":
                    result.stdout = "True\n"
                elif secure_boot == "disabled":
                    result.stdout = "False\n"
                else:
                    result.returncode = 1
                    result.stderr = "Not a UEFI system"

        # sc query for services
        elif cmd[0] == "sc" and "query" in cmd_str:
            if sc_services_output is not None:
                result.stdout = sc_services_output
            else:
                # Default to empty if expect_clean, otherwise return a test service
                if expect_clean:
                    result.stdout = ""
                else:
                    result.stdout = "SERVICE_NAME: TestService\nSTATUS        : 4  RUNNING\n"

        # bcdedit command
        elif "bcdedit" in cmd_str:
            if bcdedit_output is not None:
                result.stdout = bcdedit_output
            else:
                # Default clean output
                result.stdout = "Windows Boot Manager\n  identifier              {bootmgr}\n"

        return result

    return fake_run


def test_win_rootkit_check_discovered():
    mod = _get_module()
    assert mod.name == "win_rootkit_check"
    assert mod.category == "security"
    assert Platform.WIN32 in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_win_rootkit_check_all_pass():
    """Test when all rootkit checks pass (no issues found)."""
    mod = _get_module()
    fake_run = _make_run_result(expect_clean=True)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues  # Should have INFO finding
    assert any(f.data.get("check") == "all_passed" for f in result.findings)
    assert any(f.severity == Severity.INFO for f in result.findings)


def test_win_rootkit_check_unsigned_drivers():
    """Test detection of unsigned drivers."""
    mod = _get_module()
    unsigned = ["driver1.sys", "driver2.sys"]
    fake_run = _make_run_result(drivers=unsigned)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "unsigned_drivers" for f in result.findings)
    critical = [f for f in result.findings if f.data.get("check") == "unsigned_drivers"]
    assert critical[0].severity == Severity.CRITICAL


def test_win_rootkit_check_alternate_data_streams():
    """Test detection of Alternate Data Streams."""
    mod = _get_module()
    ads = ["cmd.exe", "notepad.exe"]
    fake_run = _make_run_result(ads_files=ads)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "alternate_data_streams" for f in result.findings)
    ads_finding = [f for f in result.findings if f.data.get("check") == "alternate_data_streams"]
    assert ads_finding[0].severity == Severity.WARNING


def test_win_rootkit_check_secure_boot_disabled():
    """Test detection of disabled Secure Boot."""
    mod = _get_module()
    fake_run = _make_run_result(secure_boot="disabled")
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "secure_boot_disabled" for f in result.findings)
    critical = [f for f in result.findings if f.data.get("check") == "secure_boot_disabled"]
    assert critical[0].severity == Severity.CRITICAL


def test_win_rootkit_check_secure_boot_enabled():
    """Test when Secure Boot is enabled."""
    mod = _get_module()
    fake_run = _make_run_result(secure_boot="enabled", expect_clean=True)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    # Should only have INFO for all_passed
    assert any(f.data.get("check") == "all_passed" for f in result.findings)


def test_win_rootkit_check_hidden_services():
    """Test detection of hidden services."""
    mod = _get_module()
    ps_services = ["Service1", "Service2"]
    sc_output = "SERVICE_NAME: Service1\nSTATUS: 4 RUNNING\n\nSERVICE_NAME: HiddenService\nSTATUS: 4 RUNNING\n"
    fake_run = _make_run_result(ps_services=ps_services, sc_services_output=sc_output)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "hidden_services" for f in result.findings)
    hidden = [f for f in result.findings if f.data.get("check") == "hidden_services"]
    assert hidden[0].severity == Severity.WARNING


def test_win_rootkit_check_boot_tampering():
    """Test detection of boot configuration tampering."""
    mod = _get_module()
    bcdedit_output = (
        "Windows Boot Manager\n"
        "identifier              {bootmgr}\n"
        "debug                   Yes\n"
        "debugtype               Serial\n"
        "nointegritychecks       Yes\n"
    )
    fake_run = _make_run_result(bcdedit_output=bcdedit_output)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "boot_tampering" for f in result.findings)
    boot = [f for f in result.findings if f.data.get("check") == "boot_tampering"]
    assert boot[0].severity == Severity.WARNING


def test_win_rootkit_check_multiple_issues():
    """Test when multiple issues are detected."""
    mod = _get_module()
    unsigned = ["bad_driver.sys"]
    ads = ["suspicious.exe"]
    ps_services = ["LegitService"]
    sc_output = "SERVICE_NAME: LegitService\n\nSERVICE_NAME: HiddenEvil\n"
    fake_run = _make_run_result(
        drivers=unsigned,
        ads_files=ads,
        secure_boot="disabled",
        ps_services=ps_services,
        sc_services_output=sc_output,
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have findings for: unsigned drivers, ADS, secure boot, hidden services
    checks = [f.data.get("check") for f in result.findings]
    assert "unsigned_drivers" in checks
    assert "alternate_data_streams" in checks
    assert "secure_boot_disabled" in checks
    assert "hidden_services" in checks


def test_win_rootkit_check_fix_unsigned_drivers():
    """Test fix recommendation for unsigned drivers."""
    mod = _get_module()
    unsigned = ["bad.sys"]
    fake_run = _make_run_result(drivers=unsigned)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # Check that we got action(s) for the findings
    assert len(fix.actions) > 0
    assert any("unsigned" in a.title.lower() for a in fix.actions)


def test_win_rootkit_check_fix_secure_boot():
    """Test fix recommendation for disabled Secure Boot."""
    mod = _get_module()
    fake_run = _make_run_result(secure_boot="disabled")
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    secure_boot_action = [a for a in fix.actions if "secure" in a.title.lower()]
    assert len(secure_boot_action) > 0
    # Fix actions should not actually succeed (they're informational)
    assert not secure_boot_action[0].success


def test_win_rootkit_check_handles_subprocess_error():
    """Test graceful handling of subprocess errors."""
    mod = _get_module()

    def error_run(cmd, **kwargs):
        raise OSError("Command failed")

    with patch("subprocess.run", side_effect=error_run):
        result = mod.check(_make_profile())
    # Should still complete without crashing
    assert isinstance(result.findings, list)
