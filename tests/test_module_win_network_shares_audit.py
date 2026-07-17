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
    return next(m for m in modules if m.name == "win_network_shares_audit")


def _make_run_result(
    smb1_enabled=False,
    net_share_output=None,
    shares_data=None,
    share_access_data=None,
):
    """Create a fake subprocess.run that returns appropriate results.

    Args:
        smb1_enabled: If True, SMBv1 is enabled
        net_share_output: Output from 'net share' command
        shares_data: Dict of share_name -> {path, ...} for PowerShell Get-SmbShare
        share_access_data: Dict of share_name -> [{account, access_right, ...}]
    """

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        # SMBv1 check
        if "Get-SmbServerConfiguration" in cmd_str and "EnableSMB1Protocol" in cmd_str:
            result.stdout = "True" if smb1_enabled else "False"

        # net share command
        elif cmd[0:1] == ["net"] and "share" in cmd_str:
            if net_share_output is not None:
                result.stdout = net_share_output
            else:
                # Default output with some shares
                result.stdout = (
                    "\nShare name   C$\n"
                    "Path         C:\\\n"
                    "Remark       Default share\n"
                    "\nShare name   ADMIN$\n"
                    "Path         C:\\Windows\n"
                    "Remark       Remote Admin\n"
                    "\nShare name   Public\n"
                    "Path         C:\\Users\\Public\\Documents\n"
                    "Remark       Public share\n"
                    "\nThe command completed successfully.\n"
                )

        # PowerShell Get-SmbShareAccess (must be checked BEFORE Get-SmbShare)
        elif "Get-SmbShareAccess" in cmd_str and "ConvertTo-Json" in cmd_str:
            # Extract share name from command string
            import re as regex
            match = regex.search(r"-Name\s+['\"]([^'\"]+)['\"]", cmd_str)
            if match:
                share_name = match.group(1)
                if share_access_data and share_name in share_access_data:
                    access = share_access_data[share_name]
                    # Return as JSON array
                    if isinstance(access, list):
                        result.stdout = json.dumps(access)
                    else:
                        result.stdout = json.dumps([access])
                else:
                    # Default: admin access only
                    result.stdout = json.dumps(
                        [
                            {
                                "Name": share_name,
                                "AccountName": "BUILTIN\\Administrators",
                                "AccessControlType": "Allow",
                                "AccessRight": "FULL",
                            }
                        ]
                    )
            else:
                result.stdout = "[]"

        # PowerShell Get-SmbShare (checked AFTER Get-SmbShareAccess)
        elif "Get-SmbShare" in cmd_str and "ConvertTo-Json" in cmd_str:
            # Extract share name from command string
            # The command is passed as: powershell -Command "Get-SmbShare -Name 'ShareName' | ..."
            import re as regex
            match = regex.search(r"-Name\s+['\"]([^'\"]+)['\"]", cmd_str)
            if match:
                share_name = match.group(1)
                if shares_data and share_name in shares_data:
                    result.stdout = json.dumps(shares_data[share_name])
                else:
                    # Default response for a share
                    result.stdout = json.dumps(
                        {
                            "Name": share_name,
                            "Path": f"C:\\{share_name}",
                            "Description": "Test share",
                        }
                    )
            else:
                result.stdout = "[]"

        return result

    return fake_run


def test_win_network_shares_audit_discovered():
    mod = _get_module()
    assert mod.name == "win_network_shares_audit"
    assert mod.category == "security"
    assert Platform.WIN32 in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_win_network_shares_audit_smb1_enabled():
    """Test detection of enabled SMBv1."""
    mod = _get_module()
    fake_run = _make_run_result(smb1_enabled=True)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert len(critical_findings) > 0
    assert any(f.data.get("check") == "smb1_enabled" for f in critical_findings)


def test_win_network_shares_audit_smb1_disabled():
    """Test when SMBv1 is disabled."""
    mod = _get_module()
    fake_run = _make_run_result(smb1_enabled=False)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    # Should have INFO finding for shares enumerated
    assert result.has_issues
    assert any(f.data.get("check") == "shares_enumerated" for f in result.findings)


def test_win_network_shares_audit_everyone_write_access():
    """Test detection of Everyone with write access."""
    mod = _get_module()
    net_output = (
        "\nShare name   C$\n"
        "Path         C:\\\n"
        "\nShare name   TestShare\n"
        "Path         C:\\TestShare\n"
        "\nThe command completed successfully.\n"
    )
    shares = {
        "C$": {"Name": "C$", "Path": "C:\\", "Description": ""},
        "TestShare": {
            "Name": "TestShare",
            "Path": "C:\\TestShare",
            "Description": "Test share",
        },
    }
    access = {
        "C$": [
            {
                "Name": "C$",
                "AccountName": "BUILTIN\\Administrators",
                "AccessControlType": "Allow",
                "AccessRight": "FULL",
            }
        ],
        "TestShare": [
            {
                "Name": "TestShare",
                "AccountName": "Everyone",
                "AccessControlType": "Allow",
                "AccessRight": "CHANGE",
            }
        ],
    }
    fake_run = _make_run_result(
        smb1_enabled=False,
        net_share_output=net_output,
        shares_data=shares,
        share_access_data=access,
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) > 0
    assert any(
        f.data.get("check") == "everyone_write_access" for f in warning_findings
    )


def test_win_network_shares_audit_sensitive_directory():
    """Test detection of shares pointing to sensitive directories."""
    mod = _get_module()
    net_output = (
        "\nShare name   C$\n"
        "Path         C:\\\n"
        "\nShare name   UserDocs\n"
        "Path         C:\\Users\\TestUser\\Documents\n"
        "\nThe command completed successfully.\n"
    )
    shares = {
        "C$": {"Name": "C$", "Path": "C:\\", "Description": ""},
        "UserDocs": {
            "Name": "UserDocs",
            "Path": "C:\\Users\\TestUser\\Documents",
            "Description": "User documents",
        },
    }
    access = {
        "C$": [
            {
                "Name": "C$",
                "AccountName": "BUILTIN\\Administrators",
                "AccessControlType": "Allow",
                "AccessRight": "FULL",
            }
        ],
        "UserDocs": [
            {
                "Name": "UserDocs",
                "AccountName": "BUILTIN\\Users",
                "AccessControlType": "Allow",
                "AccessRight": "READ",
            }
        ],
    }
    fake_run = _make_run_result(
        smb1_enabled=False,
        net_share_output=net_output,
        shares_data=shares,
        share_access_data=access,
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert any(
        f.data.get("check") == "sensitive_directory" for f in warning_findings
    )


def test_win_network_shares_audit_shares_enumerated():
    """Test basic shares enumeration."""
    mod = _get_module()
    fake_run = _make_run_result(smb1_enabled=False)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert any(f.data.get("check") == "shares_enumerated" for f in info_findings)


def test_win_network_shares_audit_multiple_issues():
    """Test when multiple issues are detected."""
    mod = _get_module()
    net_output = (
        "\nShare name   C$\n"
        "Path         C:\\\n"
        "\nShare name   PublicShare\n"
        "Path         C:\\Users\\Public\\Share\n"
        "\nShare name   DataShare\n"
        "Path         D:\\Data\n"
        "\nThe command completed successfully.\n"
    )
    shares = {
        "C$": {"Name": "C$", "Path": "C:\\", "Description": ""},
        "PublicShare": {
            "Name": "PublicShare",
            "Path": "C:\\Users\\Public\\Share",
            "Description": "Public",
        },
        "DataShare": {"Name": "DataShare", "Path": "D:\\Data", "Description": "Data"},
    }
    access = {
        "C$": [
            {
                "Name": "C$",
                "AccountName": "BUILTIN\\Administrators",
                "AccessControlType": "Allow",
                "AccessRight": "FULL",
            }
        ],
        "PublicShare": [
            {
                "Name": "PublicShare",
                "AccountName": "Everyone",
                "AccessControlType": "Allow",
                "AccessRight": "FULL",
            }
        ],
        "DataShare": [
            {
                "Name": "DataShare",
                "AccountName": "BUILTIN\\Users",
                "AccessControlType": "Allow",
                "AccessRight": "READ",
            }
        ],
    }
    fake_run = _make_run_result(
        smb1_enabled=True,
        net_share_output=net_output,
        shares_data=shares,
        share_access_data=access,
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have CRITICAL for SMBv1 and WARNING for Everyone access
    critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(critical_findings) > 0
    assert len(warning_findings) > 0


def test_win_network_shares_audit_fix_smb1():
    """Test fix recommendation for SMBv1."""
    mod = _get_module()
    fake_run = _make_run_result(smb1_enabled=True)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    smb1_actions = [a for a in fix.actions if "SMBv1" in a.title]
    assert len(smb1_actions) > 0
    # Fix actions should not actually succeed (they're informational)
    assert not smb1_actions[0].success


def test_win_network_shares_audit_fix_everyone_write():
    """Test fix recommendation for Everyone write access."""
    mod = _get_module()
    net_output = (
        "\nShare name   C$\n"
        "Path         C:\\\n"
        "\nShare name   OpenShare\n"
        "Path         C:\\OpenShare\n"
        "\nThe command completed successfully.\n"
    )
    shares = {
        "C$": {"Name": "C$", "Path": "C:\\", "Description": ""},
        "OpenShare": {
            "Name": "OpenShare",
            "Path": "C:\\OpenShare",
            "Description": "Open",
        },
    }
    access = {
        "C$": [
            {
                "Name": "C$",
                "AccountName": "BUILTIN\\Administrators",
                "AccessControlType": "Allow",
                "AccessRight": "FULL",
            }
        ],
        "OpenShare": [
            {
                "Name": "OpenShare",
                "AccountName": "Everyone",
                "AccessControlType": "Allow",
                "AccessRight": "FULL",
            }
        ],
    }
    fake_run = _make_run_result(
        smb1_enabled=False,
        net_share_output=net_output,
        shares_data=shares,
        share_access_data=access,
    )
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    # Should have action for restricting OpenShare
    share_actions = [a for a in fix.actions if "OpenShare" in a.title]
    assert len(share_actions) > 0


def test_win_network_shares_audit_handles_subprocess_error():
    """Test graceful handling of subprocess errors."""
    mod = _get_module()

    def error_run(cmd, **kwargs):
        raise OSError("Command failed")

    with patch("subprocess.run", side_effect=error_run):
        result = mod.check(_make_profile())
    # Should still complete without crashing
    assert isinstance(result.findings, list)


def test_win_network_shares_audit_empty_shares_list():
    """Test handling when no shares are found."""
    mod = _get_module()
    net_output = "The command completed successfully.\n"
    fake_run = _make_run_result(smb1_enabled=False, net_share_output=net_output)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    # Should handle gracefully and report no shares
    assert result.has_issues
    assert any(f.data.get("check") == "shares_list" for f in result.findings)
