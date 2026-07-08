import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


# Sample gpresult output with GPOs applied
GPRESULT_COMPUTER_OUTPUT = r"""
Applied Group Policy Objects
========================================

DC=contoso,DC=com\Microsoft\Windows\System
Domain Admins Policy
Default Domain Policy

The following GPOs were not applied because they were filtered out:
N/A
"""

GPRESULT_COMPUTER_NO_GPOS = """
Applied Group Policy Objects
========================================

Local Group Policy

The following GPOs were not applied because they were filtered out:
N/A
"""

GPRESULT_USER_OUTPUT = """
Applied Group Policy Objects
========================================

Default User Group Policy
Desktop Management Policy

The following GPOs were not applied because they were filtered out:
N/A
"""

# Sample net accounts output with weak password policy
NET_ACCOUNTS_WEAK = """
Force user logoff how long after time expires?:       Never
Minimum password age (days):                          0
Maximum password age (days):                          90
Minimum password length:                              6
Length of password history maintained:                24
Lockout threshold:                                    5
Lockout duration (minutes):                           30
Lockout observation window (minutes):                 30
Computer role:                                        SERVER
The command completed successfully.
"""

NET_ACCOUNTS_STRONG = """
Force user logoff how long after time expires?:       Never
Minimum password age (days):                          0
Maximum password age (days):                          90
Minimum password length:                              14
Length of password history maintained:                24
Lockout threshold:                                    5
Lockout duration (minutes):                           30
Lockout observation window (minutes):                 30
Computer role:                                        SERVER
The command completed successfully.
"""

AUDITPOL_OUTPUT = """
System audit policy

Category/Subcategory                      Audit Type      Setting
  System
    Security State Change               Success and Failure
    Security System Extension           Success and Failure
    Integrity Verification              No Auditing
"""


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
    return next(m for m in modules if m.name == "win_group_policy_audit")


def _fake_subprocess_run(
    is_domain_joined=True,
    has_gpos=False,
    has_restrictive_policy=False,
    password_min_length=14,
    has_applocker=False,
):
    """Create a mock subprocess.run that returns appropriate responses."""

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""

        if isinstance(cmd, list):
            cmd_str = " ".join(str(c) for c in cmd)

            # Handle gpresult calls
            if "gpresult" in cmd_str:
                if "/scope:computer" in cmd_str:
                    result.stdout = (
                        GPRESULT_COMPUTER_OUTPUT if has_gpos else GPRESULT_COMPUTER_NO_GPOS
                    )
                elif "/scope:user" in cmd_str:
                    result.stdout = GPRESULT_USER_OUTPUT if has_gpos else ""
                else:
                    result.stdout = ""

            # Handle WMI domain check
            elif "Get-WmiObject" in cmd_str and "PartOfDomain" in cmd_str:
                result.stdout = "true" if is_domain_joined else "false"

            # Handle registry policy checks
            elif "Get-ItemProperty" in cmd_str:
                if has_restrictive_policy:
                    result.stdout = "1"
                else:
                    result.stdout = ""

            # Handle net accounts
            elif "net" in cmd_str and "accounts" in cmd_str:
                if password_min_length < 8:
                    result.stdout = NET_ACCOUNTS_WEAK
                else:
                    result.stdout = NET_ACCOUNTS_STRONG

            # Handle auditpol
            elif "auditpol" in cmd_str:
                result.stdout = AUDITPOL_OUTPUT

            # Handle AppLocker check
            elif "Get-AppLockerPolicy" in cmd_str:
                result.stdout = "5" if has_applocker else "0"

            else:
                result.stdout = ""

        return result

    return fake_run


def test_win_group_policy_audit_discovered():
    """Test that the module is discovered and has correct metadata."""
    mod = _get_module()
    assert mod.name == "win_group_policy_audit"
    assert mod.category == "security"
    assert Platform.WIN32 in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_win_group_policy_audit_domain_joined_no_gpos():
    """Test a domain-joined machine with no extra GPOs (clean state)."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_subprocess_run(is_domain_joined=True)):
        result = mod.check(_make_profile())
    # Should have info finding about GPO status
    assert result.has_issues
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert any("Group Policy status report" in f.title for f in info_findings)


def test_win_group_policy_audit_stale_gpos_warning():
    """Test that stale domain GPOs on non-domain machine trigger WARNING."""
    mod = _get_module()
    with patch(
        "subprocess.run",
        side_effect=_fake_subprocess_run(
            is_domain_joined=False, has_gpos=True
        ),
    ):
        result = mod.check(_make_profile())
    assert result.has_issues
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert any("Stale domain Group Policies" in f.title for f in warning_findings)


def test_win_group_policy_audit_weak_password_policy():
    """Test that weak password minimum length triggers WARNING."""
    mod = _get_module()
    with patch(
        "subprocess.run",
        side_effect=_fake_subprocess_run(
            is_domain_joined=True, password_min_length=6
        ),
    ):
        result = mod.check(_make_profile())
    assert result.has_issues
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert any("minimum length" in f.title.lower() for f in warning_findings)


def test_win_group_policy_audit_restrictive_policy():
    """Test that restrictive policies trigger WARNING."""
    mod = _get_module()
    with patch(
        "subprocess.run",
        side_effect=_fake_subprocess_run(
            is_domain_joined=True, has_restrictive_policy=True
        ),
    ):
        result = mod.check(_make_profile())
    assert result.has_issues
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert any("disabled by policy" in f.title.lower() for f in warning_findings)


def test_win_group_policy_audit_applocker_info():
    """Test that AppLocker policies are reported as INFO."""
    mod = _get_module()
    with patch(
        "subprocess.run",
        side_effect=_fake_subprocess_run(is_domain_joined=True, has_applocker=True),
    ):
        result = mod.check(_make_profile())
    # Should have info finding about AppLocker
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert any("AppLocker" in f.title for f in info_findings)


def test_win_group_policy_audit_fix_stale_gpos():
    """Test that fix action is generated for stale GPOs."""
    mod = _get_module()
    with patch(
        "subprocess.run",
        side_effect=_fake_subprocess_run(
            is_domain_joined=False, has_gpos=True
        ),
    ):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # Should have action for stale GPOs
    assert len(fix.actions) > 0
    assert any("stale" in a.title.lower() for a in fix.actions)


def test_win_group_policy_audit_clean_machine():
    """Test a clean domain-joined machine with strong policies."""
    mod = _get_module()
    with patch(
        "subprocess.run",
        side_effect=_fake_subprocess_run(
            is_domain_joined=True,
            has_gpos=False,
            has_restrictive_policy=False,
            password_min_length=14,
        ),
    ):
        result = mod.check(_make_profile())
    # Should have at least info about status
    assert result.has_issues  # info findings still count as issues
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warnings) == 0  # No warnings on clean machine
