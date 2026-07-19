import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules

# Sample cmdkey output with minimal credentials
MINIMAL_CREDS = """
Currently stored credentials:

Target: Domain:target=example.local
Type: Domain Password
User: DOMAIN\\user1

Target: LegacyGeneric:target=https://internal.example.com
Type: Generic
User: internal_user
"""

# Sample cmdkey output with >50 credentials (credential sprawl)
MANY_CREDS = """
Currently stored credentials:
"""
# Build a large credential list
for i in range(52):
    if i % 3 == 0:
        MANY_CREDS += f"""
Target: Domain:target=service{i}.example.com
Type: Domain Password
User: DOMAIN\\user{i}
"""
    elif i % 3 == 1:
        MANY_CREDS += f"""
Target: LegacyGeneric:target=https://service{i}.com
Type: Generic
User: user{i}
"""
    else:
        MANY_CREDS += f"""
Target: WindowsLive:target=service{i}
Type: Generic
User: user{i}
"""

# Sample cmdkey output with generic credentials to sensitive services
GENERIC_SENSITIVE_CREDS = """
Currently stored credentials:

Target: LegacyGeneric:target=https://github.com
Type: Generic
User: github_user

Target: LegacyGeneric:target=https://outlook.com
Type: Generic
User: user@outlook.com

Target: LegacyGeneric:target=https://azure.microsoft.com
Type: Generic
User: azure_user

Target: Domain:target=internal.example.com
Type: Domain Password
User: DOMAIN\\internal_user
"""

# Sample cmdkey output with domain credentials
DOMAIN_CREDS_WITH_MANY = """
Currently stored credentials:

Target: Domain:target=oldomain.example.com
Type: Domain Password
User: OLDDOMAIN\\user1

Target: Domain:target=previous-corp.local
Type: Domain Password
User: CORP\\admin

Target: LegacyGeneric:target=https://github.com
Type: Generic
User: github_user
"""

# wmic output for domain-joined machine
WMIC_DOMAIN_JOINED = """
PartOfDomain
TRUE
"""

# wmic output for non-domain-joined machine
WMIC_NOT_DOMAIN_JOINED = """
PartOfDomain
FALSE
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
    return next(
        m for m in modules if m.name == "win_credential_manager_audit"
    )


def _fake_run(cmdkey_output, wmic_output):
    """Create a mock subprocess.run that handles both cmdkey and wmic."""

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""

        if cmd[0] == "cmdkey":
            result.stdout = cmdkey_output
        elif cmd[0] == "wmic":
            result.stdout = wmic_output
        else:
            result.stdout = ""

        return result

    return fake_run


def test_win_credential_manager_audit_discovered():
    mod = _get_module()
    assert mod.name == "win_credential_manager_audit"
    assert mod.category == "security"
    assert Platform.WIN32 in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_minimal_credentials_healthy():
    """Test with minimal credentials - no warnings, only info."""
    mod = _get_module()
    with patch(
        "subprocess.run", side_effect=_fake_run(MINIMAL_CREDS, WMIC_DOMAIN_JOINED)
    ):
        result = mod.check(_make_profile())

    # Should only have INFO finding (no warnings)
    assert result.has_issues  # Has the INFO summary
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warnings) == 0
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert len(info_findings) == 1


def test_credential_sprawl_warning():
    """Test >50 credentials triggers WARNING."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(MANY_CREDS, WMIC_DOMAIN_JOINED)):
        result = mod.check(_make_profile())

    # Should have credential sprawl warning
    sprawl_warnings = [
        f
        for f in result.findings
        if f.severity == Severity.WARNING
        and "sprawl" in f.title.lower()
    ]
    assert len(sprawl_warnings) == 1
    assert sprawl_warnings[0].data["credential_count"] == 52


def test_domain_credentials_on_non_domain_joined():
    """Test domain credentials on non-domain-joined machine triggers WARNING."""
    mod = _get_module()
    with patch(
        "subprocess.run",
        side_effect=_fake_run(DOMAIN_CREDS_WITH_MANY, WMIC_NOT_DOMAIN_JOINED),
    ):
        result = mod.check(_make_profile())

    # Should have domain credentials warning
    domain_warnings = [
        f
        for f in result.findings
        if f.severity == Severity.WARNING
        and "domain credentials" in f.title.lower()
    ]
    assert len(domain_warnings) == 1
    assert domain_warnings[0].data["domain_credential_count"] == 2


def test_generic_sensitive_credentials_warning():
    """Test generic credentials to sensitive services triggers WARNING."""
    mod = _get_module()
    with patch(
        "subprocess.run",
        side_effect=_fake_run(GENERIC_SENSITIVE_CREDS, WMIC_DOMAIN_JOINED),
    ):
        result = mod.check(_make_profile())

    # Should have generic sensitive credentials warning
    generic_warnings = [
        f
        for f in result.findings
        if f.severity == Severity.WARNING
        and "generic" in f.title.lower()
    ]
    assert len(generic_warnings) == 1
    assert generic_warnings[0].data["generic_sensitive_count"] == 3


def test_info_inventory_summary():
    """Test INFO finding with inventory summary is always present."""
    mod = _get_module()
    with patch(
        "subprocess.run", side_effect=_fake_run(MINIMAL_CREDS, WMIC_DOMAIN_JOINED)
    ):
        result = mod.check(_make_profile())

    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert len(info_findings) == 1
    assert "inventory" in info_findings[0].title.lower()
    assert info_findings[0].data["total_credentials"] == 2
    assert "Domain Password" in info_findings[0].data["by_type"]
    assert "Generic" in info_findings[0].data["by_type"]


def test_fix_credential_sprawl():
    """Test fix for credential sprawl."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(MANY_CREDS, WMIC_DOMAIN_JOINED)):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    # Should have an action for sprawl
    sprawl_actions = [
        a for a in fix.actions if a.data.get("issue_type") == "credential_sprawl"
    ]
    assert len(sprawl_actions) == 1
    assert sprawl_actions[0].success is True
    assert sprawl_actions[0].risk_level == RiskLevel.SAFE


def test_fix_domain_credentials():
    """Test fix for domain credentials."""
    mod = _get_module()
    with patch(
        "subprocess.run",
        side_effect=_fake_run(DOMAIN_CREDS_WITH_MANY, WMIC_NOT_DOMAIN_JOINED),
    ):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    # Should have an action for domain credentials
    domain_actions = [
        a for a in fix.actions if a.data.get("issue_type") == "domain_credentials"
    ]
    assert len(domain_actions) == 1
    assert domain_actions[0].success is True


def test_fix_generic_credentials():
    """Test fix for generic sensitive credentials."""
    mod = _get_module()
    with patch(
        "subprocess.run",
        side_effect=_fake_run(GENERIC_SENSITIVE_CREDS, WMIC_DOMAIN_JOINED),
    ):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    # Should have an action for generic credentials
    generic_actions = [
        a for a in fix.actions if a.data.get("issue_type") == "generic_credentials"
    ]
    assert len(generic_actions) == 1
    assert generic_actions[0].success is True


def test_fix_multiple_warnings():
    """Test fix when multiple warnings are present."""
    # Create output with >50 creds and domain creds
    many_with_domain = MANY_CREDS + """
Target: Domain:target=olddomain.local
Type: Domain Password
User: OLD\\admin
"""
    mod = _get_module()
    with patch(
        "subprocess.run",
        side_effect=_fake_run(many_with_domain, WMIC_NOT_DOMAIN_JOINED),
    ):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    # Should have actions for both sprawl and domain credentials
    assert len(fix.actions) >= 2
    assert any(a.data.get("issue_type") == "credential_sprawl" for a in fix.actions)
    assert any(a.data.get("issue_type") == "domain_credentials" for a in fix.actions)


def test_empty_credentials_output():
    """Test handling of empty credentials list."""
    mod = _get_module()
    empty_output = "Currently stored credentials:\n"
    with patch(
        "subprocess.run", side_effect=_fake_run(empty_output, WMIC_DOMAIN_JOINED)
    ):
        result = mod.check(_make_profile())

    # Should only have INFO finding with zero count
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert len(info_findings) == 1
    assert info_findings[0].data["total_credentials"] == 0


def test_subprocess_failure_graceful():
    """Test graceful handling when subprocess fails."""

    def fake_run_fail(cmd, **kwargs):
        raise OSError("Command failed")

    mod = _get_module()
    with patch("subprocess.run", side_effect=fake_run_fail):
        result = mod.check(_make_profile())

    # Should handle gracefully with empty credentials
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert len(info_findings) == 1
    assert info_findings[0].data["total_credentials"] == 0


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.win_credential_manager_audit.") for c in declared)
