import sys
import json
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
    return next(m for m in modules if m.name == "win_firewall_rules_audit")


# PowerShell JSON output examples

HEALTHY_PROFILES = json.dumps(
    [
        {
            "Name": "Domain",
            "Enabled": True,
            "DefaultInboundAction": "Block",
            "DefaultOutboundAction": "Allow",
        },
        {
            "Name": "Private",
            "Enabled": True,
            "DefaultInboundAction": "Block",
            "DefaultOutboundAction": "Allow",
        },
        {
            "Name": "Public",
            "Enabled": True,
            "DefaultInboundAction": "Block",
            "DefaultOutboundAction": "Allow",
        },
    ]
)

DANGEROUS_INBOUND_ALLOW = json.dumps(
    [
        {
            "Name": "Public",
            "Enabled": True,
            "DefaultInboundAction": "Allow",
            "DefaultOutboundAction": "Allow",
        },
    ]
)

HEALTHY_RULES = json.dumps([])

FEW_RULES = json.dumps(
    [
        {
            "DisplayName": "Rule 1",
            "Profile": "Domain",
            "Program": "C:\\Program Files\\App1\\app.exe",
        },
        {
            "DisplayName": "Rule 2",
            "Profile": "Private",
            "Program": "C:\\Program Files\\App2\\app.exe",
        },
    ]
)

RULES_WITH_ANY_PROGRAM = json.dumps(
    [
        {
            "DisplayName": "Allow All Programs",
            "Profile": "Domain",
            "Program": "Any",
        },
        {
            "DisplayName": "Restricted Rule",
            "Profile": "Domain",
            "Program": "C:\\Program Files\\App\\app.exe",
        },
    ]
)

RULES_WITH_ANY_PORT = json.dumps(
    [
        {
            "DisplayName": "Allow All Ports",
            "Profile": "Domain",
            "Program": "C:\\Program Files\\App\\app.exe",
            "LocalPort": "Any",
        },
    ]
)

EXCESSIVE_RULES = json.dumps(
    [{"DisplayName": f"Rule {i}", "Profile": "Domain", "Program": f"C:\\App{i}\\app.exe"}
     for i in range(105)]
)


def _fake_powershell_run(profiles_output, rules_output=""):
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        if not isinstance(cmd, list):
            return result

        # Check if it's a PowerShell command for profiles
        if len(cmd) >= 4 and "Get-NetFirewallProfile" in cmd[-1]:
            result.stdout = profiles_output
        # Check if it's a PowerShell command for rules
        elif len(cmd) >= 4 and "Get-NetFirewallRule" in cmd[-1]:
            result.stdout = rules_output or HEALTHY_RULES
        return result

    return fake_run


def test_module_discovered():
    mod = _get_module()
    assert mod.name == "win_firewall_rules_audit"
    assert mod.category == "security"
    assert Platform.WIN32 in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_healthy_firewall_rules():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_powershell_run(HEALTHY_PROFILES, HEALTHY_RULES)):
        result = mod.check(_make_profile())
    # Should only have INFO finding (summary)
    assert result.has_issues
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert len(info_findings) == 1
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert len(warning_findings) == 0
    assert len(critical_findings) == 0


def test_dangerous_default_inbound_allow():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_powershell_run(DANGEROUS_INBOUND_ALLOW)):
        result = mod.check(_make_profile())
    assert result.has_issues
    critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert len(critical_findings) == 1
    assert "DefaultInboundAction set to Allow" in critical_findings[0].title


def test_allow_all_programs_rule():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_powershell_run(HEALTHY_PROFILES, RULES_WITH_ANY_PROGRAM)):
        result = mod.check(_make_profile())
    assert result.has_issues
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    # Should have warning about "Allow All Programs" rule + summary
    allow_all_warnings = [f for f in warning_findings if "allow all programs" in f.title.lower()]
    assert len(allow_all_warnings) >= 1


def test_allow_all_ports_rule():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_powershell_run(HEALTHY_PROFILES, RULES_WITH_ANY_PORT)):
        result = mod.check(_make_profile())
    assert result.has_issues
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    # Should have warning about "Allow All Ports" rule
    allow_all_port_warnings = [f for f in warning_findings if "allow all ports" in f.title.lower()]
    assert len(allow_all_port_warnings) >= 1


def test_excessive_rules():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_powershell_run(HEALTHY_PROFILES, EXCESSIVE_RULES)):
        result = mod.check(_make_profile())
    assert result.has_issues
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    # Should have warning about excessive rules
    excessive_warnings = [f for f in warning_findings if "excessive" in f.title.lower()]
    assert len(excessive_warnings) >= 1


def test_few_restricted_rules_summary():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_powershell_run(HEALTHY_PROFILES, FEW_RULES)):
        result = mod.check(_make_profile())
    # Should have at least one INFO summary finding
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert len(info_findings) >= 1
    assert "summary" in info_findings[0].title.lower()


def test_fix_critical_issue():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_powershell_run(DANGEROUS_INBOUND_ALLOW)):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # Should have actions for critical findings
    assert len(fix.actions) > 0
    critical_actions = [a for a in fix.actions if "dangerous" in a.title.lower()]
    assert len(critical_actions) >= 1


def test_fix_warning_allow_all_programs():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_powershell_run(HEALTHY_PROFILES, RULES_WITH_ANY_PROGRAM)):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # Should have actions suggesting rule review
    review_actions = [a for a in fix.actions if "review" in a.title.lower()]
    assert len(review_actions) > 0


def test_fix_warning_allow_all_ports():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_powershell_run(HEALTHY_PROFILES, RULES_WITH_ANY_PORT)):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    review_actions = [a for a in fix.actions if "review" in a.title.lower()]
    assert len(review_actions) > 0


def test_fix_is_informational():
    """Verify that fix actions are all RiskLevel.SAFE and don't modify the system."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_powershell_run(DANGEROUS_INBOUND_ALLOW, RULES_WITH_ANY_PROGRAM)):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # All actions should be SAFE and have success=True (they're informational)
    for action in fix.actions:
        assert action.risk_level == RiskLevel.SAFE
        assert action.success is True


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.win_firewall_rules_audit.") for c in declared)
