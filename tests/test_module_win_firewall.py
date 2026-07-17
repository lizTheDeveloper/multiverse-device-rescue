import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules

ALL_ON = """
Domain Profile Settings:
----------------------------------------------------------------------
State                                 ON
Firewall Policy                       BlockInbound,AllowOutbound

Private Profile Settings:
----------------------------------------------------------------------
State                                 ON
Firewall Policy                       BlockInbound,AllowOutbound

Public Profile Settings:
----------------------------------------------------------------------
State                                 ON
Firewall Policy                       BlockInbound,AllowOutbound

Ok.
"""

PUBLIC_OFF = """
Domain Profile Settings:
----------------------------------------------------------------------
State                                 ON

Private Profile Settings:
----------------------------------------------------------------------
State                                 ON

Public Profile Settings:
----------------------------------------------------------------------
State                                 OFF

Ok.
"""

PRIVATE_OFF = """
Domain Profile Settings:
----------------------------------------------------------------------
State                                 ON

Private Profile Settings:
----------------------------------------------------------------------
State                                 OFF

Public Profile Settings:
----------------------------------------------------------------------
State                                 ON

Ok.
"""

DOMAIN_OFF = """
Domain Profile Settings:
----------------------------------------------------------------------
State                                 OFF

Private Profile Settings:
----------------------------------------------------------------------
State                                 ON

Public Profile Settings:
----------------------------------------------------------------------
State                                 ON

Ok.
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
    return next(m for m in modules if m.name == "win_firewall")


def _fake_show_run(show_output, set_returncode=0):
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        if cmd[:3] == ["netsh", "advfirewall", "show"]:
            result.stdout = show_output
        elif cmd[:3] == ["netsh", "advfirewall", "set"]:
            # Real netsh rejects unknown/wrong profile keywords, so a test
            # double that accepts anything would hide a wrong-keyword bug
            # (e.g. "currentprofile" instead of "domainprofile").
            valid_keywords = {"domainprofile", "privateprofile", "publicprofile"}
            if cmd[3] not in valid_keywords:
                result.returncode = 1
                result.stderr = f"The following command was not found: netsh advfirewall set {cmd[3]}."
                return result
            result.stdout = "Ok.\n"
            result.returncode = set_returncode
            if set_returncode != 0:
                result.stderr = "Access is denied."
        return result
    return fake_run


def test_win_firewall_discovered():
    mod = _get_module()
    assert mod.name == "win_firewall"
    assert mod.category == "security"
    assert Platform.WIN32 in mod.platforms
    assert mod.risk_level == RiskLevel.MODERATE


def test_win_firewall_healthy():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_show_run(ALL_ON)):
        result = mod.check(_make_profile())
    assert not result.has_issues


def test_win_firewall_public_off_is_critical():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_show_run(PUBLIC_OFF)):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.severity == Severity.CRITICAL for f in result.findings)
    assert result.findings[0].data["profile_name"] == "Public Profile"


def test_win_firewall_private_off_is_warning():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_show_run(PRIVATE_OFF)):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert result.findings[0].severity == Severity.WARNING
    assert result.findings[0].data["profile_name"] == "Private Profile"


def test_win_firewall_fix_enables_profile():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_show_run(PUBLIC_OFF)):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert len(fix.actions) == 1


def test_win_firewall_fix_enables_domain_profile_with_correct_keyword():
    # Regression test: the fix must use netsh's real "domainprofile"
    # keyword, not "currentprofile" (which targets whatever profile is
    # active right now rather than the reported Domain Profile).
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_show_run(DOMAIN_OFF)):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert len(fix.actions) == 1


def test_win_firewall_fix_handles_permission_failure():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_show_run(PUBLIC_OFF, set_returncode=1)):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert not fix.all_succeeded
    assert "Access is denied" in fix.actions[0].error
