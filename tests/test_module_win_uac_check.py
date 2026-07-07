import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules

# Registry query outputs for different UAC configurations
HEALTHY_UAC = r"""
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
    EnableLUA    REG_DWORD    0x1
    ConsentPromptBehaviorAdmin    REG_DWORD    0x5
    PromptOnSecureDesktop    REG_DWORD    0x1
"""

UAC_DISABLED = r"""
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
    EnableLUA    REG_DWORD    0x0
    ConsentPromptBehaviorAdmin    REG_DWORD    0x5
    PromptOnSecureDesktop    REG_DWORD    0x1
"""

UAC_NEVER_NOTIFY = r"""
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
    EnableLUA    REG_DWORD    0x1
    ConsentPromptBehaviorAdmin    REG_DWORD    0x0
    PromptOnSecureDesktop    REG_DWORD    0x1
"""

SECURE_DESKTOP_DISABLED = r"""
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
    EnableLUA    REG_DWORD    0x1
    ConsentPromptBehaviorAdmin    REG_DWORD    0x5
    PromptOnSecureDesktop    REG_DWORD    0x0
"""

MULTIPLE_ISSUES = r"""
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
    EnableLUA    REG_DWORD    0x0
    ConsentPromptBehaviorAdmin    REG_DWORD    0x0
    PromptOnSecureDesktop    REG_DWORD    0x0
"""

REG_NOT_FOUND = "The system was unable to find the specified registry key or value.\r\n"


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
    return next(m for m in modules if m.name == "win_uac_check")


def _fake_reg_run(config_output):
    """Factory function that returns a mock subprocess.run for registry queries."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        if len(cmd) >= 3 and cmd[0] == "reg" and cmd[1] == "query":
            # This is a reg query command
            value_name = cmd[4] if len(cmd) > 4 else None
            if value_name:
                # Return only the relevant lines for this value
                for line in config_output.splitlines():
                    if value_name in line:
                        result.stdout = line + "\n"
                        break
                else:
                    # Value not found
                    result.returncode = 1
                    result.stderr = REG_NOT_FOUND
            else:
                result.stdout = config_output
        return result

    return fake_run


def test_win_uac_check_discovered():
    mod = _get_module()
    assert mod.name == "win_uac_check"
    assert mod.category == "security"
    assert Platform.WIN32 in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_win_uac_check_healthy():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_reg_run(HEALTHY_UAC)):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert len(result.findings) == 1
    assert result.findings[0].severity == Severity.INFO
    assert "properly configured" in result.findings[0].title.lower()


def test_win_uac_check_uac_disabled_is_critical():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_reg_run(UAC_DISABLED)):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.severity == Severity.CRITICAL for f in result.findings)
    critical = next(f for f in result.findings if f.severity == Severity.CRITICAL)
    assert critical.data["setting"] == "EnableLUA"
    assert critical.data["value"] == "0"


def test_win_uac_check_never_notify_is_warning():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_reg_run(UAC_NEVER_NOTIFY)):
        result = mod.check(_make_profile())
    assert result.has_issues
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert any(f.data["setting"] == "ConsentPromptBehaviorAdmin" for f in warnings)


def test_win_uac_check_secure_desktop_disabled_is_warning():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_reg_run(SECURE_DESKTOP_DISABLED)):
        result = mod.check(_make_profile())
    assert result.has_issues
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert any(f.data["setting"] == "PromptOnSecureDesktop" for f in warnings)


def test_win_uac_check_multiple_issues():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_reg_run(MULTIPLE_ISSUES)):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert len(result.findings) == 3
    assert any(f.severity == Severity.CRITICAL for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_win_uac_check_fix_provides_instructions():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_reg_run(UAC_DISABLED)):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert not fix.all_succeeded
    assert len(fix.actions) == 1
    assert "Enable User Account Control" in fix.actions[0].title
    assert fix.actions[0].error is not None


def test_win_uac_check_fix_handles_multiple_issues():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_reg_run(MULTIPLE_ISSUES)):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # Should have actions for each finding (excluding INFO findings)
    assert len(fix.actions) == 3
    assert not fix.all_succeeded
    action_titles = [a.title for a in fix.actions]
    assert any("Enable User Account Control" in t for t in action_titles)
    assert any("Never notify" in t or "prompt behavior" in t for t in action_titles)
    assert any("Secure Desktop" in t for t in action_titles)
