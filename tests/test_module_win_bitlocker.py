import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


HEALTHY_SYSTEM = """
C:
    Device Name: C:
    Mount Point: C:\\
    Status: FullyEncrypted
    Protection Status: Protection On
    Encryption Method: AES 256
    Percentage Encrypted: 100.0%
    Encrypted Volume: True
    Key Protectors:
        Tpm
        Recovery Password

D:
    Device Name: D:
    Mount Point: D:\\
    Status: FullyEncrypted
    Protection Status: Protection On
    Encryption Method: AES 128
    Percentage Encrypted: 100.0%
    Encrypted Volume: True
    Key Protectors:
        Recovery Password
"""

OS_DRIVE_NOT_ENCRYPTED = """
C:
    Device Name: C:
    Mount Point: C:\\
    Status: EncryptionPending
    Protection Status: Protection Off
    Encryption Method: N/A
    Percentage Encrypted: 0.0%
    Encrypted Volume: False
    Key Protectors:
        None
"""

ENCRYPTION_SUSPENDED = """
C:
    Device Name: C:
    Mount Point: C:\\
    Status: EncryptionSuspended
    Protection Status: Protection Off
    Encryption Method: AES 256
    Percentage Encrypted: 50.0%
    Encrypted Volume: False
    Key Protectors:
        Recovery Password
        Tpm
"""

NO_RECOVERY_KEY = """
C:
    Device Name: C:
    Mount Point: C:\\
    Status: FullyEncrypted
    Protection Status: Protection On
    Encryption Method: AES 256
    Percentage Encrypted: 100.0%
    Encrypted Volume: True
    Key Protectors:
        Tpm
        Numerical Password
"""

MIXED_VOLUMES = """
C:
    Device Name: C:
    Mount Point: C:\\
    Status: FullyEncrypted
    Protection Status: Protection On
    Encryption Method: AES 256
    Percentage Encrypted: 100.0%
    Encrypted Volume: True
    Key Protectors:
        Tpm
        Recovery Password

D:
    Device Name: D:
    Mount Point: D:\\
    Status: EncryptionSuspended
    Protection Status: Protection Off
    Encryption Method: AES 128
    Percentage Encrypted: 75.0%
    Encrypted Volume: False
    Key Protectors:
        Recovery Password
"""

MANAGE_BDE_ERROR = ""


def _make_profile():
    return SystemProfile(
        platform=Platform.WIN32,
        os_name="Windows",
        os_version="11",
        architecture="x86_64",
        cpu_model="Intel Core i7",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "win_bitlocker")


def _fake_run(output, returncode=0):
    def fake_subprocess_run(cmd, **kwargs):
        result = MagicMock()
        result.stdout = output
        result.stderr = ""
        result.returncode = returncode
        return result
    return fake_subprocess_run


def test_win_bitlocker_discovered():
    mod = _get_module()
    assert mod.name == "win_bitlocker"
    assert mod.category == "security"
    assert Platform.WIN32 in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_win_bitlocker_healthy_system():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(HEALTHY_SYSTEM)):
        result = mod.check(_make_profile())
    # Should only have INFO findings for healthy system
    assert all(f.severity == Severity.INFO for f in result.findings)
    assert len(result.findings) == 2  # One for C:, one for D:


def test_win_bitlocker_os_drive_not_encrypted():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(OS_DRIVE_NOT_ENCRYPTED)):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.severity == Severity.CRITICAL for f in result.findings)
    critical_finding = next(
        f for f in result.findings if f.severity == Severity.CRITICAL
    )
    assert "C:" in critical_finding.title


def test_win_bitlocker_encryption_suspended():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(ENCRYPTION_SUSPENDED)):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.severity == Severity.WARNING for f in result.findings)
    warning_finding = next(
        f for f in result.findings if f.severity == Severity.WARNING
    )
    assert "suspended" in warning_finding.title.lower()


def test_win_bitlocker_no_recovery_key():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(NO_RECOVERY_KEY)):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have both a WARNING about no recovery key and an INFO about status
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warnings) > 0
    assert any("recovery key" in w.title.lower() for w in warnings)


def test_win_bitlocker_mixed_volumes():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(MIXED_VOLUMES)):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have at least one WARNING (for suspended D:) and one INFO (for healthy C:)
    assert any(f.severity == Severity.WARNING for f in result.findings)
    assert any(f.severity == Severity.INFO for f in result.findings)


def test_win_bitlocker_manage_bde_error():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(MANAGE_BDE_ERROR)):
        result = mod.check(_make_profile())
    # Should not crash if manage-bde fails
    assert not result.has_issues


def test_win_bitlocker_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(OS_DRIVE_NOT_ENCRYPTED)):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action for the critical issue
    assert len(fix.actions) > 0


def test_win_bitlocker_fix_suspended_encryption():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(ENCRYPTION_SUSPENDED)):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    # Should have an action to resume encryption
    assert any("resume" in a.title.lower() for a in fix.actions)


def test_win_bitlocker_fix_no_recovery_key():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(NO_RECOVERY_KEY)):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    # Should have an action to add recovery key
    assert any("recovery key" in a.title.lower() for a in fix.actions)
