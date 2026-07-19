import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


def _make_profile():
    return SystemProfile(
        platform=Platform.DARWIN,
        os_name="macOS",
        os_version="15.2",
        architecture="arm64",
        cpu_model="Apple M2",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "kernel_extensions_audit")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_no_kexts():
    """No kexts loaded or unable to retrieve"""
    def fake_run(cmd, **kwargs):
        return _make_subprocess_result(stdout="", returncode=1)
    return fake_run


def _fake_run_only_apple_kexts():
    """Only Apple kernel extensions (no issues)"""
    def fake_run(cmd, **kwargs):
        # Simulate kextstat output
        stdout = """Index Refs Address                Size     Wired Name (Version) <Address>
    0   36 0xffffff7f80200000    0x70c000 0x70c000 com.apple.kext.foo (1.0.0)
    1   24 0xffffff7f80300000    0x40c000 0x40c000 com.apple.kext.bar (2.1.0)
    2   15 0xffffff7f80400000    0x20c000 0x20c000 apple.kext.baz (1.2.3)
"""
        return _make_subprocess_result(stdout=stdout)
    return fake_run


def _fake_run_mixed_kexts():
    """Mix of Apple and third-party kexts"""
    def fake_run(cmd, **kwargs):
        stdout = """Index Refs Address                Size     Wired Name (Version) <Address>
    0   36 0xffffff7f80200000    0x70c000 0x70c000 com.apple.kext.foo (1.0.0)
    1   24 0xffffff7f80300000    0x40c000 0x40c000 com.vmware.kext.usb (2.1.0)
    2   15 0xffffff7f80400000    0x20c000 0x20c000 com.sensible.kext.driver (1.2.3)
"""
        return _make_subprocess_result(stdout=stdout)
    return fake_run


def _fake_run_problematic_kexts():
    """Problematic kexts that should trigger WARNING"""
    def fake_run(cmd, **kwargs):
        stdout = """Index Refs Address                Size     Wired Name (Version) <Address>
    0   36 0xffffff7f80200000    0x70c000 0x70c000 com.apple.kext.foo (1.0.0)
    1   24 0xffffff7f80300000    0x40c000 0x40c000 com.kaspersky.kext.av (2.1.0)
    2   15 0xffffff7f80400000    0x20c000 0x20c000 com.norton.kext.av (1.2.3)
    3   10 0xffffff7f80500000    0x10c000 0x10c000 com.oracle.virtualbox.kext (6.1.0)
"""
        return _make_subprocess_result(stdout=stdout)
    return fake_run


def _fake_run_kmutil_format():
    """Newer macOS (Monterey+) kmutil format"""
    def fake_run(cmd, **kwargs):
        # Check if this is a kmutil call
        if cmd[0] == "kmutil":
            stdout = """Index Bundle identifier                   Version
    0 com.apple.kext.foo                 1.0.0
    1 com.kaspersky.kext.av              2.1.0
    2 com.sensible.third.party           1.2.3
"""
            return _make_subprocess_result(stdout=stdout)
        else:
            # kextstat fails
            return _make_subprocess_result(returncode=1)
    return fake_run


def test_kernel_extensions_audit_discovered():
    """Module should be discoverable with correct properties"""
    mod = _get_module()
    assert mod.name == "kernel_extensions_audit"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.DARWIN in mod.platforms


def test_kernel_extensions_audit_no_kexts():
    """Unable to retrieve kexts should produce INFO finding"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_kexts()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert len(result.findings) == 1
    assert result.findings[0].severity == Severity.INFO
    assert "Unable to audit" in result.findings[0].title


def test_kernel_extensions_audit_only_apple_kexts():
    """Only Apple kexts should produce no findings"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_only_apple_kexts()):
        result = mod.check(_make_profile())
    assert not result.has_issues
    assert len(result.findings) == 0


def test_kernel_extensions_audit_mixed_kexts():
    """Third-party non-problematic kexts should produce INFO finding"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_mixed_kexts()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have one finding for third-party kexts
    third_party_findings = [f for f in result.findings if "third-party" in f.title.lower()]
    assert len(third_party_findings) == 1
    assert third_party_findings[0].severity == Severity.INFO
    # Should list the third-party kexts
    kexts = third_party_findings[0].data.get("kexts", [])
    assert "com.vmware.kext.usb" in kexts
    assert "com.sensible.kext.driver" in kexts


def test_kernel_extensions_audit_problematic_kexts():
    """Known problematic kexts should produce WARNING finding"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_problematic_kexts()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have finding for problematic kexts
    problematic_findings = [f for f in result.findings if "problematic" in f.title.lower()]
    assert len(problematic_findings) == 1
    assert problematic_findings[0].severity == Severity.WARNING
    # Should list the problematic kexts
    kexts = problematic_findings[0].data.get("kexts", [])
    assert "com.kaspersky.kext.av" in kexts
    assert "com.norton.kext.av" in kexts
    assert "com.oracle.virtualbox.kext" in kexts


def test_kernel_extensions_audit_problematic_not_in_third_party():
    """Problematic kexts should not appear in third-party list"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_problematic_kexts()):
        result = mod.check(_make_profile())
    # Get the third-party finding if it exists
    third_party_findings = [f for f in result.findings if "third-party" in f.title.lower()]
    # Should not list problematic kexts in third-party list
    if third_party_findings:
        kexts = third_party_findings[0].data.get("kexts", [])
        assert "com.kaspersky.kext.av" not in kexts
        assert "com.norton.kext.av" not in kexts


def test_kernel_extensions_audit_kmutil_fallback():
    """Should fall back to kmutil on newer macOS"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_kmutil_format()):
        result = mod.check(_make_profile())
    # Should have findings for both problematic and third-party kexts
    assert result.has_issues
    problematic_findings = [f for f in result.findings if "problematic" in f.title.lower()]
    third_party_findings = [f for f in result.findings if "third-party" in f.title.lower()]
    # Should find Kaspersky as problematic
    assert len(problematic_findings) == 1
    assert "com.kaspersky.kext.av" in problematic_findings[0].data.get("kexts", [])
    # Should find sensible.third.party as third-party
    if third_party_findings:
        assert "com.sensible.third.party" in third_party_findings[0].data.get("kexts", [])


def test_kernel_extensions_audit_fix_is_informational():
    """fix() should return informational actions, never modify system"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_problematic_kexts()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed
    assert fix.all_succeeded
    # Should have actions
    assert len(fix.actions) > 0
    # All actions should be SAFE risk level (informational)
    assert all(a.risk_level == RiskLevel.SAFE for a in fix.actions)
    # All actions should mark success=True
    assert all(a.success for a in fix.actions)


def test_kernel_extensions_audit_fix_creates_actions_per_finding():
    """Should create one action per finding"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_problematic_kexts()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # Should have one action per finding
    assert len(fix.actions) == len(check.findings)


def test_kernel_extensions_audit_fix_problematic_has_guidance():
    """Fix for problematic kexts should provide remediation guidance"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_problematic_kexts()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # Find action for problematic kexts
    problematic_actions = [a for a in fix.actions if "problematic" in a.title.lower()]
    assert len(problematic_actions) > 0
    action = problematic_actions[0]
    # Should mention update or remove
    description = action.description.lower()
    assert "update" in description or "remove" in description or "uninstall" in description


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.kernel_extensions_audit.") for c in declared)
