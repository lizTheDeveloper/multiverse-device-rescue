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
    return next(m for m in modules if m.name == "kext_audit")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_no_third_party_kexts():
    """No third-party kexts loaded"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "kextstat" in cmd_str:
            # Only Apple kexts
            return _make_subprocess_result(
                "Index Refs Address            Size       Wired      Name (Version) <Linked Against>\n"
                "    1    0 0xffffff7f80000000 0x1000     0x1000     com.apple.driver.AppleACPIPlatform (1.0) <7 6 5 4 3 1>\n"
                "    2    0 0xffffff7f80001000 0x2000     0x2000     com.apple.driver.AppleNVMe (2.0) <7 6 5 4 3 1>\n"
            )
        elif "find" in cmd_str and "/Library/Extensions" in cmd_str:
            return _make_subprocess_result("")
        return _make_subprocess_result()
    return fake_run


def _fake_run_with_virtualbox():
    """VirtualBox kext loaded"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "kextstat" in cmd_str:
            return _make_subprocess_result(
                "Index Refs Address            Size       Wired      Name (Version) <Linked Against>\n"
                "    1    0 0xffffff7f80000000 0x1000     0x1000     com.apple.driver.AppleACPIPlatform (1.0) <7 6 5 4 3 1>\n"
                "    2    3 0xffffff7f80001000 0x5000     0x4000     org.virtualbox.kext.VBoxDrv (7.0.6) <7 6 5 4 3 1>\n"
                "    3    1 0xffffff7f80006000 0x2000     0x1000     org.virtualbox.kext.VBoxNetFlt (7.0.6) <2 1>\n"
            )
        elif "find" in cmd_str and "/Library/Extensions" in cmd_str:
            return _make_subprocess_result("")
        return _make_subprocess_result()
    return fake_run


def _fake_run_with_vmware():
    """VMware kext loaded"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "kextstat" in cmd_str:
            return _make_subprocess_result(
                "Index Refs Address            Size       Wired      Name (Version) <Linked Against>\n"
                "    1    0 0xffffff7f80000000 0x1000     0x1000     com.apple.driver.AppleACPIPlatform (1.0) <7 6 5 4 3 1>\n"
                "    2    2 0xffffff7f80001000 0x3000     0x2000     com.vmware.kext.vmci (13.5.12) <7 6 5 4 3 1>\n"
            )
        elif "find" in cmd_str and "/Library/Extensions" in cmd_str:
            return _make_subprocess_result("")
        return _make_subprocess_result()
    return fake_run


def _fake_run_with_unsigned_kext():
    """Unsigned third-party kext loaded"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "kextstat" in cmd_str:
            return _make_subprocess_result(
                "Index Refs Address            Size       Wired      Name (Version) <Linked Against>\n"
                "    1    0 0xffffff7f80000000 0x1000     0x1000     com.apple.driver.AppleACPIPlatform (1.0) <7 6 5 4 3 1>\n"
                "    2    1 0xffffff7f80001000 0x3000     0x2000     com.example.driver.Unsigned (1.0.0)\n"
            )
        elif "find" in cmd_str and "/Library/Extensions" in cmd_str:
            return _make_subprocess_result("")
        return _make_subprocess_result()
    return fake_run


def _fake_run_with_kext_files():
    """Kext files in /Library/Extensions/"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "kextstat" in cmd_str:
            return _make_subprocess_result(
                "Index Refs Address            Size       Wired      Name (Version) <Linked Against>\n"
                "    1    0 0xffffff7f80000000 0x1000     0x1000     com.apple.driver.AppleACPIPlatform (1.0) <7 6 5 4 3 1>\n"
            )
        elif "find" in cmd_str and "/Library/Extensions" in cmd_str:
            return _make_subprocess_result(
                "/Library/Extensions/OldDriver.kext\n"
                "/Library/Extensions/LegacyHW.kext\n"
            )
        return _make_subprocess_result()
    return fake_run


def test_kext_audit_discovered():
    mod = _get_module()
    assert mod.name == "kext_audit"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE


def test_kext_audit_no_third_party_kexts():
    """No third-party kexts should result in no issues"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_third_party_kexts()):
        result = mod.check(_make_profile())
    assert not result.has_issues


def test_kext_audit_virtualbox_detected():
    """VirtualBox kext should be flagged as WARNING"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_with_virtualbox()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have warnings for VirtualBox kexts
    vbox_findings = [f for f in result.findings if "VirtualBox" in f.title or "virtualbox" in str(f.data)]
    assert len(vbox_findings) > 0
    assert any(f.severity == Severity.WARNING for f in vbox_findings)


def test_kext_audit_vmware_detected():
    """VMware kext should be flagged as WARNING"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_with_vmware()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have warnings for VMware kexts
    vmware_findings = [f for f in result.findings if "VMware" in f.title or "vmware" in str(f.data)]
    assert len(vmware_findings) > 0
    assert any(f.severity == Severity.WARNING for f in vmware_findings)


def test_kext_audit_unsigned_kext_critical():
    """Unsigned kext should be flagged as CRITICAL"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_with_unsigned_kext()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have a CRITICAL finding for unsigned kext
    assert any(f.severity == Severity.CRITICAL for f in result.findings)


def test_kext_audit_kext_files_detected():
    """Kext files in /Library/Extensions/ should be flagged as WARNING"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_with_kext_files()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have findings about kext files
    kext_file_findings = [f for f in result.findings if f.data.get("source") == "filesystem"]
    assert len(kext_file_findings) > 0
    assert any(f.severity == Severity.WARNING for f in kext_file_findings)


def test_kext_audit_fix_is_informational():
    """fix() should be informational and not modify anything"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_with_virtualbox()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action
    assert len(fix.actions) > 0


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.kext_audit.") for c in declared)
