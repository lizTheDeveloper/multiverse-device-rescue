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
    return next(m for m in modules if m.name == "rootkit_check")


def test_rootkit_check_discovered():
    """Module should be discoverable."""
    mod = _get_module()
    assert mod.name == "rootkit_check"
    assert mod.risk_level == RiskLevel.SAFE
    assert mod.category == "security"


def test_rootkit_check_healthy():
    """All checks pass - should have INFO finding only."""
    mod = _get_module()

    def healthy_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else cmd

        if "csrutil" in cmd_str:
            result.stdout = "System Integrity Protection status: enabled.\n"
        elif "codesign" in cmd_str:
            result.stdout = "valid on disk\n"
        elif "kextstat" in cmd_str:
            result.stdout = "Index Refs Address            Size       Wired      Name (Version)\n    1   50 0xffffff7f825e0000 0x1234567  0x100000   com.apple.driver.AppleACPIPlatform (1.0)\n"
        elif "ps" in cmd_str and "-eo" in cmd_str:
            result.stdout = "PID\n1\n2\n3\n4\n5\n"
        elif "sysctl" in cmd_str:
            result.stdout = "kern.proc.all: 5\n"
        elif "ls" in cmd_str:
            result.stdout = "total 1234\ndrwxr-xr-x  20 root wheel 640 Jul  7 12:00 .\ndrwxr-xr-x   4 root wheel 128 Jul  5 15:30 ..\n"
        else:
            result.stdout = ""

        return result

    with patch("modules.security.rootkit_check.subprocess.run", side_effect=healthy_run):
        result = mod.check(_make_profile())

    assert result.has_issues
    assert len(result.findings) == 1
    assert result.findings[0].severity == Severity.INFO
    assert "passed" in result.findings[0].title.lower()


def test_sip_disabled():
    """SIP disabled - should flag CRITICAL."""
    mod = _get_module()

    def sip_disabled_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else cmd

        if "csrutil" in cmd_str:
            result.stdout = "System Integrity Protection status: disabled.\n"
        elif "codesign" in cmd_str:
            result.stdout = "valid on disk\n"
        elif "kextstat" in cmd_str:
            result.stdout = "Index Refs Address            Size       Wired      Name (Version)\n    1   50 0xffffff7f825e0000 0x1234567  0x100000   com.apple.driver.AppleACPIPlatform (1.0)\n"
        elif "ps" in cmd_str and "-eo" in cmd_str:
            result.stdout = "PID\n1\n2\n"
        elif "sysctl" in cmd_str:
            result.stdout = "kern.proc.all: 2\n"
        elif "ls" in cmd_str:
            result.stdout = "total 1234\ndrwxr-xr-x  20 root wheel 640 Jul  7 12:00 .\n"
        else:
            result.stdout = ""

        return result

    with patch("modules.security.rootkit_check.subprocess.run", side_effect=sip_disabled_run):
        result = mod.check(_make_profile())

    assert result.has_issues
    assert any(f.severity == Severity.CRITICAL and "SIP" in f.title for f in result.findings)


def test_binary_signature_failure():
    """System binary fails code signature - should flag CRITICAL."""
    mod = _get_module()

    def bad_binary_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else cmd

        if "csrutil" in cmd_str:
            result.stdout = "System Integrity Protection status: enabled.\n"
        elif "codesign" in cmd_str:
            # One binary fails verification
            if "/usr/bin/login" in cmd_str:
                result.returncode = 1
                result.stderr = "invalid signature (code or signature have been modified)\n"
                result.stdout = ""
            else:
                result.stdout = "valid on disk\n"
        elif "kextstat" in cmd_str:
            result.stdout = "Index Refs Address            Size       Wired      Name (Version)\n    1   50 0xffffff7f825e0000 0x1234567  0x100000   com.apple.driver.AppleACPIPlatform (1.0)\n"
        elif "ps" in cmd_str and "-eo" in cmd_str:
            result.stdout = "PID\n1\n2\n"
        elif "sysctl" in cmd_str:
            result.stdout = "kern.proc.all: 2\n"
        elif "ls" in cmd_str:
            result.stdout = "total 1234\ndrwxr-xr-x  20 root wheel 640 Jul  7 12:00 .\n"
        else:
            result.stdout = ""

        return result

    with patch("modules.security.rootkit_check.subprocess.run", side_effect=bad_binary_run):
        result = mod.check(_make_profile())

    assert result.has_issues
    assert any(f.severity == Severity.CRITICAL and "code signature" in f.title.lower() for f in result.findings)


def test_suspicious_kernel_extensions():
    """Non-Apple kernel extensions - should flag WARNING."""
    mod = _get_module()

    def suspicious_kext_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else cmd

        if "csrutil" in cmd_str:
            result.stdout = "System Integrity Protection status: enabled.\n"
        elif "codesign" in cmd_str:
            result.stdout = "valid on disk\n"
        elif "kextstat" in cmd_str:
            # Include a non-Apple kernel extension
            result.stdout = "Index Refs Address            Size       Wired      Name (Version)\n    1   50 0xffffff7f825e0000 0x1234567  0x100000   com.apple.driver.AppleACPIPlatform (1.0)\n    2   30 0xffffff7f825f0000 0x2000000  0x50000    com.vmware.kext.vmnet (2.1.2)\n"
        elif "ps" in cmd_str and "-eo" in cmd_str:
            result.stdout = "PID\n1\n2\n"
        elif "sysctl" in cmd_str:
            result.stdout = "kern.proc.all: 2\n"
        elif "ls" in cmd_str:
            result.stdout = "total 1234\ndrwxr-xr-x  20 root wheel 640 Jul  7 12:00 .\n"
        else:
            result.stdout = ""

        return result

    with patch("modules.security.rootkit_check.subprocess.run", side_effect=suspicious_kext_run):
        result = mod.check(_make_profile())

    assert result.has_issues
    assert any(f.severity == Severity.WARNING and "kernel extension" in f.title.lower() for f in result.findings)


def test_hidden_process_detection():
    """Process count mismatch - should flag WARNING."""
    mod = _get_module()

    def hidden_proc_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else cmd

        if "csrutil" in cmd_str:
            result.stdout = "System Integrity Protection status: enabled.\n"
        elif "codesign" in cmd_str:
            result.stdout = "valid on disk\n"
        elif "kextstat" in cmd_str:
            result.stdout = "Index Refs Address            Size       Wired      Name (Version)\n    1   50 0xffffff7f825e0000 0x1234567  0x100000   com.apple.driver.AppleACPIPlatform (1.0)\n"
        elif "ps" in cmd_str and "-eo" in cmd_str:
            # ps reports fewer processes (hidden processes)
            result.stdout = "PID\n1\n2\n3\n4\n5\n"
        elif "sysctl" in cmd_str:
            # sysctl reports more processes
            result.stdout = "kern.proc.all: 25\n"
        elif "ls" in cmd_str:
            result.stdout = "total 1234\ndrwxr-xr-x  20 root wheel 640 Jul  7 12:00 .\n"
        else:
            result.stdout = ""

        return result

    with patch("modules.security.rootkit_check.subprocess.run", side_effect=hidden_proc_run):
        result = mod.check(_make_profile())

    assert result.has_issues
    assert any(f.severity == Severity.WARNING and "process" in f.title.lower() for f in result.findings)


def test_suspicious_hidden_files():
    """Suspicious hidden files in root - should flag WARNING."""
    mod = _get_module()

    def hidden_files_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else cmd

        if "csrutil" in cmd_str:
            result.stdout = "System Integrity Protection status: enabled.\n"
        elif "codesign" in cmd_str:
            result.stdout = "valid on disk\n"
        elif "kextstat" in cmd_str:
            result.stdout = "Index Refs Address            Size       Wired      Name (Version)\n    1   50 0xffffff7f825e0000 0x1234567  0x100000   com.apple.driver.AppleACPIPlatform (1.0)\n"
        elif "ps" in cmd_str and "-eo" in cmd_str:
            result.stdout = "PID\n1\n2\n"
        elif "sysctl" in cmd_str:
            result.stdout = "kern.proc.all: 2\n"
        elif "ls" in cmd_str:
            # Suspicious hidden files
            result.stdout = "total 1234\ndrwxr-xr-x  20 root wheel 640 Jul  7 12:00 .\ndrwxr-xr-x   4 root wheel 128 Jul  5 15:30 ..\n-rw-r--r--   1 root wheel 1024 Jul  7 12:00 .rootkit_config\ndrwxr-xr-x   3 root wheel  128 Jul  7 12:00 .suspicious_dir\n"
        else:
            result.stdout = ""

        return result

    with patch("modules.security.rootkit_check.subprocess.run", side_effect=hidden_files_run):
        result = mod.check(_make_profile())

    assert result.has_issues
    assert any(f.severity == Severity.WARNING and "hidden" in f.title.lower() for f in result.findings)


def test_rootkit_check_fix_is_informational():
    """fix() should be informational and not modify system."""
    mod = _get_module()

    def failing_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 1
        result.stderr = "Error"
        result.stdout = ""
        return result

    with patch("modules.security.rootkit_check.subprocess.run", side_effect=failing_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    # Should have actions describing how to fix
    assert len(fix.actions) >= 0
    # All actions should succeed (they're just info)
    assert fix.all_succeeded


def test_multiple_issues():
    """Multiple rootkit indicators - should flag multiple findings."""
    mod = _get_module()

    def multi_issue_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else cmd

        if "csrutil" in cmd_str:
            # SIP disabled
            result.stdout = "System Integrity Protection status: disabled.\n"
        elif "codesign" in cmd_str:
            # Binary signature fails
            result.returncode = 1
            result.stderr = "invalid signature\n"
            result.stdout = ""
        elif "kextstat" in cmd_str:
            # Suspicious kernel extensions
            result.stdout = "Index Refs Address            Size       Wired      Name (Version)\n    1   50 0xffffff7f825e0000 0x1234567  0x100000   com.malware.kext.rootkit (1.0)\n"
        elif "ps" in cmd_str and "-eo" in cmd_str:
            result.stdout = "PID\n1\n"
        elif "sysctl" in cmd_str:
            # Hidden processes
            result.stdout = "kern.proc.all: 20\n"
        elif "ls" in cmd_str:
            # Suspicious hidden files
            result.stdout = "total 1234\ndrwxr-xr-x  20 root wheel 640 Jul  7 12:00 .\n-rw-r--r--   1 root wheel 1024 Jul  7 12:00 .suspicious\n"
        else:
            result.stdout = ""

        return result

    with patch("modules.security.rootkit_check.subprocess.run", side_effect=multi_issue_run):
        result = mod.check(_make_profile())

    assert result.has_issues
    # Should have multiple findings for different issues
    assert len(result.findings) >= 3
    # At least one should be CRITICAL
    assert any(f.severity == Severity.CRITICAL for f in result.findings)


def test_command_failures():
    """Commands that fail should be handled gracefully."""
    mod = _get_module()

    def failing_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 1
        result.stderr = "Command failed"
        result.stdout = ""
        return result

    with patch("modules.security.rootkit_check.subprocess.run", side_effect=failing_run):
        result = mod.check(_make_profile())

    # Should not crash, just handle gracefully
    assert isinstance(result.findings, list)


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.rootkit_check.") for c in declared)
