import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
import plistlib

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
    return next(m for m in modules if m.name == "pram_nvram_check")


def _make_nvram_plist(audio_volume=None, crash_indicators=None):
    """Create a mock NVRAM plist output."""
    nvram_dict = {}
    if audio_volume:
        nvram_dict["SystemAudioVolume"] = audio_volume
    if crash_indicators:
        for indicator in crash_indicators:
            nvram_dict[indicator] = b"1"
    return plistlib.dumps(nvram_dict)


def _fake_run_normal_nvram():
    """Mock subprocess for normal NVRAM state."""

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""

        if isinstance(cmd, list):
            cmd_str = cmd[0]
        else:
            cmd_str = cmd

        if "bless" in cmd_str:
            result.stdout = "/dev/disk0s1\n"
        elif "nvram" in cmd_str:
            if "-xp" in cmd:
                # Return plist with normal settings
                nvram_dict = {"SystemAudioVolume": "50"}
                result.stdout = plistlib.dumps(nvram_dict).decode()
            else:
                # boot-args query
                result.stdout = "boot-args\t\n"

        return result

    return fake_run


def _fake_run_no_startup_disk():
    """Mock subprocess for missing startup disk."""

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""

        if isinstance(cmd, list):
            cmd_str = cmd[0]
        else:
            cmd_str = cmd

        if "bless" in cmd_str:
            result.stdout = ""
        elif "nvram" in cmd_str:
            if "-xp" in cmd:
                nvram_dict = {"SystemAudioVolume": "50"}
                result.stdout = plistlib.dumps(nvram_dict).decode()
            else:
                result.stdout = "boot-args\t\n"

        return result

    return fake_run


def _fake_run_unusual_boot_args():
    """Mock subprocess for unusual boot arguments."""

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""

        if isinstance(cmd, list):
            cmd_str = cmd[0]
        else:
            cmd_str = cmd

        if "bless" in cmd_str:
            result.stdout = "/dev/disk0s1\n"
        elif "nvram" in cmd_str:
            if "-xp" in cmd:
                nvram_dict = {"SystemAudioVolume": "50"}
                result.stdout = plistlib.dumps(nvram_dict).decode()
            else:
                result.stdout = "boot-args\t-v debug\n"

        return result

    return fake_run


def _fake_run_with_crash_indicators():
    """Mock subprocess with crash indicators."""

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""

        if isinstance(cmd, list):
            cmd_str = cmd[0]
        else:
            cmd_str = cmd

        if "bless" in cmd_str:
            result.stdout = "/dev/disk0s1\n"
        elif "nvram" in cmd_str:
            if "-xp" in cmd:
                nvram_dict = {
                    "SystemAudioVolume": "50",
                    "panic-action": b"1",
                }
                result.stdout = plistlib.dumps(nvram_dict).decode()
            else:
                result.stdout = "boot-args\t\n"

        return result

    return fake_run


def test_pram_nvram_check_discovered():
    mod = _get_module()
    assert mod.name == "pram_nvram_check"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE


def test_pram_nvram_check_normal():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_normal_nvram()):
        result = mod.check(_make_profile())
    # Should have findings but no critical issues
    assert result.has_issues is False or all(f.severity != Severity.CRITICAL for f in result.findings)


def test_pram_nvram_check_no_startup_disk():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_startup_disk()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "startup_disk_not_set" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_pram_nvram_check_unusual_boot_args():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_unusual_boot_args()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "unusual_boot_args" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_pram_nvram_check_crash_indicators():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_with_crash_indicators()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "crash_indicators" for f in result.findings)


def test_pram_nvram_check_fix_no_startup_disk():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_startup_disk()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert any(a.title == "Set startup disk" for a in fix.actions)
    assert all(a.success for a in fix.actions)


def test_pram_nvram_check_fix_unusual_boot_args():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_unusual_boot_args()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert any(a.title == "Reset NVRAM/PRAM" for a in fix.actions)
    assert all(a.success for a in fix.actions)
