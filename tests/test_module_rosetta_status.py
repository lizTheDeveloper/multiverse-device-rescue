import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
import subprocess

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


def _make_profile():
    return SystemProfile(
        platform=Platform.DARWIN,
        os_name="macOS",
        os_version="14.0",
        architecture="arm64",
        cpu_model="Apple M1",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "rosetta_status")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_apple_silicon_with_rosetta():
    """Apple Silicon Mac with Rosetta 2 installed"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "uname" in cmd_str and "-m" in cmd_str:
            return _make_subprocess_result(stdout="arm64\n")
        elif "arch" in cmd_str and "-x86_64" in cmd_str:
            return _make_subprocess_result(stdout="", returncode=0)
        elif "sysctl" in cmd_str:
            return _make_subprocess_result(stdout="Apple M1\n")
        return _make_subprocess_result()
    return fake_run


def _fake_run_apple_silicon_without_rosetta():
    """Apple Silicon Mac without Rosetta 2"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "uname" in cmd_str and "-m" in cmd_str:
            return _make_subprocess_result(stdout="arm64\n")
        elif "arch" in cmd_str and "-x86_64" in cmd_str:
            # Rosetta not installed - arch command fails
            raise subprocess.CalledProcessError(1, cmd)
        elif "sysctl" in cmd_str:
            return _make_subprocess_result(stdout="Apple M1\n")
        return _make_subprocess_result()
    return fake_run


def _fake_run_intel_mac():
    """Intel Mac"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "uname" in cmd_str and "-m" in cmd_str:
            return _make_subprocess_result(stdout="x86_64\n")
        elif "sysctl" in cmd_str:
            return _make_subprocess_result(stdout="Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz\n")
        return _make_subprocess_result()
    return fake_run


def _fake_run_uname_fails():
    """Fallback to sysctl when uname fails"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "uname" in cmd_str and "-m" in cmd_str:
            # uname fails, fall back to sysctl
            raise subprocess.CalledProcessError(1, cmd)
        elif "sysctl" in cmd_str:
            return _make_subprocess_result(stdout="Apple M2\n")
        elif "arch" in cmd_str and "-x86_64" in cmd_str:
            return _make_subprocess_result(stdout="", returncode=0)
        return _make_subprocess_result()
    return fake_run


def test_rosetta_status_discovered():
    mod = _get_module()
    assert mod.name == "rosetta_status"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE


def test_apple_silicon_with_rosetta():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_apple_silicon_with_rosetta()):
        with patch("os.path.exists", return_value=True):
            result = mod.check(_make_profile())
    assert result.has_issues
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert "Rosetta 2 is installed" in finding.title
    assert finding.severity == Severity.INFO
    assert finding.data.get("architecture") == "arm64"
    assert finding.data.get("rosetta_installed") is True


def test_apple_silicon_without_rosetta():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_apple_silicon_without_rosetta()):
        with patch("os.path.exists", return_value=False):
            result = mod.check(_make_profile())
    assert result.has_issues
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert "NOT installed" in finding.title
    assert finding.severity == Severity.WARNING
    assert finding.data.get("architecture") == "arm64"
    assert finding.data.get("rosetta_installed") is False


def test_intel_mac():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_intel_mac()):
        with patch("os.path.exists", return_value=False):
            result = mod.check(_make_profile())
    assert result.has_issues
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert "Intel Mac" in finding.title
    assert finding.severity == Severity.INFO
    assert finding.data.get("architecture") == "x86_64"


def test_uname_fails_fallback_to_sysctl():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_uname_fails()):
        with patch("os.path.exists", return_value=True):
            result = mod.check(_make_profile())
    # Should still detect Apple Silicon via sysctl
    assert result.has_issues
    finding = result.findings[0]
    assert finding.data.get("architecture") == "arm64"


def test_fix_apple_silicon_without_rosetta():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_apple_silicon_without_rosetta()):
        with patch("os.path.exists", return_value=False):
            check = mod.check(_make_profile())
            fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert len(fix.actions) == 1
    assert "Install Rosetta 2" in fix.actions[0].title
    assert "softwareupdate" in fix.actions[0].description


def test_fix_apple_silicon_with_rosetta():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_apple_silicon_with_rosetta()):
        with patch("os.path.exists", return_value=True):
            check = mod.check(_make_profile())
            fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert len(fix.actions) == 1
    assert "Rosetta 2 is installed" in fix.actions[0].title


def test_fix_intel_mac():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_intel_mac()):
        with patch("os.path.exists", return_value=False):
            check = mod.check(_make_profile())
            fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert len(fix.actions) == 1
    assert "no action needed" in fix.actions[0].title
