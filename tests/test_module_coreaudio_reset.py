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
    return next(m for m in modules if m.name == "coreaudio_reset")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_healthy():
    """Normal case: coreaudiod running, devices found, correct output"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "pgrep" in cmd_str and "coreaudiod" in cmd_str:
            return _make_subprocess_result(stdout="12345\n", returncode=0)
        elif "system_profiler" in cmd_str and "SPAudioDataType" in cmd_str:
            return _make_subprocess_result(
                "Audio (Built-in):\n"
                "    Internal Microphone:\n"
                "        Input Channels: 2\n"
                "    Internal Speakers:\n"
                "        Output Channels: 2\n"
            )
        elif "com.apple.sound.default.output" in cmd_str:
            return _make_subprocess_result(stdout="Internal Speakers\n")
        return _make_subprocess_result()

    return fake_run


def _fake_run_coreaudiod_not_running():
    """CoreAudio daemon has crashed"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "pgrep" in cmd_str and "coreaudiod" in cmd_str:
            return _make_subprocess_result(returncode=1)
        elif "system_profiler" in cmd_str and "SPAudioDataType" in cmd_str:
            return _make_subprocess_result(
                "Audio (Built-in):\n"
                "    Internal Speakers:\n"
                "        Output Channels: 2\n"
            )
        return _make_subprocess_result()

    return fake_run


def _fake_run_no_output_devices():
    """No output devices detected"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "pgrep" in cmd_str and "coreaudiod" in cmd_str:
            return _make_subprocess_result(stdout="12345\n", returncode=0)
        elif "system_profiler" in cmd_str and "SPAudioDataType" in cmd_str:
            return _make_subprocess_result(
                "Audio (Built-in):\n"
                "    Internal Microphone:\n"
                "        Input Channels: 2\n"
            )
        return _make_subprocess_result()

    return fake_run


def _fake_run_unexpected_device():
    """Output routed to unexpected device"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "pgrep" in cmd_str and "coreaudiod" in cmd_str:
            return _make_subprocess_result(stdout="12345\n", returncode=0)
        elif "system_profiler" in cmd_str and "SPAudioDataType" in cmd_str:
            return _make_subprocess_result(
                "Audio (Built-in):\n"
                "    Internal Speakers:\n"
                "        Output Channels: 2\n"
            )
        elif "com.apple.sound.default.output" in cmd_str:
            return _make_subprocess_result(stdout="HDMI Output\n")
        return _make_subprocess_result()

    return fake_run


def _fake_run_multiple_devices():
    """Multiple output devices connected"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "pgrep" in cmd_str and "coreaudiod" in cmd_str:
            return _make_subprocess_result(stdout="12345\n", returncode=0)
        elif "system_profiler" in cmd_str and "SPAudioDataType" in cmd_str:
            return _make_subprocess_result(
                "Audio (Built-in):\n"
                "    Internal Speakers:\n"
                "        Output Channels: 2\n"
                "    USB Audio Device:\n"
                "        Output Channels: 2\n"
                "    HDMI Output:\n"
                "        Output Channels: 2\n"
                "    External Headphones:\n"
                "        Output Channels: 2\n"
            )
        elif "com.apple.sound.default.output" in cmd_str:
            return _make_subprocess_result(stdout="Internal Speakers\n")
        return _make_subprocess_result()

    return fake_run


def test_coreaudio_reset_discovered():
    """Module should be discoverable"""
    mod = _get_module()
    assert mod.name == "coreaudio_reset"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE


def test_coreaudio_reset_healthy():
    """Healthy case: coreaudiod running, devices detected"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        result = mod.check(_make_profile())
    # Should have findings (devices_info) but no warnings
    assert result.has_issues
    assert any(f.data.get("check") == "devices_info" for f in result.findings)
    assert not any(f.severity == Severity.WARNING for f in result.findings)


def test_coreaudio_reset_coreaudiod_not_running():
    """CoreAudio daemon has crashed"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_coreaudiod_not_running()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "coreaudiod_not_running" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_coreaudio_reset_no_output_devices():
    """No output devices detected"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_output_devices()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "no_output_devices" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_coreaudio_reset_unexpected_device():
    """Output routed to unexpected device"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_unexpected_device()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "unexpected_output_device" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_coreaudio_reset_multiple_devices():
    """Multiple output devices detected"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_multiple_devices()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "multiple_output_devices" for f in result.findings)
    assert any(f.severity == Severity.INFO for f in result.findings)


def test_coreaudio_reset_fix_is_informational():
    """fix() should be informational and always succeed"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_coreaudiod_not_running()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action
    assert len(fix.actions) > 0
