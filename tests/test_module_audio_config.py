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
    return next(m for m in modules if m.name == "audio_config")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_healthy():
    """Normal case: audio devices found, not muted, normal volume"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "system_profiler" in cmd_str and "SPAudioDataType" in cmd_str:
            return _make_subprocess_result(
                "Audio (Built-in):\n"
                "    Internal Microphone:\n"
                "        Input Channels: 2\n"
                "    Internal Speakers:\n"
                "        Output Channels: 2\n"
            )
        elif "com.apple.sound.beep.muted" in cmd_str:
            return _make_subprocess_result(stdout="0\n")
        elif "osascript" in cmd_str:
            return _make_subprocess_result(stdout="75\n")
        elif "com.apple.sound.default.output" in cmd_str:
            return _make_subprocess_result(stdout="Internal Speakers\n")
        return _make_subprocess_result()

    return fake_run


def _fake_run_muted():
    """Audio is muted"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "system_profiler" in cmd_str and "SPAudioDataType" in cmd_str:
            return _make_subprocess_result(
                "Audio (Built-in):\n"
                "    Internal Speakers:\n"
                "        Output Channels: 2\n"
            )
        elif "com.apple.sound.beep.muted" in cmd_str:
            return _make_subprocess_result(stdout="1\n")
        elif "osascript" in cmd_str:
            return _make_subprocess_result(stdout="50\n")
        return _make_subprocess_result()

    return fake_run


def _fake_run_low_volume():
    """Volume is very low"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "system_profiler" in cmd_str and "SPAudioDataType" in cmd_str:
            return _make_subprocess_result(
                "Audio (Built-in):\n"
                "    Internal Speakers:\n"
                "        Output Channels: 2\n"
            )
        elif "com.apple.sound.beep.muted" in cmd_str:
            return _make_subprocess_result(stdout="0\n")
        elif "osascript" in cmd_str:
            return _make_subprocess_result(stdout="5\n")
        return _make_subprocess_result()

    return fake_run


def _fake_run_device_disconnected():
    """Output device is not in available devices list"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "system_profiler" in cmd_str and "SPAudioDataType" in cmd_str:
            return _make_subprocess_result(
                "Audio (Built-in):\n"
                "    Internal Speakers:\n"
                "        Output Channels: 2\n"
            )
        elif "com.apple.sound.beep.muted" in cmd_str:
            return _make_subprocess_result(stdout="0\n")
        elif "osascript" in cmd_str:
            return _make_subprocess_result(stdout="70\n")
        elif "com.apple.sound.default.output" in cmd_str:
            return _make_subprocess_result(stdout="HDMI Output\n")
        return _make_subprocess_result()

    return fake_run


def _fake_run_no_devices():
    """No audio devices detected"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "system_profiler" in cmd_str and "SPAudioDataType" in cmd_str:
            return _make_subprocess_result(
                "Audio:\n"
                "  No audio devices found.\n"
            )
        return _make_subprocess_result()

    return fake_run


def test_audio_config_discovered():
    mod = _get_module()
    assert mod.name == "audio_config"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE


def test_audio_config_healthy():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        result = mod.check(_make_profile())
    # Should have INFO findings about devices, but no warnings
    assert result.has_issues
    assert any(f.data.get("check") == "devices_info" for f in result.findings)
    assert not any(f.severity == Severity.WARNING for f in result.findings)


def test_audio_config_muted():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_muted()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "audio_muted" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_audio_config_low_volume():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_low_volume()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "volume_low" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_audio_config_device_disconnected():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_device_disconnected()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "device_not_connected" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_audio_config_no_devices():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_devices()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "no_devices_found" for f in result.findings)


def test_audio_config_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_muted()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action
    assert len(fix.actions) > 0
