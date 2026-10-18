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
    return next(m for m in modules if m.name == "audio_troubleshoot")


def _fake_run_healthy_audio():
    """Mock subprocess for healthy audio setup (output and input, normal volume)."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""
        if isinstance(cmd, list):
            if "system_profiler" in cmd:
                result.stdout = """Audio (Intel):
    Devices:
    Internal Microphone:
        Input Channels: 2
    Internal Speakers:
        Output Channels: 2
"""
            elif cmd[0] == "defaults":
                cmd_str = " ".join(cmd)
                if "com.apple.sound.default.output" in cmd_str:
                    result.stdout = "Internal Speakers"
                elif "com.apple.sound.default.input" in cmd_str:
                    result.stdout = "Internal Microphone"
                elif "com.apple.sound.beep.muted" in cmd_str:
                    result.stdout = "0"
                else:
                    result.stdout = ""
            elif cmd[0] == "osascript":
                result.stdout = "75"
        return result
    return fake_run


def _fake_run_muted_audio():
    """Mock subprocess for muted audio."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""
        if isinstance(cmd, list):
            if "system_profiler" in cmd:
                result.stdout = """Audio (Intel):
    Devices:
    Internal Microphone:
        Input Channels: 2
    Internal Speakers:
        Output Channels: 2
"""
            elif cmd[0] == "defaults":
                cmd_str = " ".join(cmd)
                if "com.apple.sound.default.output" in cmd_str:
                    result.stdout = "Internal Speakers"
                elif "com.apple.sound.default.input" in cmd_str:
                    result.stdout = "Internal Microphone"
                elif "com.apple.sound.beep.muted" in cmd_str:
                    result.stdout = "1"
                else:
                    result.stdout = ""
            elif cmd[0] == "osascript":
                result.stdout = "50"
        return result
    return fake_run


def _fake_run_zero_volume_audio():
    """Mock subprocess for audio at zero volume."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""
        if isinstance(cmd, list):
            if "system_profiler" in cmd:
                result.stdout = """Audio (Intel):
    Devices:
    Internal Microphone:
        Input Channels: 2
    Internal Speakers:
        Output Channels: 2
"""
            elif cmd[0] == "defaults":
                cmd_str = " ".join(cmd)
                if "com.apple.sound.default.output" in cmd_str:
                    result.stdout = "Internal Speakers"
                elif "com.apple.sound.default.input" in cmd_str:
                    result.stdout = "Internal Microphone"
                elif "com.apple.sound.beep.muted" in cmd_str:
                    result.stdout = "0"
                else:
                    result.stdout = ""
            elif cmd[0] == "osascript":
                result.stdout = "0"
        return result
    return fake_run


def _fake_run_no_input_device():
    """Mock subprocess for missing input device (microphone)."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""
        if isinstance(cmd, list):
            if "system_profiler" in cmd:
                result.stdout = """Audio (Intel):
    Devices:
    Internal Speakers:
        Output Channels: 2
"""
            elif cmd[0] == "defaults":
                cmd_str = " ".join(cmd)
                if "com.apple.sound.default.output" in cmd_str:
                    result.stdout = "Internal Speakers"
                elif "com.apple.sound.default.input" in cmd_str:
                    result.stdout = ""
                elif "com.apple.sound.beep.muted" in cmd_str:
                    result.stdout = "0"
                else:
                    result.stdout = ""
            elif cmd[0] == "osascript":
                result.stdout = "60"
        return result
    return fake_run


def _fake_run_disconnected_output_device():
    """Mock subprocess for audio routed to disconnected device."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""
        if isinstance(cmd, list):
            if "system_profiler" in cmd:
                result.stdout = """Audio (Intel):
    Devices:
    Internal Microphone:
        Input Channels: 2
    Internal Speakers:
        Output Channels: 2
"""
            elif cmd[0] == "defaults":
                cmd_str = " ".join(cmd)
                if "com.apple.sound.default.output" in cmd_str:
                    result.stdout = "Headphones"
                elif "com.apple.sound.default.input" in cmd_str:
                    result.stdout = "Internal Microphone"
                elif "com.apple.sound.beep.muted" in cmd_str:
                    result.stdout = "0"
                else:
                    result.stdout = ""
            elif cmd[0] == "osascript":
                result.stdout = "50"
        return result
    return fake_run


def _fake_run_no_devices():
    """Mock subprocess for no audio devices detected."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""
        if isinstance(cmd, list):
            if "system_profiler" in cmd:
                result.stdout = "Audio (Intel):\n    No audio devices detected."
            elif cmd[0] == "defaults":
                result.stdout = ""
            elif cmd[0] == "osascript":
                result.stdout = "0"
        return result
    return fake_run


def _fake_run_hdmi_output_device():
    """Mock subprocess for audio routed to HDMI."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""
        if isinstance(cmd, list):
            if "system_profiler" in cmd:
                result.stdout = """Audio (Intel):
    Devices:
    Internal Microphone:
        Input Channels: 2
    Internal Speakers:
        Output Channels: 2
    HDMI Output:
        Output Channels: 2
"""
            elif cmd[0] == "defaults":
                cmd_str = " ".join(cmd)
                if "com.apple.sound.default.output" in cmd_str:
                    result.stdout = "HDMI Output"
                elif "com.apple.sound.default.input" in cmd_str:
                    result.stdout = "Internal Microphone"
                elif "com.apple.sound.beep.muted" in cmd_str:
                    result.stdout = "0"
                else:
                    result.stdout = ""
            elif cmd[0] == "osascript":
                result.stdout = "50"
        return result
    return fake_run


def test_audio_troubleshoot_discovered():
    mod = _get_module()
    assert mod.name == "audio_troubleshoot"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.DARWIN in mod.platforms


def test_audio_troubleshoot_healthy():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy_audio()):
        result = mod.check(_make_profile())
    # Should have INFO finding for devices, no warnings
    assert result.has_issues  # has_issues includes INFO
    assert any(f.severity == Severity.INFO for f in result.findings)
    assert not any(f.severity == Severity.WARNING for f in result.findings)


def test_audio_troubleshoot_muted():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_muted_audio()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "audio_muted" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_audio_troubleshoot_zero_volume():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_zero_volume_audio()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "volume_zero" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_audio_troubleshoot_no_input_device():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_input_device()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "no_input_device" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_audio_troubleshoot_disconnected_output():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_disconnected_output_device()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "output_device_disconnected" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_audio_troubleshoot_no_devices():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_devices()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "no_devices" for f in result.findings)
    # An empty device list is "couldn't check", not a warning (review fix)
    assert all(f.severity == Severity.INFO for f in result.findings)


def test_audio_troubleshoot_hdmi_output():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_hdmi_output_device()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "unexpected_output_device" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_audio_troubleshoot_fix_muted():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_muted_audio()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert len(fix.actions) > 0
    assert all(a.success for a in fix.actions)
    assert any("unmute" in a.title.lower() for a in fix.actions)


def test_audio_troubleshoot_fix_zero_volume():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_zero_volume_audio()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert len(fix.actions) > 0
    assert any("increase" in a.title.lower() for a in fix.actions)


def test_audio_troubleshoot_fix_no_input():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_input_device()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert any("microphone" in a.title.lower() for a in fix.actions)


def test_audio_troubleshoot_fix_disconnected():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_disconnected_output_device()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert any("switch" in a.title.lower() for a in fix.actions)


# --- Regression: real SPAudioDataType layout on macOS 26.3.1 ------------------
# Devices sit under "Devices:" at 8 spaces with details at 10. The old parser
# expected 4 spaces, found one device called "Devices", and said "No
# microphone was found" on a MacBook Pro with a built-in microphone.

_SP_AUDIO_MACOS26 = """Audio:

    Devices:

        LG ULTRAGEAR:

          Manufacturer: GSM
          Output Channels: 2
          Current SampleRate: 48000
          Transport: HDMI
          Output Source: Default

        MacBook Pro Microphone:

          Default Input Device: Yes
          Input Channels: 1
          Manufacturer: Apple Inc.
          Current SampleRate: 48000
          Transport: Built-in
          Input Source: MacBook Pro Microphone

        MacBook Pro Speakers:

          Default Output Device: Yes
          Default System Output Device: Yes
          Manufacturer: Apple Inc.
          Output Channels: 2
          Current SampleRate: 48000
          Transport: Built-in
          Output Source: MacBook Pro Speakers

"""


def _fake_macos26(profiler=_SP_AUDIO_MACOS26):
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""
        if "system_profiler" in cmd:
            result.stdout = profiler
        elif cmd[0] == "osascript":
            result.stdout = "75"
        return result
    return fake_run


def test_macos26_builtin_microphone_is_found():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_macos26()):
        result = mod.check(_make_profile())
    assert not any(f.data.get("check") == "no_input_device" for f in result.findings)


def test_macos26_parser_names_each_device():
    from importlib import import_module
    parse = import_module(type(_get_module()).__module__)._parse_audio_devices
    devices = {d["name"]: d["type"] for d in parse(_SP_AUDIO_MACOS26)}
    assert devices == {
        "LG ULTRAGEAR": "output",
        "MacBook Pro Microphone": "input",
        "MacBook Pro Speakers": "output",
    }


def test_unreadable_device_list_is_not_no_microphone():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_macos26(profiler="")):
        result = mod.check(_make_profile())
    assert not any(f.data.get("check") == "no_input_device" for f in result.findings)


def test_really_no_microphone_still_warns():
    mod = _get_module()
    no_mic = _SP_AUDIO_MACOS26.split("        MacBook Pro Microphone:")[0]
    with patch("subprocess.run", side_effect=_fake_macos26(profiler=no_mic)):
        result = mod.check(_make_profile())
    assert any(f.data.get("check") == "no_input_device" for f in result.findings)


def test_audio_heading_is_exact_not_prefix():
    """Review fix: only the 'Audio' section heading is skipped; a device whose
    name starts with 'Audio' is still a device."""
    from importlib import import_module
    parse = import_module(type(_get_module()).__module__)._parse_audio_devices
    out = (
        "Audio:\n\n    Devices:\n\n"
        "        Audio Interface 2x2:\n\n          Input Channels: 2\n"
        "          Transport: USB\n"
    )
    assert [(d["name"], d["type"]) for d in parse(out)] == [("Audio Interface 2x2", "input")]
