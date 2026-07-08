import json
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


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
    return next(m for m in modules if m.name == "win_audio_check")


def _make_run_result(
    devices=None,
    audio_service_status=None,
    endpoint_service_status=None,
    device_query_fail=False,
):
    """Create a fake subprocess.run that returns appropriate results."""

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        # Handle device query failure
        if device_query_fail and "powershell" in cmd_str and "Get-PnpDevice" in cmd_str and "AudioEndpoint" in cmd_str:
            result.returncode = 1
            return result

        # PowerShell: Get audio endpoint devices
        if "powershell" in cmd_str and "Get-PnpDevice" in cmd_str and "AudioEndpoint" in cmd_str:
            if devices is not None:
                result.stdout = json.dumps(devices)
            else:
                result.stdout = json.dumps([
                    {
                        "FriendlyName": "Speakers",
                        "Status": "OK",
                        "InstanceId": "HDAUDIO\\FUNC_01&VEN_10EC&DEV_0269"
                    }
                ])

        # sc query: Get service status
        elif "sc" in cmd and "query" in cmd_str:
            if "Audiosrv" in cmd_str:
                if audio_service_status:
                    result.stdout = audio_service_status
                else:
                    # Default: service running, automatic startup
                    result.stdout = (
                        "SERVICE_NAME: Audiosrv\n"
                        "        TYPE               : 20  WIN32_SHARE_PROCESS\n"
                        "        STATE              : 4  RUNNING\n"
                        "        WIN32_EXIT_CODE    : 0  (0x0)\n"
                        "        SERVICE_EXIT_CODE  : 0  (0x0)\n"
                        "        CHECKPOINT         : 0x0\n"
                        "        WAIT_HINT          : 0x0\n"
                        "        START_TYPE         : 2  AUTO_START\n"
                    )
            elif "AudioEndpointBuilder" in cmd_str:
                if endpoint_service_status:
                    result.stdout = endpoint_service_status
                else:
                    # Default: service running, automatic startup
                    result.stdout = (
                        "SERVICE_NAME: AudioEndpointBuilder\n"
                        "        TYPE               : 20  WIN32_SHARE_PROCESS\n"
                        "        STATE              : 4  RUNNING\n"
                        "        WIN32_EXIT_CODE    : 0  (0x0)\n"
                        "        SERVICE_EXIT_CODE  : 0  (0x0)\n"
                        "        CHECKPOINT         : 0x0\n"
                        "        WAIT_HINT          : 0x0\n"
                        "        START_TYPE         : 2  AUTO_START\n"
                    )

        return result

    return fake_run


def test_win_audio_check_discovered():
    """Test that module is properly discovered."""
    mod = _get_module()
    assert mod.name == "win_audio_check"
    assert mod.category == "integrity"
    assert Platform.WIN32 in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_win_audio_check_device_found():
    """Test detection of working audio device."""
    mod = _get_module()
    devices = [
        {
            "FriendlyName": "Speakers",
            "Status": "OK",
            "InstanceId": "HDAUDIO\\FUNC_01&VEN_10EC"
        }
    ]
    fake_run = _make_run_result(devices=devices)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "device_info" for f in result.findings)
    device_finding = [f for f in result.findings if f.data.get("check") == "device_info"]
    assert device_finding[0].severity == Severity.INFO


def test_win_audio_check_device_error():
    """Test detection of audio device with error status."""
    mod = _get_module()
    devices = [
        {
            "FriendlyName": "Speakers",
            "Status": "Error",
            "InstanceId": "HDAUDIO\\FUNC_01&VEN_10EC"
        }
    ]
    fake_run = _make_run_result(devices=devices)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "device_error" for f in result.findings)
    error_finding = [f for f in result.findings if f.data.get("check") == "device_error"]
    assert error_finding[0].severity == Severity.WARNING


def test_win_audio_check_audio_service_stopped():
    """Test detection of stopped Windows Audio service (CRITICAL)."""
    mod = _get_module()
    service_status = (
        "SERVICE_NAME: Audiosrv\n"
        "        TYPE               : 20  WIN32_SHARE_PROCESS\n"
        "        STATE              : 1  STOPPED\n"
        "        WIN32_EXIT_CODE    : 0  (0x0)\n"
        "        SERVICE_EXIT_CODE  : 0  (0x0)\n"
        "        CHECKPOINT         : 0x0\n"
        "        WAIT_HINT          : 0x0\n"
        "        START_TYPE         : 2  AUTO_START\n"
    )
    fake_run = _make_run_result(audio_service_status=service_status)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "audio_service_not_running" for f in result.findings)
    service_error = [f for f in result.findings if f.data.get("check") == "audio_service_not_running"]
    assert service_error[0].severity == Severity.CRITICAL


def test_win_audio_check_audio_service_running():
    """Test when Windows Audio service is running."""
    mod = _get_module()
    service_status = (
        "SERVICE_NAME: Audiosrv\n"
        "        TYPE               : 20  WIN32_SHARE_PROCESS\n"
        "        STATE              : 4  RUNNING\n"
        "        START_TYPE         : 2  AUTO_START\n"
    )
    fake_run = _make_run_result(audio_service_status=service_status)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "audio_service_status" for f in result.findings)
    service_info = [f for f in result.findings if f.data.get("check") == "audio_service_status"]
    assert service_info[0].severity == Severity.INFO


def test_win_audio_check_endpoint_builder_stopped():
    """Test detection of stopped Audio Endpoint Builder service (WARNING)."""
    mod = _get_module()
    endpoint_status = (
        "SERVICE_NAME: AudioEndpointBuilder\n"
        "        TYPE               : 20  WIN32_SHARE_PROCESS\n"
        "        STATE              : 1  STOPPED\n"
        "        WIN32_EXIT_CODE    : 0  (0x0)\n"
        "        SERVICE_EXIT_CODE  : 0  (0x0)\n"
        "        CHECKPOINT         : 0x0\n"
        "        WAIT_HINT          : 0x0\n"
        "        START_TYPE         : 2  AUTO_START\n"
    )
    fake_run = _make_run_result(endpoint_service_status=endpoint_status)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "endpoint_builder_not_running" for f in result.findings)
    endpoint_error = [f for f in result.findings if f.data.get("check") == "endpoint_builder_not_running"]
    assert endpoint_error[0].severity == Severity.WARNING


def test_win_audio_check_endpoint_builder_running():
    """Test when Audio Endpoint Builder service is running."""
    mod = _get_module()
    endpoint_status = (
        "SERVICE_NAME: AudioEndpointBuilder\n"
        "        TYPE               : 20  WIN32_SHARE_PROCESS\n"
        "        STATE              : 4  RUNNING\n"
        "        START_TYPE         : 2  AUTO_START\n"
    )
    fake_run = _make_run_result(endpoint_service_status=endpoint_status)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "endpoint_builder_status" for f in result.findings)
    endpoint_info = [f for f in result.findings if f.data.get("check") == "endpoint_builder_status"]
    assert endpoint_info[0].severity == Severity.INFO


def test_win_audio_check_device_query_failed():
    """Test handling of failed device query."""
    mod = _get_module()
    fake_run = _make_run_result(device_query_fail=True)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "device_query_failed" for f in result.findings)
    failed = [f for f in result.findings if f.data.get("check") == "device_query_failed"]
    assert failed[0].severity == Severity.WARNING


def test_win_audio_check_multiple_devices():
    """Test detection of multiple audio devices."""
    mod = _get_module()
    devices = [
        {
            "FriendlyName": "Speakers",
            "Status": "OK",
            "InstanceId": "HDAUDIO\\FUNC_01&VEN_10EC"
        },
        {
            "FriendlyName": "Headphones",
            "Status": "OK",
            "InstanceId": "HDAUDIO\\FUNC_02&VEN_10EC"
        }
    ]
    fake_run = _make_run_result(devices=devices)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    device_infos = [f for f in result.findings if f.data.get("check") == "device_info"]
    assert len(device_infos) == 2


def test_win_audio_check_no_devices():
    """Test handling when no audio devices are found."""
    mod = _get_module()
    fake_run = _make_run_result(devices=[])
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "no_devices" for f in result.findings)
    no_devices = [f for f in result.findings if f.data.get("check") == "no_devices"]
    assert no_devices[0].severity == Severity.WARNING


def test_win_audio_check_fix_device_error():
    """Test fix recommendation for device error."""
    mod = _get_module()
    devices = [
        {
            "FriendlyName": "Speakers",
            "Status": "Error",
            "InstanceId": "HDAUDIO\\FUNC_01&VEN_10EC"
        }
    ]
    fake_run = _make_run_result(devices=devices)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    device_actions = [a for a in fix.actions if "device" in a.title.lower()]
    assert len(device_actions) > 0


def test_win_audio_check_fix_audio_service_error():
    """Test fix recommendation for stopped audio service."""
    mod = _get_module()
    service_status = (
        "SERVICE_NAME: Audiosrv\n"
        "        STATE              : 1  STOPPED\n"
        "        START_TYPE         : 2  AUTO_START\n"
    )
    fake_run = _make_run_result(audio_service_status=service_status)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    service_actions = [a for a in fix.actions if "audio" in a.title.lower() and "service" in a.title.lower()]
    assert len(service_actions) > 0


def test_win_audio_check_fix_endpoint_builder_error():
    """Test fix recommendation for stopped endpoint builder service."""
    mod = _get_module()
    endpoint_status = (
        "SERVICE_NAME: AudioEndpointBuilder\n"
        "        STATE              : 1  STOPPED\n"
        "        START_TYPE         : 2  AUTO_START\n"
    )
    fake_run = _make_run_result(endpoint_service_status=endpoint_status)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    endpoint_actions = [a for a in fix.actions if "endpoint" in a.title.lower()]
    assert len(endpoint_actions) > 0


def test_win_audio_check_handles_subprocess_error():
    """Test graceful handling of subprocess errors."""
    mod = _get_module()

    def error_run(cmd, **kwargs):
        raise OSError("Command failed")

    with patch("subprocess.run", side_effect=error_run):
        result = mod.check(_make_profile())
    # Should handle error gracefully
    assert isinstance(result.findings, list)
