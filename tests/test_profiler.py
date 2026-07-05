import subprocess
from unittest.mock import patch, MagicMock

from rescue.models import Platform, SystemProfile
from rescue.profiler.base import detect_platform, gather_profile
from rescue.profiler.darwin import gather_darwin_profile, _parse_df_output, _parse_ps_output


def test_detect_platform_darwin():
    with patch("rescue.profiler.base.sys") as mock_sys:
        mock_sys.platform = "darwin"
        assert detect_platform() == Platform.DARWIN


def test_detect_platform_win32():
    with patch("rescue.profiler.base.sys") as mock_sys:
        mock_sys.platform = "win32"
        assert detect_platform() == Platform.WIN32


def test_detect_platform_linux():
    with patch("rescue.profiler.base.sys") as mock_sys:
        mock_sys.platform = "linux"
        assert detect_platform() == Platform.LINUX


def test_detect_platform_unsupported():
    with patch("rescue.profiler.base.sys") as mock_sys:
        mock_sys.platform = "freebsd"
        try:
            detect_platform()
            assert False, "Should have raised RuntimeError"
        except RuntimeError as e:
            assert "Unsupported platform" in str(e)


def test_parse_df_output():
    df_output = """Filesystem   1024-blocks      Used Available Capacity  Mounted on
/dev/disk3s1   460857696 316498192 121579504    73%    /
devfs                399       399         0   100%    /dev
/dev/disk3s5   460857696   262144 121579504     1%    /System/Volumes/VM
"""
    disks = _parse_df_output(df_output)
    assert len(disks) == 2  # /dev/ entries only, devfs excluded
    assert disks[0].mount_point == "/"
    assert disks[0].total_bytes == 460857696 * 1024
    assert disks[0].used_bytes == 316498192 * 1024


def test_parse_ps_output():
    ps_output = """USER               PID  %CPU %MEM      VSZ    RSS   TT  STAT STARTED      TIME COMMAND
root                 1   0.0  0.1 410327040  13040   ??  Ss   Sat08AM   3:22.85 /sbin/launchd
annhoward         5678  12.3  1.5 418955264  65536   ??  S    10:00AM   1:23.45 /Applications/Spotify.app/Contents/MacOS/Spotify
"""
    processes = _parse_ps_output(ps_output)
    assert len(processes) == 2
    assert processes[0].pid == 1
    assert processes[0].name == "launchd"
    assert processes[1].cpu_percent == 12.3
    assert processes[1].name == "Spotify"


def test_gather_darwin_profile():
    mock_results = {
        ("sysctl", "-n", "machdep.cpu.brand_string"): "Apple M2",
        ("sysctl", "-n", "hw.ncpu"): "8",
        ("sysctl", "-n", "hw.memsize"): "17179869184",
        ("hostname",): "test-mac.local",
    }

    df_output = """Filesystem   1024-blocks      Used Available Capacity  Mounted on
/dev/disk3s1   460857696 316498192 121579504    73%    /
"""

    ps_output = """USER               PID  %CPU %MEM      VSZ    RSS   TT  STAT STARTED      TIME COMMAND
root                 1   0.0  0.1 410327040  13040   ??  Ss   Sat08AM   3:22.85 /sbin/launchd
"""

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        cmd_tuple = tuple(cmd)
        if cmd_tuple in mock_results:
            result.stdout = mock_results[cmd_tuple]
        elif cmd_tuple == ("df", "-k"):
            result.stdout = df_output
        elif cmd_tuple[0] == "ps":
            result.stdout = ps_output
        else:
            result.stdout = ""
        result.returncode = 0
        return result

    with patch("rescue.profiler.darwin.subprocess.run", side_effect=fake_run), \
         patch("rescue.profiler.darwin.platform.mac_ver", return_value=("15.2", ("", "", ""), "")), \
         patch("rescue.profiler.darwin.platform.machine", return_value="arm64"):
        profile = gather_darwin_profile()

    assert profile.platform == Platform.DARWIN
    assert profile.os_name == "macOS"
    assert profile.os_version == "15.2"
    assert profile.architecture == "arm64"
    assert profile.cpu_model == "Apple M2"
    assert profile.cpu_cores == 8
    assert profile.ram_bytes == 17179869184
    assert profile.hostname == "test-mac.local"
    assert len(profile.disks) == 1
    assert len(profile.processes) == 1
