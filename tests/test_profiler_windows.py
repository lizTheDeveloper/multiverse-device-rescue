from unittest.mock import patch, MagicMock

from rescue.models import Platform
from rescue.profiler.base import gather_profile
from rescue.profiler.windows import (
    gather_windows_profile,
    _parse_wmic_list,
    _parse_disk_rows,
    _parse_process_rows,
)


def test_parse_wmic_list_single_block():
    output = "Caption=C:\r\nFreeSpace=107374182400\r\nSize=256060514304\r\n"
    rows = _parse_wmic_list(output)
    assert rows == [
        {"Caption": "C:", "FreeSpace": "107374182400", "Size": "256060514304"}
    ]


def test_parse_wmic_list_multiple_blocks():
    output = (
        "Caption=C:\r\n"
        "FreeSpace=107374182400\r\n"
        "Size=256060514304\r\n"
        "\r\n"
        "Caption=D:\r\n"
        "FreeSpace=53687091200\r\n"
        "Size=107374182400\r\n"
    )
    rows = _parse_wmic_list(output)
    assert len(rows) == 2
    assert rows[0]["Caption"] == "C:"
    assert rows[1]["Caption"] == "D:"


def test_parse_disk_rows():
    rows = [
        {"Caption": "C:", "FreeSpace": "107374182400", "Size": "256060514304"},
        {"Caption": "D:", "FreeSpace": "", "Size": "107374182400"},
    ]
    disks = _parse_disk_rows(rows)
    assert len(disks) == 2
    assert disks[0].device == "C:"
    assert disks[0].mount_point == "C:"
    assert disks[0].total_bytes == 256060514304
    assert disks[0].free_bytes == 107374182400
    assert disks[0].used_bytes == 256060514304 - 107374182400
    assert disks[0].filesystem == "NTFS"
    # blank FreeSpace defaults to 0 instead of crashing
    assert disks[1].free_bytes == 0
    assert disks[1].used_bytes == 107374182400


def test_parse_process_rows():
    rows = [
        {"Name": "explorer.exe", "ProcessId": "4321", "WorkingSetSize": "52428800"},
        {"Name": "svchost.exe", "ProcessId": "812", "WorkingSetSize": ""},
    ]
    processes = _parse_process_rows(rows)
    assert len(processes) == 2
    assert processes[0].pid == 4321
    assert processes[0].name == "explorer.exe"
    assert processes[0].memory_bytes == 52428800
    assert processes[1].memory_bytes == 0


def test_gather_windows_profile():
    os_output = "Caption=Microsoft Windows 11 Pro\r\nVersion=10.0.22621\r\n"
    cpu_output = "Name=Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz\r\nNumberOfCores=8\r\n"
    mem_output = "TotalPhysicalMemory=17179869184\r\n"
    disk_output = (
        "Caption=C:\r\nFreeSpace=107374182400\r\nSize=256060514304\r\n"
        "\r\n"
        "Caption=D:\r\nFreeSpace=53687091200\r\nSize=107374182400\r\n"
    )
    process_output = (
        "Name=explorer.exe\r\nProcessId=4321\r\nWorkingSetSize=52428800\r\n"
    )

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        cmd = tuple(cmd)
        if cmd[:2] == ("wmic", "os"):
            result.stdout = os_output
        elif cmd[:2] == ("wmic", "cpu"):
            result.stdout = cpu_output
        elif cmd[:2] == ("wmic", "computersystem"):
            result.stdout = mem_output
        elif cmd[:2] == ("wmic", "logicaldisk"):
            result.stdout = disk_output
        elif cmd[:2] == ("wmic", "process"):
            result.stdout = process_output
        elif cmd == ("hostname",):
            result.stdout = "DESKTOP-TEST\r\n"
        else:
            result.stdout = ""
        return result

    with patch("rescue.profiler.windows.subprocess.run", side_effect=fake_run), \
         patch("rescue.profiler.windows.platform.machine", return_value="AMD64"):
        profile = gather_windows_profile()

    assert profile.platform == Platform.WIN32
    assert profile.os_name == "Microsoft Windows 11 Pro"
    assert profile.os_version == "10.0.22621"
    assert profile.architecture == "AMD64"
    assert profile.cpu_model == "Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz"
    assert profile.cpu_cores == 8
    assert profile.ram_bytes == 17179869184
    assert profile.hostname == "DESKTOP-TEST"
    assert len(profile.disks) == 2
    assert len(profile.processes) == 1


def test_gather_profile_dispatches_to_windows():
    with patch("rescue.profiler.base.sys") as mock_sys, \
         patch("rescue.profiler.windows.gather_windows_profile") as mock_gather:
        mock_sys.platform = "win32"
        mock_gather.return_value = "fake-profile"
        result = gather_profile()

    assert result == "fake-profile"
    mock_gather.assert_called_once()
