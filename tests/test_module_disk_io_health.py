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
    return next(m for m in modules if m.name == "disk_io_health")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_healthy_ssd():
    """SSD with TRIM enabled - no issues"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "system_profiler SPStorageDataType" in cmd_str:
            return _make_subprocess_result(
                "Data:\n    Internal SSD:\n      Solid State Drive: Yes\n"
            )
        elif "system_profiler SPSerialATADataType" in cmd_str:
            return _make_subprocess_result(
                "SATA Controller:\n  TRIM Support: Yes\n"
            )
        elif "system_profiler SPNVMeDataType" in cmd_str:
            return _make_subprocess_result(stdout="", returncode=1)
        elif "iostat" in cmd_str:
            return _make_subprocess_result(
                "                      r/s     w/s   Kr/s   Kw/s ms/r ms/w %busy\n"
                "disk0              10.5    20.3  205.8 1024.5  1.2  2.1  45.2\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_hdd():
    """HDD detected - warning expected"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "system_profiler SPStorageDataType" in cmd_str:
            return _make_subprocess_result(
                "Data:\n    Internal HDD:\n      Solid State Drive: No\n"
            )
        elif "system_profiler SPSerialATADataType" in cmd_str:
            return _make_subprocess_result(
                "SATA Controller:\n  TRIM Support: N/A\n"
            )
        elif "system_profiler SPNVMeDataType" in cmd_str:
            return _make_subprocess_result(stdout="", returncode=1)
        elif "iostat" in cmd_str:
            return _make_subprocess_result(
                "                      r/s     w/s   Kr/s   Kw/s ms/r ms/w %busy\n"
                "disk0              25.0    15.5  512.0  256.0  5.1  3.2  78.5\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_ssd_no_trim():
    """SSD without TRIM enabled - warning expected"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "system_profiler SPStorageDataType" in cmd_str:
            return _make_subprocess_result(
                "Data:\n    SSD:\n      Solid State Drive: Yes\n"
            )
        elif "system_profiler SPSerialATADataType" in cmd_str:
            return _make_subprocess_result(
                "SATA Controller:\n  TRIM Support: No\n"
            )
        elif "system_profiler SPNVMeDataType" in cmd_str:
            return _make_subprocess_result(stdout="", returncode=1)
        elif "iostat" in cmd_str:
            return _make_subprocess_result(
                "                      r/s     w/s   Kr/s   Kw/s ms/r ms/w %busy\n"
                "disk0              12.5    18.0  220.0 980.5  1.5  2.3  50.1\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_nvme_ssd():
    """NVMe SSD - trim typically enabled"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "system_profiler SPStorageDataType" in cmd_str:
            return _make_subprocess_result(
                "Data:\n    NVMe SSD:\n      Solid State Drive: Yes\n"
            )
        elif "system_profiler SPSerialATADataType" in cmd_str:
            return _make_subprocess_result(stdout="", returncode=1)
        elif "system_profiler SPNVMeDataType" in cmd_str:
            return _make_subprocess_result(
                "NVMe Controller:\n  Model: Samsung 970 EVO\n"
            )
        elif "iostat" in cmd_str:
            return _make_subprocess_result(
                "                      r/s     w/s   Kr/s   Kw/s ms/r ms/w %busy\n"
                "disk0               8.2    14.5  180.5  890.2  0.8  1.9  38.5\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_command_failure():
    """system_profiler and iostat commands fail"""
    def fake_run(cmd, **kwargs):
        return _make_subprocess_result(stdout="", returncode=1)
    return fake_run


def test_disk_io_health_discovered():
    mod = _get_module()
    assert mod.name == "disk_io_health"
    assert mod.category == "performance"
    assert mod.risk_level == RiskLevel.SAFE


def test_disk_io_health_healthy_ssd():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy_ssd()):
        result = mod.check(_make_profile())
    assert not result.has_issues or all(
        f.severity == Severity.INFO for f in result.findings
    )


def test_disk_io_health_hdd_detected():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_hdd()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "hdd_detected" for f in result.findings)


def test_disk_io_health_ssd_no_trim():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_ssd_no_trim()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "trim_disabled" for f in result.findings)


def test_disk_io_health_nvme_ssd():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_nvme_ssd()):
        result = mod.check(_make_profile())
    assert not result.has_issues or all(
        f.severity == Severity.INFO for f in result.findings
    )


def test_disk_io_health_command_failure():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_command_failure()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "disk_info_failed" for f in result.findings)


def test_disk_io_health_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_hdd()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action
    assert len(fix.actions) > 0
