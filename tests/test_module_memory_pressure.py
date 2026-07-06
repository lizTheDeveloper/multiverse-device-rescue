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
        ram_bytes=8 * 1024**3,  # 8 GB
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "memory_pressure")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_healthy():
    """Normal case: no memory pressure issues"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        # 8 GB machine
        if "sysctl" in cmd_str and "hw.memsize" in cmd_str:
            # 8GB = 8589934592 bytes
            return _make_subprocess_result(
                "hw.memsize: 8589934592\n"
            )
        elif "vm_stat" in cmd_str:
            # Apple Silicon: page size 16384 bytes
            # 8GB = 8589934592 bytes = 524288 pages
            # 50% free, 30% active, 15% inactive, 5% wired, 0 compressed
            vm_stat_output = (
                "Mach Virtual Memory Statistics: (page size of 16384 bytes)\n"
                "Pages free:                        262144.\n"  # 50% = 4GB
                "Pages active:                      157286.\n"  # 30% = 2.4GB
                "Pages inactive:                     78643.\n"  # 15% = 1.2GB
                "Pages speculative:                      0.\n"
                "Pages throttled:                        0.\n"
                "Pages wired down:                   26214.\n"  # 5% = 0.4GB
                "Pages purgeable:                        0.\n"
                "File-backed pages:                      0.\n"
                "Pages stolen by iokit:                  0.\n"
                "Compressed pages:                       0.\n"
            )
            return _make_subprocess_result(vm_stat_output)
        elif "sysctl" in cmd_str and "vm.swapusage" in cmd_str:
            # No swap usage
            return _make_subprocess_result(
                "vm.swapusage: total = 0.00M  used = 0.00M  free = 0.00M  (encrypted)\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_warning_swap():
    """Warning: 2.5 GB swap used"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        # 8 GB machine
        if "sysctl" in cmd_str and "hw.memsize" in cmd_str:
            return _make_subprocess_result("hw.memsize: 8589934592\n")
        elif "vm_stat" in cmd_str:
            vm_stat_output = (
                "Mach Virtual Memory Statistics: (page size of 16384 bytes)\n"
                "Pages free:                        262144.\n"
                "Pages active:                      157286.\n"
                "Pages inactive:                     78643.\n"
                "Pages speculative:                      0.\n"
                "Pages throttled:                        0.\n"
                "Pages wired down:                   26214.\n"
                "Pages purgeable:                        0.\n"
                "File-backed pages:                      0.\n"
                "Pages stolen by iokit:                  0.\n"
                "Compressed pages:                       0.\n"
            )
            return _make_subprocess_result(vm_stat_output)
        elif "sysctl" in cmd_str and "vm.swapusage" in cmd_str:
            # 2.5 GB swap used (should trigger WARNING)
            return _make_subprocess_result(
                "vm.swapusage: total = 4096.00M  used = 2560.00M  free = 1536.00M  (encrypted)\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_critical_swap():
    """Critical: 60% of physical RAM as swap (4.8 GB swap on 8 GB machine)"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        # 8 GB machine
        if "sysctl" in cmd_str and "hw.memsize" in cmd_str:
            return _make_subprocess_result("hw.memsize: 8589934592\n")
        elif "vm_stat" in cmd_str:
            vm_stat_output = (
                "Mach Virtual Memory Statistics: (page size of 16384 bytes)\n"
                "Pages free:                        262144.\n"
                "Pages active:                      157286.\n"
                "Pages inactive:                     78643.\n"
                "Pages speculative:                      0.\n"
                "Pages throttled:                        0.\n"
                "Pages wired down:                   26214.\n"
                "Pages purgeable:                        0.\n"
                "File-backed pages:                      0.\n"
                "Pages stolen by iokit:                  0.\n"
                "Compressed pages:                       0.\n"
            )
            return _make_subprocess_result(vm_stat_output)
        elif "sysctl" in cmd_str and "vm.swapusage" in cmd_str:
            # 4.8 GB swap = 60% of 8 GB (should trigger CRITICAL)
            return _make_subprocess_result(
                "vm.swapusage: total = 10240.00M  used = 4915.20M  free = 5324.80M  (encrypted)\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_warning_memory_pressure():
    """Warning: free+inactive pages < 10% of total"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        # 8 GB machine
        if "sysctl" in cmd_str and "hw.memsize" in cmd_str:
            return _make_subprocess_result("hw.memsize: 8589934592\n")
        elif "vm_stat" in cmd_str:
            # Total: 524288 pages
            # Free + Inactive should be < 52428 (10%)
            # Let's say: free=20000, inactive=20000, total=40000 (7.6%)
            vm_stat_output = (
                "Mach Virtual Memory Statistics: (page size of 16384 bytes)\n"
                "Pages free:                         20000.\n"  # 3.8%
                "Pages active:                      300000.\n"  # 57.2%
                "Pages inactive:                     20000.\n"  # 3.8%
                "Pages speculative:                      0.\n"
                "Pages throttled:                        0.\n"
                "Pages wired down:                  180000.\n"  # 34.4%
                "Pages purgeable:                        0.\n"
                "File-backed pages:                      0.\n"
                "Pages stolen by iokit:                  0.\n"
                "Compressed pages:                    4288.\n"  # Some compressed
            )
            return _make_subprocess_result(vm_stat_output)
        elif "sysctl" in cmd_str and "vm.swapusage" in cmd_str:
            return _make_subprocess_result(
                "vm.swapusage: total = 0.00M  used = 0.00M  free = 0.00M  (encrypted)\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_with_compressed():
    """Healthy but with significant compressed memory"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        # 8 GB machine
        if "sysctl" in cmd_str and "hw.memsize" in cmd_str:
            return _make_subprocess_result("hw.memsize: 8589934592\n")
        elif "vm_stat" in cmd_str:
            vm_stat_output = (
                "Mach Virtual Memory Statistics: (page size of 16384 bytes)\n"
                "Pages free:                        262144.\n"
                "Pages active:                      157286.\n"
                "Pages inactive:                     78643.\n"
                "Pages speculative:                      0.\n"
                "Pages throttled:                        0.\n"
                "Pages wired down:                   26214.\n"
                "Pages purgeable:                        0.\n"
                "File-backed pages:                      0.\n"
                "Pages stolen by iokit:                  0.\n"
                "Compressed pages:                  100000.\n"  # ~1.5 GB compressed
            )
            return _make_subprocess_result(vm_stat_output)
        elif "sysctl" in cmd_str and "vm.swapusage" in cmd_str:
            return _make_subprocess_result(
                "vm.swapusage: total = 0.00M  used = 0.00M  free = 0.00M  (encrypted)\n"
            )
        return _make_subprocess_result()
    return fake_run


def test_memory_pressure_module_discovered():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    names = [m.name for m in modules]
    assert "memory_pressure" in names


def test_memory_pressure_module_metadata():
    mod = _get_module()
    assert mod.name == "memory_pressure"
    assert mod.category == "performance"
    assert mod.platforms == [Platform.DARWIN]
    assert mod.risk_level == RiskLevel.SAFE


def test_memory_pressure_healthy():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        result = mod.check(_make_profile())
    assert not result.has_issues


def test_memory_pressure_warning_swap():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_warning_swap()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.severity == Severity.WARNING for f in result.findings)
    assert any("swap" in f.title.lower() for f in result.findings)


def test_memory_pressure_critical_swap():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_critical_swap()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.severity == Severity.CRITICAL for f in result.findings)


def test_memory_pressure_warning_low_free_pages():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_warning_memory_pressure()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_memory_pressure_with_compressed_memory():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_with_compressed()):
        result = mod.check(_make_profile())
    # Should be healthy but might report compressed memory info
    # At least should complete without error
    assert isinstance(result.findings, list)


def test_memory_pressure_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_warning_swap()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.AUTO)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action for any finding
    if check.has_issues:
        assert len(fix.actions) > 0


def test_memory_pressure_report():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_warning_swap()):
        check = mod.check(_make_profile())
        report = mod.report(check)
    assert "memory_pressure" in report
