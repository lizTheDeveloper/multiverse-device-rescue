import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


def _make_profile(ram_bytes=16 * 1024**3):
    return SystemProfile(
        platform=Platform.DARWIN,
        os_name="macOS",
        os_version="15.2",
        architecture="arm64",
        cpu_model="Apple M2",
        cpu_cores=8,
        ram_bytes=ram_bytes,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "swap_usage")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_healthy():
    """Normal case: minimal swap usage"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "vm.swapusage" in cmd_str:
            return _make_subprocess_result(
                "vm.swapusage: total = 4096.00M  used = 512.00M  free = 3584.00M  (encrypted)\n"
            )
        elif "vm.compressor_mode" in cmd_str:
            return _make_subprocess_result(
                "vm.compressor_mode: 1\n"
            )
        elif "kern.memorystatus_vm_pressure_level" in cmd_str:
            return _make_subprocess_result(
                "kern.memorystatus_vm_pressure_level: 0\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_warning():
    """Warning case: swap > 50% of RAM"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "vm.swapusage" in cmd_str:
            # 16GB RAM, swap 9GB (56% of RAM)
            return _make_subprocess_result(
                "vm.swapusage: total = 16384.00M  used = 9216.00M  free = 7168.00M  (encrypted)\n"
            )
        elif "vm.compressor_mode" in cmd_str:
            return _make_subprocess_result(
                "vm.compressor_mode: 1\n"
            )
        elif "kern.memorystatus_vm_pressure_level" in cmd_str:
            return _make_subprocess_result(
                "kern.memorystatus_vm_pressure_level: 1\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_critical():
    """Critical case: swap > physical RAM"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "vm.swapusage" in cmd_str:
            # 16GB RAM, swap 20GB (exceeds RAM)
            return _make_subprocess_result(
                "vm.swapusage: total = 32768.00M  used = 20480.00M  free = 12288.00M  (encrypted)\n"
            )
        elif "vm.compressor_mode" in cmd_str:
            return _make_subprocess_result(
                "vm.compressor_mode: 1\n"
            )
        elif "kern.memorystatus_vm_pressure_level" in cmd_str:
            return _make_subprocess_result(
                "kern.memorystatus_vm_pressure_level: 2\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_compressor_disabled():
    """Case: memory compression disabled"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "vm.swapusage" in cmd_str:
            return _make_subprocess_result(
                "vm.swapusage: total = 4096.00M  used = 256.00M  free = 3840.00M  (encrypted)\n"
            )
        elif "vm.compressor_mode" in cmd_str:
            return _make_subprocess_result(
                "vm.compressor_mode: 0\n"
            )
        elif "kern.memorystatus_vm_pressure_level" in cmd_str:
            return _make_subprocess_result(
                "kern.memorystatus_vm_pressure_level: 0\n"
            )
        return _make_subprocess_result()
    return fake_run


def test_swap_usage_discovered():
    mod = _get_module()
    assert mod.name == "swap_usage"
    assert mod.category == "performance"
    assert mod.risk_level == RiskLevel.SAFE


def test_swap_usage_healthy():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        result = mod.check(_make_profile())
    # Healthy case should have INFO findings but no WARNING/CRITICAL
    assert result.has_issues
    assert not any(
        f.severity == Severity.CRITICAL for f in result.findings
    )
    assert not any(
        f.severity == Severity.WARNING for f in result.findings
    )


def test_swap_usage_warning():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_warning()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "warning_swap_usage" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_swap_usage_critical():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_critical()):
        result = mod.check(_make_profile(ram_bytes=16 * 1024**3))
    assert result.has_issues
    assert any(f.data.get("check") == "critical_swap_exceeds_ram" for f in result.findings)
    assert any(f.severity == Severity.CRITICAL for f in result.findings)


def test_swap_usage_compressor_disabled():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_compressor_disabled()):
        result = mod.check(_make_profile())
    assert result.has_issues
    compressor_finding = next(
        (f for f in result.findings if f.data.get("check") == "compressor_mode"),
        None,
    )
    assert compressor_finding is not None
    assert compressor_finding.data.get("compressor_mode") == 0


def test_swap_usage_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_warning()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action for warning
    assert len(fix.actions) > 0
