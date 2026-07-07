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
    return next(m for m in modules if m.name == "gpu_health")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_healthy():
    """Normal case: GPU with Metal support, good VRAM, no panics"""

    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "system_profiler" in cmd_str and "SPDisplaysDataType" in cmd_str:
            return _make_subprocess_result(
                stdout="""Graphics/Displays:

  Apple M2:

    Chipset Model: Apple M2
    Type: Integrated GPU
    Vendor: Apple
    VRAM (Dynamic, Shared): 4 GB
    Metal Support: Supported
"""
            )
        elif "log show" in cmd_str and "GPU" in cmd_str:
            return _make_subprocess_result(stdout="")
        return _make_subprocess_result()

    return fake_run


def _fake_run_no_metal():
    """GPU without Metal support"""

    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "system_profiler" in cmd_str and "SPDisplaysDataType" in cmd_str:
            return _make_subprocess_result(
                stdout="""Graphics/Displays:

  Intel HD Graphics 4000:

    Chipset Model: Intel HD Graphics 4000
    Type: Integrated GPU
    Vendor: Intel
    VRAM (Shared): 1536 MB
"""
            )
        elif "log show" in cmd_str and "GPU" in cmd_str:
            return _make_subprocess_result(stdout="")
        return _make_subprocess_result()

    return fake_run


def _fake_run_low_vram():
    """GPU with very low VRAM"""

    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "system_profiler" in cmd_str and "SPDisplaysDataType" in cmd_str:
            return _make_subprocess_result(
                stdout="""Graphics/Displays:

  Apple M2:

    Chipset Model: Apple M2
    Type: Integrated GPU
    Vendor: Apple
    VRAM (Dynamic, Shared): 256 MB
"""
            )
        elif "log show" in cmd_str and "GPU" in cmd_str:
            return _make_subprocess_result(stdout="")
        return _make_subprocess_result()

    return fake_run


def _fake_run_with_panics():
    """GPU with kernel panics"""

    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "system_profiler" in cmd_str and "SPDisplaysDataType" in cmd_str:
            return _make_subprocess_result(
                stdout="""Graphics/Displays:

  Apple M2:

    Chipset Model: Apple M2
    Type: Integrated GPU
    Vendor: Apple
    VRAM (Dynamic, Shared): 4 GB
"""
            )
        elif "log show" in cmd_str and "GPU" in cmd_str:
            return _make_subprocess_result(
                stdout="""2026-07-05 10:23:45.123 kernel GPU panic detected
2026-07-04 14:11:22.456 kernel GPU device reset
2026-07-03 09:45:33.789 kernel GPU fault error"""
            )
        return _make_subprocess_result()

    return fake_run


def _fake_run_no_gpu_info():
    """System profiler returns empty"""

    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "system_profiler" in cmd_str and "SPDisplaysDataType" in cmd_str:
            return _make_subprocess_result(stdout="", returncode=1)
        elif "log show" in cmd_str and "GPU" in cmd_str:
            return _make_subprocess_result(stdout="")
        return _make_subprocess_result()

    return fake_run


def test_gpu_health_discovered():
    mod = _get_module()
    assert mod.name == "gpu_health"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE


def test_gpu_health_healthy():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        result = mod.check(_make_profile())
    # Should have GPU info but no warnings
    assert result.has_issues
    assert any(f.data.get("check") == "gpu_info" for f in result.findings)
    # No warnings about Metal, VRAM, or panics
    assert not any(f.severity == Severity.WARNING for f in result.findings)


def test_gpu_health_no_metal_support():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_metal()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(
        f.data.get("check") == "no_metal_support" for f in result.findings
    )


def test_gpu_health_low_vram():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_low_vram()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "low_vram" for f in result.findings)


def test_gpu_health_with_panics():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_with_panics()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(
        f.data.get("check") == "gpu_kernel_panics" for f in result.findings
    )


def test_gpu_health_no_gpu_info():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_gpu_info()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "no_gpu_info" for f in result.findings)


def test_gpu_health_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action
    assert len(fix.actions) > 0
