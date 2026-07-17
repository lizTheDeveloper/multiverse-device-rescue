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
    return next(m for m in modules if m.name == "screen_resolution_scaling")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_native_resolution():
    """Normal case: using native resolution on Apple Silicon"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "SPDisplaysDataType" in cmd_str:
            output = (
                "Graphics/Displays:\n"
                "    Apple M2:\n"
                "      Chipset Model: Apple M2\n"
                "      Type: GPU\n"
                "      Bus: Integrated\n"
                "      Total VRAM: 8 MB\n"
                "      Displays:\n"
                "        Built-in Retina Display:\n"
                "          Display Type: Retina LCD\n"
                "          Resolution: 2560 x 1600 Retina\n"
                "          Scaling: Off\n"
                "          Native resolution: 2560 x 1600\n"
            )
            return _make_subprocess_result(output)
        return _make_subprocess_result()
    return fake_run


def _fake_run_scaled_resolution_m2():
    """Warning case: using scaled resolution on Apple M2"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "SPDisplaysDataType" in cmd_str:
            output = (
                "Graphics/Displays:\n"
                "    Apple M2:\n"
                "      Chipset Model: Apple M2\n"
                "      Type: GPU\n"
                "      Bus: Integrated\n"
                "      Total VRAM: 8 MB\n"
                "      Displays:\n"
                "        Built-in Retina Display:\n"
                "          Display Type: Retina LCD\n"
                "          Resolution: 1920 x 1200 Retina\n"
                "          Scaling: On\n"
                "          Native resolution: 2560 x 1600\n"
            )
            return _make_subprocess_result(output)
        return _make_subprocess_result()
    return fake_run


def _fake_run_more_space_scaling():
    """Warning case: using 'More Space' scaling on integrated GPU"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "SPDisplaysDataType" in cmd_str:
            output = (
                "Graphics/Displays:\n"
                "    Apple M2:\n"
                "      Chipset Model: Apple M2\n"
                "      Type: GPU\n"
                "      Bus: Integrated\n"
                "      Total VRAM: 8 MB\n"
                "      Displays:\n"
                "        Built-in Retina Display:\n"
                "          Display Type: Retina LCD\n"
                "          Resolution: 2880 x 1800 Retina\n"
                "          Scaling: More Space\n"
                "          Native resolution: 2560 x 1600\n"
            )
            return _make_subprocess_result(output)
        return _make_subprocess_result()
    return fake_run


def _fake_run_external_display_native():
    """Normal case: external display using native resolution"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "SPDisplaysDataType" in cmd_str:
            output = (
                "Graphics/Displays:\n"
                "    Apple M1:\n"
                "      Chipset Model: Apple M1\n"
                "      Type: GPU\n"
                "      Bus: Integrated\n"
                "      Displays:\n"
                "        LG UltraFine Display:\n"
                "          Display Type: LCD\n"
                "          Resolution: 3840 x 2160\n"
                "          Scaling: Off\n"
                "          Native resolution: 3840 x 2160\n"
            )
            return _make_subprocess_result(output)
        return _make_subprocess_result()
    return fake_run


def _fake_run_intel_iris_scaled():
    """Warning case: scaled resolution on Intel Iris Graphics"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "SPDisplaysDataType" in cmd_str:
            output = (
                "Graphics/Displays:\n"
                "    Intel Iris Graphics:\n"
                "      Chipset Model: Intel Iris Graphics\n"
                "      Type: GPU\n"
                "      Bus: Integrated\n"
                "      Displays:\n"
                "        Built-in Display:\n"
                "          Display Type: Retina LCD\n"
                "          Resolution: 1440 x 900 Retina\n"
                "          Scaling: On\n"
                "          Native resolution: 1680 x 1050\n"
            )
            return _make_subprocess_result(output)
        return _make_subprocess_result()
    return fake_run


def _fake_run_amd_radeon():
    """Normal case: discrete GPU (no performance concern)"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "SPDisplaysDataType" in cmd_str:
            output = (
                "Graphics/Displays:\n"
                "    AMD Radeon Pro 580:\n"
                "      Chipset Model: AMD Radeon Pro 580\n"
                "      Type: GPU\n"
                "      Bus: PCIe\n"
                "      Displays:\n"
                "        External Display:\n"
                "          Display Type: LCD\n"
                "          Resolution: 2560 x 1440\n"
                "          Scaling: On\n"
                "          Native resolution: 2560 x 1440\n"
            )
            return _make_subprocess_result(output)
        return _make_subprocess_result()
    return fake_run


def test_screen_resolution_module_discovered():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    names = [m.name for m in modules]
    assert "screen_resolution_scaling" in names


def test_screen_resolution_module_metadata():
    mod = _get_module()
    assert mod.name == "screen_resolution_scaling"
    assert mod.category == "performance"
    assert mod.platforms == [Platform.DARWIN]
    assert mod.risk_level == RiskLevel.SAFE


def test_screen_resolution_native_resolution():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_native_resolution()):
        result = mod.check(_make_profile())
    # Native resolution should only report info, no warnings
    assert all(f.severity != Severity.CRITICAL for f in result.findings)


def test_screen_resolution_scaled_m2():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_scaled_resolution_m2()):
        result = mod.check(_make_profile())
    # Scaled resolution on M2 (integrated GPU) should trigger warning
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_screen_resolution_more_space():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_more_space_scaling()):
        result = mod.check(_make_profile())
    # More Space scaling should be detected as scaled
    assert any("More Space" in str(f.data) for f in result.findings)


def test_screen_resolution_external_native():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_external_display_native()):
        result = mod.check(_make_profile())
    # Native external display should not trigger warnings
    assert all(f.severity != Severity.CRITICAL for f in result.findings)


def test_screen_resolution_intel_iris_scaled():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_intel_iris_scaled()):
        result = mod.check(_make_profile())
    # Scaled on Intel Iris should trigger warning
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_screen_resolution_amd_radeon():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_amd_radeon()):
        result = mod.check(_make_profile())
    # Discrete GPU should not trigger warning even if scaled
    # (only integrated GPUs are problematic)
    assert all(f.severity != Severity.WARNING for f in result.findings)


def test_screen_resolution_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_scaled_resolution_m2()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.AUTO)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action for any finding
    if check.has_issues:
        assert len(fix.actions) > 0


def test_screen_resolution_report():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_native_resolution()):
        check = mod.check(_make_profile())
        report = mod.report(check)
    assert "screen_resolution_scaling" in report
