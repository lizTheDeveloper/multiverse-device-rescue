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
    return next(m for m in modules if m.name == "win_disk_space")


def _wmic_output(caption: str, free: int, size: int) -> str:
    return (
        "Caption  FreeSpace     Size\r\n"
        f"{caption}       {free}  {size}\r\n"
    )


def test_win_disk_space_discovered():
    mod = _get_module()
    assert mod.name == "win_disk_space"
    assert mod.category == "performance"
    assert Platform.WIN32 in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_win_disk_space_healthy():
    mod = _get_module()
    size = 256060514304
    free = int(size * 0.5)  # 50% used
    fake_result = MagicMock()
    fake_result.stdout = _wmic_output("C:", free, size)
    with patch("subprocess.run", return_value=fake_result):
        result = mod.check(_make_profile())
    assert not result.has_issues


def test_win_disk_space_warning():
    mod = _get_module()
    size = 256060514304
    free = int(size * 0.15)  # 85% used
    fake_result = MagicMock()
    fake_result.stdout = _wmic_output("C:", free, size)
    with patch("subprocess.run", return_value=fake_result):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert result.findings[0].severity == Severity.WARNING
    assert result.findings[0].data["caption"] == "C:"


def test_win_disk_space_critical():
    mod = _get_module()
    size = 256060514304
    free = int(size * 0.02)  # 98% used
    fake_result = MagicMock()
    fake_result.stdout = _wmic_output("D:", free, size)
    with patch("subprocess.run", return_value=fake_result):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert result.findings[0].severity == Severity.CRITICAL


def test_win_disk_space_fix_is_informational():
    mod = _get_module()
    size = 256060514304
    free = int(size * 0.15)
    fake_result = MagicMock()
    fake_result.stdout = _wmic_output("C:", free, size)
    with patch("subprocess.run", return_value=fake_result):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.AUTO)
    assert fix.all_succeeded


def test_win_disk_space_handles_missing_wmic():
    mod = _get_module()
    with patch("subprocess.run", side_effect=OSError("wmic not found")):
        result = mod.check(_make_profile())
    assert not result.has_issues
