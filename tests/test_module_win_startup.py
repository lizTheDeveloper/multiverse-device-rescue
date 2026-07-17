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
    return next(m for m in modules if m.name == "win_startup")


def _startup_block(name: str) -> str:
    return (
        f"Caption={name}\r\n"
        f"Command=C:\\Program Files\\{name}\\{name}.exe /background\r\n"
        f"Location=HKU\\S-1-5-21-000\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\r\n"
        f"Name={name}\r\n"
        f"User=DESKTOP\\annhoward\r\n"
    )


def _make_wmic_output(names: list[str]) -> str:
    return "\r\n".join(_startup_block(n) for n in names)


def test_win_startup_discovered():
    mod = _get_module()
    assert mod.name == "win_startup"
    assert mod.category == "performance"
    assert Platform.WIN32 in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_win_startup_healthy_few_items():
    mod = _get_module()
    fake_result = MagicMock()
    fake_result.stdout = _make_wmic_output(["OneDrive", "Dropbox"])
    with patch("subprocess.run", return_value=fake_result):
        result = mod.check(_make_profile())
    assert not result.has_issues


def test_win_startup_warning_threshold():
    mod = _get_module()
    fake_result = MagicMock()
    fake_result.stdout = _make_wmic_output([f"App{i}" for i in range(5)])
    with patch("subprocess.run", return_value=fake_result):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert result.findings[0].severity == Severity.WARNING
    assert result.findings[0].data["count"] == 5


def test_win_startup_critical_threshold():
    mod = _get_module()
    fake_result = MagicMock()
    fake_result.stdout = _make_wmic_output([f"App{i}" for i in range(12)])
    with patch("subprocess.run", return_value=fake_result):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert result.findings[0].severity == Severity.CRITICAL
    assert result.findings[0].data["count"] == 12


def test_win_startup_fix_is_informational():
    mod = _get_module()
    fake_result = MagicMock()
    fake_result.stdout = _make_wmic_output([f"App{i}" for i in range(6)])
    with patch("subprocess.run", return_value=fake_result):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.AUTO)
    assert fix.all_succeeded
    assert "App0" in fix.actions[0].description
