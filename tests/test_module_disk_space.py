import sys
from pathlib import Path

# Add project root so modules/ is importable via discover_modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import (
    SystemProfile, Platform, DiskInfo, CheckResult,
    Severity, RiskLevel, Mode,
)
from rescue.registry import discover_modules


def _make_profile(disk_used_pct: float) -> SystemProfile:
    total = 500 * 1024**3  # 500 GB
    used = int(total * disk_used_pct)
    free = total - used
    return SystemProfile(
        platform=Platform.DARWIN,
        os_name="macOS",
        os_version="15.2",
        architecture="arm64",
        cpu_model="Apple M2",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
        disks=[
            DiskInfo(
                device="/dev/disk1s1",
                mount_point="/",
                total_bytes=total,
                used_bytes=used,
                free_bytes=free,
                filesystem="apfs",
            )
        ],
    )


def test_disk_space_module_discovered():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    names = [m.name for m in modules]
    assert "disk_space" in names


def test_disk_space_healthy():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    mod = next(m for m in modules if m.name == "disk_space")

    profile = _make_profile(0.50)  # 50% full
    result = mod.check(profile)
    assert not result.has_issues


def test_disk_space_warning():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    mod = next(m for m in modules if m.name == "disk_space")

    profile = _make_profile(0.85)  # 85% full
    result = mod.check(profile)
    assert result.has_issues
    assert result.findings[0].severity == Severity.WARNING


def test_disk_space_critical():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    mod = next(m for m in modules if m.name == "disk_space")

    profile = _make_profile(0.97)  # 97% full
    result = mod.check(profile)
    assert result.has_issues
    assert result.findings[0].severity == Severity.CRITICAL


def test_disk_space_fix_is_informational():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    mod = next(m for m in modules if m.name == "disk_space")

    assert mod.risk_level == RiskLevel.SAFE

    profile = _make_profile(0.85)
    check = mod.check(profile)
    fix = mod.fix(check, Mode.AUTO)
    assert fix.all_succeeded  # informational fix always succeeds


def test_disk_space_report():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    mod = next(m for m in modules if m.name == "disk_space")

    profile = _make_profile(0.85)
    check = mod.check(profile)
    report = mod.report(check)
    assert "disk_space" in report
    assert "85" in report or "warning" in report.lower()
