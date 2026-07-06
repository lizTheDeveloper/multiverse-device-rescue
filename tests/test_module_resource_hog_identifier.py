import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import (
    SystemProfile, Platform, ProcessInfo, Severity, RiskLevel, Mode,
)
from rescue.registry import discover_modules


def _make_profile(processes):
    return SystemProfile(
        platform=Platform.DARWIN,
        os_name="macOS",
        os_version="15.2",
        architecture="arm64",
        cpu_model="Apple M2",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,  # 16 GB
        processes=processes,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "resource_hog_identifier")


def test_resource_hog_identifier_discovered():
    mod = _get_module()
    assert mod.name == "resource_hog_identifier"
    assert mod.risk_level == RiskLevel.MODERATE


def test_resource_hog_healthy():
    mod = _get_module()
    profile = _make_profile([
        ProcessInfo(pid=1, name="launchd", cpu_percent=0.5,
                    memory_bytes=10 * 1024**2, command="/sbin/launchd"),
        ProcessInfo(pid=200, name="Finder", cpu_percent=2.0,
                    memory_bytes=200 * 1024**2,
                    command="/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder"),
    ])
    result = mod.check(profile)
    assert not result.has_issues


def test_resource_hog_warning_cpu():
    mod = _get_module()
    profile = _make_profile([
        ProcessInfo(pid=500, name="Spotify", cpu_percent=65.0,
                    memory_bytes=300 * 1024**2,
                    command="/Applications/Spotify.app/Contents/MacOS/Spotify"),
    ])
    result = mod.check(profile)
    assert result.has_issues
    assert result.findings[0].severity == Severity.WARNING


def test_resource_hog_critical_cpu():
    mod = _get_module()
    profile = _make_profile([
        ProcessInfo(pid=600, name="Chrome Helper", cpu_percent=95.0,
                    memory_bytes=500 * 1024**2,
                    command="/Applications/Google Chrome.app/Contents/Frameworks/Chrome Helper"),
    ])
    result = mod.check(profile)
    assert result.has_issues
    assert result.findings[0].severity == Severity.CRITICAL


def test_resource_hog_critical_memory():
    mod = _get_module()
    ram = 16 * 1024**3
    profile = _make_profile([
        ProcessInfo(pid=700, name="Docker", cpu_percent=5.0,
                    memory_bytes=int(ram * 0.30),
                    command="/Applications/Docker.app/Contents/MacOS/Docker"),
    ])
    result = mod.check(profile)
    assert result.has_issues
    assert result.findings[0].severity == Severity.CRITICAL


def test_resource_hog_fix_is_informational():
    """fix() should provide informational actions without actually killing processes"""
    mod = _get_module()
    profile = _make_profile([
        ProcessInfo(pid=500, name="Spotify", cpu_percent=65.0,
                    memory_bytes=300 * 1024**2,
                    command="/Applications/Spotify.app/Contents/MacOS/Spotify"),
    ])
    check = mod.check(profile)

    fix = mod.fix(check, Mode.MANUAL)

    assert fix.all_succeeded
    assert len(fix.actions) == 1
    action = fix.actions[0]
    assert action.success is True
    assert action.risk_level == RiskLevel.SAFE
    assert "Spotify" in action.title or "500" in action.title


def test_resource_hog_fix_multiple():
    """fix() should handle multiple resource hogs"""
    mod = _get_module()
    profile = _make_profile([
        ProcessInfo(pid=500, name="Spotify", cpu_percent=65.0,
                    memory_bytes=300 * 1024**2,
                    command="/Applications/Spotify.app/Contents/MacOS/Spotify"),
        ProcessInfo(pid=600, name="Chrome", cpu_percent=85.0,
                    memory_bytes=500 * 1024**2,
                    command="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
    ])
    check = mod.check(profile)
    fix = mod.fix(check, Mode.MANUAL)

    assert fix.all_succeeded
    assert len(fix.actions) == 2
