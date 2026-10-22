import json
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

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
        ram_bytes=16 * 1024**3,
        processes=processes,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "process_scanner")


def test_process_scanner_discovered():
    mod = _get_module()
    assert mod.name == "process_scanner"
    assert mod.risk_level == RiskLevel.MODERATE


def test_known_bloatware_data_file_valid():
    data_file = (
        Path(__file__).parent.parent
        / "modules" / "bloatware" / "process_scanner" / "data" / "known_bloatware.json"
    )
    with open(data_file) as f:
        data = json.load(f)
    assert len(data) >= 5
    for entry in data:
        assert "process_pattern" in entry
        assert "name" in entry
        assert "category" in entry
        assert "description" in entry


def test_process_scanner_healthy():
    mod = _get_module()
    profile = _make_profile([
        ProcessInfo(pid=1, name="Finder", cpu_percent=1.0, memory_bytes=50 * 1024**2,
                    command="/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder"),
    ])
    result = mod.check(profile)
    assert not result.has_issues


def test_process_scanner_finds_scareware():
    mod = _get_module()
    profile = _make_profile([
        ProcessInfo(pid=42, name="MacKeeper Helper", cpu_percent=8.0,
                    memory_bytes=150 * 1024**2,
                    command="/Applications/MacKeeper.app/Contents/MacOS/MacKeeper Helper"),
        ProcessInfo(pid=1, name="Finder", cpu_percent=1.0, memory_bytes=50 * 1024**2,
                    command="/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder"),
    ])
    result = mod.check(profile)
    assert result.has_issues
    assert len(result.findings) == 1
    assert result.findings[0].severity == Severity.CRITICAL
    assert result.findings[0].data["pid"] == 42


def test_process_scanner_fix_informational():
    """fix() is informational only: reports suspicious processes without executing kill commands."""
    mod = _get_module()
    profile = _make_profile([
        ProcessInfo(pid=42, name="MacKeeper Helper", cpu_percent=8.0,
                    memory_bytes=150 * 1024**2,
                    command="/Applications/MacKeeper.app/Contents/MacOS/MacKeeper Helper"),
    ])
    check = mod.check(profile)

    # Patch subprocess to verify it's NOT called
    with patch("subprocess.run") as mock_run:
        fix = mod.fix(check, Mode.MANUAL)

    # Verify no subprocess calls were made
    mock_run.assert_not_called()

    # Verify fix succeeded and produced informational actions
    assert fix.all_succeeded
    assert len(fix.actions) == 1
    action = fix.actions[0]
    assert "MacKeeper" in action.title or "MacKeeper" in action.description
    assert action.success is True
    assert action.error is None


def _finding_for(name, command):
    mod = _get_module()
    profile = _make_profile([
        ProcessInfo(pid=77, name=name, cpu_percent=1.0, memory_bytes=10 * 1024**2, command=command),
    ])
    result = mod.check(profile)
    assert len(result.findings) == 1
    return result.findings[0]


def test_adware_finding_has_check_adware_and_no_usually_ignore():
    f = _finding_for("Genieo", "/Applications/Genieo.app/Contents/MacOS/Genieo")
    assert f.data["check"] == "adware"
    assert f.data["bloatware_category"] == "adware"
    assert "usually ignore" not in f.description
    assert f.description.startswith("This program shows unwanted ads or changes your browser")
    assert f.severity == Severity.WARNING


def test_scareware_and_cryptominer_get_their_own_first_line():
    s = _finding_for("MacKeeper", "/Applications/MacKeeper.app/Contents/MacOS/MacKeeper")
    assert s.data["check"] == "scareware"
    assert "usually ignore" not in s.description
    assert s.description.startswith("This program shows fake warnings")
    m = _finding_for("xmrig", "/tmp/.x/xmrig --donate-level 1")
    assert m.data["check"] == "cryptominer"
    assert "usually ignore" not in m.description
    assert m.description.startswith("This program uses your computer to make money for someone else")
    for f in (s, m):
        assert f.severity == Severity.CRITICAL


def test_pup_keeps_todays_wording():
    f = _finding_for("InstallMac", "/Applications/InstallMac.app/Contents/MacOS/InstallMac")
    assert f.data["check"] == "pup"
    assert "You can usually ignore this" in f.description
    assert f.description.startswith("We found InstallMac Installer running on your device.")
