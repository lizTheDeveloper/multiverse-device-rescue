import json
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, RiskLevel, Severity, Mode
from rescue.registry import discover_modules


def _make_profile():
    return SystemProfile(
        platform=Platform.WIN32,
        os_name="Windows",
        os_version="11",
        architecture="x86_64",
        cpu_model="Intel Core i7",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "win_bloatware")


def _fake_powershell_run(csv_output=""):
    """Factory for creating fake subprocess.run that mocks PowerShell Get-AppxPackage."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        if len(cmd) >= 2 and cmd[0] == "powershell":
            result.stdout = csv_output
            result.returncode = 0
        else:
            raise AssertionError(f"unexpected command {cmd}")
        return result
    return fake_run


# Sample PowerShell outputs (CSV format with header)
POWERSHELL_NO_APPS = '"Name","Publisher"\n'

POWERSHELL_SYSTEM_APPS = (
    '"Name","Publisher"\n'
    '"Microsoft.Windows.ShellExperienceHost","Microsoft Corporation"\n'
    '"Microsoft.VCLibs.140.00","Microsoft Corporation"\n'
    '"Microsoft.NET.Native.Runtime.2.2","Microsoft Corporation"\n'
)

POWERSHELL_WITH_BLOATWARE = (
    '"Name","Publisher"\n'
    '"Microsoft.Windows.ShellExperienceHost","Microsoft Corporation"\n'
    '"Microsoft.VCLibs.140.00","Microsoft Corporation"\n'
    '"king.com.CandyCrushSodaSaga","king.com"\n'
    '"Microsoft.Xbox.TCUI","Microsoft Corporation"\n'
    '"Microsoft.MixedRealityPortal","Microsoft Corporation"\n'
    '"Microsoft.SkypeApp","Microsoft Corporation"\n'
)

POWERSHELL_MANY_BLOATWARE = (
    '"Name","Publisher"\n'
    '"CandyCrush","king.com.CandyCrushSodaSaga"\n'
    '"BubbleWitch3Saga","king.com.BubbleWitch3Saga"\n'
    '"FarmHeroesSaga","king.com.FarmHeroesSaga"\n'
    '"DisneyMagicKingdoms","Disney"\n'
    '"MarchOfEmpires","Playa Games"\n'
    '"Microsoft.MixedReality.Portal","Microsoft Corporation"\n'
    '"Microsoft.3DViewer","Microsoft Corporation"\n'
    '"Microsoft.People","Microsoft Corporation"\n'
    '"Microsoft.XboxApp","Microsoft Corporation"\n'
)

POWERSHELL_MIXED_APPS = (
    '"Name","Publisher"\n'
    '"Microsoft.Windows.ShellExperienceHost","Microsoft Corporation"\n'
    '"Mozilla.Firefox","Mozilla"\n'
    '"Google.Chrome","Google Inc."\n'
    '"CandyCrush","king.com.CandyCrushSodaSaga"\n'
    '"Microsoft.XboxApp","Microsoft Corporation"\n'
    '"VLC.MediaPlayer","VideoLAN"\n'
)


def test_win_bloatware_discovered():
    """Test that the module is discovered correctly."""
    mod = _get_module()
    assert mod.name == "win_bloatware"
    assert mod.category == "bloatware"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.WIN32 in mod.platforms


def test_known_bloatware_data_file_valid():
    """Test that the bloatware data file exists and is valid."""
    data_file = (
        Path(__file__).parent.parent
        / "modules" / "bloatware" / "win_bloatware" / "data" / "known_bloatware.json"
    )
    assert data_file.exists(), f"Data file not found at {data_file}"

    with open(data_file) as f:
        data = json.load(f)

    assert len(data) >= 10, "Should have at least 10 known bloatware entries"
    for entry in data:
        assert "name" in entry, "Each entry must have 'name'"
        assert "publisher_pattern" in entry, "Each entry must have 'publisher_pattern'"
        assert "app_pattern" in entry, "Each entry must have 'app_pattern'"
        assert "description" in entry, "Each entry must have 'description'"
        assert "estimated_resource_savings" in entry, "Each entry must have 'estimated_resource_savings'"


def test_win_bloatware_no_apps_installed():
    """Test when no apps are installed."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_powershell_run(POWERSHELL_NO_APPS)):
        result = mod.check(_make_profile())

    assert result.has_issues
    # Should only have the summary finding
    assert len(result.findings) == 1
    assert result.findings[0].data["total_apps"] == 0
    assert result.findings[0].data["bloatware_count"] == 0


def test_win_bloatware_system_apps_only():
    """Test with only system apps (no bloatware detected)."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_powershell_run(POWERSHELL_SYSTEM_APPS)):
        result = mod.check(_make_profile())

    assert result.has_issues
    # Summary should be the only finding
    summary = [f for f in result.findings if "summary" in f.title.lower()]
    assert len(summary) == 1
    assert summary[0].data["bloatware_count"] == 0
    assert summary[0].data["total_apps"] == 3


def test_win_bloatware_detects_candy_crush():
    """Test detection of Candy Crush bloatware."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_powershell_run(POWERSHELL_WITH_BLOATWARE)):
        result = mod.check(_make_profile())

    assert result.has_issues
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warnings) > 0

    # Should find at least Candy Crush
    bloatware_titles = [f.title for f in warnings]
    assert any("Candy Crush" in title for title in bloatware_titles)


def test_win_bloatware_detects_xbox():
    """Test detection of Xbox app as bloatware."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_powershell_run(POWERSHELL_WITH_BLOATWARE)):
        result = mod.check(_make_profile())

    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    bloatware_names = [f.data.get("bloatware_name", "") for f in warnings]
    assert any("Xbox" in name for name in bloatware_names)


def test_win_bloatware_detects_mixed_reality():
    """Test detection of Mixed Reality Portal as bloatware."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_powershell_run(POWERSHELL_WITH_BLOATWARE)):
        result = mod.check(_make_profile())

    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    bloatware_names = [f.data.get("bloatware_name", "") for f in warnings]
    assert any("Reality" in name or "VR" in name for name in bloatware_names)


def test_win_bloatware_detects_skype():
    """Test detection of Skype as bloatware."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_powershell_run(POWERSHELL_WITH_BLOATWARE)):
        result = mod.check(_make_profile())

    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    bloatware_names = [f.data.get("bloatware_name", "") for f in warnings]
    assert any("Skype" in name for name in bloatware_names)


def test_win_bloatware_multiple_bloatware():
    """Test detection of multiple bloatware apps."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_powershell_run(POWERSHELL_MANY_BLOATWARE)):
        result = mod.check(_make_profile())

    assert result.has_issues
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    # Should detect multiple bloatware apps
    assert len(warnings) >= 3

    # Should have summary
    summary = [f for f in result.findings if f.severity == Severity.INFO]
    assert len(summary) >= 1
    assert summary[0].data["bloatware_count"] >= 3


def test_win_bloatware_mixed_apps():
    """Test with a mix of legitimate and bloatware apps."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_powershell_run(POWERSHELL_MIXED_APPS)):
        result = mod.check(_make_profile())

    assert result.has_issues
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    infos = [f for f in result.findings if f.severity == Severity.INFO]

    # Should find at least some bloatware (Candy Crush, Xbox)
    assert len(warnings) >= 2
    # Should have summary info
    assert len(infos) >= 1
    assert infos[0].data["total_apps"] == 6


def test_win_bloatware_powershell_failure():
    """Test graceful handling when PowerShell fails."""
    mod = _get_module()

    def fake_run_failure(cmd, **kwargs):
        if "powershell" in cmd[0]:
            raise OSError("PowerShell not found")
        raise AssertionError(f"unexpected command {cmd}")

    with patch("subprocess.run", side_effect=fake_run_failure):
        result = mod.check(_make_profile())

    # Should not crash, should return findings with empty app list
    assert result.has_issues
    summary = [f for f in result.findings if "summary" in f.title.lower()]
    assert len(summary) >= 1
    assert summary[0].data["total_apps"] == 0


def test_win_bloatware_powershell_timeout():
    """Test graceful handling when PowerShell times out."""
    mod = _get_module()

    def fake_run_timeout(cmd, **kwargs):
        if "powershell" in cmd[0]:
            raise TimeoutError("Command timed out")
        raise AssertionError(f"unexpected command {cmd}")

    with patch("subprocess.run", side_effect=fake_run_timeout):
        result = mod.check(_make_profile())

    # Should not crash
    assert result.has_issues


def test_win_bloatware_fix_is_informational():
    """Test that fix() is informational and doesn't execute removal."""
    mod = _get_module()

    with patch("subprocess.run", side_effect=_fake_powershell_run(POWERSHELL_WITH_BLOATWARE)):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    # Verify fix succeeded and produced informational actions
    assert fix.all_succeeded
    assert len(fix.actions) > 0

    # Actions should describe how to remove, not actually remove
    for action in fix.actions:
        assert action.success is True
        assert action.error is None
        # Should contain instructions about removing
        full_text = f"{action.title} {action.description}"
        assert any(keyword in full_text.lower() for keyword in ["remove", "uninstall", "settings", "powershell"])


def test_win_bloatware_fix_provides_removal_instructions():
    """Test that fix provides specific removal instructions."""
    mod = _get_module()

    with patch("subprocess.run", side_effect=_fake_powershell_run(POWERSHELL_WITH_BLOATWARE)):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    # Should have removal instructions for bloatware
    bloatware_actions = [a for a in fix.actions if "Remove bloatware" in a.title]
    assert len(bloatware_actions) > 0

    # Each should contain both GUI and PowerShell removal methods
    for action in bloatware_actions:
        assert "Settings" in action.description or "Apps & features" in action.description
        assert "PowerShell" in action.description or "Remove-AppxPackage" in action.description


def test_win_bloatware_summary_action():
    """Test that fix provides a summary action."""
    mod = _get_module()

    with patch("subprocess.run", side_effect=_fake_powershell_run(POWERSHELL_WITH_BLOATWARE)):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    # Should have a summary action
    summary_actions = [a for a in fix.actions if "Review" in a.title or "summary" in a.description.lower()]
    assert len(summary_actions) >= 1


def test_win_bloatware_csv_parsing():
    """Test that CSV parsing works correctly with quoted fields."""
    mod = _get_module()

    # Create a test with special characters in names/publishers
    special_csv = (
        '"Name","Publisher"\n'
        '"My App, Inc.","Company, Ltd."\n'
        '"Normal App","Publisher"\n'
    )

    with patch("subprocess.run", side_effect=_fake_powershell_run(special_csv)):
        result = mod.check(_make_profile())

    # Should parse without crashing
    assert result.has_issues
    summary = [f for f in result.findings if "summary" in f.title.lower()]
    assert len(summary) >= 1
    assert summary[0].data["total_apps"] == 2


def test_win_bloatware_resource_savings_in_findings():
    """Test that estimated resource savings are included in findings."""
    mod = _get_module()

    with patch("subprocess.run", side_effect=_fake_powershell_run(POWERSHELL_WITH_BLOATWARE)):
        result = mod.check(_make_profile())

    warnings = [f for f in result.findings if f.severity == Severity.WARNING]

    # Each bloatware finding should have resource savings data
    for finding in warnings:
        assert "resource_savings" in finding.data
        assert "Estimated resource savings" in finding.description


def test_win_bloatware_empty_output():
    """Test handling of empty PowerShell output."""
    mod = _get_module()

    with patch("subprocess.run", side_effect=_fake_powershell_run("")):
        result = mod.check(_make_profile())

    # Should not crash
    assert result.has_issues
