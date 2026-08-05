import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import (
    Mode,
    Platform,
    ProcessInfo,
    RiskLevel,
    Severity,
    SystemProfile,
)
from rescue.registry import discover_modules

DATA_FILE = (
    Path(__file__).parent.parent
    / "modules" / "security" / "stalkerware_scan" / "data" / "known_stalkerware.json"
)


def _make_profile(processes=(), installed=(), platform=Platform.DARWIN):
    return SystemProfile(
        platform=platform,
        os_name="macOS",
        os_version="15.2",
        architecture="arm64",
        cpu_model="Apple M2",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
        processes=list(processes),
        installed_software=list(installed),
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "stalkerware_scan")


def _namespace(mod):
    return sys.modules[type(mod).__module__]


def _process(name, command=""):
    return ProcessInfo(
        pid=42, name=name, cpu_percent=1.0, memory_bytes=1024, command=command or name
    )


def _check(mod, profile):
    """Run check with the filesystem and registry scans stubbed out."""
    namespace = _namespace(mod)
    with patch("subprocess.run", return_value=MagicMock(stdout="", returncode=0)):
        with patch.object(namespace, "_DARWIN_APP_DIRS", []):
            with patch.object(namespace, "_DARWIN_PERSISTENCE_DIRS", []):
                return mod.check(profile)


def test_module_discovered():
    mod = _get_module()
    assert mod.name == "stalkerware_scan"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE
    assert set(mod.platforms) == {Platform.DARWIN, Platform.WIN32, Platform.LINUX}


def test_data_file_is_valid_and_categorised():
    with open(DATA_FILE) as f:
        data = json.load(f)
    entries = data["entries"]
    assert len(entries) >= 20
    valid_categories = {
        "stalkerware",
        "employee_monitoring",
        "parental_control",
        "remote_access",
    }
    for entry in entries:
        assert entry["category"] in valid_categories
        assert entry["severity"] in {"critical", "warning", "info"}
        assert entry["platforms"]
        assert entry["description"]


def test_clean_machine_has_no_findings():
    mod = _get_module()
    result = _check(mod, _make_profile(processes=[_process("Finder")]))
    assert not result.has_issues


def test_stalkerware_process_is_critical():
    mod = _get_module()
    result = _check(
        mod,
        _make_profile(processes=[_process("mSpy Agent", "/Applications/mSpy.app/agent")]),
    )

    findings = result.findings
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].data["stalkerware_category"] == "stalkerware"
    assert findings[0].data["confidence"] == "high"


def test_remote_access_tool_is_reported_without_calling_it_malware():
    mod = _get_module()
    result = _check(mod, _make_profile(installed=["TeamViewer Host"]))

    assert len(result.findings) == 1
    assert result.findings[0].severity == Severity.INFO
    assert result.findings[0].data["stalkerware_category"] == "remote_access"


def test_short_product_names_do_not_match_inside_longer_words():
    mod = _get_module()
    # "bark" is a parental-control product; "barkeeper" is not it.
    result = _check(mod, _make_profile(processes=[_process("barkeeper")]))
    assert not result.has_issues


def test_platform_specific_entries_are_skipped_on_other_platforms():
    mod = _get_module()
    # Spyrix is a Windows-only product in the dataset.
    result = _check(
        mod, _make_profile(processes=[_process("spyrix")], platform=Platform.DARWIN)
    )
    assert not result.has_issues

    result = _check(
        mod, _make_profile(processes=[_process("spyrix")], platform=Platform.LINUX)
    )
    assert not result.has_issues


def test_the_same_product_found_twice_is_reported_once_per_location():
    mod = _get_module()
    result = _check(
        mod,
        _make_profile(
            processes=[_process("mSpy Agent", "/Applications/mSpy.app/agent")],
            installed=["mSpy"],
        ),
    )
    locations = {f.data["location"] for f in result.findings}
    assert len(result.findings) == len(locations) == 2


def test_fix_leads_with_safety_guidance_before_removal():
    mod = _get_module()
    result = _check(
        mod,
        _make_profile(processes=[_process("mSpy Agent", "/Applications/mSpy.app/agent")]),
    )

    fix = mod.fix(result, Mode.CLI)
    titles = [action.title for action in fix.actions]

    assert titles[0] == "Read this before removing the monitoring software"
    assert "1-800-799-7233" in fix.actions[0].description
    removal_index = next(i for i, t in enumerate(titles) if t.startswith("Remove mSpy"))
    assert removal_index > 0
    assert all(action.kind.value == "guidance" for action in fix.actions)


def test_remote_access_only_findings_skip_the_stalkerware_safety_preamble():
    mod = _get_module()
    result = _check(mod, _make_profile(installed=["AnyDesk"]))

    fix = mod.fix(result, Mode.CLI)
    titles = [action.title for action in fix.actions]

    assert titles == ["Account for the remote access tool AnyDesk"]


def test_fix_does_nothing_without_findings():
    mod = _get_module()
    result = _check(mod, _make_profile())
    assert mod.fix(result, Mode.CLI).actions == []


def test_missing_data_file_is_reported_as_unavailable_not_healthy():
    mod = _get_module()
    namespace = _namespace(mod)
    with patch.object(namespace, "DATA_FILE", Path("/does/not/exist.json")):
        result = mod.check(_make_profile())
    assert result.error is not None
    assert not result.findings
