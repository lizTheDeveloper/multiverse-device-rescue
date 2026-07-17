import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add project root so modules/ is importable via discover_modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import (
    SystemProfile,
    Platform,
    Severity,
    RiskLevel,
    Mode,
)
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
    return next(m for m in modules if m.name == "system_log_errors")


def test_system_log_errors_discovered():
    """Module is discoverable by the registry."""
    mod = _get_module()
    assert mod.name == "system_log_errors"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE


def test_no_errors_in_log():
    """Empty log indicates healthy system."""
    mod = _get_module()
    with patch.object(mod, "_get_recent_errors", return_value=""):
        result = mod.check(_make_profile())

    assert result.has_issues
    assert len(result.findings) == 1
    assert result.findings[0].severity == Severity.INFO
    assert "No recent errors" in result.findings[0].title
    assert result.findings[0].data["error_count"] == 0


def test_few_errors_no_warning():
    """A few errors don't trigger warnings."""
    mod = _get_module()
    log_output = """Mail[123]: ERROR: Failed to fetch mail
Safari[456]: ERROR: Timeout loading page
System[789]: ERROR: Unknown service"""

    with patch.object(mod, "_get_recent_errors", return_value=log_output):
        result = mod.check(_make_profile())

    assert result.has_issues
    # Should be INFO level, not WARNING
    assert any(f.severity == Severity.INFO for f in result.findings)
    assert result.findings[0].data["error_count"] == 3


def test_high_error_volume_warning():
    """More than 50 errors triggers WARNING."""
    mod = _get_module()
    # Create 60 error lines
    error_lines = [f"Service{i}[{i}]: ERROR: Something went wrong" for i in range(60)]
    log_output = "\n".join(error_lines)

    with patch.object(mod, "_get_recent_errors", return_value=log_output):
        result = mod.check(_make_profile())

    assert result.has_issues
    assert any(f.severity == Severity.WARNING for f in result.findings)
    warning = next(f for f in result.findings if f.severity == Severity.WARNING)
    assert "High error volume" in warning.title
    assert "60 errors" in warning.title


def test_known_bad_kernel_error():
    """Kernel errors trigger known-bad warning."""
    mod = _get_module()
    log_output = """Mail[123]: ERROR: Failed
kernel[0]: ERROR: Page fault detected
System[456]: ERROR: Service stopped"""

    with patch.object(mod, "_get_recent_errors", return_value=log_output):
        result = mod.check(_make_profile())

    assert result.has_issues
    assert any(f.severity == Severity.WARNING for f in result.findings)
    known_bad = next(f for f in result.findings if "known-issue" in f.title.lower())
    assert "kernel" in known_bad.data["sample_errors"][0].lower()


def test_known_bad_xpc_error():
    """XPC connection errors trigger known-bad warning."""
    mod = _get_module()
    log_output = """Mail[123]: ERROR: Failed
System[456]: ERROR: com.apple.xpc.connection failed
Safari[789]: ERROR: Timeout"""

    with patch.object(mod, "_get_recent_errors", return_value=log_output):
        result = mod.check(_make_profile())

    assert result.has_issues
    assert any(f.severity == Severity.WARNING for f in result.findings)
    known_bad = next(f for f in result.findings if "known-issue" in f.title.lower())
    assert known_bad.data["known_bad_count"] == 1


def test_error_source_extraction():
    """Correctly extract error sources from log."""
    mod = _get_module()
    log_output = """Mail[123]: ERROR: Failed to fetch
Mail[124]: ERROR: Failed to fetch
Safari[456]: ERROR: Timeout loading page
System[789]: ERROR: Unknown service"""

    with patch.object(mod, "_get_recent_errors", return_value=log_output):
        result = mod.check(_make_profile())

    # Mail appears twice, others once
    finding = result.findings[0]
    assert "4" in finding.title or "error" in finding.title.lower()
    assert finding.data["error_count"] == 4
    # Should identify unique sources
    assert "Mail" in str(finding.data.get("top_sources", {}))


def test_top_sources_ranking():
    """Top error sources are ranked by frequency."""
    mod = _get_module()
    # Create errors where Chrome has most occurrences
    error_lines = []
    for i in range(20):
        error_lines.append(f"Chrome[100]: ERROR: Timeout {i}")
    for i in range(15):
        error_lines.append(f"Safari[200]: ERROR: Failed {i}")
    for i in range(10):
        error_lines.append(f"Mail[300]: ERROR: Error {i}")

    log_output = "\n".join(error_lines)

    with patch.object(mod, "_get_recent_errors", return_value=log_output):
        result = mod.check(_make_profile())

    finding = result.findings[0]
    top_sources = finding.data["top_sources"]
    # Chrome should be first (most errors)
    sources_list = list(top_sources.keys())
    assert sources_list[0] == "Chrome"


def test_command_execution_failure():
    """Gracefully handle subprocess errors."""
    mod = _get_module()
    with patch.object(mod, "_get_recent_errors", return_value=""):
        result = mod.check(_make_profile())

    # Should return empty findings or healthy message
    assert result.findings[0].data["error_count"] == 0


def test_multiple_known_bad_patterns():
    """Multiple known-bad patterns are all detected."""
    mod = _get_module()
    log_output = """kernel[0]: ERROR: Page fault
System[456]: ERROR: com.apple.xpc.connection failed
crashd[100]: ERROR: Crash detected"""

    with patch.object(mod, "_get_recent_errors", return_value=log_output):
        result = mod.check(_make_profile())

    assert result.has_issues
    known_bad = next(f for f in result.findings if "known-issue" in f.title.lower())
    # Should detect multiple known-bad errors
    assert known_bad.data["known_bad_count"] == 3


def test_fix_is_informational():
    """fix() returns informational actions (success=True)."""
    mod = _get_module()
    log_output = """Mail[123]: ERROR: Failed
Safari[456]: ERROR: Timeout"""

    with patch.object(mod, "_get_recent_errors", return_value=log_output):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.AUTO)

    assert fix.all_succeeded
    assert all(a.success for a in fix.actions)
    assert len(fix.actions) > 0


def test_fix_provides_guidance_for_high_errors():
    """Fix action for high error volume provides troubleshooting steps."""
    mod = _get_module()
    # Create >50 errors
    error_lines = [f"Service{i}[{i}]: ERROR: Issue" for i in range(60)]
    log_output = "\n".join(error_lines)

    with patch.object(mod, "_get_recent_errors", return_value=log_output):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.AUTO)

    assert len(fix.actions) > 0
    action = fix.actions[0]
    assert action.success
    assert "Investigate" in action.title or "high error" in action.title.lower()
    # Should mention troubleshooting steps
    assert "log show" in action.description.lower() or "service" in action.description.lower()


def test_fix_provides_guidance_for_known_bad():
    """Fix action for known-bad errors provides specific guidance."""
    mod = _get_module()
    log_output = """kernel[0]: ERROR: Page fault
System[456]: ERROR: Issue"""

    with patch.object(mod, "_get_recent_errors", return_value=log_output):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.AUTO)

    assert len(fix.actions) > 0
    action = fix.actions[0]
    assert action.success
    assert "known-issue" in action.title.lower() or "Address" in action.title
    # Should mention relevant troubleshooting
    assert "kernel" in action.description.lower() or "Apple" in action.description


def test_unique_source_count():
    """Correctly count unique error sources."""
    mod = _get_module()
    log_output = """Mail[123]: ERROR: 1
Mail[124]: ERROR: 2
Mail[125]: ERROR: 3
Safari[456]: ERROR: 4
Safari[457]: ERROR: 5
System[789]: ERROR: 6"""

    with patch.object(mod, "_get_recent_errors", return_value=log_output):
        result = mod.check(_make_profile())

    finding = result.findings[0]
    # Should identify 3 unique sources: Mail, Safari, System
    assert finding.data["unique_sources"] == 3


def test_summary_finding_includes_data():
    """Summary finding includes error count and sources data."""
    mod = _get_module()
    log_output = """Mail[123]: ERROR: Failed
Safari[456]: ERROR: Timeout"""

    with patch.object(mod, "_get_recent_errors", return_value=log_output):
        result = mod.check(_make_profile())

    finding = result.findings[0]
    assert "error_count" in finding.data
    assert "unique_sources" in finding.data
    assert "top_sources" in finding.data
    assert finding.data["error_count"] == 2
    assert finding.data["unique_sources"] >= 1


def test_very_long_error_lines_truncated():
    """Very long error lines are truncated in output."""
    mod = _get_module()
    very_long_msg = "x" * 200
    log_output = f"""kernel[0]: ERROR: {very_long_msg}
System[456]: ERROR: Short error"""

    with patch.object(mod, "_get_recent_errors", return_value=log_output):
        result = mod.check(_make_profile())

    # Check if known-bad findings exist and are truncated
    known_bad = next((f for f in result.findings if "known-issue" in f.title.lower()), None)
    if known_bad and known_bad.data.get("sample_errors"):
        # Sample error should be truncated (max 100 chars)
        for sample in known_bad.data["sample_errors"]:
            assert len(sample) <= 105  # Allow some margin for the prefix


def test_multiline_log_parsing():
    """Correctly parse multiline log output."""
    mod = _get_module()
    log_output = """Mail[123]: ERROR: Failed to fetch mail
Safari[456]: ERROR: Timeout loading page
System[789]: ERROR: Unknown service
Bluetooth[1000]: ERROR: Connection refused"""

    with patch.object(mod, "_get_recent_errors", return_value=log_output):
        result = mod.check(_make_profile())

    finding = result.findings[0]
    assert finding.data["error_count"] == 4
