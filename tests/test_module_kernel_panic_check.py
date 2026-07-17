import sys
import time
import os
from pathlib import Path
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import (
    SystemProfile,
    Platform,
    Severity,
    RiskLevel,
    Mode,
    CheckResult,
    Finding,
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
    return next(m for m in modules if m.name == "kernel_panic_check")


def test_kernel_panic_check_discovered():
    """Test that the kernel_panic_check module is discovered correctly."""
    mod = _get_module()
    assert mod.name == "kernel_panic_check"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.DARWIN in mod.platforms


def test_kernel_panic_check_no_panics(tmp_path):
    """Test when there are no panic files."""
    mod = _get_module()

    system_panic_dir = tmp_path / "Library" / "Logs" / "DiagnosticReports"
    user_panic_dir = tmp_path / "home" / "Library" / "Logs" / "DiagnosticReports"
    system_panic_dir.mkdir(parents=True, exist_ok=True)
    user_panic_dir.mkdir(parents=True, exist_ok=True)

    with patch.object(mod, "_system_panic_dir", return_value=system_panic_dir):
        with patch.object(mod, "_user_panic_dir", return_value=user_panic_dir):
            result = mod.check(_make_profile())

    # No panic files means no findings
    assert not result.has_issues
    assert len(result.findings) == 0


def test_kernel_panic_check_single_recent_panic(tmp_path):
    """Test with one recent kernel panic (should be WARNING)."""
    mod = _get_module()

    system_panic_dir = tmp_path / "system" / "DiagnosticReports"
    user_panic_dir = tmp_path / "user" / "DiagnosticReports"
    system_panic_dir.mkdir(parents=True, exist_ok=True)
    user_panic_dir.mkdir(parents=True, exist_ok=True)

    # Create a panic file from today in system directory
    panic_file = system_panic_dir / "kernel_2026-07-06_001.panic"
    panic_file.write_text("panic log content\n")

    with patch.object(mod, "_system_panic_dir", return_value=system_panic_dir):
        with patch.object(mod, "_user_panic_dir", return_value=user_panic_dir):
            result = mod.check(_make_profile())

    assert result.has_issues
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) == 1
    assert warning_findings[0].data.get("panic_count") == 1


def test_kernel_panic_check_two_recent_panics(tmp_path):
    """Test with two recent kernel panics (should be WARNING)."""
    mod = _get_module()

    system_panic_dir = tmp_path / "system" / "DiagnosticReports"
    user_panic_dir = tmp_path / "user" / "DiagnosticReports"
    system_panic_dir.mkdir(parents=True, exist_ok=True)
    user_panic_dir.mkdir(parents=True, exist_ok=True)

    # Create two panic files in system directory
    panic_file1 = system_panic_dir / "kernel_2026-07-06_001.panic"
    panic_file1.write_text("panic log content\n")
    panic_file2 = system_panic_dir / "kernel_2026-07-05_002.panic"
    panic_file2.write_text("panic log content\n")

    with patch.object(mod, "_system_panic_dir", return_value=system_panic_dir):
        with patch.object(mod, "_user_panic_dir", return_value=user_panic_dir):
            result = mod.check(_make_profile())

    assert result.has_issues
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) == 1
    assert warning_findings[0].data.get("panic_count") == 2


def test_kernel_panic_check_three_recent_panics(tmp_path):
    """Test with three recent kernel panics (should be CRITICAL)."""
    mod = _get_module()

    system_panic_dir = tmp_path / "system" / "DiagnosticReports"
    user_panic_dir = tmp_path / "user" / "DiagnosticReports"
    system_panic_dir.mkdir(parents=True, exist_ok=True)
    user_panic_dir.mkdir(parents=True, exist_ok=True)

    # Create three panic files from recent dates
    now = time.time()
    for i in range(3):
        # Create files from the last few days
        mtime = now - (i * 24 * 60 * 60)
        panic_file = system_panic_dir / f"kernel_2026-07-{6-i:02d}_00{i+1}.panic"
        panic_file.write_text("panic log content\n")
        # Set file modification time
        os.utime(panic_file, (mtime, mtime))

    with patch.object(mod, "_system_panic_dir", return_value=system_panic_dir):
        with patch.object(mod, "_user_panic_dir", return_value=user_panic_dir):
            result = mod.check(_make_profile())

    assert result.has_issues
    critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert len(critical_findings) == 1
    assert critical_findings[0].data.get("panic_count") == 3


def test_kernel_panic_check_panics_older_than_30_days(tmp_path):
    """Test that panics older than 30 days are ignored."""
    mod = _get_module()

    panic_dir = tmp_path / "DiagnosticReports"
    panic_dir.mkdir(parents=True, exist_ok=True)

    # Create panic file from 31 days ago
    now = time.time()
    old_mtime = now - (31 * 24 * 60 * 60)
    old_panic = panic_dir / "kernel_2026-06-05_001.panic"
    old_panic.write_text("panic log content\n")
    os.utime(old_panic, (old_mtime, old_mtime))

    with patch.object(mod, "_system_panic_dir", return_value=panic_dir):
        with patch.object(mod, "_user_panic_dir", return_value=panic_dir):
            result = mod.check(_make_profile())

    # Should show no recent panics
    assert result.has_issues
    assert any("no kernel panics" in f.title.lower() for f in result.findings)


def test_kernel_panic_check_mixed_old_and_recent(tmp_path):
    """Test with mix of old and recent panic files."""
    mod = _get_module()

    system_panic_dir = tmp_path / "system" / "DiagnosticReports"
    user_panic_dir = tmp_path / "user" / "DiagnosticReports"
    system_panic_dir.mkdir(parents=True, exist_ok=True)
    user_panic_dir.mkdir(parents=True, exist_ok=True)

    now = time.time()

    # Create old panic (31 days ago) in system directory
    old_panic = system_panic_dir / "kernel_2026-06-05_001.panic"
    old_panic.write_text("panic log content\n")
    os.utime(old_panic, (now - 31 * 24 * 60 * 60, now - 31 * 24 * 60 * 60))

    # Create recent panic (1 day ago) in system directory
    recent_panic = system_panic_dir / "kernel_2026-07-05_002.panic"
    recent_panic.write_text("panic log content\n")
    os.utime(recent_panic, (now - 1 * 24 * 60 * 60, now - 1 * 24 * 60 * 60))

    with patch.object(mod, "_system_panic_dir", return_value=system_panic_dir):
        with patch.object(mod, "_user_panic_dir", return_value=user_panic_dir):
            result = mod.check(_make_profile())

    assert result.has_issues
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) == 1
    assert warning_findings[0].data.get("panic_count") == 1


def test_kernel_panic_check_scans_both_directories(tmp_path):
    """Test that both system and user panic directories are scanned."""
    mod = _get_module()

    system_panic_dir = tmp_path / "system" / "DiagnosticReports"
    user_panic_dir = tmp_path / "user" / "DiagnosticReports"
    system_panic_dir.mkdir(parents=True, exist_ok=True)
    user_panic_dir.mkdir(parents=True, exist_ok=True)

    # Create panic in system directory
    sys_panic = system_panic_dir / "kernel_2026-07-06_001.panic"
    sys_panic.write_text("panic log content\n")

    # Create panic in user directory
    user_panic = user_panic_dir / "kernel_2026-07-06_002.panic"
    user_panic.write_text("panic log content\n")

    with patch.object(mod, "_system_panic_dir", return_value=system_panic_dir):
        with patch.object(mod, "_user_panic_dir", return_value=user_panic_dir):
            result = mod.check(_make_profile())

    assert result.has_issues
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) == 1
    assert warning_findings[0].data.get("panic_count") == 2


def test_kernel_panic_check_identifies_gpu_causes(tmp_path):
    """Test identification of GPU-related panic causes."""
    mod = _get_module()

    panic_dir = tmp_path / "DiagnosticReports"
    panic_dir.mkdir(parents=True, exist_ok=True)

    # Create panic file with GPU-related keywords
    panic_file = panic_dir / "kernel_2026-07-06_001.panic"
    panic_file.write_text(
        "panic(cpu 0 caller ...): GPU hang detected\n"
        "Metal: device error\n"
    )

    with patch.object(mod, "_system_panic_dir", return_value=panic_dir):
        with patch.object(mod, "_user_panic_dir", return_value=panic_dir):
            result = mod.check(_make_profile())

    causes_findings = [
        f for f in result.findings if "identified potential panic causes" in f.title.lower()
    ]
    assert len(causes_findings) > 0
    assert "Graphics/GPU issue" in str(causes_findings[0].data.get("identified_causes", {})) or \
           "Metal/GPU issue" in str(causes_findings[0].data.get("identified_causes", {}))


def test_kernel_panic_check_identifies_memory_causes(tmp_path):
    """Test identification of memory-related panic causes."""
    mod = _get_module()

    panic_dir = tmp_path / "DiagnosticReports"
    panic_dir.mkdir(parents=True, exist_ok=True)

    # Create panic file with memory-related keywords
    panic_file = panic_dir / "kernel_2026-07-06_001.panic"
    panic_file.write_text("panic: memory error detected\nram failure\n")

    with patch.object(mod, "_system_panic_dir", return_value=panic_dir):
        with patch.object(mod, "_user_panic_dir", return_value=panic_dir):
            result = mod.check(_make_profile())

    causes_findings = [
        f for f in result.findings if "identified potential panic causes" in f.title.lower()
    ]
    assert len(causes_findings) > 0
    assert "Memory/RAM issue" in str(causes_findings[0].data.get("identified_causes", {}))


def test_kernel_panic_check_identifies_kext_causes(tmp_path):
    """Test identification of kernel extension-related panic causes."""
    mod = _get_module()

    panic_dir = tmp_path / "DiagnosticReports"
    panic_dir.mkdir(parents=True, exist_ok=True)

    # Create panic file with kext-related keywords
    panic_file = panic_dir / "kernel_2026-07-06_001.panic"
    panic_file.write_text("panic: kext failure\nkernel extension error\n")

    with patch.object(mod, "_system_panic_dir", return_value=panic_dir):
        with patch.object(mod, "_user_panic_dir", return_value=panic_dir):
            result = mod.check(_make_profile())

    causes_findings = [
        f for f in result.findings if "identified potential panic causes" in f.title.lower()
    ]
    assert len(causes_findings) > 0


def test_kernel_panic_check_fix_no_panics():
    """Test fix action when there are no panics."""
    mod = _get_module()

    # Create check result with no panics
    check_result = CheckResult(
        module_name=mod.name,
        findings=[
            Finding(
                title="No kernel panics",
                description="No panics",
                severity=Severity.INFO,
                category=mod.category,
                data={"panic_count": 0},
            )
        ],
    )

    fix = mod.fix(check_result, Mode.MANUAL)
    assert fix.all_succeeded
    assert len(fix.actions) > 0


def test_kernel_panic_check_fix_single_panic():
    """Test fix action with single panic (WARNING level)."""
    mod = _get_module()

    # Manually construct check result for testing
    check_result = CheckResult(
        module_name=mod.name,
        findings=[
            Finding(
                title="Kernel panics detected: 1 in last 30 days",
                description="One panic detected",
                severity=Severity.WARNING,
                category=mod.category,
                data={
                    "panic_count": 1,
                    "most_recent_date": "2026-07-06 10:00:00",
                    "severity_level": "WARNING",
                },
            )
        ],
    )

    fix = mod.fix(check_result, Mode.MANUAL)
    assert fix.all_succeeded
    assert len(fix.actions) > 0


def test_kernel_panic_check_fix_critical_panics():
    """Test fix action with critical panics (3+ count)."""
    mod = _get_module()

    check_result = CheckResult(
        module_name=mod.name,
        findings=[
            Finding(
                title="Kernel panics detected: 3 in last 30 days",
                description="Critical panics detected",
                severity=Severity.CRITICAL,
                category=mod.category,
                data={
                    "panic_count": 3,
                    "most_recent_date": "2026-07-06 10:00:00",
                    "severity_level": "CRITICAL",
                },
            )
        ],
    )

    fix = mod.fix(check_result, Mode.MANUAL)
    assert fix.all_succeeded
    assert len(fix.actions) > 0
    assert any("critical" in a.title.lower() for a in fix.actions)


def test_kernel_panic_check_fix_gpu_causes():
    """Test fix action suggests GPU troubleshooting."""
    mod = _get_module()

    check_result = CheckResult(
        module_name=mod.name,
        findings=[
            Finding(
                title="Kernel panics detected: 2 in last 30 days",
                description="GPU panics",
                severity=Severity.WARNING,
                category=mod.category,
                data={
                    "panic_count": 2,
                    "identified_causes": {"Graphics/GPU issue": 2},
                },
            )
        ],
    )

    fix = mod.fix(check_result, Mode.MANUAL)
    assert fix.all_succeeded
    assert any("gpu" in a.title.lower() or "graphics" in a.title.lower() for a in fix.actions)


def test_kernel_panic_check_fix_memory_causes():
    """Test fix action suggests memory testing."""
    mod = _get_module()

    check_result = CheckResult(
        module_name=mod.name,
        findings=[
            Finding(
                title="Kernel panics detected: 2 in last 30 days",
                description="Memory panics",
                severity=Severity.WARNING,
                category=mod.category,
                data={
                    "panic_count": 2,
                    "identified_causes": {"Memory/RAM issue": 2},
                },
            )
        ],
    )

    fix = mod.fix(check_result, Mode.MANUAL)
    assert fix.all_succeeded
    assert any("memory" in a.title.lower() or "memory" in a.description.lower() for a in fix.actions)


def test_kernel_panic_check_fix_thunderbolt_causes():
    """Test fix action suggests Thunderbolt troubleshooting."""
    mod = _get_module()

    check_result = CheckResult(
        module_name=mod.name,
        findings=[
            Finding(
                title="Kernel panics detected: 2 in last 30 days",
                description="Thunderbolt panics",
                severity=Severity.WARNING,
                category=mod.category,
                data={
                    "panic_count": 2,
                    "identified_causes": {"Thunderbolt issue": 2},
                },
            )
        ],
    )

    fix = mod.fix(check_result, Mode.MANUAL)
    assert fix.all_succeeded
    assert any("thunderbolt" in a.title.lower() or "thunderbolt" in a.description.lower() for a in fix.actions)


def test_kernel_panic_check_fix_kext_causes():
    """Test fix action suggests kernel extension troubleshooting."""
    mod = _get_module()

    check_result = CheckResult(
        module_name=mod.name,
        findings=[
            Finding(
                title="Kernel panics detected: 2 in last 30 days",
                description="Kext panics",
                severity=Severity.WARNING,
                category=mod.category,
                data={
                    "panic_count": 2,
                    "identified_causes": {"Third-party kernel extension": 2},
                },
            )
        ],
    )

    fix = mod.fix(check_result, Mode.MANUAL)
    assert fix.all_succeeded
    assert any(
        "kernel extension" in a.title.lower() or "kext" in a.description.lower()
        for a in fix.actions
    )


def test_kernel_panic_check_all_findings_required_fields(tmp_path):
    """Test that all findings have required fields."""
    mod = _get_module()

    panic_dir = tmp_path / "DiagnosticReports"
    panic_dir.mkdir(parents=True, exist_ok=True)

    panic_file = panic_dir / "kernel_2026-07-06_001.panic"
    panic_file.write_text("panic log content\n")

    with patch.object(mod, "_system_panic_dir", return_value=panic_dir):
        with patch.object(mod, "_user_panic_dir", return_value=panic_dir):
            result = mod.check(_make_profile())

    for finding in result.findings:
        assert finding.title
        assert finding.description
        assert finding.severity in [Severity.INFO, Severity.WARNING, Severity.CRITICAL]
        assert finding.category == "integrity"
        assert isinstance(finding.data, dict)


def test_kernel_panic_check_all_actions_required_fields():
    """Test that all actions have required fields."""
    mod = _get_module()

    check_result = CheckResult(
        module_name=mod.name,
        findings=[
            Finding(
                title="Kernel panics detected: 3 in last 30 days",
                description="Critical panics",
                severity=Severity.CRITICAL,
                category=mod.category,
                data={
                    "panic_count": 3,
                    "identified_causes": {"Graphics/GPU issue": 2, "Memory/RAM issue": 1},
                },
            )
        ],
    )

    fix = mod.fix(check_result, Mode.MANUAL)

    for action in fix.actions:
        assert action.title
        assert action.description
        assert action.risk_level in [RiskLevel.SAFE, RiskLevel.MODERATE, RiskLevel.DESTRUCTIVE]
        assert isinstance(action.success, bool)
