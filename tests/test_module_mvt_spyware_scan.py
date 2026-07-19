import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


def _make_profile(platform=Platform.DARWIN):
    return SystemProfile(
        platform=platform,
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
    return next(m for m in modules if m.name == "mvt_spyware_scan")


def test_module_discovered():
    mod = _get_module()
    assert mod.name == "mvt_spyware_scan"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.DARWIN in mod.platforms
    assert Platform.LINUX in mod.platforms


def test_no_backups_no_findings():
    """No findings when no device backups are found."""
    mod = _get_module()
    with patch.object(Path, "exists", return_value=False):
        with patch.object(Path, "is_dir", return_value=False):
            result = mod.check(_make_profile())
    # Should report info that no backups were found, not an error
    assert not any(f.severity == Severity.CRITICAL for f in result.findings)


def test_mvt_not_installed_reports_info():
    """When MVT is not installed, report as informational finding."""
    mod = _get_module()

    with patch.object(Path, "exists", return_value=True):
        with patch.object(Path, "is_dir", return_value=True):
            with patch.object(Path, "iterdir", return_value=[Path("/fake/backup")]):
                with patch("shutil.which", return_value=None):
                    result = mod.check(_make_profile())

    mvt_findings = [
        f for f in result.findings if f.data.get("check") == "mvt_not_installed"
    ]
    assert len(mvt_findings) > 0
    assert mvt_findings[0].severity == Severity.INFO


def test_default_check_does_not_launch_mvt_scan():
    """A read-only check() must NOT auto-launch the heavy `mvt check-backup`
    forensic scan. On a large backup that scan loads gigabytes into memory (in
    MVT's own process) and can freeze the machine, so backup scanning is
    opt-in. By default check() only *reports* that a scan is available.
    """
    mod = _get_module()

    with patch.object(Path, "exists", return_value=True):
        with patch.object(Path, "is_dir", return_value=True):
            with patch.object(
                Path, "iterdir", return_value=[Path("/fake/backup/abc123")]
            ):
                with patch("shutil.which", return_value="/usr/local/bin/mvt-ios"):
                    with patch("subprocess.run") as mock_run:
                        with patch.object(mod, "_run_mvt_scan") as mock_scan:
                            result = mod.check(_make_profile())

    # The forensic scan must not have been launched.
    mock_run.assert_not_called()
    mock_scan.assert_not_called()
    # Instead, check() surfaces that a scan is available to run explicitly.
    available = [
        f for f in result.findings if f.data.get("check") == "mvt_scan_available"
    ]
    assert len(available) == 1
    assert available[0].severity == Severity.INFO


def test_opt_in_scan_with_detection():
    """When backup scanning is explicitly enabled via configure(), MVT runs and
    spyware indicators are reported as critical findings."""
    mod = _get_module()
    mod.configure({"scan_backups": True})

    with patch.object(Path, "exists", return_value=True):
        with patch.object(Path, "is_dir", return_value=True):
            with patch.object(
                Path, "iterdir", return_value=[Path("/fake/backup/abc123")]
            ):
                with patch("shutil.which", return_value="/usr/local/bin/mvt-ios"):
                    # Keep the backup under the size guard so it is scanned.
                    with patch.object(mod, "_estimate_backup_size", return_value=1024):
                        with patch.object(
                            mod,
                            "_run_mvt_scan",
                            return_value=[
                                {
                                    "module": "safari_history",
                                    "indicator": "suspicious-domain.com",
                                    "indicator_type": "domain-name",
                                }
                            ],
                        ):
                            result = mod.check(_make_profile())

    spyware_findings = [
        f for f in result.findings if f.data.get("check") == "mvt_spyware_detected"
    ]
    assert len(spyware_findings) > 0
    assert spyware_findings[0].severity == Severity.CRITICAL


def test_opt_in_scan_skips_oversized_backup():
    """Even when opted in, a backup larger than the size guard is skipped rather
    than scanned — this is the memory-safety valve that prevents the freeze."""
    mod = _get_module()
    mod.configure({"scan_backups": True, "max_backup_bytes": 1024})

    with patch.object(Path, "exists", return_value=True):
        with patch.object(Path, "is_dir", return_value=True):
            with patch.object(
                Path, "iterdir", return_value=[Path("/fake/backup/huge")]
            ):
                with patch("shutil.which", return_value="/usr/local/bin/mvt-ios"):
                    with patch.object(
                        mod, "_estimate_backup_size", return_value=50 * 1024**3
                    ):
                        with patch.object(mod, "_run_mvt_scan") as mock_scan:
                            result = mod.check(_make_profile())

    mock_scan.assert_not_called()
    too_large = [
        f for f in result.findings if f.data.get("check") == "mvt_backup_too_large"
    ]
    assert len(too_large) == 1


def test_fix_provides_guidance():
    """fix() provides informational guidance for spyware remediation."""
    mod = _get_module()
    from rescue.models import CheckResult, Finding

    check = CheckResult(
        module_name="mvt_spyware_scan",
        findings=[
            Finding(
                title="Spyware indicator detected",
                description="Pegasus indicator in safari_history",
                severity=Severity.CRITICAL,
                category="security",
                data={
                    "check": "mvt_spyware_detected",
                    "module": "safari_history",
                    "indicator": "suspicious-domain.com",
                },
            ),
        ],
    )

    fix = mod.fix(check, Mode.MANUAL)

    assert len(fix.actions) > 0
    assert fix.all_succeeded
    action_text = " ".join(a.description for a in fix.actions).lower()
    assert "factory reset" in action_text or "update" in action_text


def test_windows_reports_wsl_requirement():
    """On Windows, report that MVT requires WSL."""
    mod = _get_module()
    result = mod.check(_make_profile(platform=Platform.WIN32))

    wsl_findings = [
        f for f in result.findings if f.data.get("check") == "mvt_requires_wsl"
    ]
    assert len(wsl_findings) > 0


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(
        c.startswith("security.mvt_spyware_scan.") for c in declared
    )
