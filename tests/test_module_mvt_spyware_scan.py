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


# --------------------------------------------------------------------------
# Opted-in scanning. These stub discovery and the MVT run; the parser tests
# below use MVT's real output, captured from mvt 2026.10.26 run against MVT's
# own sample iPhone backup and AndroidQF acquisition (tests/fixtures/mvt/).
# --------------------------------------------------------------------------

import json
import subprocess as sp
import zipfile

FIXTURES = Path(__file__).parent / "fixtures" / "mvt"
UUID = "3f2c9a1e-7b4d-4e8a-9c1f-2a6b8d0e5f13"


def _target(kind="ios", name="abc123", encrypted=False):
    return {"kind": kind, "path": Path(f"/fake/{name}"), "encrypted": encrypted}


def _scan(mod, targets, *, alerts=(), indicators=True, size=None):
    """Run an opted-in check() over stubbed targets. ``alerts`` is the list
    _run_mvt_scan returns for every target (or a side_effect list)."""
    side = alerts if isinstance(alerts, list) and alerts and isinstance(alerts[0], (list, type(None))) else None
    with patch.object(mod, "_discover_targets", return_value=targets), \
         patch("shutil.which", side_effect=lambda b: f"/usr/local/bin/{b}"), \
         patch.object(mod, "_indicators_present", return_value=indicators), \
         patch.object(mod, "_estimate_backup_size", return_value=size) as est, \
         patch.object(mod, "_run_mvt_scan", side_effect=side, return_value=None if side else list(alerts)) as run:
        result = mod.check(_make_profile())
    return result, run, est


def _checks(result):
    return [f.data.get("check") for f in result.findings]


def _opted(**cfg):
    mod = _get_module()
    mod.configure({"scan_backups": True, **cfg})
    return mod


def _alert(level="CRITICAL", ioc="Stalkerware Indicators of Compromise", module="aqf_packages", message="m", indicator="com.example.spy"):
    return {"module": module, "level": level, "message": message, "indicator": indicator if ioc else None,
            "indicator_type": "app_ids" if ioc else None, "ioc_name": ioc}


def test_indicator_match_is_critical_detection():
    mod = _opted()
    result, _, _ = _scan(mod, [_target("android", UUID + ".zip")], alerts=[_alert()])
    det = [f for f in result.findings if f.data.get("check") == "mvt_spyware_detected"]
    assert len(det) == 1 and det[0].severity == Severity.CRITICAL
    assert "Stalkerware" in det[0].title
    assert "mvt_clean_scan" not in _checks(result)


def test_high_heuristic_is_a_warning_not_clean():
    mod = _opted()
    result, _, _ = _scan(mod, [_target("android", UUID + ".zip")],
                         alerts=[_alert(level="HIGH", ioc=None, module="root_binaries", message='Found root binary "su"')])
    sig = [f for f in result.findings if f.data.get("check") == "mvt_suspicious_signal"]
    assert len(sig) == 1 and sig[0].severity == Severity.WARNING
    assert "mvt_clean_scan" not in _checks(result)


def test_medium_alerts_are_one_info_note_and_still_clean():
    mod = _opted()
    result, _, _ = _scan(mod, [_target("android", UUID + ".zip")],
                         alerts=[_alert(level="MEDIUM", ioc=None, message=f"note {i}") for i in range(3)])
    notes = [f for f in result.findings if f.data.get("check") == "mvt_suspicious_signal"]
    assert len(notes) == 1 and notes[0].severity == Severity.INFO and notes[0].data["count"] == 3
    assert "mvt_clean_scan" in _checks(result)


def test_large_backup_is_scanned_by_default():
    """No size limit unless one is configured: most real iPhone backups are
    tens of GB, and skipping them made the iPhone check skip almost everyone."""
    mod = _opted()
    result, run, est = _scan(mod, [_target()], size=60 * 1024**3)
    run.assert_called_once()
    est.assert_not_called()
    assert "mvt_backup_too_large" not in _checks(result)
    assert "mvt_clean_scan" in _checks(result)


def test_configured_size_limit_still_skips():
    mod = _opted(max_backup_bytes=1024)
    result, run, _ = _scan(mod, [_target()], size=50 * 1024**3)
    run.assert_not_called()
    assert "mvt_backup_too_large" in _checks(result)
    assert "mvt_clean_scan" not in _checks(result)


def test_scanning_raises_the_module_timeout():
    """The orchestrator's 60s default would abandon every real scan."""
    mod = _opted()
    assert getattr(mod, "check_timeout", 0) >= mod.mvt_timeout


def test_no_indicator_lists_means_no_scan_and_no_clean():
    """MVT doesn't download its lists by itself; without them every scan
    reads clean, so we don't run one."""
    mod = _opted()
    result, run, _ = _scan(mod, [_target()], indicators=False)
    run.assert_not_called()
    checks = _checks(result)
    assert "mvt_no_indicators" in checks and "mvt_clean_scan" not in checks
    f = next(f for f in result.findings if f.data.get("check") == "mvt_no_indicators")
    assert "download-iocs" in f.description


def test_encrypted_ios_backup_is_not_scanned_and_not_clean():
    mod = _opted()
    result, run, _ = _scan(mod, [_target(encrypted=True)])
    run.assert_not_called()
    assert "mvt_backup_encrypted" in _checks(result)
    assert "mvt_clean_scan" not in _checks(result)
    enc = next(f for f in result.findings if f.data.get("check") == "mvt_backup_encrypted")
    assert "decrypt-backup" in enc.description


def test_encrypted_androidqf_is_not_scanned_and_not_clean():
    mod = _opted()
    result, run, _ = _scan(mod, [_target("android", UUID + ".zip.age", encrypted=True)])
    run.assert_not_called()
    enc = next(f for f in result.findings if f.data.get("check") == "mvt_backup_encrypted")
    assert "age" in enc.description and "mvt_clean_scan" not in _checks(result)


def test_failed_scan_is_incomplete_not_clean():
    mod = _opted()
    result, _, _ = _scan(mod, [_target()], alerts=[None])
    assert "mvt_scan_incomplete" in _checks(result)
    assert "mvt_clean_scan" not in _checks(result)


def test_clean_count_only_includes_finished_scans():
    mod = _opted()
    result, _, _ = _scan(mod, [_target(name="a"), _target(name="b")], alerts=[[], None])
    clean = [f for f in result.findings if f.data.get("check") == "mvt_clean_scan"]
    assert len(clean) == 1 and clean[0].data["backups_scanned"] == 1
    assert "mvt_scan_incomplete" in _checks(result)


def test_android_needs_mvt_android():
    mod = _opted(look_for="android")
    with patch.object(mod, "_discover_targets", return_value=[_target("android", UUID + ".zip")]), \
         patch("shutil.which", side_effect=lambda b: "/bin/mvt-ios" if b == "mvt-ios" else None):
        result = mod.check(_make_profile())
    assert _checks(result) == ["mvt_not_installed"]


def test_look_for_rejects_unknown_values():
    import pytest
    with pytest.raises(ValueError):
        _get_module().configure({"look_for": "blackberry"})


def test_no_targets_message_matches_what_was_looked_for():
    mod = _opted(look_for="android")
    with patch.object(mod, "_discover_targets", return_value=[]):
        result = mod.check(_make_profile())
    f = result.findings[0]
    assert f.data["check"] == "no_backups_found" and "AndroidQF" in f.description


# ------------------------------------------------------------ the parser

def test_parse_real_ios_output(tmp_path):
    """mvt-ios check-backup on MVT's sample backup with its test indicators:
    three CRITICAL indicator matches, plus LOW/INFORMATIONAL notes we drop.
    (The old parser looked for a "detected": true key MVT never writes, so it
    reported none of these.)"""
    (tmp_path / "alerts.json").write_text((FIXTURES / "ios_alerts.json").read_text())
    alerts = _get_module()._parse_mvt_output(tmp_path)
    assert len(alerts) == 3
    assert all(a["level"] == "CRITICAL" and a["ioc_name"] == "TestMalware" for a in alerts)
    assert {a["indicator"] for a in alerts} == {"Launch", "example.org"}


def test_parse_real_androidqf_output(tmp_path):
    """mvt-android check-androidqf on MVT's sample acquisition, with an
    indicator for one of its apps: one indicator match, four HIGH root-binary
    heuristics, several MEDIUM notes, and an INFORMATIONAL one we drop."""
    (tmp_path / "alerts.json").write_text((FIXTURES / "androidqf_alerts.json").read_text())
    alerts = _get_module()._parse_mvt_output(tmp_path)
    matches = [a for a in alerts if a["ioc_name"]]
    assert [(a["indicator"], a["indicator_type"]) for a in matches] == [("com.malware.blah", "app_ids")]
    assert sum(1 for a in alerts if a["level"] == "HIGH" and not a["ioc_name"]) == 4
    assert all(a["level"] in ("MEDIUM", "HIGH", "CRITICAL") for a in alerts)


def test_parse_falls_back_to_detected_files(tmp_path):
    (tmp_path / "aqf_packages_detected.json").write_text((FIXTURES / "aqf_packages_detected.json").read_text())
    alerts = _get_module()._parse_mvt_output(tmp_path)
    assert any(a["indicator"] == "com.malware.blah" for a in alerts)


def test_parse_missing_output_is_empty(tmp_path):
    assert _get_module()._parse_mvt_output(tmp_path / "nope") == []


def test_real_output_end_to_end_reports_detections(tmp_path):
    """check() over the real Android output: the stalkerware match is
    CRITICAL, the root binaries are warnings, nothing reads clean."""
    data = json.loads((FIXTURES / "androidqf_alerts.json").read_text())
    (tmp_path / "alerts.json").write_text(json.dumps(data))
    mod = _opted(look_for="android")
    parsed = mod._parse_mvt_output(tmp_path)
    result, _, _ = _scan(mod, [_target("android", UUID + ".zip")], alerts=parsed)
    sev = {f.data["check"]: f.severity for f in result.findings}
    assert sev["mvt_spyware_detected"] == Severity.CRITICAL
    assert "mvt_clean_scan" not in sev


# ------------------------------------------------------------ running MVT

def test_run_mvt_scan_nonzero_exit_returns_none(tmp_path):
    mod = _get_module()
    with patch("subprocess.run", return_value=sp.CompletedProcess([], 1)):
        assert mod._run_mvt_scan("/usr/local/bin/mvt-ios", tmp_path) is None
    with patch("subprocess.run", side_effect=sp.TimeoutExpired("mvt", 1)):
        assert mod._run_mvt_scan("/usr/local/bin/mvt-ios", tmp_path) is None
    with patch("subprocess.run", return_value=sp.CompletedProcess([], 0)):
        assert mod._run_mvt_scan("/usr/local/bin/mvt-ios", tmp_path) == []


def _make_aqf_zip(folder: Path) -> Path:
    z = folder / f"{UUID}.zip"
    with zipfile.ZipFile(z, "w") as zf:  # flat, like AndroidQF 1.8+
        zf.writestr("acquisition.json", "{}")
        zf.writestr("packages.json", "[]")
        zf.writestr("getprop.txt", "")
    return z


def test_androidqf_zip_is_unpacked_one_folder_down_then_deleted(tmp_path):
    """MVT's AndroidQF modules look for */packages.json, so a flat AndroidQF
    zip has to be scanned as <tmp>/<UUID>/packages.json, and that copy must
    not outlive the scan."""
    z = _make_aqf_zip(tmp_path)
    seen = {}

    def fake_run(args, **kw):
        target = Path(args[-1])
        seen["args"] = args
        seen["target"] = target
        seen["has_packages"] = (target / "packages.json").exists()
        return sp.CompletedProcess(args, 0)

    with patch("subprocess.run", side_effect=fake_run):
        assert _get_module()._run_mvt_scan("/bin/mvt-android", z, "android") == []
    assert seen["args"][1] == "check-androidqf" and "--non-interactive" in seen["args"]
    assert seen["target"].name == UUID and seen["has_packages"]
    assert not seen["target"].exists()


# ------------------------------------------------------------ discovery

def test_discovers_androidqf_zip_and_ignores_other_zips(tmp_path):
    z = _make_aqf_zip(tmp_path)
    other = tmp_path / "1b2c3d4e-0000-4000-8000-000000000000.zip"
    with zipfile.ZipFile(other, "w") as zf:
        zf.writestr("photo.jpg", "x")
    (tmp_path / "notes.zip").write_bytes(b"")
    age = tmp_path / "5d6e7f80-1111-4111-8111-111111111111.zip.age"
    age.write_bytes(b"age-encryption.org/v1")
    mod = _get_module()
    with patch.object(mod, "_androidqf_roots", return_value=[tmp_path]):
        found = sorted(p.name for p in mod._discover_androidqf(_make_profile()))
    assert found == sorted([z.name, age.name])


def test_discover_targets_respects_look_for(tmp_path):
    _make_aqf_zip(tmp_path)
    mod = _get_module()
    mod.configure({"look_for": "ios"})
    with patch.object(mod, "_androidqf_roots", return_value=[tmp_path]), \
         patch.object(mod, "_discover_backups", return_value=[]):
        assert mod._discover_targets(_make_profile()) == []
    mod.configure({"look_for": "android"})
    with patch.object(mod, "_androidqf_roots", return_value=[tmp_path]):
        targets = mod._discover_targets(_make_profile())
    assert [(t["kind"], t["encrypted"]) for t in targets] == [("android", False)]


def test_indicators_present_reads_mvt_data_folder(tmp_path, monkeypatch):
    mod = _get_module()
    monkeypatch.delenv("MVT_STIX2", raising=False)
    monkeypatch.setenv("MVT_DATA_FOLDER", str(tmp_path))
    assert mod._indicators_present() is False
    (tmp_path / "indicators").mkdir()
    (tmp_path / "indicators" / "stalkerware.stix2").write_text("{}")
    assert mod._indicators_present() is True


def test_is_encrypted_reads_manifest(tmp_path):
    import plistlib
    mod = _get_module()
    (tmp_path / "Manifest.plist").write_bytes(plistlib.dumps({"IsEncrypted": True}))
    assert mod._is_encrypted(tmp_path) is True
    (tmp_path / "Manifest.plist").write_bytes(plistlib.dumps({"IsEncrypted": False}))
    assert mod._is_encrypted(tmp_path) is False
    assert mod._is_encrypted(tmp_path / "missing") is False
