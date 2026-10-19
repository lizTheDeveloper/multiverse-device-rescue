"""The same finding from different checks shares a key; an opt-in check that
wasn't started says so, distinct from "couldn't run"."""
import json
from types import SimpleNamespace

from rescue.check_names import error_kind
from rescue.models import CheckResult, Finding, Severity
from rescue.same_finding import same_key
from rescue.serialize import checks_to_json


def _f(module, title, data, severity="warning"):
    return module, {"title": title, "severity": severity, "data": data}


def test_twins_from_different_checks_share_one_key():
    pairs = [
        [_f("app_crash_analyzer", "a", {"check": "unstable_app", "app_name": "chrome_crashpad_handler", "crash_count": 50}),
         _f("application_crash_report", "b", {"app_name": "chrome_crashpad_handler", "crash_count": 50}),
         _f("crash_log_analyzer", "c", {"app_name": "chrome_crashpad_handler", "crash_count": 50})],
        [_f("audio_config", "a", {"check": "volume_low", "volume_percent": 0}),
         _f("audio_troubleshoot", "b", {"check": "volume_zero", "volume_percent": 0})],
        [_f("backup_status", "a", {"check": "no_destination"}),
         _f("time_machine_health", "b", {"check": "no_destination_configured"})],
        [_f("memory_pressure", "a", {"check": "swap_usage"}), _f("memory_pressure_check", "b", {"check": "high_swap_usage"})],
        [_f("login_password_policy", "a", {"check": "screensaver_timeout"}),
         _f("screen_lock_check", "b", {"check": "screensaver_idle_time"})],
        [_f("firewall_audit", "a", {"check": "stealth_mode"}), _f("firewall_rules_audit", "b", {"check": "stealth_disabled"})],
        [_f("accessibility_permissions", "a", {"check": "excessive_accessibility"}),
         _f("app_permissions", "b", {"check": "accessibility_access"})],
        [_f("launch_agent_audit", "a", {"check": "suspicious_path", "label": "x.task"}),
         _f("launchd_persistence_audit", "b", {"check": "suspicious_path", "label": "x.task"})],
    ]
    keys = []
    for group in pairs:
        got = {same_key(m, f) for m, f in group}
        assert len(got) == 1 and None not in got, group
        keys.append(got.pop())
    assert len(set(keys)) == len(keys), "different things never share a key"


def test_different_problems_and_monitoring_checks_get_no_shared_key():
    a = same_key("launch_agent_audit", {"data": {"check": "suspicious_path", "label": "x.task"}})
    b = same_key("launch_agent_audit", {"data": {"check": "missing_program", "label": "x.task"}})
    assert a != b
    # Unrecognised apps that can control the Mac is its own (markable) finding.
    assert same_key("accessibility_permissions", {"data": {"check": "suspicious_accessibility"}}) is None
    assert same_key("audio_config", {"data": {"check": "volume_low", "volume_percent": 12}}) is None
    for m in ("stalkerware_scan", "mvt_spyware_scan", "keylogger_indicators"):
        assert same_key(m, {"data": {"check": "no_destination", "label": "x"}}) is None
    assert same_key("x", None) is None and same_key("x", {"data": "odd"}) is None


def test_same_key_is_in_the_document():
    mod = SimpleNamespace(name="audio_config", category="performance")
    check = CheckResult(module_name="audio_config", findings=[
        Finding(title="Your volume is set very low (0%)", description="d", severity=Severity.WARNING,
                category="performance", data={"check": "volume_low", "volume_percent": 0})])
    f = json.loads(checks_to_json([(mod, check)], "darwin"))["modules"][0]["findings"][0]
    assert f["same_key"] == "audio:volume_zero"


def test_an_opt_in_check_not_started_is_its_own_kind():
    assert error_kind(None, True, True, not_started=True) == "not_started"
    assert error_kind("timed out", True, True, not_started=True) == "timeout"
    assert error_kind(None, False, True, not_started=True) == "unsupported"
    mod = SimpleNamespace(name="mvt_spyware_scan", category="security")
    check = CheckResult(module_name="mvt_spyware_scan", not_started=True, findings=[
        Finding(title="1 device backup(s) found (scan available)", description="d", severity=Severity.INFO,
                category="security", code="security.mvt_spyware_scan.mvt_scan_available",
                data={"check": "mvt_scan_available", "backups_found": 1})])
    entry = json.loads(checks_to_json([(mod, check)], "darwin"))["modules"][0]
    assert entry["status"] == "ok" and entry["supported"] is True and entry["complete"] is True
    assert entry["not_started"] is True and entry["error_kind"] == "not_started"
    plain = json.loads(checks_to_json([(mod, CheckResult(module_name="mvt_spyware_scan"))], "darwin"))["modules"][0]
    assert plain["not_started"] is False and plain["error_kind"] is None


def test_mvt_with_a_backup_and_no_opt_in_is_not_started(tmp_path, monkeypatch):
    from pathlib import Path

    from rescue.models import Platform, SystemProfile
    from rescue.registry import discover_modules

    mod = next(m for m in discover_modules(Path(__file__).parent.parent / "modules") if m.name == "mvt_spyware_scan")
    monkeypatch.setattr(mod, "_discover_backups", lambda profile: [tmp_path])
    import shutil
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/local/bin/mvt-ios" if name == "mvt-ios" else None)
    profile = SystemProfile(platform=Platform.DARWIN, os_name="macOS", os_version="15", architecture="arm64",
                            cpu_model="x", cpu_cores=8, ram_bytes=1)
    result = mod.check(profile)
    assert result.not_started is True
    assert [f.code for f in result.findings] == ["security.mvt_spyware_scan.mvt_scan_available"]
