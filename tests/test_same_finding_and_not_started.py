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
        [_f("launch_agent_audit", "a", {"check": "suspicious_path", "label": "x.task", "plist": "/Library/LaunchAgents/x.task.plist"}),
         _f("launchd_persistence_audit", "b", {"check": "suspicious_path", "label": "x.task", "plist": "/Library/LaunchAgents/x.task.plist"})],
    ]
    # UX round 5 (N3): the near-duplicates the audit found.
    pairs += [
        [_f("energy_saver_check", "Your Mac is set to never sleep", {"check": "computer_sleep_disabled", "setting": "sleep", "value": "0"}),
         _f("energy_settings", "Your Mac is set to never sleep", {"setting": "sleep", "value": 0, "issue": "battery_drain"}),
         _f("power_settings", "Your Mac is set to never sleep", {"setting": "sleep", "value": 0, "issue": "never_sleeps"})],
        [_f("energy_saver_check", "Your screen is set to never turn off", {"check": "display_sleep_disabled", "setting": "displaysleep"}),
         _f("lock_screen_check", "Your Mac screen never turns off automatically", {"check": "display_sleep"})],
        [_f("resource_hog_identifier", "opencode is using a lot of your computer's power", {"pid": 6538, "name": "opencode", "cpu_percent": 122.3}),
         _f("crypto_miner_detect", "A program called opencode is using a lot of power", {"check": "high_cpu_process", "pid": 6538, "process": "opencode"})],
        [_f("system_log_errors", "Your Mac logged 83,759 errors in the last hour", {"error_count": 83759, "unique_sources": 103, "top_sources": {}}),
         _f("system_log_errors", "Found 4,837 errors from known Mac issues", {"known_bad_count": 4837, "sample_errors": []})],
        [_f("login_items_cleanup", "Many apps start automatically (40)", {"type": "excessive_login_items", "count": 40}),
         _f("startup_optimizer", "33 apps start automatically in the background", {"items": [], "count": 33})],
    ]
    pairs[2].append(_f("time_machine_check", "Your Mac is not automatically backing up your files", {"check": "not_configured"}))
    pairs[6].append(_f("accessibility_permissions", "Apps you may not recognize can control your Mac (11)",
                       {"check": "suspicious_accessibility", "apps": []}))
    keys = []
    for group in pairs:
        got = {same_key(m, f) for m, f in group}
        assert len(got) == 1 and None not in got, group
        keys.append(got.pop())
    assert len(set(keys)) == len(keys), "different things never share a key"


def test_different_problems_and_monitoring_checks_get_no_shared_key():
    p = "/Library/LaunchAgents/x.task.plist"
    a = same_key("launch_agent_audit", {"data": {"check": "suspicious_path", "label": "x.task", "plist": p}})
    b = same_key("launch_agent_audit", {"data": {"check": "missing_program", "label": "x.task", "plist": p}})
    assert a != b
    # A check id another module uses for something else gets no key there.
    assert same_key("some_other_check", {"data": {"check": "suspicious_accessibility"}}) is None
    assert same_key("some_other_check", {"data": {"check": "not_configured"}}) is None
    assert same_key("energy_settings", {"severity": "warning", "data": {"setting": "sleep", "value": 10}}) is None
    assert same_key("system_log_errors", {"severity": "info", "data": {"error_count": 3, "top_sources": {}}}) is None
    assert same_key("resource_hog_identifier", {"data": {"pid": 1, "cpu_percent": 90}}) != \
        same_key("crypto_miner_detect", {"data": {"check": "high_cpu_process", "pid": 2}})
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


def test_a_task_copying_a_label_never_merges_with_the_real_one():
    """A label is chosen by whoever made the task: the settings file is the identity."""
    real = {"data": {"check": "suspicious_path", "label": "com.google.keystone.agent",
                     "plist": "/Library/LaunchAgents/com.google.keystone.agent.plist"}}
    rogue = {"data": {"check": "suspicious_path", "label": "com.google.keystone.agent",
                      "plist": "/Users/ann/Library/LaunchAgents/com.google.keystone.agent.plist"}}
    a = same_key("launch_agent_audit", real)
    b = same_key("launchd_persistence_audit", rogue)
    assert a and b and a != b
    assert "/Library/LaunchAgents/com.google.keystone.agent.plist" in a
    # No settings file known: no shared key at all (never by label alone).
    assert same_key("launch_agent_audit", {"data": {"check": "suspicious_path", "label": "x.task"}}) is None
    # scheduled_tasks_audit names its file "location".
    loc = same_key("scheduled_tasks_audit", {"data": {"check": "suspicious_path", "label": "x", "location": "/L/x.plist"}})
    assert loc == "task:/L/x.plist:x:suspicious_path"
