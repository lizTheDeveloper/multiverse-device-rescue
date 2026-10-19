"""Synthetic scan documents shaped like the round-4 audit's replays (ux6):
the near-duplicates, four extensions, four unfinished checks and an iPhone
backup scan waiting (full), the same plus monitoring software (held), an
errors scan and a nearly clean one. Nothing here comes from a real computer:
the home folder is /Users/example and every name is made up.

Run from the repo root: python desktop/test/fixtures/make-ux6-fixtures.py
(same_key and titles are filled by the engine's own rules)."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from rescue.same_finding import same_key  # noqa: E402
from rescue.wording import tidy  # noqa: E402

OUT = Path(__file__).resolve().parent
HOME = "/Users/example"


def finding(title, severity, category, data=None, code=None, **extra):
    return {"title": title, "severity": severity, "category": category, "code": code,
            "description": title + ".", "data": data or {}, **extra}


def mod(name, category, findings=(), status="ok", supported=True, complete=True, error=None,
        error_kind=None, not_started=False):
    m = {"name": name, "category": category, "status": status, "error": error, "supported": supported,
         "unsupported_reason": None if supported else "This check doesn't run on this computer.",
         "complete": complete, "error_kind": error_kind, "findings": []}
    if not_started:
        m["not_started"] = True
    for f in findings:
        f = dict(f)
        f["title"] = tidy(f["title"])
        key = same_key(name, f)
        if key:
            f["same_key"] = key
        m["findings"].append(f)
    return m


def task(label, check, code, title, severity="warning"):
    plist = f"{HOME}/Library/LaunchAgents/{label}.plist"
    return finding(title, severity, "security", {"check": check, "label": label, "plist": plist,
                                                 "program": f"{HOME}/.example-tool/bin/run"}, code)


def full():
    s, p, i = "security", "performance", "integrity"
    ext = lambda n: finding(f"Extension with broad permissions: {n}", "warning", s,  # noqa: E731
                            {"check": "broad_permissions", "extension": n, "permissions": ["tabs"]},
                            "security.chrome_extensions.broad_permissions")
    return [
        mod("code_signature_audit", s, [finding("App Example Photos was changed after it was signed", "critical", s,
            {"check": "tampered_binary", "path": "/Applications/Example Photos.app", "apps_checked": 16, "apps_total": 110},
            "security.code_signature_audit.tampered_binary")], complete=False),
        mod("energy_saver_check", p, [
            finding("Your Mac is set to never sleep", "warning", p, {"check": "computer_sleep_disabled", "setting": "sleep", "value": "0"}),
            finding("Your screen is set to never turn off", "warning", p, {"check": "display_sleep_disabled", "setting": "displaysleep", "value": "0"}),
            finding("Hard drive sleep is turned off", "info", p, {"check": "disk_sleep_disabled"})]),
        mod("energy_settings", p, [finding("Your Mac is set to never sleep", "warning", p, {"setting": "sleep", "value": 0, "issue": "battery_drain"})]),
        mod("power_settings", p, [finding("Your Mac is set to never sleep", "warning", p, {"setting": "sleep", "value": 0, "issue": "never_sleeps"})]),
        mod("lock_screen_check", s, [finding("Your Mac screen never turns off automatically", "warning", s, {"check": "display_sleep"},
                                             "security.lock_screen_check.display_sleep")]),
        mod("accessibility_permissions", s, [
            finding("Apps you may not recognize can control your Mac (3)", "warning", s,
                    {"check": "suspicious_accessibility", "apps": ["com.example.one", "com.example.two", "com.example.three"]},
                    "security.accessibility_permissions.suspicious_accessibility", markable={"id": "k-apps", "kind": "apps"}),
            finding("Many apps can control your Mac (14)", "warning", s, {"check": "excessive_accessibility", "count": 14},
                    "security.accessibility_permissions.excessive_accessibility")]),
        mod("app_permissions", s, [finding("14 apps can control your Mac", "warning", s, {"check": "accessibility_access", "apps": []},
                                           "security.app_permissions.accessibility_access")]),
        mod("system_log_errors", i, [
            finding("Your Mac logged 83759 errors in the last hour", "warning", i, {"error_count": 83759, "unique_sources": 9, "top_sources": {}}),
            finding("Found 4837 errors from known Mac issues", "warning", i, {"known_bad_count": 4837})]),
        mod("login_items_cleanup", "bloatware", [finding("Many apps start automatically (40)", "warning", "bloatware",
                                                         {"type": "excessive_login_items", "count": 40})]),
        mod("startup_optimizer", p, [finding("33 apps start automatically in the background", "warning", p, {"items": [], "count": 33})]),
        mod("backup_status", i, [finding("No backup drive is set up for Time Machine", "warning", i, {"check": "no_destination"})]),
        mod("time_machine_check", i, [finding("Your Mac is not automatically backing up your files", "warning", i, {"check": "not_configured"})]),
        mod("time_machine_health", i, [finding("No Time Machine backup destination is set up", "warning", i, {"check": "no_destination_configured"})]),
        mod("resource_hog_identifier", p, [finding("exampled is using a lot of your computer's power", "warning", p,
                                                   {"pid": 4242, "name": "exampled", "cpu_percent": 122.3})]),
        mod("crypto_miner_detect", s, [finding("A program called exampled is using a lot of power", "warning", s,
                                               {"check": "high_cpu_process", "pid": 4242, "process": "exampled", "cpu_percent": 104.3},
                                               "security.crypto_miner_detect.high_cpu_process")]),
        mod("chrome_extensions", s, [ext("Example Tabs"), ext("Example Passwords"), ext("Example Helper"), ext("Example Reader")]),
        mod("launch_agent_audit", s, [
            task("com.example.sync", "suspicious_path", "security.launch_agent_audit.suspicious_path",
                 "Background task 'com.example.sync' runs from a hidden folder"),
            task("com.example.old", "missing_program", "security.launch_agent_audit.missing_program",
                 "Background task 'com.example.old' points to a missing program")]),
        mod("launchd_persistence_audit", s, [task("com.example.sync", "suspicious_path", "security.launchd_persistence_audit.suspicious_path",
                                                  "Background task runs from a hidden folder: com.example.sync")]),
        mod("ai_threat_indicators", s, [
            finding("AI-related program running: /Applications/Example A.app", "info", s, {"check": "ai_process"}, "security.ai_threat_indicators.ai_process"),
            finding("AI-related program running: /Applications/Example B.app", "info", s, {"check": "ai_process"}, "security.ai_threat_indicators.ai_process")]),
        mod("disk_space", p, [finding("Your disk is 92% full", "warning", p, {"used_pct": 0.92})]),
        mod("firewall_audit", "network", [finding("Your Mac responds to network pings", "warning", "network", {"check": "stealth_mode"})]),
        mod("firewall_rules_audit", "network", [finding("Your Mac responds to network pings", "warning", "network", {"check": "stealth_disabled"})]),
        mod("dns_config", i, [finding("DNS configuration", "info", i, {"servers": ["192.0.2.1"]})]),
        mod("update_checker", i, [finding("Couldn't check for macOS updates", "info", i, {})], complete=False),
        mod("large_files_finder", p, [finding("Found 3 large files", "info", p, {"count": 3})], complete=False),
        mod("storage_cleanup", p, [finding("Caches you could clean: 2 GB", "info", p, {"bytes": 2000000000})], complete=False),
        mod("mvt_spyware_scan", s, [finding("An iPhone backup can be checked for spyware", "info", s, {},
                                            "security.mvt_spyware_scan.mvt_scan_available")], not_started=True),
    ]


def held():
    keylog = mod("keylogger_indicators", "security", [finding("Example Keys can see what you type", "critical", "security",
                 {"check": "known_keylogger", "name": "Example Keys"}, "security.keylogger_indicators.known_keyloggers")])
    return full() + [keylog]


def errors():
    s, i = "security", "integrity"
    err = lambda n, k: mod(n, s, status="error", error=f"{n} failed ({k})", error_kind=k)  # noqa: E731
    return [
        mod("hosts_file_check", s, [finding("1 website name is being redirected", "warning", s, {"check": "redirect"}),
                                    finding("A custom hosts entry found", "info", s, {"check": "custom"})]),
        mod("dns_config", i, [finding("DNS configuration", "info", i, {})]),
        mod("firewall_audit", s, [finding("Your Mac responds to network pings", "warning", s, {"check": "stealth_mode"})]),
        mod("login_items", "bloatware", [finding("Login item: Example One", "info", "bloatware", {"item_name": "Example One"}),
                                         finding("Known extra software starts at login: Example Sync", "warning", "bloatware", {"item_name": "Example Sync"}),
                                         finding("Login item: Example Two", "info", "bloatware", {"item_name": "Example Two"}),
                                         finding("Login item: Example Three", "info", "bloatware", {"item_name": "Example Three"})]),
        mod("disk_space", "performance", [finding("Your disk is 92% full", "warning", "performance", {"used_pct": 0.92})]),
        err("code_signature_audit", "timeout"), err("launch_agent_audit", "permission"), err("keylogger_indicators", "timeout"),
        err("session_revocation_scan", "permission"),
        mod("stalkerware_scan", s, supported=False),
        mod("time_machine_check", i, [finding("Your Mac is not automatically backing up your files", "warning", i, {"check": "not_configured"})],
            complete=False),
    ]


def clean():
    i = "integrity"
    return [
        mod("dns_config", i, [finding("DNS configuration", "info", i, {})]),
        mod("firewall_audit", "security"),
        mod("login_items", "bloatware", [finding(f"Login item: Example {n}", "info", "bloatware", {"item_name": f"Example {n}"}) for n in ("One", "Two", "Three")]),
        mod("disk_space", "performance"),
        mod("hosts_file_check", "security", [finding("A custom hosts entry found", "info", "security", {"check": "custom"})]),
        mod("update_checker", i, [finding("Couldn't check for macOS updates", "info", i, {})], complete=False),
        mod("time_machine_check", i, supported=False),
    ]


for name, build in (("full", full), ("held", held), ("errors", errors), ("clean", clean)):
    doc = {"schema_version": 1, "platform": "darwin", "synthetic": True, "modules": build()}
    (OUT / f"ux6-{name}.json").write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")
