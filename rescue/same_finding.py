"""One key for the same finding reported by different checks.

Several checks look at the same thing and say so in their own words: three
crash checks all report chrome_crashpad_handler, two audio checks the volume at
0%, two persistence checks the same background task. Each finding keeps its
own check and wording; ``same_key`` gives those that mean the same thing one
key, so a screen can show them as one item and count them once.

``same_key(module, finding_dict)`` -> str | None. Deterministic from the
finding alone, so a streamed entry and the final document agree. None means
"no known twin": the screens fall back to their own identity rule. Monitoring
checks never get one (they are never merged).
"""
from __future__ import annotations

import re

_MONITORING = {"stalkerware_scan", "mvt_spyware_scan", "keylogger_indicators"}

# check id (data["check"]) -> shared key, for checks that say one thing.
_BY_CHECK = {
    # Time Machine has no backup drive.
    "no_destination": "backup:no_destination",
    "no_destination_configured": "backup:no_destination",
    # Swap in use.
    "swap_usage": "memory:swap_in_use",
    "high_swap_usage": "memory:swap_in_use",
    # Swap summary notes.
    "swap_status": "memory:swap_status",
    # The screensaver waits long before locking.
    "screensaver_timeout": "screen_lock:screensaver_wait",
    "screensaver_idle_time": "screen_lock:screensaver_wait",
    # The Mac answers pings (firewall stealth mode off).
    "stealth_mode": "firewall:answers_pings",
    "stealth_disabled": "firewall:answers_pings",
    # Apps allowed to control the Mac (Accessibility): the count, the list,
    # and the list of apps someone may not recognise are one item (the one
    # that can be marked leads it on the screens).
    "excessive_accessibility": "permissions:accessibility",
    "accessibility_access": "permissions:accessibility",
    "suspicious_accessibility": "permissions:accessibility",
    # Time Machine is not backing up because no destination is set up.
    "not_configured": "backup:no_destination",
    # The Mac never sleeps / the screen never turns off.
    "computer_sleep_disabled": "power:never_sleep",
    "display_sleep_disabled": "display:never_off",
    "display_sleep": "display:never_off",
}

# data["check"] values that mean different things in different modules: only
# these modules may use the key above.
_CHECK_MODULES = {
    "not_configured": {"time_machine_check"},
    "display_sleep": {"lock_screen_check"},
    "display_sleep_disabled": {"energy_saver_check"},
    "computer_sleep_disabled": {"energy_saver_check"},
    "suspicious_accessibility": {"accessibility_permissions"},
}

# Checks about one app's crashes; the app's name is the identity.
_CRASH_MODULES = {"app_crash_analyzer", "application_crash_report", "crash_log_analyzer"}
# Checks about background tasks; the task's settings file and label are the identity.
_INVENTORY = {"agent_info", "non_apple_info", "launch_agent_info"}
_TASK_MODULES = {"launch_agent_audit", "launchd_persistence_audit", "scheduled_tasks_audit", "login_items_audit"}


def _text(v) -> str:
    return v.strip() if isinstance(v, str) else ""


def _severity(finding: dict) -> str:
    sev = finding.get("severity")
    return str(getattr(sev, "value", sev) or "")


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_")


def same_key(module: str, finding: dict) -> str | None:
    if module in _MONITORING or not isinstance(finding, dict):
        return None
    data = finding.get("data") if isinstance(finding.get("data"), dict) else {}
    check = _text(data.get("check"))
    if check in _BY_CHECK and module in _CHECK_MODULES.get(check, {module}):
        return _BY_CHECK[check]
    # "Your Mac is set to never sleep" from the power and energy checks.
    if module in ("energy_settings", "power_settings") and data.get("setting") == "sleep" \
            and str(data.get("value")) == "0":
        return "power:never_sleep"
    # Two counts of the same system log errors in one check.
    if module == "system_log_errors" and ("known_bad_count" in data or "top_sources" in data) \
            and _severity(finding) != "info":
        return "logs:errors"
    # Many apps start automatically: the login-items count and the
    # background-items list.
    if (module == "login_items_cleanup" and data.get("type") == "excessive_login_items") \
            or (module == "startup_optimizer" and isinstance(data.get("items"), list) and _severity(finding) != "info"):
        return "startup:many_items"
    # One running program using a lot of the processor, seen by a performance
    # check and the miner check: the same process id in the same scan.
    pid = data.get("pid")
    if isinstance(pid, int) and not isinstance(pid, bool) and (
            module == "resource_hog_identifier" and isinstance(data.get("cpu_percent"), (int, float))
            or module == "crypto_miner_detect" and check == "high_cpu_process"):
        return f"process:{pid}:high_cpu"
    if check in ("volume_low", "volume_zero") and data.get("volume_percent") == 0:
        return "audio:volume_zero"
    if module in _CRASH_MODULES:
        app = _text(data.get("app_name"))
        if app and isinstance(data.get("crash_count"), int):
            return f"crashes:{app}"
        if isinstance(data.get("total_crashes"), int) or check == "crash_summary":
            return "crashes:summary"
    if module in _TASK_MODULES:
        label = _text(data.get("label"))
        # The task's settings file, not its label alone: whoever made a task
        # picks its label, so a rogue task copying a familiar label must not
        # merge into (and hide behind) the familiar one. No file, no merge.
        plist = next((p for p in (_text(data.get(k)) for k in ("plist", "location", "path")) if p), "")
        if label and check and plist:
            # The same problem with the same task. The plain inventory line has
            # a different id in each check, so those share one.
            kind = "inventory" if check in _INVENTORY else _norm(check)
            return f"task:{plist}:{label}:{kind}"
    return None
