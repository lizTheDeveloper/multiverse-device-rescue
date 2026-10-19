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
    # Many apps allowed to control the Mac (Accessibility). The list of apps
    # someone may not recognise is its own finding (it can be marked).
    "excessive_accessibility": "permissions:accessibility",
    "accessibility_access": "permissions:accessibility",
}

# Checks about one app's crashes; the app's name is the identity.
_CRASH_MODULES = {"app_crash_analyzer", "application_crash_report", "crash_log_analyzer"}
# Checks about background tasks; the task's settings file (or label) is the identity.
_INVENTORY = {"agent_info", "non_apple_info", "launch_agent_info"}
_TASK_MODULES = {"launch_agent_audit", "launchd_persistence_audit", "scheduled_tasks_audit", "login_items_audit"}


def _text(v) -> str:
    return v.strip() if isinstance(v, str) else ""


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_")


def same_key(module: str, finding: dict) -> str | None:
    if module in _MONITORING or not isinstance(finding, dict):
        return None
    data = finding.get("data") if isinstance(finding.get("data"), dict) else {}
    check = _text(data.get("check"))
    if check in _BY_CHECK:
        return _BY_CHECK[check]
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
        if label and check:
            # The same problem with the same task. The plain inventory line has
            # a different id in each check, so those share one.
            kind = "inventory" if check in _INVENTORY else _norm(check)
            return f"task:{label}:{kind}"
    return None
