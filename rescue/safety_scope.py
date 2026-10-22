"""Which findings carry the removal warning ("removing it can alert whoever set
it up; talk to an advocate first").

The warning is a safety control, so it is decided here, once, by finding code,
not by each screen guessing from wording. It belongs on findings that are
monitoring-capable or could be someone else's install:

- monitoring software (stalkerware, iPhone spyware, keyloggers): those checks
  are never touched here; every screen always treats them as monitoring;
- remote access and screen sharing, saved login keys, other signed-in sessions;
- keyboard, input, accessibility, screen-recording, camera and microphone access;
- configuration (MDM) profiles, DNS that is redirected or goes through a
  profile, proxies, added root certificates, system extensions;
- background tasks, login items and scheduled jobs whose maker wasn't verified;
- browser extensions with broad access;
- an app whose code signature was tampered with (critical only; an old
  signature format is not tampering).

Not on harmless leftovers (a task whose program is gone), crashes, storage,
updates, router settings, counts of items, or old-format signatures.

``removal_alert(module, finding_dict)`` -> bool. ``serialize`` then:
- in scope: sets ``remediation.safety_note`` (when there is a walkthrough) and
  ``removal_alert: true`` on the finding;
- out of scope (a finding with a code): drops ``safety_note`` and takes the
  "removing it can alert them / talk to an advocate" sentences out of the
  description and the steps, so no screen can infer the warning from them.
A finding without a code is left as its check wrote it. Info findings never
carry it (an inventory would repeat it on every line).
"""
from __future__ import annotations

import re

MONITORING_MODULES = frozenset({"stalkerware_scan", "mvt_spyware_scan", "keylogger_indicators"})

# Always in scope (non-info).
ALERT_CODES = frozenset({
    # Remote access, screen sharing, saved keys, other sessions.
    "security.remote_login_check.ssh_enabled",
    "security.remote_login_check.remote_access_unknown",
    "security.remote_login_check.screen_sharing_enabled",
    "security.remote_login_check.remote_management_enabled",
    "security.remote_login_check.remote_apple_events_enabled",
    "security.win_rdp_check.rdp_enabled_no_nla",
    "security.win_rdp_check.rdp_enabled_with_nla",
    "security.sharing_services.screen_sharing",
    "security.sharing_services.file_sharing",
    "security.sharing_services.remote_login",
    "security.sharing_services.sharing_unknown",
    "security.sharing_services.remote_management",
    "security.sharing_preferences_audit.screen_sharing",
    "security.sharing_preferences_audit.file_sharing",
    "security.sharing_preferences_audit.remote_login",
    "security.sharing_preferences_audit.sharing_unknown",
    "security.sharing_preferences_audit.remote_management",
    "security.remote_access_tools.tool_found",
    "security.remote_access_tools.several_tools",
    "security.remote_access_tools.unattended_recent",
    "security.remote_access_tools.running_now",
    "security.win_remote_access_audit.teamviewer_installed",
    "security.win_remote_access_audit.anydesk_installed",
    "security.win_remote_access_audit.vnc_installed",
    "security.win_remote_access_audit.logmein_installed",
    "security.win_remote_access_audit.chrome_remote_desktop",
    "security.win_remote_access_audit.rdp_enabled",
    "security.win_remote_access_audit.multiple_tools",
    "security.session_revocation_scan.ssh_authorized_keys",
    "security.session_revocation_scan.browser_sessions",
    "security.session_revocation_scan.system_accounts",
    "security.ai_worm_git_ssh.ssh_authorized_keys_recent",
    "security.network_connections_monitor.backdoor_ports",
    # Keyboard, input, accessibility, screen, camera and microphone access.
    "security.accessibility_permissions.accessibility_access",
    "security.accessibility_permissions.suspicious_accessibility",
    "security.accessibility_permissions.excessive_accessibility",
    "security.app_permissions.accessibility_access",
    "security.app_permissions.full_disk_access",
    "security.app_permissions.screen_recording",
    "security.app_permissions.camera_access",
    "security.app_permissions.microphone_access",
    "security.privacy_permissions_audit.camera_access",
    "security.privacy_permissions_audit.microphone_access",
    "security.privacy_permissions_audit.screen_recording_access",
    "security.privacy_permissions_audit.accessibility_access",
    "security.privacy_permissions_audit.full_disk_access",
    "security.privacy_permissions_audit.excessive_camera",
    "security.privacy_permissions_audit.excessive_microphone",
    "security.privacy_permissions_audit.camera_microphone_combo",
    "security.privacy_permissions_audit.screen_accessibility_combo",
    # Configuration profiles, Screen Time set up by someone else.
    "security.mdm_enrollment.mdm_enrolled",
    "security.mdm_enrollment.supervised",
    "security.mdm_enrollment.profiles_installed",
    "security.mdm_enrollment_check.mdm_enrollment",
    "security.mdm_enrollment_check.restrictions_profiles",
    "security.mdm_enrollment_check.all_profiles",
    "security.mdm_enrollment_check.dep_status",
    "security.screen_time_audit.screen_time_enabled",
    "security.screen_time_audit.screen_time_no_passcode",
    "security.screen_time_audit.content_privacy_restrictions",
    "security.screen_time_audit.downtime_enabled",
    "security.screen_time_audit.app_limits_configured",
    "security.screen_time_audit.communication_limits_configured",
    "security.screen_time_parental.screen_time_enabled",
    "security.screen_time_parental.screen_time_no_passcode",
    "security.screen_time_parental.content_privacy_restrictions",
    "security.screen_time_parental.app_limits_configured",
    "security.screen_time_parental.downtime_enabled",
    "security.screen_time_parental.communication_limits_configured",
    "security.screen_time_parental.managed_accounts",
    # DNS that is redirected or goes through a profile; proxies; traffic interception.
    "security.dns_poisoning_check.malicious_dns",
    "security.dns_poisoning_check.suspicious_dns",
    "security.dns_poisoning_check.dns_filtering_profile",
    "security.network_proxy.pac_url_detected",
    "security.network_proxy.proxy_enabled",
    "network.network_proxy_check.remote_pac_url",
    "network.network_proxy_check.pac_url_detected",
    "network.network_proxy_check.suspicious_localhost_proxy",
    "network.network_proxy_check.proxy_enabled",
    "security.win_proxy_detect.localhost_suspicious",
    "security.win_proxy_detect.ie_proxy_enabled",
    "security.win_proxy_detect.pac_configured",
    "security.win_proxy_detect.system_proxy",
    "network.arp_spoof_check.gateway_impersonation",
    "network.arp_spoof_check.duplicate_mac",
    "security.certificate_audit.user_root_cas",
    "security.certificate_trust_audit.suspicious_certificates",
    "security.certificate_trust_audit.self_signed_root_certs",
    "security.certificate_trust_audit.user_added_certs",
    "security.system_extensions.active_extension",
    "security.system_extensions.unusual_state",
    # Browser extensions with broad access.
    "security.chrome_extensions.broad_permissions",
    "security.browser_extension_audit.malicious_extension",
    "security.browser_extension_audit.adware_extension",
    "security.browser_extension_audit.excessive_permissions",
    "security.safari_extensions.legacy_extensions",
    "security.safari_extensions.app_extensions",
    "security.security_baseline_diff.new_browser_extension",
    # Hidden or known-bad software, extra admin accounts.
    "security.launchd_persistence_audit.known_malware",
    "security.suspicious_processes.known_malware",
    "security.suspicious_processes.suspicious_paths",
    "security.suspicious_processes.suspicious_names",
    "security.rootkit_check.binary_integrity",
    "security.rootkit_check.kernel_extensions",
    "security.rootkit_check.hidden_processes",
    "security.rootkit_check.hidden_files",
    "security.win_rootkit_check.unsigned_drivers",
    "security.win_rootkit_check.hidden_services",
    "security.win_rootkit_check.boot_tampering",
    "security.linux_account_audit.extra_uid0_account",
    "security.user_account_audit.admin_accounts",
    "security.win_local_admin_audit.excessive_admin_accounts",
    "security.win_user_accounts.multiple_admin_accounts",
})

# Something that starts on its own: in scope unless every program it names has
# a verified maker that isn't Apple (an Apple interpreter runs anyone's script).
UNVERIFIED_ALERT_CODES = frozenset({
    "security.launch_agent_audit.suspicious_path",
    "security.launch_agent_audit.obfuscated_name",
    "security.launchd_persistence_audit.suspicious_path",
    "security.launchd_persistence_audit.keepalive_runatload",
    "security.scheduled_tasks_audit.suspicious_launch_agent",
    "security.security_baseline_diff.new_persistence",
    "security.cron_jobs_audit.rce_in_cron",
    "security.cron_jobs_audit.suspicious_path",
    "security.cron_jobs_audit.obfuscated_command",
    "security.linux_persistence_audit.suspicious_content",
    "security.linux_persistence_audit.volatile_path_execution",
    "security.linux_persistence_audit.ld_preload_set",
    "security.win_autoruns_audit.temp_path_execution",
    "security.win_autoruns_audit.obfuscated_command",
    "security.win_scheduled_tasks.non_microsoft_tasks",
    "security.win_scheduled_tasks.suspicious_path",
    "security.win_scheduled_tasks.encoded_command",
    "security.win_scheduled_tasks_security.encoded_powershell",
    "security.win_scheduled_tasks_security.temp_path_system",
    "security.win_scheduled_tasks_security.non_microsoft_system",
    "security.win_scheduled_tasks_security.hidden_attributes",
    "security.win_services_audit.suspicious_path",
})

# Critical only: an app changed after it was signed. An old signature format
# (a warning) is not tampering.
CRITICAL_ALERT_CODES = frozenset({
    "security.code_signature_audit.tampered_binary",
})

ALL_ALERT_CODES = ALERT_CODES | UNVERIFIED_ALERT_CODES | CRITICAL_ALERT_CODES


def _severity(finding: dict) -> str:
    sev = finding.get("severity")
    return getattr(sev, "value", sev) if sev is not None else ""


def _verified_non_apple(finding: dict) -> bool:
    entries = finding.get("made_by")
    if finding.get("makers_verified") is not True or not isinstance(entries, list) or not entries:
        return False
    return all(isinstance(e, dict) and e.get("verified") is True
               and not str(e.get("name") or "").lower().startswith("apple") for e in entries)


def removal_alert(module: str | None, finding: dict) -> bool:
    """True when this finding carries the removal warning (see the module doc).
    Monitoring checks are not decided here (see ``decides``)."""
    if not isinstance(finding, dict):
        return False
    sev = _severity(finding)
    if sev not in ("critical", "warning"):
        return False
    code = finding.get("code")
    if code in ALERT_CODES:
        return True
    if code in CRITICAL_ALERT_CODES:
        return sev == "critical"
    if code in UNVERIFIED_ALERT_CODES:
        return not _verified_non_apple(finding)
    return False


def decides(module: str | None, finding: dict) -> bool:
    """Whether this module's rule applies: every finding with a code, except
    the monitoring checks' own (always treated as monitoring by the screens)."""
    return isinstance(finding, dict) and module not in MONITORING_MODULES and bool(finding.get("code"))


# The warning sentences a check wrote into its own text: "If you think someone
# close to you set this up to monitor you, removing it can alert them.", "Talk
# to an advocate first (US National Domestic Violence Hotline: …).", "…,
# because removing it can alert them."
_ALERT = re.compile(
    r"\b(?:remov\w*|uninstall\w*|delet\w*|disabl\w*|chang\w*|(?:switch|turn)\w*\s+(?:\S+\s+){0,3}?off)\b"
    r"[^.!?]*?\b(?:can|may|could|might|will|would)\s+(?:alert|tip\s+off|notify|warn)\b", re.I)
_ADVOCATE = re.compile(r"\btalk to an advocate\b|799-7233|START to 88788", re.I)
_SAFETY_STEP = re.compile(r"\bsafety\b|\bsafe to\b|\bwhether it.s safe\b", re.I)
_SENTENCE = re.compile(r"[^.!?]+(?:[.!?]+[)\"”’']*|$)\s*")


def _drop_alert_sentences(text: str) -> str:
    if not isinstance(text, str) or not (_ALERT.search(text) or _ADVOCATE.search(text)):
        return text
    paragraphs = []
    for para in text.split("\n\n"):
        if not (_ALERT.search(para) or _ADVOCATE.search(para)):
            paragraphs.append(para)
            continue
        lead = para[: len(para) - len(para.lstrip())]
        kept = "".join(s for s in _SENTENCE.findall(para.strip())
                       if s.strip() and not (_ALERT.search(s) or _ADVOCATE.search(s))).strip()
        # A "What to do:" paragraph keeps its label when only its warning went.
        if kept:
            paragraphs.append(lead + kept)
    return "\n\n".join(paragraphs)


def apply(module: str | None, out: dict, safety_note: str) -> None:
    """Set or clear the removal warning on a serialized finding, in place."""
    if not decides(module, out):
        return
    rem = out.get("remediation") if isinstance(out.get("remediation"), dict) else None
    if removal_alert(module, out):
        out["removal_alert"] = True
        if rem is not None:
            rem["safety_note"] = safety_note
        return
    out.pop("removal_alert", None)
    if rem is not None:
        rem.pop("safety_note", None)
        steps = rem.get("steps")
        if isinstance(steps, list):
            # A step that is only the safety decision ("Decide whether this is
            # a safety situation first") goes; other steps lose the sentences.
            kept = []
            for step in steps:
                if isinstance(step, dict) and _SAFETY_STEP.search(str(step.get("title") or "")) \
                        and _ADVOCATE.search(str(step.get("body") or "")):
                    continue
                if isinstance(step, dict) and isinstance(step.get("body"), str):
                    step["body"] = _drop_alert_sentences(step["body"])
                kept.append(step)
            if len(kept) != len(steps):
                rem["steps"] = kept
                rem["all_steps"] = False
    if isinstance(out.get("description"), str):
        out["description"] = _drop_alert_sentences(out["description"])
