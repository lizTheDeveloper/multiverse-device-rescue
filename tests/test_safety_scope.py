"""The removal warning ("removing it can alert them; talk to an advocate")
is decided by finding code in rescue/safety_scope.py (UX round 5, ruling 1):
on monitoring-capable findings and possible someone-else's installs only."""

from pathlib import Path

import pytest

from rescue import safety_scope
from rescue.models import CheckResult, Finding, Severity
from rescue.registry import discover_modules
from rescue.remediation import build_catalog, load_remediation_walkthroughs, render_catalog_markdown
from rescue.serialize import SAFETY_NOTE, module_entry

ROOT = Path(__file__).resolve().parent.parent
ALL = discover_modules(ROOT / "modules")
WALKTHROUGHS = load_remediation_walkthroughs(ROOT / "guides" / "remediation")
EMITTED = {c for m in ALL for c in getattr(m, "emits_codes", [])}

ALERT = ("If you think someone close to you set this up to monitor you, removing it can alert them. "
         "Talk to an advocate first (US National Domestic Violence Hotline: 1-800-799-7233, or text START to 88788).")


class Mod:
    def __init__(self, name, category="security"):
        self.name = name
        self.category = category


def entry(module, code, severity=Severity.WARNING, data=None, made_by=None):
    finding = Finding(title="t", severity=severity, category="security", code=code, data=data or {},
                      description=f"What it saw.\n\n{ALERT}\n\nWhat to do: look at it, and switch it off rather than "
                                  "deleting it. If someone you know may be monitoring you, talk to an advocate first, "
                                  "because removing it can alert them.")
    mb = {id(finding): made_by} if made_by else None
    out = module_entry(Mod(module), CheckResult(module_name=module, findings=[finding]), WALKTHROUGHS, made_by=mb)
    return out["findings"][0]


def no_alert_text(f):
    texts = [f.get("description") or ""] + [s.get("body") or "" for s in (f.get("remediation") or {}).get("steps", [])]
    return not any("799-7233" in t or "can alert" in t for t in texts)


def test_every_listed_code_is_one_a_check_emits():
    stale = sorted(safety_scope.ALL_ALERT_CODES - EMITTED)
    assert not stale, f"no module emits these: {stale}"


def test_the_three_lists_do_not_overlap():
    a, u, c = safety_scope.ALERT_CODES, safety_scope.UNVERIFIED_ALERT_CODES, safety_scope.CRITICAL_ALERT_CODES
    assert not (a & u) and not (a & c) and not (u & c)


# Which codes carry it (the ruling's list), and which never do.
CARRY = [
    ("remote_login_check", "security.remote_login_check.screen_sharing_enabled"),
    ("sharing_services", "security.sharing_services.remote_management"),
    ("session_revocation_scan", "security.session_revocation_scan.ssh_authorized_keys"),
    ("accessibility_permissions", "security.accessibility_permissions.suspicious_accessibility"),
    ("app_permissions", "security.app_permissions.accessibility_access"),
    ("privacy_permissions_audit", "security.privacy_permissions_audit.screen_accessibility_combo"),
    ("mdm_enrollment", "security.mdm_enrollment.profiles_installed"),
    ("dns_poisoning_check", "security.dns_poisoning_check.dns_filtering_profile"),
    ("network_proxy", "security.network_proxy.proxy_enabled"),
    ("chrome_extensions", "security.chrome_extensions.broad_permissions"),
    ("launch_agent_audit", "security.launch_agent_audit.suspicious_path"),
    ("launchd_persistence_audit", "security.launchd_persistence_audit.suspicious_path"),
    ("security_baseline_diff", "security.security_baseline_diff.new_persistence"),
]
NEVER = [
    ("launch_agent_audit", "security.launch_agent_audit.missing_program"),  # harmless leftover
    ("code_signature_audit", "security.code_signature_audit.old_signature_format"),
    ("code_signature_audit", "security.code_signature_audit.unsigned_system_app"),
    ("router_security_audit", "network.router_security_audit.admin_service_open"),
    ("security_baseline_diff", "security.security_baseline_diff.new_listening_port"),
    ("app_crash_analyzer", "integrity.app_crash_analyzer.frequent_crashes"),
]


@pytest.mark.parametrize("module,code", CARRY)
def test_carries_the_warning(module, code):
    assert code in safety_scope.ALL_ALERT_CODES
    f = entry(module, code)
    assert f["removal_alert"] is True
    if code in WALKTHROUGHS:
        assert f["remediation"]["safety_note"] == SAFETY_NOTE
    assert "799-7233" in f["description"]  # its own words are kept


@pytest.mark.parametrize("module,code", NEVER)
def test_never_carries_it(module, code):
    assert code not in safety_scope.ALL_ALERT_CODES
    f = entry(module, code)
    assert "removal_alert" not in f
    assert "safety_note" not in (f.get("remediation") or {})
    assert no_alert_text(f), f
    # The rest of its words stay, "What to do:" included.
    assert f["description"].startswith("What it saw.")
    assert "What to do: look at it, and switch it off rather than deleting it." in f["description"]


def test_router_walkthrough_loses_its_safety_step_when_out_of_scope():
    f = entry("router_security_audit", "network.router_security_audit.admin_service_open")
    titles = [s["title"] for s in f["remediation"]["steps"]]
    assert titles and not any("safety" in t.lower() for t in titles)
    assert f["remediation"]["all_steps"] is False


def test_tamper_only_when_critical():
    code = "security.code_signature_audit.tampered_binary"
    crit = entry("code_signature_audit", code, severity=Severity.CRITICAL)
    assert crit["removal_alert"] is True and crit["remediation"]["safety_note"] == SAFETY_NOTE
    warn = entry("code_signature_audit", code, severity=Severity.WARNING)
    assert "removal_alert" not in warn and no_alert_text(warn)


def test_info_never_carries_it():
    f = entry("chrome_extensions", "security.chrome_extensions.broad_permissions", severity=Severity.INFO)
    assert "removal_alert" not in f and "safety_note" not in (f.get("remediation") or {})


def test_a_task_whose_maker_is_verified_and_not_apple_is_out_an_apple_interpreter_is_in():
    code = "security.launch_agent_audit.suspicious_path"
    data = {"label": "com.example.agent", "program": "/Applications/Ex.app/Contents/MacOS/ex",
            "plist": "/Library/LaunchAgents/com.example.agent.plist"}
    verified = [{"subject": data["program"], "name": "Example Inc.", "verified": True, "how": "Developer ID signature"},
                {"subject": data["plist"], "name": "Example Inc.", "verified": True, "how": "Developer ID signature"}]
    assert "removal_alert" not in entry("launch_agent_audit", code, data=data, made_by=verified)
    apple = [{**e, "name": "Apple"} for e in verified]
    assert entry("launch_agent_audit", code, data=data, made_by=apple)["removal_alert"] is True
    unknown = [{**verified[0]}, {**verified[1], "verified": False, "name": "Unknown maker"}]
    assert entry("launch_agent_audit", code, data=data, made_by=unknown)["removal_alert"] is True


def test_monitoring_checks_are_left_as_they_wrote_it():
    f = entry("stalkerware_scan", "security.stalkerware_scan.monitoring_software_found", severity=Severity.CRITICAL)
    assert "799-7233" in f["description"]
    assert "removal_alert" not in f


def test_a_finding_without_a_code_is_left_alone():
    f = entry("network_proxy_detect", None)
    assert "799-7233" in f["description"]


def test_catalog_says_which_codes_carry_it():
    md = render_catalog_markdown(build_catalog(ALL, WALKTHROUGHS))
    assert "| Code | Module | Walkthrough | Removal warning |" in md
    row = next(line for line in md.splitlines() if "`security.launch_agent_audit.missing_program`" in line)
    assert row.endswith("| — |")
    row = next(line for line in md.splitlines() if "`security.launch_agent_audit.suspicious_path`" in line)
    assert row.endswith("| if the maker isn't verified |")
    row = next(line for line in md.splitlines() if "`security.code_signature_audit.tampered_binary`" in line)
    assert row.endswith("| critical only |")
    row = next(line for line in md.splitlines() if "`security.chrome_extensions.broad_permissions`" in line)
    assert row.endswith("| yes |")
    assert (ROOT / "docs" / "REMEDIATION_CATALOG.md").read_text(encoding="utf-8") == md
