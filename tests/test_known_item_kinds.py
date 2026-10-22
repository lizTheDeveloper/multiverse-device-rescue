"""'Marked as mine' for settings and installed items (rescue.known_items.ITEM_KINDS).

Every kind follows the background-task rules: an exact match on every pinned
field, a stale mark when the evidence changes, fail closed on a damaged or
untrusted list, never a downgrade for a critical finding, never anything for
the monitoring-software checks, and a fresh check at write time (--expect-id).
"""

import json
import os
import sys
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from rescue import cli as cli_mod
from rescue import known_items
from rescue.known_items import (
    ITEM_CODES,
    ITEM_KINDS,
    NEVER_MARKABLE_MODULES,
    KnownItemsStore,
    apply_item_marks,
    item_identity,
    item_markable,
)
from rescue.models import CheckResult, Finding, Severity
from rescue.orchestrator import _apply_item_marks
from rescue.serialize import checks_to_json

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX file permissions for the list")

SHA = "a" * 64
SHA2 = "b" * 64


def _f(code, data, severity=Severity.WARNING, title="Something is on"):
    return Finding(title=title, description="What the check saw.", severity=severity,
                   category="security", data=dict(data), code=code)


# kind -> (code, data, data with the same item but changed evidence, data for a different item)
CASES = {
    "sharing_service": (
        "security.sharing_services.screen_sharing",
        {"service": "screen_sharing"},
        None,  # only "on" is ever reported, so there is nothing to go stale
        {"service": "file_sharing"},
    ),
    "network_proxy": (
        "security.network_proxy.proxy_enabled",
        {"check": "proxy_enabled", "interface": "Wi-Fi", "proxy_servers": ["HTTP proxy.example:8080"]},
        {"check": "proxy_enabled", "interface": "Wi-Fi", "proxy_servers": ["HTTP evil.example:8080"]},
        {"check": "proxy_enabled", "interface": "Ethernet", "proxy_servers": ["HTTP proxy.example:8080"]},
    ),
    "dns_profile": (
        "security.dns_poisoning_check.dns_filtering_profile",
        {"check": "dns_filtering_profile", "provider": "NextDNS", "servers": ["45.90.28.163", "45.90.30.163"],
         "profile_ids": []},
        {"check": "dns_filtering_profile", "provider": "NextDNS", "servers": ["45.90.28.99", "45.90.30.99"],
         "profile_ids": []},
        {"check": "dns_filtering_profile", "provider": "Control D", "servers": ["45.90.28.163", "45.90.30.163"],
         "profile_ids": []},
    ),
    "system_extension": (
        "security.system_extensions.unusual_state",
        {"check": "unusual_state", "name": "com.example.filter", "team_id": "ABCDE12345",
         "state": "activated waiting for user", "category": "network"},
        {"check": "unusual_state", "name": "com.example.filter", "team_id": "ZZZZZ99999",
         "state": "activated waiting for user", "category": "network"},
        {"check": "unusual_state", "name": "com.other.filter", "team_id": "ABCDE12345",
         "state": "activated waiting for user", "category": "network"},
    ),
    "browser_extension": (
        "security.browser_extension_audit.excessive_permissions",
        {"check": "excessive_permissions", "browser": "Chrome", "extension": "Helper",
         "extension_id": "abcdefghijklmnopabcdefghijklmnop", "permissions": ["tabs", "<all_urls>", "cookies"]},
        {"check": "excessive_permissions", "browser": "Chrome", "extension": "Helper",
         "extension_id": "abcdefghijklmnopabcdefghijklmnop",
         "permissions": ["tabs", "<all_urls>", "cookies", "webRequest"]},
        {"check": "excessive_permissions", "browser": "Chrome", "extension": "Helper",
         "extension_id": "ponmlkjihgfedcbaponmlkjihgfedcba", "permissions": ["tabs", "<all_urls>", "cookies"]},
    ),
    "app_permissions": (
        "security.app_permissions.accessibility_access",
        {"check": "accessibility_access", "apps": ["com.example.one", "com.example.two"]},
        {"check": "accessibility_access", "apps": ["com.example.one", "com.example.two", "com.evil.keys"]},
        None,  # one finding per check: a different list is the same item, changed
    ),
    "ssh_authorized_keys": (
        "security.session_revocation_scan.ssh_authorized_keys",
        {"check": "ssh_authorized_keys", "key_count": 1, "list_sha256": SHA},
        {"check": "ssh_authorized_keys", "key_count": 2, "list_sha256": SHA2},
        None,
    ),
    "remote_tool": (
        "security.remote_access_tools.tool_found",
        {"check": "tool_found", "tool": "AnyDesk", "tool_id": "anydesk", "path": "/Applications/AnyDesk.app",
         "lets_in_unattended": False, "last_incoming": "2026-03-01", "incoming_count": 2},
        # A newer incoming connection: the same tool, changed evidence.
        {"check": "tool_found", "tool": "AnyDesk", "tool_id": "anydesk", "path": "/Applications/AnyDesk.app",
         "lets_in_unattended": False, "last_incoming": "2026-03-09", "incoming_count": 3},
        {"check": "tool_found", "tool": "TeamViewer", "tool_id": "teamviewer",
         "path": "/Applications/TeamViewer.app", "lets_in_unattended": False, "last_incoming": "2026-03-01",
         "incoming_count": 2},
    ),
    "ai_tooling": (
        "security.ai_threat_indicators.ai_api_key_found",
        {"check": "ai_api_key_found", "key_name": "ANTHROPIC_API_KEY"},
        None,
        {"check": "ai_api_key_found", "key_name": "OPENAI_API_KEY"},
    ),
}


def _module_of(code):
    return code.split(".")[1]


def _mark(kind, code, data):
    hit = item_identity(_f(code, data))
    assert hit and hit[0] == kind
    item, _ = KnownItemsStore().add(kind, hit[1], via="test")
    return item


def _apply(code, data, severity=Severity.WARNING):
    f = _f(code, data, severity)
    findings = [f]
    apply_item_marks(_module_of(code), findings)
    return f, findings


def test_every_kind_has_a_case():
    assert set(CASES) == set(ITEM_KINDS)


def test_no_kind_covers_a_monitoring_software_check():
    for kind, spec in ITEM_KINDS.items():
        assert not set(spec["modules"]) & NEVER_MARKABLE_MODULES, kind
    for code in ITEM_CODES:
        assert _module_of(code) not in NEVER_MARKABLE_MODULES
    for module in NEVER_MARKABLE_MODULES:
        assert known_items.markable(_f(f"security.{module}.monitoring_software_found", {"service": "x"}), module) is None


@pytest.mark.parametrize("kind", sorted(CASES))
def test_exact_match_is_downgraded_and_stays_listed(kind):
    code, data, _, _ = CASES[kind]
    item = _mark(kind, code, data)
    f, findings = _apply(code, data)
    assert f.severity == Severity.INFO
    assert f.data["marked_by_user"] is True
    assert f.data["known_item_id"] == item.id
    assert f.data["original_severity"] == "warning"
    assert f.data["original_title"] == "Something is on"
    assert "marked as yours" in f.title
    assert "Stop treating this as mine" in f.description
    assert len(findings) == 1  # never hidden, nothing added


@pytest.mark.parametrize("kind", sorted(CASES))
def test_a_different_item_is_left_alone(kind):
    code, data, _, other = CASES[kind]
    if other is None:
        pytest.skip("one finding per check for this kind")
    _mark(kind, code, data)
    f, _ = _apply(code, other)
    assert f.severity == Severity.WARNING
    assert "marked_by_user" not in f.data and "mark_stale" not in f.data


@pytest.mark.parametrize("kind", sorted(CASES))
def test_changed_evidence_makes_the_mark_stale(kind):
    code, data, changed, _ = CASES[kind]
    if changed is None:
        pytest.skip("this kind has no evidence that can change while it is the same item")
    item = _mark(kind, code, data)
    f, _ = _apply(code, changed)
    assert f.severity == Severity.WARNING
    assert f.data["mark_stale"] is True
    assert f.data["known_item_id"] == item.id
    assert "has changed since you marked it" in f.description


@pytest.mark.parametrize("kind", sorted(CASES))
def test_a_mark_for_one_finding_code_does_not_cover_another(kind):
    code, data, _, _ = CASES[kind]
    _mark(kind, code, data)
    other_codes = [c for c, k in ITEM_CODES.items() if k == kind and c != code]
    for other in other_codes:
        f = _f(other, data)
        apply_item_marks(_module_of(other), [f])
        assert f.severity == Severity.WARNING and "marked_by_user" not in f.data


@pytest.mark.parametrize("kind", sorted(CASES))
def test_critical_is_tagged_never_downgraded(kind):
    code, data, _, _ = CASES[kind]
    _mark(kind, code, data)
    f, _ = _apply(code, data, Severity.CRITICAL)
    assert f.severity == Severity.CRITICAL
    assert f.data["user_mark_ignored"] is True
    assert "marked_by_user" not in f.data


@pytest.mark.parametrize("kind", sorted(CASES))
def test_damaged_list_fails_closed_and_says_so(kind, _isolated_known_items):
    code, data, _, _ = CASES[kind]
    _mark(kind, code, data)
    _isolated_known_items.write_text("{not json")
    f, findings = _apply(code, data)
    assert f.severity == Severity.WARNING and "marked_by_user" not in f.data
    assert any(x.data.get("check") == "known_items_ignored" for x in findings)


@pytest.mark.parametrize("kind", sorted(CASES))
def test_list_others_can_write_is_not_trusted(kind, _isolated_known_items):
    code, data, _, _ = CASES[kind]
    _mark(kind, code, data)
    os.chmod(_isolated_known_items, 0o666)
    f, findings = _apply(code, data)
    assert f.severity == Severity.WARNING and "marked_by_user" not in f.data
    assert any(x.data.get("check") == "known_items_ignored" for x in findings)


@pytest.mark.parametrize("kind", sorted(CASES))
def test_tampered_entry_matches_nothing(kind, _isolated_known_items):
    code, data, _, _ = CASES[kind]
    _mark(kind, code, data)
    doc = json.loads(_isolated_known_items.read_text())
    entry = doc["items"][0]
    key = next(k for k in entry["identity"] if k != "code")
    doc["items"].append(dict(entry, identity=dict(entry["identity"], extra="x")))  # wrong shape
    entry["identity"][key] = ""  # an empty pinned field
    _isolated_known_items.write_text(json.dumps(doc))
    f, _ = _apply(code, data)
    assert f.severity == Severity.WARNING and "marked_by_user" not in f.data


@pytest.mark.parametrize("kind", sorted(CASES))
def test_markable_only_for_warnings_with_full_evidence(kind):
    code, data, _, _ = CASES[kind]
    module = _module_of(code)
    offer = item_markable(_f(code, data), module)
    assert offer and offer["kind"] == kind and offer["code"] == code
    assert offer["id"] == known_items.item_id(kind, item_identity(_f(code, data))[1])
    assert offer["will_change"] and offer["how_to_undo"] and isinstance(offer["monitoring"], bool)
    assert isinstance(offer["group"], str) and len(offer["group"]) == 12
    assert item_markable(_f(code, data, Severity.CRITICAL), module) is None
    assert item_markable(_f(code, data, Severity.INFO), module) is None
    assert item_markable(_f(code, data), "some_other_module") is None
    assert item_markable(_f(code, {"check": "x"}), module) is None  # evidence missing
    marked = _f(code, dict(data, marked_by_user=True))
    assert item_markable(marked, module) is None


def test_unknown_team_or_empty_lists_cannot_be_pinned():
    code = "security.system_extensions.unusual_state"
    assert item_identity(_f(code, {"name": "com.x", "team_id": "unknown", "state": "waiting"})) is None
    assert item_identity(_f("security.app_permissions.accessibility_access", {"apps": []})) is None
    assert item_identity(_f("security.network_proxy.proxy_enabled", {"interface": "Wi-Fi", "proxy_servers": []})) is None
    assert item_identity(_f("security.session_revocation_scan.ssh_authorized_keys", {"key_count": 1})) is None


def test_monitoring_capable_kinds_say_so():
    def offer(code, data):
        return item_markable(_f(code, data), _module_of(code))

    assert offer("security.sharing_services.screen_sharing", {"service": "screen_sharing"})["monitoring"] is True
    assert offer("security.remote_login_check.ssh_enabled", {"service": "ssh"})["monitoring"] is True
    assert offer("security.sharing_services.printer_sharing", {"service": "printer_sharing"})["monitoring"] is False
    for kind in ("network_proxy", "dns_profile", "system_extension", "browser_extension", "app_permissions", "ssh_authorized_keys"):
        code, data, _, _ = CASES[kind]
        assert offer(code, data)["monitoring"] is True, kind


def test_the_same_service_on_several_checks_is_one_item():
    a = item_markable(_f("security.sharing_services.remote_login", {"service": "remote_login"}), "sharing_services")
    b = item_markable(_f("security.remote_login_check.ssh_enabled", {"service": "ssh"}), "remote_login_check")
    c = item_markable(_f("security.sharing_services.file_sharing", {"service": "file_sharing"}), "sharing_services")
    assert a["group"] == b["group"] != c["group"]
    assert a["id"] != b["id"]


class _Mod:
    def __init__(self, name):
        self.name = name


def test_scan_json_offers_groups_and_then_shows_marked():
    rl = _f("security.sharing_services.remote_login", {"service": "remote_login"})
    ssh = _f("security.remote_login_check.ssh_enabled", {"service": "ssh"})
    results = [(_Mod("sharing_services"), CheckResult("sharing_services", [rl])),
               (_Mod("remote_login_check"), CheckResult("remote_login_check", [ssh]))]
    doc = json.loads(checks_to_json(results, "darwin"))
    offers = [f["markable"] for m in doc["modules"] for f in m["findings"]]
    assert len(offers) == 2 and offers[0]["ids"] == offers[1]["ids"] and len(offers[0]["ids"]) == 2

    for f in (rl, ssh):
        KnownItemsStore().add(*item_identity(f), via="test")
    rl2 = _f("security.sharing_services.remote_login", {"service": "remote_login"})
    ssh2 = _f("security.remote_login_check.ssh_enabled", {"service": "ssh"})
    apply_item_marks("sharing_services", [rl2])
    apply_item_marks("remote_login_check", [ssh2])
    results = [(_Mod("sharing_services"), CheckResult("sharing_services", [rl2])),
               (_Mod("remote_login_check"), CheckResult("remote_login_check", [ssh2]))]
    doc = json.loads(checks_to_json(results, "darwin"))
    found = [f for m in doc["modules"] for f in m["findings"]]
    assert all("markable" not in f for f in found)
    assert all(f["data"]["marked_by_user"] is True and f["severity"] == "info" for f in found)
    assert found[0]["marked_ids"] == found[1]["marked_ids"] and len(found[0]["marked_ids"]) == 2


def test_orchestrator_helper_reads_the_list_once_and_never_raises():
    code, data, _, _ = CASES["sharing_service"]
    _mark("sharing_service", code, data)
    f = _f(code, data)
    with patch.object(KnownItemsStore, "load_for_scan", wraps=KnownItemsStore().load_for_scan) as load:
        marks = _apply_item_marks("sharing_services", [f], None)
        _apply_item_marks("sharing_services", [_f(code, data)], marks)
        assert load.call_count == 1
    assert f.data.get("marked_by_user") is True
    with patch.object(known_items, "apply_item_marks", side_effect=RuntimeError("boom")):
        _apply_item_marks("sharing_services", [_f(code, data)], None)  # no exception


# --- CLI ----------------------------------------------------------------------


def _invoke(args, findings_by_module, tty=False, input=None):
    def check_quietly(mod, profile):
        return CheckResult(mod.name, [_f(c, d) for c, d in findings_by_module.get(mod.name, [])])

    with patch.object(cli_mod, "_stdin_is_tty", return_value=tty), \
         patch.object(cli_mod, "_run_startup_integrity_check"), \
         patch.object(cli_mod, "gather_profile", return_value=None), \
         patch.object(cli_mod, "_check_quietly", side_effect=check_quietly):
        return CliRunner().invoke(cli_mod.main, args, input=input)


def _offer(code, data):
    return item_markable(_f(code, data), _module_of(code))


def test_cli_add_item_with_expect_id_then_list_and_remove():
    code, data, _, _ = CASES["network_proxy"]
    offer = _offer(code, data)
    r = _invoke(["known", "add", "--code", code, "--expect-id", offer["id"], "--json", "--i-understand"],
                {"network_proxy": [(code, data)]})
    assert r.exit_code == 0, r.output
    doc = json.loads(r.stdout)
    assert doc["status"] == "marked" and doc["ids"] == [offer["id"]] and doc["kind"] == "network_proxy"
    assert KnownItemsStore().load()[0].identity["proxies"] == "HTTP proxy.example:8080"
    r = _invoke(["known", "list"], {})
    assert "network_proxy" in r.output and "proxy.example:8080" in r.output
    r = _invoke(["known", "remove", offer["id"], "--json"], {})
    assert json.loads(r.stdout)["status"] == "removed" and KnownItemsStore().load() == []


def test_cli_add_item_refuses_when_the_check_now_sees_something_else():
    code, data, changed, _ = CASES["network_proxy"]
    offer = _offer(code, data)
    r = _invoke(["known", "add", "--code", code, "--expect-id", offer["id"], "--json", "--i-understand"],
                {"network_proxy": [(code, changed)]})
    assert r.exit_code == 2
    assert json.loads(r.stdout)["status"] == "refused" and "changed since the checkup" in json.loads(r.stdout)["message"]
    assert KnownItemsStore().load() == []


def test_cli_add_item_needs_a_person_and_an_expect_id():
    code, data, _, _ = CASES["sharing_service"]
    offer = _offer(code, data)
    found = {"sharing_services": [(code, data)]}
    r = _invoke(["known", "add", "--code", code, "--expect-id", offer["id"], "--json"], found)
    assert r.exit_code == 2 and KnownItemsStore().load() == []
    r = _invoke(["known", "add", "--code", code, "--json", "--i-understand"], found)
    assert r.exit_code == 2 and KnownItemsStore().load() == []
    r = _invoke(["known", "add", "--code", code, "--expect-id", offer["id"]], found, tty=True, input="n\n")
    assert r.exit_code == 1 and KnownItemsStore().load() == []
    r = _invoke(["known", "add", "--code", code, "--expect-id", offer["id"]], found, tty=True, input="y\n")
    assert r.exit_code == 0 and len(KnownItemsStore().load()) == 1


def test_cli_refuses_monitoring_software_and_unknown_codes():
    for code in ("security.stalkerware_scan.monitoring_software_found",
                 "security.keylogger_indicators.suspicious_input_monitor",
                 "security.network_proxy.pac_url_detected"):
        r = _invoke(["known", "add", "--code", code, "--expect-id", "a" * 12, "--json", "--i-understand"], {})
        assert r.exit_code == 2 and json.loads(r.stdout)["status"] == "refused"
    assert KnownItemsStore().load() == []


def test_cli_one_answer_for_one_item_on_two_checks_all_or_nothing():
    a = ("security.sharing_services.remote_login", {"service": "remote_login"})
    b = ("security.remote_login_check.ssh_enabled", {"service": "ssh"})
    oa, ob = _offer(*a), _offer(*b)
    args = ["known", "add", "--code", a[0], "--expect-id", oa["id"], "--code", b[0], "--expect-id", ob["id"],
            "--json", "--i-understand"]
    # One of the two checks no longer sees it: nothing is saved.
    r = _invoke(args, {"sharing_services": [a]})
    assert r.exit_code == 2 and KnownItemsStore().load() == []
    r = _invoke(args, {"sharing_services": [a], "remote_login_check": [b]})
    assert r.exit_code == 0, r.output
    assert sorted(json.loads(r.stdout)["ids"]) == sorted([oa["id"], ob["id"]])
    # Two different items cannot be marked with one answer.
    c = ("security.sharing_services.file_sharing", {"service": "file_sharing"})
    oc = _offer(*c)
    r = _invoke(["known", "add", "--code", a[0], "--expect-id", oa["id"], "--code", c[0], "--expect-id", oc["id"],
                 "--json", "--i-understand"], {"sharing_services": [a, c]})
    assert r.exit_code == 2


def test_cli_refuses_to_write_over_an_untrusted_list(_isolated_known_items):
    code, data, _, _ = CASES["ai_tooling"]
    _isolated_known_items.write_text('{"items": []}')
    os.chmod(_isolated_known_items, 0o666)
    r = _invoke(["known", "add", "--code", code, "--expect-id", _offer(code, data)["id"], "--json", "--i-understand"],
                {"ai_threat_indicators": [(code, data)]})
    assert r.exit_code == 1 and json.loads(r.stdout)["status"] == "failed"


def test_background_task_still_needs_label_and_program():
    r = _invoke(["known", "add", "--code", "security.launch_agent_audit.suspicious_path", "--label", "x",
                 "--json", "--i-understand"], {})
    assert r.exit_code == 2 and json.loads(r.stdout)["status"] == "refused"


# --- the evidence the modules now record -------------------------------------


def test_session_scan_fingerprints_the_key_list_without_returning_keys(tmp_path):
    from rescue.registry import discover_modules
    from pathlib import Path

    mod = next(m for m in discover_modules(Path(__file__).parent.parent / "modules") if m.name == "session_revocation_scan")
    keys = tmp_path / "authorized_keys"
    keys.write_text("# comment\nssh-ed25519 AAAAC3Nza secret-comment@host\n")
    mod.authorized_keys_path = keys
    data = mod._authorized_keys_data(1)
    assert len(data["list_sha256"]) == 64 and "secret-comment" not in json.dumps(data)
    keys.write_text("ssh-ed25519 AAAAC3Nza secret-comment@host\nssh-rsa BBBB other@host\n")
    assert mod._authorized_keys_data(2)["list_sha256"] != data["list_sha256"]


# --- retiring a mark when the item is gone ----------------------------------------


def _scan(module, findings, supported=True):
    """What the orchestrator does after one check: returns the findings it ends with."""
    findings = list(findings)
    _apply_item_marks(module, findings, None, supported)
    return findings


@pytest.mark.parametrize("kind", sorted(CASES))
def test_a_mark_is_retired_when_the_check_no_longer_sees_the_item(kind):
    code, data, _, _ = CASES[kind]
    item = _mark(kind, code, data)
    out = _scan(_module_of(code), [])  # the check ran cleanly and found nothing
    assert KnownItemsStore().load() == []
    notice = [f for f in out if f.data.get("check") == "known_item_retired"]
    assert len(notice) == 1 and notice[0].data["known_item_id"] == item.id
    assert notice[0].severity == Severity.INFO and "No longer marked as yours" in notice[0].title
    # It comes back: flagged again, not covered.
    f = _f(code, data)
    _scan(_module_of(code), [f])
    assert f.severity == Severity.WARNING and "marked_by_user" not in f.data


def test_sharing_service_off_then_on_is_flagged_again():
    code = "security.sharing_services.screen_sharing"
    _mark("sharing_service", code, {"service": "screen_sharing"})
    on = _f(code, {"service": "screen_sharing"})
    _scan("sharing_services", [on])
    assert on.data.get("marked_by_user") is True  # still on: still covered
    _scan("sharing_services", [_f("security.sharing_services.file_sharing", {"service": "file_sharing"})])  # off
    again = _f(code, {"service": "screen_sharing"})
    _scan("sharing_services", [again])  # someone turned it back on
    assert again.severity == Severity.WARNING and "marked_by_user" not in again.data


@pytest.mark.parametrize("kind", sorted(CASES))
def test_changed_evidence_is_stale_not_retired(kind):
    code, data, changed, _ = CASES[kind]
    if changed is None:
        pytest.skip("no evidence that can change")
    _mark(kind, code, data)
    out = _scan(_module_of(code), [_f(code, changed)])
    assert len(KnownItemsStore().load()) == 1
    assert out[0].data.get("mark_stale") is True


def test_nothing_is_retired_when_the_check_could_not_look_or_for_other_checks():
    code, data, _, _ = CASES["network_proxy"]
    _mark("network_proxy", code, data)
    _scan("network_proxy", [], supported=False)
    _scan("sharing_services", [])  # a different check knows nothing about proxies
    _scan("launch_agent_audit", [])  # not an item check at all
    assert len(KnownItemsStore().load()) == 1


def test_background_task_marks_are_never_retired_this_way():
    item, _ = KnownItemsStore().add("background_task", {
        "code": "security.launch_agent_audit.suspicious_path", "label": "x", "plist": "/p/x.plist",
        "program": "/a/python", "arguments_sha256": SHA, "content_sha256": SHA2,
    }, via="test")
    assert known_items.marks_gone("launch_agent_audit", [], KnownItemsStore().load()) == []
    assert KnownItemsStore().load()[0].id == item.id


def test_an_untrusted_list_is_never_written(_isolated_known_items):
    code, data, _, _ = CASES["sharing_service"]
    _mark("sharing_service", code, data)
    before = _isolated_known_items.read_text()
    os.chmod(_isolated_known_items, 0o666)
    out = _scan("sharing_services", [])
    assert _isolated_known_items.read_text() == before
    assert not any(f.data.get("check") == "known_item_retired" for f in out)
    # And if the list turns untrusted between reading and writing, nothing is removed.
    os.chmod(_isolated_known_items, 0o600)
    items = KnownItemsStore().load()
    os.chmod(_isolated_known_items, 0o666)
    assert known_items.retire_marks(items) == []
    assert _isolated_known_items.read_text() == before


def test_only_the_gone_item_is_retired():
    a = ("security.sharing_services.screen_sharing", {"service": "screen_sharing"})
    b = ("security.sharing_services.printer_sharing", {"service": "printer_sharing"})
    _mark("sharing_service", *a)
    kept = _mark("sharing_service", *b)
    _scan("sharing_services", [_f(*b)])
    assert [i.id for i in KnownItemsStore().load()] == [kept.id]
