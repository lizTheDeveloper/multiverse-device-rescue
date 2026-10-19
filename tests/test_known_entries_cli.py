"""`rescue known add --item`: mark some entries of one list finding.

The person names the finding (--code, --expect-id: the whole list as the
checkup showed it) and each entry (--item, from markable.items). The check
runs again now; every entry must still be there, unchanged, or nothing is
saved. Without --i-understand it needs a person at a terminal.
"""

import json
import sys
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from rescue import cli as cli_mod
from rescue import known_items
from rescue.known_items import KnownItemsStore, apply_item_marks, item_markable
from rescue.models import CheckResult, Finding, Severity
from rescue.serialize import checks_to_json

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX file permissions for the list")

ACC = "security.app_permissions.accessibility_access"
SIGNERS: dict = {}


@pytest.fixture(autouse=True)
def _signers(monkeypatch):
    SIGNERS.clear()
    monkeypatch.setattr(known_items, "app_signer", lambda app: SIGNERS.get(app, "team:ABCDE12345"))


def _f(code, data, severity=Severity.WARNING):
    return Finding(title="Apps with Accessibility access", description="What the check saw.",
                   severity=severity, category="security", data=dict(data), code=code)


def _apps(*apps):
    return {"check": "accessibility_access", "apps": list(apps)}


def _offer(data):
    return item_markable(_f(ACC, data), "app_permissions")


def _ids(offer, *apps):
    return [next(r["id"] for r in offer["items"] if r["key"] == a) for a in apps]


def _invoke(args, apps, tty=False, input=None):
    def check_quietly(mod, profile):
        found = [_f(ACC, _apps(*apps))] if mod.name == "app_permissions" and apps else []
        return CheckResult(mod.name, found)

    with patch.object(cli_mod, "_stdin_is_tty", return_value=tty), \
         patch.object(cli_mod, "_run_startup_integrity_check"), \
         patch.object(cli_mod, "gather_profile", return_value=None), \
         patch.object(cli_mod, "_check_quietly", side_effect=check_quietly):
        return CliRunner().invoke(cli_mod.main, args, input=input)


def _add(offer, item_ids, *extra):
    args = ["known", "add", "--code", ACC, "--expect-id", offer["id"]]
    for i in item_ids:
        args += ["--item", i]
    return args + ["--json", *extra]


def test_the_offer_lists_every_entry_with_its_own_id():
    offer = _offer(_apps("com.example.one", "com.example.two"))
    assert [r["key"] for r in offer["items"]] == ["com.example.one", "com.example.two"]
    assert all(isinstance(r["id"], str) and len(r["id"]) == 12 for r in offer["items"])
    assert len({r["id"] for r in offer["items"]}) == 2
    assert offer["id"] not in {r["id"] for r in offer["items"]}  # the whole-list id stays separate
    assert all(r["monitoring"] is True for r in offer["items"])
    assert "The ones you leave unticked keep their warning." in offer["items_will_change"]


def test_an_entry_that_cannot_be_checked_now_is_listed_without_an_id():
    SIGNERS["com.example.two"] = None
    offer = _offer(_apps("com.example.one", "com.example.two"))
    assert [r["key"] for r in offer["items"]] == ["com.example.one", "com.example.two"]
    assert next(r for r in offer["items"] if r["key"] == "com.example.two")["id"] is None


def test_a_list_too_long_to_show_entry_by_entry_has_no_items():
    many = [f"com.example.app{i}" for i in range(known_items.MAX_LIST_ENTRIES + 1)]
    offer = _offer(_apps(*many))
    assert "items" not in offer and offer["id"]


def test_marking_some_saves_only_those_then_list_and_remove_one():
    apps = ("com.example.one", "com.example.two", "com.example.three")
    offer = _offer(_apps(*apps))
    want = _ids(offer, "com.example.one", "com.example.three")
    r = _invoke(_add(offer, want, "--i-understand"), apps)
    assert r.exit_code == 0, r.output
    doc = json.loads(r.stdout)
    assert doc["status"] == "marked" and sorted(doc["ids"]) == sorted(want)
    assert doc["kind"] == "app_permission_entry" and doc["label"] == "2 of 3 apps"
    assert sorted(i.identity["app"] for i in KnownItemsStore().load()) == ["com.example.one", "com.example.three"]
    listed = _invoke(["known", "list"], ())
    assert listed.output.count("app_permission_entry") == 2
    r = _invoke(["known", "remove", want[0], "--json"], ())
    assert json.loads(r.stdout)["status"] == "removed"
    assert [i.identity["app"] for i in KnownItemsStore().load()] == ["com.example.three"]


def test_nothing_is_saved_when_any_entry_changed_since_the_checkup():
    apps = ("com.example.one", "com.example.two")
    offer = _offer(_apps(*apps))
    want = _ids(offer, *apps)
    SIGNERS["com.example.two"] = "team:ZZZZZ99999"
    r = _invoke(_add(offer, want, "--i-understand"), apps)
    assert r.exit_code == 2 and "changed since the checkup" in json.loads(r.stdout)["message"]
    assert KnownItemsStore().load() == []


def test_an_item_id_the_checkup_never_offered_is_refused():
    apps = ("com.example.one",)
    offer = _offer(_apps(*apps))
    r = _invoke(_add(offer, ["0123456789ab"], "--i-understand"), apps)
    assert r.exit_code == 2 and KnownItemsStore().load() == []


def test_marking_some_needs_the_person():
    apps = ("com.example.one", "com.example.two")
    offer = _offer(_apps(*apps))
    want = _ids(offer, "com.example.one")
    r = _invoke(_add(offer, want), apps)
    assert r.exit_code == 2 and KnownItemsStore().load() == []
    plain = _add(offer, want)[:-1]  # without --json
    r = _invoke(plain, apps, tty=True, input="n\n")
    assert r.exit_code == 1 and KnownItemsStore().load() == []
    r = _invoke(plain, apps, tty=True, input="y\n")
    assert r.exit_code == 0 and len(KnownItemsStore().load()) == 1
    assert "com.example.one" in r.output and "made by: team:ABCDE12345" in r.output
    assert "The other 1 on the list keep their warning." in r.output


def test_the_shape_of_the_command_is_checked_first():
    apps = ("com.example.one",)
    offer = _offer(_apps(*apps))
    one = _ids(offer, "com.example.one")
    camera = "security.privacy_permissions_audit.excessive_camera"
    bad = [
        ["known", "add", "--code", ACC, "--item", one[0], "--json", "--i-understand"],
        _add(offer, one + one, "--i-understand"),
        _add(offer, ["NOT-AN-ID"], "--i-understand"),
        ["known", "add", "--code", ACC, "--expect-id", offer["id"], "--code", camera, "--expect-id", "a" * 12,
         "--item", one[0], "--json", "--i-understand"],
        _add(offer, one, "--label", "x", "--i-understand"),
    ]
    for args in bad:
        r = _invoke(args, apps)
        assert r.exit_code == 2, args
    assert KnownItemsStore().load() == []


def test_monitoring_software_and_whole_only_kinds_refuse_items():
    for code in ("security.stalkerware_scan.monitoring_software_found", "security.network_proxy.proxy_enabled"):
        r = _invoke(["known", "add", "--code", code, "--expect-id", "a" * 12, "--item", "b" * 12,
                     "--json", "--i-understand"], ())
        assert r.exit_code == 2, code
    assert KnownItemsStore().load() == []


def test_scan_json_shows_which_entries_are_marked():
    apps = ("com.example.one", "com.example.two")
    offer = _offer(_apps(*apps))
    _invoke(_add(offer, _ids(offer, "com.example.one"), "--i-understand"), apps)
    f = _f(ACC, _apps(*apps))
    apply_item_marks("app_permissions", [f])

    class _Mod:
        name = "app_permissions"
        category = "security"

    doc = json.loads(checks_to_json([(_Mod(), CheckResult("app_permissions", [f]))], "darwin"))
    finding = doc["modules"][0]["findings"][0]
    assert finding["data"]["unmarked"] == ["com.example.two"]
    rows = {r["key"]: r for r in finding["markable"]["items"]}
    assert rows["com.example.one"]["marked"] is True
    assert rows["com.example.one"]["id"] == finding["data"]["marked_items"][0]["id"]
    assert rows["com.example.two"].get("marked") is not True and rows["com.example.two"]["id"]


# --- entries that can't be pinned now are never marked on their own ----------------

SSH = "security.session_revocation_scan.ssh_authorized_keys"


def test_an_entry_that_cannot_be_checked_at_write_time_is_refused():
    # e.g. an unsigned app whose program can't be hashed now: no pin, no mark.
    apps = ("com.example.one", "com.example.two")
    offer = _offer(_apps(*apps))
    want = _ids(offer, *apps)
    SIGNERS["com.example.two"] = None
    r = _invoke(_add(offer, want, "--i-understand"), apps)
    assert r.exit_code == 2 and "changed since the checkup" in json.loads(r.stdout)["message"]
    assert KnownItemsStore().load() == []


def _ssh_invoke(args, data):
    def check_quietly(mod, profile):
        found = [_f(SSH, data)] if mod.name == "session_revocation_scan" else []
        return CheckResult(mod.name, found)

    with patch.object(cli_mod, "_stdin_is_tty", return_value=False), \
         patch.object(cli_mod, "_run_startup_integrity_check"), \
         patch.object(cli_mod, "gather_profile", return_value=None), \
         patch.object(cli_mod, "_check_quietly", side_effect=check_quietly):
        return CliRunner().invoke(cli_mod.main, args)


def test_keys_are_offered_one_by_one_and_one_can_be_marked(tmp_path):
    from tests.test_known_entries import _key_line, _ssh_data

    data = _ssh_data(tmp_path, _key_line(1), _key_line(2))
    offer = item_markable(_f(SSH, data), "session_revocation_scan")
    assert [r["key"] for r in offer["items"]] == [k["sha256"] for k in data["keys"]]
    assert all(r["id"] for r in offer["items"])
    args = ["known", "add", "--code", SSH, "--expect-id", offer["id"],
            "--item", offer["items"][0]["id"], "--json", "--i-understand"]
    r = _ssh_invoke(args, data)
    assert r.exit_code == 0, r.output
    doc = json.loads(r.stdout)
    assert doc["kind"] == "ssh_authorized_key" and doc["label"] == "1 of 2 remote-login keys"
    assert [i.identity["key_sha256"] for i in KnownItemsStore().load()] == [data["keys"][0]["sha256"]]


def test_a_key_list_with_a_line_that_did_not_parse_is_offered_whole_only(tmp_path):
    from tests.test_known_entries import _blob, _key_line, _ssh_data

    data = _ssh_data(tmp_path, _key_line(1), f'command="ssh-ed25519 {_blob(9)}" ssh-ed25519 {_blob(2)}')
    offer = item_markable(_f(SSH, data), "session_revocation_scan")
    assert offer["id"] and "items" not in offer
    r = _ssh_invoke(["known", "add", "--code", SSH, "--expect-id", offer["id"],
                     "--item", "0123456789ab", "--json", "--i-understand"], data)
    assert r.exit_code == 2 and "one entry at a time" in json.loads(r.stdout)["message"]
    assert KnownItemsStore().load() == []


WATCH = "Things like this can be used to watch or get into a computer. Only say yes if you set these up yourself."


def test_the_question_warns_about_watching_and_matches_how_many(tmp_path):
    apps = ("com.example.one", "com.example.two")
    offer = _offer(_apps(*apps))
    one = _add(offer, _ids(offer, "com.example.one"))[:-1]
    r = _invoke(one, apps, tty=True, input="n\n")
    assert r.exit_code == 1 and WATCH in r.output
    assert "Is this yours, and do you want to stop being warned about it?" in r.output
    both = _add(offer, _ids(offer, *apps))[:-1]
    r = _invoke(both, apps, tty=True, input="n\n")
    assert r.exit_code == 1 and WATCH in r.output
    assert "Are these yours, and do you want to stop being warned about them?" in r.output
    assert KnownItemsStore().load() == []


def test_keys_get_the_watching_caution_too(tmp_path):
    from tests.test_known_entries import _key_line, _ssh_data

    data = _ssh_data(tmp_path, _key_line(1), _key_line(2))
    offer = item_markable(_f(SSH, data), "session_revocation_scan")
    args = ["known", "add", "--code", SSH, "--expect-id", offer["id"], "--item", offer["items"][0]["id"]]

    def check_quietly(mod, profile):
        return CheckResult(mod.name, [_f(SSH, data)] if mod.name == "session_revocation_scan" else [])

    with patch.object(cli_mod, "_stdin_is_tty", return_value=True), \
         patch.object(cli_mod, "_run_startup_integrity_check"), \
         patch.object(cli_mod, "gather_profile", return_value=None), \
         patch.object(cli_mod, "_check_quietly", side_effect=check_quietly):
        r = CliRunner().invoke(cli_mod.main, args, input="n\n")
    assert r.exit_code == 1 and WATCH in r.output and KnownItemsStore().load() == []


def test_a_broken_entry_offer_is_logged_and_the_list_stays_markable_whole(monkeypatch, caplog):
    def boom(*a, **k):
        raise RuntimeError("lookup broke")

    monkeypatch.setattr(known_items, "entry_offers", boom)
    with caplog.at_level("DEBUG", logger="rescue.known_items"):
        offer = _offer(_apps("com.example.one"))
    assert offer["id"] and "items" not in offer
    assert "lookup broke" in caplog.text
