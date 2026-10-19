"""'Marked as mine' for single entries of a list (rescue.known_items.ENTRY_KINDS).

A list finding (apps with a permission, saved remote-login keys) can be marked
entry by entry. The rules are the whole-list rules, per entry: an exact match
on every pinned field, a stale mark when the evidence changes, never a
downgrade for a critical finding, never anything for monitoring-software
checks, and a mark retired only when a clean run no longer lists its entry.
"""

import base64
import hashlib
import json
import sys
from pathlib import Path

import pytest

from rescue import known_items
from rescue.known_items import (
    ENTRY_KINDS,
    KnownItemsStore,
    apply_item_marks,
    entry_identity,
    item_identity,
    list_entries,
)
from rescue.models import Finding, Severity
from rescue.orchestrator import _apply_item_marks

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX file permissions for the list")

ACC = "security.app_permissions.accessibility_access"
SSH = "security.session_revocation_scan.ssh_authorized_keys"
SIGNERS: dict = {}


@pytest.fixture(autouse=True)
def _signers(monkeypatch):
    """Who signed each app, without running codesign. Default: one team."""
    SIGNERS.clear()
    monkeypatch.setattr(known_items, "app_signer", lambda app: SIGNERS.get(app, "team:ABCDE12345"))


def _f(code, data, severity=Severity.WARNING, title="Apps with Accessibility access"):
    return Finding(title=title, description="What the check saw.", severity=severity,
                   category="security", data=dict(data), code=code)


def _apps(*apps):
    return {"check": "accessibility_access", "apps": list(apps)}


def _mark_entries(code, data, entries):
    """Save entry marks for these entries of a list finding, as `known add --item` does."""
    finding = _f(code, data)
    list_kind = item_identity(finding)[0]
    entry_kind = known_items.ENTRY_KIND_FOR[list_kind]
    rows = {r["entry"]: r for r in list_entries(list_kind, finding)}
    identities = [entry_identity(entry_kind, code, rows[e]) for e in entries]
    return [item for item, _ in KnownItemsStore().add_many(entry_kind, identities, via="test")]


def _apply(code, data, severity=Severity.WARNING):
    f = _f(code, data, severity)
    apply_item_marks(code.split(".")[1], [f])
    return f


def _id_of(saved, app):
    return next(i.id for i in saved if i.identity["app"] == app)


# --- app lists -------------------------------------------------------------------


def test_some_entries_marked_keeps_the_warning_and_lists_both():
    data = _apps("com.example.one", "com.example.two", "com.example.three")
    saved = _mark_entries(ACC, data, ["com.example.one"])
    f = _apply(ACC, data)
    assert f.severity == Severity.WARNING
    assert f.data.get("marked_by_user") is None
    assert f.data["partly_marked"] is True
    assert [m["id"] for m in f.data["marked_items"]] == [saved[0].id]
    assert f.data["marked_items"][0]["entry"] == "com.example.one"
    assert sorted(f.data["unmarked"]) == ["com.example.three", "com.example.two"]
    assert f.title == "Apps with Accessibility access (2 of 3 not marked as yours)"
    assert f.description.index("Not marked as yours (2)") < f.description.index("Marked as yours (1)")
    assert "Original details:\nWhat the check saw." in f.description


def test_every_entry_marked_downgrades_like_a_whole_list_mark():
    data = _apps("com.example.one", "com.example.two")
    _mark_entries(ACC, data, ["com.example.one", "com.example.two"])
    f = _apply(ACC, data)
    assert f.severity == Severity.INFO
    assert f.data["marked_by_user"] is True
    assert f.data["original_severity"] == "warning"
    assert f.data["original_title"] == "Apps with Accessibility access"
    assert "known_item_id" not in f.data  # that is for whole-list marks; entries are in marked_items
    assert len(f.data["marked_items"]) == 2 and f.data["unmarked"] == []
    assert f.title == "Apps you marked as yours: 2 apps"
    assert "Stop treating this as mine" in f.description


def test_a_new_entry_warns_about_only_that_one():
    _mark_entries(ACC, _apps("com.example.one", "com.example.two"), ["com.example.one", "com.example.two"])
    f = _apply(ACC, _apps("com.example.one", "com.example.two", "com.evil.keys"))
    assert f.severity == Severity.WARNING
    assert f.data["unmarked"] == ["com.evil.keys"]
    assert "(1 of 3 not marked as yours)" in f.title


def test_a_signer_change_makes_only_that_entry_stale():
    data = _apps("com.example.one", "com.example.two")
    saved = _mark_entries(ACC, data, ["com.example.one", "com.example.two"])
    SIGNERS["com.example.two"] = "team:ZZZZZ99999"
    f = _apply(ACC, data)
    assert f.severity == Severity.WARNING
    assert [m["entry"] for m in f.data["marked_items"]] == ["com.example.one"]
    assert [m["entry"] for m in f.data["stale_items"]] == ["com.example.two"]
    assert f.data["stale_items"][0]["id"] == _id_of(saved, "com.example.two")
    assert f.data["unmarked"] == ["com.example.two"]
    assert "who made it has changed since you marked it" in f.description


def test_a_maker_that_cannot_be_checked_now_is_stale_never_marked():
    data = _apps("com.example.one")
    _mark_entries(ACC, data, ["com.example.one"])
    SIGNERS["com.example.one"] = None
    f = _apply(ACC, data)
    assert f.severity == Severity.WARNING and f.data["marked_items"] == []
    assert [m["entry"] for m in f.data["stale_items"]] == ["com.example.one"]


def test_critical_is_tagged_never_downgraded():
    data = _apps("com.example.one")
    _mark_entries(ACC, data, ["com.example.one"])
    f = _apply(ACC, data, Severity.CRITICAL)
    assert f.severity == Severity.CRITICAL and f.data["user_mark_ignored"] is True
    assert f.data.get("marked_by_user") is None


def test_a_whole_list_mark_still_wins_and_entry_marks_wait():
    data = _apps("com.example.one", "com.example.two")
    kind, ident = item_identity(_f(ACC, data))
    whole, _ = KnownItemsStore().add(kind, ident, via="test")
    _mark_entries(ACC, data, ["com.example.one"])
    f = _apply(ACC, data)
    assert f.data["known_item_id"] == whole.id and f.severity == Severity.INFO
    assert "marked_items" not in f.data


def test_a_stale_whole_list_mark_lets_entry_marks_apply():
    old = _apps("com.example.one")
    kind, ident = item_identity(_f(ACC, old))
    KnownItemsStore().add(kind, ident, via="test")
    now = _apps("com.example.one", "com.example.two")
    _mark_entries(ACC, now, ["com.example.one"])
    f = _apply(ACC, now)
    assert f.data["mark_stale"] is True
    assert f.data["unmarked"] == ["com.example.two"] and f.severity == Severity.WARNING


def test_entry_marks_cover_only_their_own_code():
    _mark_entries(ACC, _apps("com.example.one"), ["com.example.one"])
    other = "security.privacy_permissions_audit.excessive_camera"
    f = _apply(other, {"check": "excessive_camera", "apps": ["com.example.one"]})
    assert "marked_items" not in f.data and f.severity == Severity.WARNING


def test_one_row_per_distinct_app_even_when_the_list_repeats_one():
    f = _f(ACC, _apps("com.example.one", "com.example.one", "com.example.two"))
    rows = list_entries("app_permissions", f)
    assert [r["entry"] for r in rows] == ["com.example.one", "com.example.two"]
    assert [r["shown"] for r in rows] == ["com.example.one", "com.example.two"]  # no names in tests


def test_an_entry_mark_is_retired_only_when_its_entry_is_gone():
    data = _apps("com.example.one", "com.example.two")
    saved = _mark_entries(ACC, data, ["com.example.one", "com.example.two"])
    findings = [_f(ACC, _apps("com.example.two"))]
    _apply_item_marks("app_permissions", findings, None, True)
    assert [i.identity["app"] for i in KnownItemsStore().load()] == ["com.example.two"]
    notices = [f for f in findings if f.data.get("check") == "known_item_retired"]
    assert [n.data["known_item_id"] for n in notices] == [_id_of(saved, "com.example.one")]


def test_entry_marks_are_kept_when_the_check_could_not_look_or_the_list_cannot_be_read():
    _mark_entries(ACC, _apps("com.example.one"), ["com.example.one"])
    _apply_item_marks("app_permissions", [], None, False)
    assert len(KnownItemsStore().load()) == 1
    too_long = _apps(*[f"com.example.app{i}" for i in range(known_items.MAX_LIST_ENTRIES + 1)])
    _apply_item_marks("app_permissions", [_f(ACC, too_long)], None, True)
    assert len(KnownItemsStore().load()) == 1


def test_a_tampered_entry_matches_nothing(_isolated_known_items):
    data = _apps("com.example.one")
    _mark_entries(ACC, data, ["com.example.one"])
    doc = json.loads(_isolated_known_items.read_text())
    doc["items"][0]["identity"]["signer"] = ""
    _isolated_known_items.write_text(json.dumps(doc))
    f = _apply(ACC, data)
    assert "marked_items" not in f.data and f.severity == Severity.WARNING


def test_entry_kinds_never_cover_monitoring_software_checks():
    for kind, spec in ENTRY_KINDS.items():
        assert not set(spec["modules"]) & known_items.NEVER_MARKABLE_MODULES, kind
        assert known_items.KINDS[kind] is spec


# --- remote-login keys -------------------------------------------------------------


def _key_line(n, comment="me@laptop", options=""):
    blob = base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519" + bytes([n]) * 32).decode()
    return f"{options} ssh-ed25519 {blob} {comment}".strip()


def _ssh_module():
    from rescue.registry import discover_modules

    modules = discover_modules(Path(__file__).parent.parent / "modules")
    return next(m for m in modules if m.name == "session_revocation_scan")


def _ssh_data(tmp_path, *lines):
    mod = _ssh_module()
    keys = tmp_path / "authorized_keys"
    keys.write_text("\n".join(lines) + "\n")
    mod.authorized_keys_path = keys
    count = sum(1 for line in lines if line.strip() and not line.strip().startswith("#"))
    return mod._authorized_keys_data(count)


def test_the_session_scan_lists_each_key_by_fingerprint_never_the_key(tmp_path):
    line = _key_line(1, "jo@example.com")
    data = _ssh_data(tmp_path, "# a comment", line)
    blob = line.split()[1]
    assert len(data["keys"]) == 1
    key = data["keys"][0]
    assert key["type"] == "ssh-ed25519" and key["comment"] == "jo@example.com"
    assert key["sha256"] == hashlib.sha256(base64.b64decode(blob)).hexdigest()
    assert len(key["line_sha256"]) == 64
    assert blob not in json.dumps(data)


def test_a_line_that_is_not_a_key_means_the_list_is_only_offered_whole(tmp_path):
    data = _ssh_data(tmp_path, _key_line(1), "not a key at all")
    assert "keys" not in data and len(data["list_sha256"]) == 64


def test_ssh_entry_marks_and_a_changed_line_is_stale(tmp_path):
    a, b = _key_line(1), _key_line(2)
    data = _ssh_data(tmp_path, a, b)
    sha_a = data["keys"][0]["sha256"]
    _mark_entries(SSH, data, [sha_a])
    f = _apply(SSH, data)
    assert [m["entry"] for m in f.data["marked_items"]] == [sha_a] and f.severity == Severity.WARNING
    changed = _ssh_data(tmp_path, _key_line(1, options='command="/bin/true"'), b)
    f = _apply(SSH, changed)
    assert [m["entry"] for m in f.data["stale_items"]] == [sha_a]
    assert "me@laptop" not in f.description  # key comments never go in the text
    assert "me@laptop" not in json.dumps(f.data["stale_items"])


# --- review fixes: key parsing like sshd, and a content pin for unsigned apps -------


def _parser():
    _ssh_module()
    return sys.modules["rescue_modules.session_revocation_scan"]._parse_key_line


def _blob(n):
    return base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519" + bytes([n]) * 32).decode()


def test_a_key_type_hidden_in_a_quoted_option_is_not_read():
    parse = _parser()
    smuggle = f'command="echo ssh-ed25519 {_blob(9)} x" ssh-ed25519 {_blob(1)} me'
    assert parse(smuggle) is None
    assert parse(f'command="x" ssh-ed25519 {_blob(1)} me ssh-rsa {_blob(2)}') is None  # two key types
    assert parse(f'ssh-ed25519 {_blob(1)} ssh-ed25519 {_blob(2)}') is None


def test_an_escaped_quote_does_not_end_the_options_early():
    parse = _parser()
    tricky = f'command="a \\" ssh-ed25519 {_blob(9)} b" ssh-ed25519 {_blob(1)} me'
    assert parse(tricky) is None
    assert parse(f'command="a \\" b" ssh-ed25519 {_blob(1)} me')["sha256"] == hashlib.sha256(base64.b64decode(_blob(1))).hexdigest()
    assert parse(f'command="never closes ssh-ed25519 {_blob(1)}') is None


def test_a_normal_key_with_options_is_read():
    parse = _parser()
    got = parse(f'no-pty,command="/bin/true --flag" ssh-ed25519 {_blob(3)} jo')
    assert got["type"] == "ssh-ed25519" and got["comment"] == "jo"


def test_a_smuggled_line_makes_the_list_whole_only(tmp_path):
    data = _ssh_data(tmp_path, _key_line(1), f'command="ssh-ed25519 {_blob(9)}" ssh-ed25519 {_blob(2)}')
    assert "keys" not in data


def _fake_app(tmp_path, name, body):
    app = tmp_path / f"{name}.app"
    (app / "Contents" / "MacOS").mkdir(parents=True)
    (app / "Contents" / "Info.plist").write_bytes(
        __import__("plistlib").dumps({"CFBundleExecutable": "run", "CFBundleIdentifier": f"com.x.{name}"}))
    (app / "Contents" / "MacOS" / "run").write_bytes(body)
    return str(app)


@pytest.fixture
def real_signer(monkeypatch):
    from rescue import attribution
    from rescue.attribution import MadeBy

    monkeypatch.undo()  # drop the autouse fake; use the real app_signer
    monkeypatch.setattr(attribution, "identify", lambda app, platform: MadeBy("?", False, "unsigned"))
    return known_items.app_signer


def test_unsigned_apps_do_not_share_a_mark_and_a_changed_binary_is_stale(tmp_path, monkeypatch, real_signer):
    one = _fake_app(tmp_path, "one", b"program one")
    two = _fake_app(tmp_path, "two", b"program two")
    sig = real_signer
    assert sig(one).startswith("unsigned:") and sig(one) != sig(two)
    data = _apps(one, two)
    monkeypatch.setattr(known_items, "app_signer", sig)
    _mark_entries(ACC, data, [one])
    f = _apply(ACC, data)
    assert [m["entry"] for m in f.data["marked_items"]] == [one] and f.data["unmarked"] == [two]
    (tmp_path / "one.app" / "Contents" / "MacOS" / "run").write_bytes(b"swapped")
    f = _apply(ACC, data)
    assert [m["entry"] for m in f.data["stale_items"]] == [one]


def test_an_unsigned_app_with_no_readable_program_is_not_offered(tmp_path, real_signer):
    assert real_signer(str(tmp_path / "missing.app")) is None


def test_all_entries_marked_over_a_stale_whole_list_mark_points_at_no_whole_mark():
    old = _apps("com.example.one")
    kind, ident = item_identity(_f(ACC, old))
    whole, _ = KnownItemsStore().add(kind, ident, via="test")
    now = _apps("com.example.one", "com.example.two")
    _mark_entries(ACC, now, ["com.example.one", "com.example.two"])
    f = _apply(ACC, now)
    assert f.severity == Severity.INFO and f.data["marked_by_user"] is True
    assert "known_item_id" not in f.data and "mark_stale" not in f.data
    assert f.data["stale_list_mark"] == {"id": whole.id}
    assert "so it's shown again" not in f.description


def test_stale_sentence_covers_every_stale_entry():
    data = _apps("com.example.one", "com.example.two")
    _mark_entries(ACC, data, ["com.example.one", "com.example.two"])
    SIGNERS["com.example.one"] = "team:ZZZZZ99999"
    SIGNERS["com.example.two"] = "team:YYYYY99999"
    f = _apply(ACC, data)
    assert "You marked these as yours" in f.description and "earliest on" in f.description


def test_critical_with_only_stale_marks_does_not_say_some_are_marked():
    data = _apps("com.example.one")
    _mark_entries(ACC, data, ["com.example.one"])
    SIGNERS["com.example.one"] = "team:ZZZZZ99999"
    f = _apply(ACC, data, Severity.CRITICAL)
    assert f.severity == Severity.CRITICAL and "Some of these are marked" not in f.description
