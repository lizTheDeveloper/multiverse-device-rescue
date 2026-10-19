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
import os
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
_REAL_APP_SIGNER = known_items.app_signer  # before any fixture swaps it


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


def test_a_maker_that_cannot_be_checked_now_warns_as_unchecked_never_changed():
    data = _apps("com.example.one")
    saved = _mark_entries(ACC, data, ["com.example.one"])
    SIGNERS["com.example.one"] = None
    f = _apply(ACC, data)
    assert f.severity == Severity.WARNING and f.data["marked_items"] == []
    assert f.data["stale_items"] == []
    assert [m["entry"] for m in f.data["unchecked_items"]] == ["com.example.one"]
    assert f.data["unchecked_items"][0]["id"] == saved[0].id
    assert f.data["unmarked"] == ["com.example.one"]
    assert "We couldn't check this one this time, so its warning is back." in f.description
    assert "has changed" not in f.description and "changed since" not in f.description


def test_a_spent_lookup_budget_is_unchecked_never_changed(monkeypatch):
    """The real app_signer with the entry lookup budget spent returns None."""
    from types import SimpleNamespace

    from rescue import attribution

    data = _apps("com.example.one", "com.example.two")
    _mark_entries(ACC, data, ["com.example.one", "com.example.two"])
    monkeypatch.setattr(known_items, "app_signer", _REAL_APP_SIGNER)
    monkeypatch.setattr(attribution.command, "run",
                        lambda *a, **k: SimpleNamespace(returncode=1, stdout="", stderr="", timed_out=False))
    known_items.reset_hash_budget()
    att = known_items._entry_attributor()
    att.lookups = att.max_lookups  # the budget is spent
    f = _apply(ACC, data)
    assert sorted(m["entry"] for m in f.data["unchecked_items"]) == ["com.example.one", "com.example.two"]
    assert f.data["stale_items"] == []
    assert "We couldn't check these this time, so their warnings are back." in f.description
    assert "changed since" not in f.description and "has changed on each" not in f.description
    offers = known_items.entry_offers(f, "app_permissions")
    assert all(o.get("unchecked") is True and "stale" not in o and o["id"] is None for o in offers)
    known_items.reset_hash_budget()


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

    # Put back the real app_signer. Not monkeypatch.undo(): that would also drop
    # conftest's RESCUE_KNOWN_ITEMS and let marks reach the person's real list.
    monkeypatch.setattr(known_items, "app_signer", _REAL_APP_SIGNER)
    monkeypatch.setattr(attribution, "identify", lambda app, platform, **kw: MadeBy("?", False, "unsigned"))
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


# --- fix round 2: hashing budget, racing files, odd option bytes -----------------------


@pytest.fixture
def hashing(monkeypatch):
    known_items.reset_hash_budget()
    yield known_items
    known_items.reset_hash_budget()


@pytest.fixture
def settled(monkeypatch):
    """Hash as if every file was last changed long ago, so hashes are cached."""
    import time as real_time
    from types import SimpleNamespace

    monkeypatch.setattr(known_items, "time", SimpleNamespace(time_ns=lambda: real_time.time_ns() + 10**11))


def _rewrite_until_ctime_moves(f, content, before):
    """Rewrite f with content (same size), restore its mtime, and repeat until
    the kernel's ctime clock has ticked past `before` (coarse on older Linux)."""
    import time as real_time

    for _ in range(400):
        f.write_bytes(content)
        os.utime(f, ns=(before.st_atime_ns, before.st_mtime_ns))
        if os.stat(f).st_ctime_ns != before.st_ctime_ns:
            return
        real_time.sleep(0.005)
    pytest.fail("ctime never changed")


def test_a_file_is_hashed_once_per_scan(tmp_path, hashing, settled, monkeypatch):
    f = tmp_path / "prog"
    f.write_bytes(b"abc")
    first = hashing._hash_regular_file(str(f))
    spent = hashing._hash_state["spent"]
    calls = []
    real = os.read
    monkeypatch.setattr(os, "read", lambda fd, n: (calls.append(1), real(fd, n))[1])
    assert hashing._hash_regular_file(str(f)) == first and not calls
    assert hashing._hash_state["spent"] == spent
    f.write_bytes(b"abcd")  # size changed: hashed again
    assert hashing._hash_regular_file(str(f)) != first


def test_a_rewrite_with_the_same_size_and_a_restored_mtime_is_hashed_again(tmp_path, hashing, settled):
    # A program can set mtime, but not ctime: the cache must not trust size + mtime.
    f = tmp_path / "prog"
    f.write_bytes(b"good")
    before = os.stat(f)
    first = hashing._hash_regular_file(str(f))
    assert len(hashing._hash_state["cache"]) == 1  # cached: the next call could reuse it
    _rewrite_until_ctime_moves(f, b"evil", before)
    after = os.stat(f)
    assert (after.st_size, after.st_mtime_ns) == (before.st_size, before.st_mtime_ns)
    second = hashing._hash_regular_file(str(f))
    assert second != first
    assert second == hashlib.sha256(b"evil").hexdigest()


def test_a_just_written_file_is_never_served_from_the_cache(tmp_path, hashing):
    # Within one tick of a coarse ctime clock a rewrite leaves (ino, size, mtime,
    # ctime) all the same, so a file changed in the last second is never cached.
    f = tmp_path / "prog"
    f.write_bytes(b"good")
    before = os.stat(f)
    assert hashing._hash_regular_file(str(f)) == hashlib.sha256(b"good").hexdigest()
    assert hashing._hash_state["cache"] == {}
    f.write_bytes(b"evil")
    os.utime(f, ns=(before.st_atime_ns, before.st_mtime_ns))
    assert hashing._hash_regular_file(str(f)) == hashlib.sha256(b"evil").hexdigest()


def test_the_cache_key_comes_only_from_the_open_handle(tmp_path, hashing, settled, monkeypatch):
    f = tmp_path / "prog"
    f.write_bytes(b"abc")
    monkeypatch.setattr(os.path, "realpath", lambda *a, **k: pytest.fail("realpath after open"))
    assert hashing._hash_regular_file(str(f)) == hashlib.sha256(b"abc").hexdigest()
    st = os.stat(f)
    assert list(hashing._hash_state["cache"]) == [
        (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)]


def test_the_scan_byte_budget_runs_out_and_those_files_get_none(tmp_path, hashing, monkeypatch):
    monkeypatch.setattr(known_items, "_SCAN_HASH_BYTES", 10)
    a, b = tmp_path / "a", tmp_path / "b"
    a.write_bytes(b"x" * 8)
    b.write_bytes(b"y" * 8)
    assert hashing._hash_regular_file(str(a)) is not None
    assert hashing._hash_regular_file(str(b)) is None
    known_items.reset_hash_budget()  # a new scan starts fresh
    assert hashing._hash_regular_file(str(b)) is not None


def test_the_per_file_cap_is_128_mb_and_holds_even_if_the_file_grows(tmp_path, hashing, monkeypatch):
    assert known_items._MAX_PROGRAM_BYTES == 128 * 1024 * 1024
    monkeypatch.setattr(known_items, "_MAX_PROGRAM_BYTES", 100)
    big = tmp_path / "big"
    big.write_bytes(b"z" * 101)
    assert hashing._hash_regular_file(str(big)) is None
    grows = tmp_path / "grows"
    grows.write_bytes(b"z" * 50)
    real_fstat = os.fstat

    def lying(fd):
        st = real_fstat(fd)
        grows.write_bytes(b"z" * 5000)  # grows after the size was read
        return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, st.st_uid, st.st_gid,
                               50, st.st_atime, st.st_mtime, st.st_ctime))

    monkeypatch.setattr(os, "fstat", lying)
    assert hashing._hash_regular_file(str(grows)) is None


def test_a_fifo_swapped_in_does_not_block_and_is_not_hashed(tmp_path, hashing):
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    assert hashing._hash_regular_file(str(fifo)) is None


def test_resolve_app_by_path_respects_the_lookup_budget(tmp_path, monkeypatch):
    from rescue import attribution

    att = attribution.Attributor("darwin", max_lookups=1)
    monkeypatch.setitem(attribution._DEFAULT, "darwin", att)
    p = tmp_path / "x"
    p.write_text("x")
    assert attribution.resolve_app(str(p), "darwin") == str(p)
    assert attribution.resolve_app(str(p), "darwin") is None


def test_options_with_a_backslash_outside_quotes_or_odd_whitespace_are_refused():
    parse = _parser()
    assert parse(f"no-pty\\x ssh-ed25519 {_blob(1)} me") is None
    assert parse(f'command="a\\"b" ssh-ed25519 {_blob(1)} me') is not None  # escaped quote inside quotes
    assert parse(f'command="a\x0bb" ssh-ed25519 {_blob(1)} me') is None
    assert parse(f"no-pty,\x0cno-x11 ssh-ed25519 {_blob(1)} me") is None
    assert parse(f'command="a\tb" ssh-ed25519 {_blob(1)} me') is not None  # tab is fine


# --- fix round: entry offers use their own lookup budget ----------------------------


def test_entry_offers_have_their_own_small_lookup_budget_per_scan(hashing):
    from rescue import attribution

    att = known_items._entry_attributor()
    assert att.max_lookups == known_items.ENTRY_MAX_LOOKUPS == 60
    assert att is known_items._entry_attributor()
    assert att is not attribution._DEFAULT.get(sys.platform)
    known_items.KnownItemsStore().load_for_scan()  # a new scan starts a new budget
    assert known_items._entry_attributor() is not att


def test_spent_entry_budget_leaves_made_by_attribution_alone(tmp_path, hashing, monkeypatch):
    from types import SimpleNamespace

    from rescue import attribution
    from rescue.models import CheckResult

    calls = []

    def fake_run(args, timeout=None):
        calls.append(args)
        return SimpleNamespace(returncode=1, stdout="", stderr="", timed_out=False)

    monkeypatch.setattr(known_items, "app_signer", _REAL_APP_SIGNER)
    monkeypatch.setattr(attribution, "_DEFAULT", {})
    monkeypatch.setattr(attribution.command, "run", fake_run)
    att = known_items._entry_attributor()
    att.lookups = att.max_lookups  # entry offers spent their whole budget
    assert [known_items.app_signer(f"com.example.app{i}") for i in range(80)] == [None] * 80
    assert not calls and attribution._DEFAULT == {}  # nothing borrowed from the shared budget
    prog = tmp_path / "prog"
    prog.write_bytes(b"x")
    finding = Finding(title="t", description="d", severity=Severity.WARNING, category="security",
                      data={"program": str(prog)})

    class _Mod:
        name = "launch_agents_audit"

    attribution.compute_made_by([(_Mod(), CheckResult("launch_agents_audit", [finding]))], "darwin")
    assert calls  # made_by still looked the program up


def test_the_isolation_guard_catches_a_test_that_drops_it(tmp_path_factory, monkeypatch):
    from tests.conftest import assert_known_items_isolated

    base = tmp_path_factory.getbasetemp()
    assert_known_items_isolated(base)  # as every test starts
    saved = os.environ["RESCUE_KNOWN_ITEMS"]
    monkeypatch.delenv("RESCUE_KNOWN_ITEMS")  # what monkeypatch.undo() would do
    with pytest.raises(AssertionError, match="real marked-as-mine list"):
        assert_known_items_isolated(base)
    monkeypatch.setenv("RESCUE_KNOWN_ITEMS", saved)  # put it back so teardown passes
