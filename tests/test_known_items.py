"""'Marked as mine': the store, the background-task downgrade, the scan JSON and the CLI."""

import json
import os
import plistlib
import shutil
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from rescue import cli as cli_mod
from rescue import known_items
from rescue.known_items import (
    BACKGROUND_TASK,
    KnownItem,
    KnownItemsError,
    KnownItemsStore,
    find_background_task,
)
from rescue.models import Finding, Platform, Severity, SystemProfile
from rescue.registry import discover_modules
from rescue.serialize import checks_to_json

# Marks cover macOS background tasks (launchd), and the store relies on POSIX
# ownership and permission bits; neither exists on Windows.
pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="macOS launchd marks; POSIX file permissions")

MODULES_DIR = Path(__file__).parent.parent / "modules"
LABEL = "ai.example.gateway"
CODES = {
    "launch_agent_audit": "security.launch_agent_audit.suspicious_path",
    "launchd_persistence_audit": "security.launchd_persistence_audit.suspicious_path",
}
LAA = CODES["launch_agent_audit"]

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")


@pytest.fixture
def tmp_path(tmp_path):
    """Not under /tmp on Linux: the checks rightly flag /tmp programs as critical."""
    if not sys.platform.startswith("linux"):
        yield tmp_path
        return
    d = Path(tempfile.mkdtemp(prefix="rescue-test-", dir=Path.home()))
    try:
        yield d
    finally:
        shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def agents_dir(tmp_path, monkeypatch):
    d = tmp_path / "LaunchAgents"
    d.mkdir()
    monkeypatch.setattr(known_items, "launchd_dirs", lambda: [d])
    return d


def _profile():
    return SystemProfile(
        platform=Platform.DARWIN, os_name="macOS", os_version="14.0", architecture="arm64",
        cpu_model="Apple M1", cpu_cores=8, ram_bytes=16 * 1024**3,
    )


def _hidden_python(tmp_path, folder=".example"):
    prog = tmp_path / folder / "agent" / "venv" / "bin" / "python"
    prog.parent.mkdir(parents=True, exist_ok=True)
    prog.write_text("#!/bin/sh\n")
    return str(prog)


def _write_task(agents_dir, program, args=None, label=LABEL):
    path = agents_dir / f"{label}.plist"
    with open(path, "wb") as fh:
        plistlib.dump({"Label": label, "ProgramArguments": args or [program, "-m", "gateway"]}, fh)
    return path


def _module(name):
    return next(m for m in discover_modules(MODULES_DIR) if m.name == name)


def _run(name, agents_dir):
    mod = _module(name)
    scan_name = "_scan_launch_agents_dir" if name == "launch_agent_audit" else "_scan_launchd_dir"
    real = getattr(mod, scan_name)

    def scan(directory):
        if directory == Path.home() / "Library" / "LaunchAgents":
            return real(agents_dir)
        return []

    with patch.object(mod, scan_name, side_effect=scan):
        return mod, mod.check(_profile())


def _mark(label, program, code=LAA, plist=None):
    item, _ = KnownItemsStore().add(
        BACKGROUND_TASK, find_background_task(label, program, plist, code), via="test"
    )
    return item


def _about(result, label=LABEL):
    return [f for f in result.findings if f.data.get("label") == label]


CONTENT = "c" * 64


def _ident(**over):
    base = known_items.background_task_identity(LABEL, "/a/python", "/p/x.plist", ["/a/python"], LAA)
    base["content_sha256"] = CONTENT
    base.update(over)
    return base


def _warning(code=LAA, **data):
    d = {"label": LABEL, "program": "/a/python", "plist": "/p/x.plist"}
    d.update(data)
    return Finding(title="t", description="d", severity=Severity.WARNING, category="security", data=d, code=code)


def _item_identity(f):
    return known_items.background_task_identity(
        f.data.get("label"), f.data.get("program"), f.data.get("plist"), ["/a/python"]
    )


# --- the store ---------------------------------------------------------------


def test_store_uses_env_override_never_real_home(_isolated_known_items):
    assert known_items.default_path() == _isolated_known_items
    assert known_items.default_path() != Path.home() / ".rescue" / "known_items.json"


def test_add_list_remove_roundtrip(tmp_path):
    store = KnownItemsStore(tmp_path / "k.json")
    item, created = store.add(BACKGROUND_TASK, _ident(), via="test")
    assert created and len(item.id) == 12
    again, created_again = store.add(BACKGROUND_TASK, _ident(), via="test")
    assert not created_again and again.id == item.id
    assert [i.id for i in store.load()] == [item.id]
    assert store.remove(item.id).id == item.id
    assert store.load() == []
    assert store.remove(item.id) is None


def test_add_refuses_an_identity_missing_a_pinned_field(tmp_path):
    store = KnownItemsStore(tmp_path / "k.json")
    no_code = known_items.background_task_identity(LABEL, "/a", "/p.plist", [])
    with pytest.raises(KnownItemsError):
        store.add(BACKGROUND_TASK, no_code)
    with pytest.raises(KnownItemsError):
        store.add(BACKGROUND_TASK, _ident(program=""))


@posix_only
def test_saved_file_is_private(tmp_path):
    store = KnownItemsStore(tmp_path / "d" / "k.json")
    store.add(BACKGROUND_TASK, _ident())
    assert (store.path.stat().st_mode & 0o777) == 0o600
    assert (store.path.parent.stat().st_mode & 0o777) == 0o700


def test_malformed_and_tampered_entries_never_match(tmp_path):
    path = tmp_path / "k.json"
    good = _ident()
    path.write_text(json.dumps({"items": [
        {"kind": "background_task", "identity": {"label": LABEL}},       # missing keys
        {"kind": "background_task", "identity": {k: v for k, v in good.items() if k != "code"}},
        {"kind": "background_task", "identity": dict(good, program="")},  # empty field
        {"kind": "background_task", "identity": dict(good, program=["/a/python"])},  # wrong type
        {"kind": "unknown", "identity": good},
        "nonsense",
        None,
        {"kind": "background_task", "identity": dict(good, extra="x")},
        {"kind": "background_task", "identity": good, "id": "000000000000"},
    ]}))
    os.chmod(path, 0o600)
    items = KnownItemsStore(path).load()
    assert len(items) == 1
    # The id in the file is ignored and recomputed from the identity.
    assert items[0].id == known_items.item_id(BACKGROUND_TASK, good)


@pytest.mark.parametrize("content", ["{not json", '{"items": [', '{"items": {}}', "[]", ""])
def test_damaged_or_partial_file_fails_closed(tmp_path, content):
    path = tmp_path / "k.json"
    path.write_text(content)
    os.chmod(path, 0o600)
    with pytest.raises(KnownItemsError):
        KnownItemsStore(path).load()
    items, problem = KnownItemsStore(path).load_for_scan()
    assert items == [] and problem
    # and nothing is written over it
    with pytest.raises(KnownItemsError):
        KnownItemsStore(path).add(BACKGROUND_TASK, _ident())
    assert path.read_text() == content


@posix_only
def test_file_others_can_write_is_ignored(tmp_path):
    store = KnownItemsStore(tmp_path / "k.json")
    store.add(BACKGROUND_TASK, _ident())
    assert store.load_for_scan()[0]
    os.chmod(store.path, 0o666)
    items, problem = store.load_for_scan()
    assert items == [] and "other users can change" in problem


@posix_only
def test_folder_others_can_write_is_ignored(tmp_path):
    store = KnownItemsStore(tmp_path / "d" / "k.json")
    store.add(BACKGROUND_TASK, _ident())
    os.chmod(store.path.parent, 0o777)
    try:
        items, problem = store.load_for_scan()
        assert items == [] and "folder" in problem
    finally:
        os.chmod(store.path.parent, 0o700)


@posix_only
def test_symlinked_list_is_never_followed(tmp_path):
    real = KnownItemsStore(tmp_path / "elsewhere" / "k.json")
    real.add(BACKGROUND_TASK, _ident())
    link_dir = tmp_path / "home"
    link_dir.mkdir(mode=0o700)
    (link_dir / "k.json").symlink_to(real.path)
    items, problem = KnownItemsStore(link_dir / "k.json").load_for_scan()
    assert items == [] and problem


def test_find_background_task_pins_code_label_program_plist_and_arguments(tmp_path, agents_dir):
    prog = _hidden_python(tmp_path)
    plist = _write_task(agents_dir, prog)
    ident = find_background_task(LABEL, prog, code=LAA)
    assert ident == {
        "code": LAA, "label": LABEL, "plist": str(plist), "program": prog,
        "arguments_sha256": known_items.arguments_sha256([prog, "-m", "gateway"]),
        "content_sha256": known_items.content_sha256(prog, [prog, "-m", "gateway"]),
    }
    assert ident["content_sha256"]


def test_find_background_task_refuses_what_it_cannot_pin(tmp_path, agents_dir, monkeypatch):
    missing = str(tmp_path / ".example" / "gone" / "python")
    _write_task(agents_dir, missing, args=[missing])
    with pytest.raises(KnownItemsError, match="could not be read"):
        find_background_task(LABEL, missing, code=LAA)
    prog = _hidden_python(tmp_path)
    _write_task(agents_dir, prog)
    monkeypatch.setattr(known_items, "MAX_HASH_BYTES", 3)
    with pytest.raises(KnownItemsError, match="too large"):
        find_background_task(LABEL, prog, code=LAA)


def test_content_pins_scripts_but_not_logs(tmp_path):
    prog = _hidden_python(tmp_path)
    script = tmp_path / ".example" / "gateway.py"
    script.write_text("print(1)\n")
    log = tmp_path / ".example" / "gateway.error.log"
    log.write_text("x\n")
    args = [prog, str(script), "--error-log", str(log)]
    first = known_items.content_sha256(prog, args)
    log.write_text("lots more log\n")
    assert known_items.content_sha256(prog, args) == first, "a log changing is not a program change"
    script.write_text("print('something else')\n")
    assert known_items.content_sha256(prog, args) != first

def test_find_background_task_refuses_mismatch_bad_code_and_outside_folders(tmp_path, agents_dir):
    prog = _hidden_python(tmp_path)
    _write_task(agents_dir, prog)
    with pytest.raises(KnownItemsError):
        find_background_task(LABEL, "/somewhere/else/python", code=LAA)
    with pytest.raises(KnownItemsError):
        find_background_task("other.label", prog, code=LAA)
    with pytest.raises(KnownItemsError, match="not a background-task finding"):
        find_background_task(LABEL, prog, code="security.some_other_module.x")
    outside = tmp_path / f"{LABEL}.plist"
    shutil.copy(agents_dir / f"{LABEL}.plist", outside)
    with pytest.raises(KnownItemsError, match="not in a background task folder"):
        find_background_task(LABEL, prog, str(outside), LAA)


# --- matching rules (apply_marks) ---------------------------------------------


def _item(**over):
    return KnownItem(kind=BACKGROUND_TASK, identity=_ident(**over), marked_at="2026-01-01T00:00:00Z")


def _same_content(_f):
    return CONTENT


def test_exact_match_downgrades():
    f = _warning()
    known_items.apply_marks([f], BACKGROUND_TASK, _item_identity, items=[_item()], content_of=_same_content)
    assert f.severity == Severity.INFO and f.data["marked_by_user"] is True


@pytest.mark.parametrize("content", ["d" * 64, None, "", RuntimeError("unreadable")])
def test_changed_or_unreadable_content_is_stale_not_downgraded(content):
    f = _warning()

    def content_of(_f):
        if isinstance(content, Exception):
            raise content
        return content

    item = _item()
    known_items.apply_marks([f], BACKGROUND_TASK, _item_identity, items=[item], content_of=content_of)
    assert f.severity == Severity.WARNING
    assert "marked_by_user" not in f.data
    assert f.data["mark_stale"] is True and f.data["known_item_id"] == item.id
    assert (
        "You marked this as yours on 2026-01-01T00:00:00Z, but the program it runs has changed "
        "since then, so it's shown again. If you updated it yourself, you can mark it again."
    ) in f.description


def test_no_content_callback_never_downgrades():
    f = _warning()
    known_items.apply_marks([f], BACKGROUND_TASK, _item_identity, items=[_item()])
    assert f.severity == Severity.WARNING and f.data.get("mark_stale") is True


@pytest.mark.parametrize("finding", [
    _warning(code="security.launch_agent_audit.obfuscated_name"),          # other code
    _warning(code="security.launchd_persistence_audit.suspicious_path"),   # other module
    _warning(code=None),                                                    # no code
    _warning(program="/a/python2"),                                         # program differs
    _warning(program="/a/pytho"),                                           # prefix of program
    _warning(plist="/p/x.plist.old"),                                       # other plist
    _warning(label=LABEL + ".x"),                                           # other label
    _warning(label=""),                                                     # empty field
])
def test_anything_but_an_exact_match_is_left_alone(finding):
    known_items.apply_marks([finding], BACKGROUND_TASK, _item_identity, items=[_item()], content_of=_same_content)
    assert finding.severity == Severity.WARNING
    assert "marked_by_user" not in finding.data
    assert "mark_stale" not in finding.data


def test_identify_that_raises_or_returns_junk_matches_nothing():
    fs = [_warning(), _warning(), _warning()]
    results = iter([RuntimeError("boom"), "not a dict", {"label": LABEL}])

    def identify(_f):
        r = next(results)
        if isinstance(r, Exception):
            raise r
        return r

    known_items.apply_marks(fs, BACKGROUND_TASK, identify, items=[_item()], content_of=_same_content)
    assert all(f.severity == Severity.WARNING for f in fs)


def test_critical_is_tagged_never_downgraded():
    f = _warning()
    f.severity = Severity.CRITICAL
    known_items.apply_marks([f], BACKGROUND_TASK, _item_identity, items=[_item()], content_of=_same_content)
    assert f.severity == Severity.CRITICAL
    assert f.data["user_mark_ignored"] is True and "marked_by_user" not in f.data


def test_ignored_list_is_reported_in_the_scan(_isolated_known_items):
    _isolated_known_items.write_text("{broken")
    os.chmod(_isolated_known_items, 0o600)
    findings = [_warning()]
    known_items.apply_marks(findings, BACKGROUND_TASK, _item_identity)
    assert findings[0].severity == Severity.WARNING
    notes = [f for f in findings if f.data.get("check") == "known_items_ignored"]
    assert len(notes) == 1 and notes[0].severity == Severity.INFO


# --- downgrade in the background-task checks -----------------------------------


@pytest.mark.parametrize("module_name", ["launch_agent_audit", "launchd_persistence_audit"])
def test_marked_task_is_downgraded_not_hidden(tmp_path, agents_dir, module_name):
    code = CODES[module_name]
    prog = _hidden_python(tmp_path)
    _write_task(agents_dir, prog)
    _, before = _run(module_name, agents_dir)
    warned = [f for f in _about(before) if f.severity == Severity.WARNING]
    assert warned and all(f.code == code for f in warned)

    item = _mark(LABEL, prog, code)
    _, after = _run(module_name, agents_dir)
    found = _about(after)
    assert len(found) == len(_about(before)), "a marked task must still be listed"
    assert all(f.severity == Severity.INFO for f in found)
    marked = [f for f in found if f.data.get("marked_by_user")]
    assert marked and all(f.code == code for f in marked)
    for f in marked:
        assert f.title == f"Background task you marked as yours: {LABEL}"
        assert f.data["known_item_id"] == item.id
        assert f.data["original_severity"] == "warning"
        assert "hidden folder" in f.data["original_title"]
        assert f"rescue known remove {item.id}" in f.description


def test_mark_for_one_check_does_not_cover_the_other(tmp_path, agents_dir):
    prog = _hidden_python(tmp_path)
    _write_task(agents_dir, prog)
    _mark(LABEL, prog, CODES["launch_agent_audit"])
    _, result = _run("launchd_persistence_audit", agents_dir)
    assert any(f.severity == Severity.WARNING for f in _about(result))
    assert not any(f.data.get("marked_by_user") for f in result.findings)


@pytest.mark.parametrize("module_name", ["launch_agent_audit", "launchd_persistence_audit"])
def test_replaced_program_content_is_shown_again_as_stale(tmp_path, agents_dir, module_name):
    prog = _hidden_python(tmp_path)
    _write_task(agents_dir, prog)
    item = _mark(LABEL, prog, CODES[module_name])
    Path(prog).write_text("#!/bin/sh\necho something else\n")
    _, result = _run(module_name, agents_dir)
    warned = [f for f in _about(result) if f.severity == Severity.WARNING]
    assert warned
    assert not any(f.data.get("marked_by_user") for f in result.findings)
    stale = [f for f in warned if f.data.get("mark_stale")]
    assert stale and stale[0].data["known_item_id"] == item.id
    assert "has changed since then, so it's shown again" in stale[0].description


def test_replaced_script_content_is_shown_again(tmp_path, agents_dir):
    prog = _hidden_python(tmp_path)
    script = tmp_path / ".example" / "gateway.py"
    script.write_text("print(1)\n")
    _write_task(agents_dir, prog, args=[prog, str(script)])
    _mark(LABEL, prog)
    _, ok = _run("launch_agent_audit", agents_dir)
    assert any(f.data.get("marked_by_user") for f in _about(ok))
    script.write_text("import os; os.system('evil')\n")
    _, result = _run("launch_agent_audit", agents_dir)
    assert any(f.severity == Severity.WARNING and f.data.get("mark_stale") for f in _about(result))
    assert not any(f.data.get("marked_by_user") for f in result.findings)


@posix_only
def test_symlink_swap_of_the_program_is_not_covered(tmp_path, agents_dir):
    real_a = Path(_hidden_python(tmp_path, folder=".a"))
    real_b = tmp_path / ".b" / "python"
    real_b.parent.mkdir()
    real_b.write_text(real_a.read_text())  # identical bytes, different file
    link = tmp_path / ".example" / "venv" / "bin" / "python"
    link.parent.mkdir(parents=True)
    link.symlink_to(real_a)
    _write_task(agents_dir, str(link))
    _mark(LABEL, str(link))
    _, ok = _run("launch_agent_audit", agents_dir)
    assert any(f.data.get("marked_by_user") for f in _about(ok))
    link.unlink()
    link.symlink_to(real_b)
    _, result = _run("launch_agent_audit", agents_dir)
    assert not any(f.data.get("marked_by_user") for f in result.findings)
    assert any(f.severity == Severity.WARNING and f.data.get("mark_stale") for f in _about(result))


def test_unreadable_program_after_marking_is_not_downgraded(tmp_path, agents_dir, monkeypatch):
    prog = _hidden_python(tmp_path)
    _write_task(agents_dir, prog)
    _mark(LABEL, prog)
    monkeypatch.setattr(known_items, "MAX_HASH_BYTES", 3)  # now "too large to check"
    known_items._HASH_CACHE.clear()
    _, result = _run("launch_agent_audit", agents_dir)
    assert any(f.severity == Severity.WARNING and f.data.get("mark_stale") for f in _about(result))
    assert not any(f.data.get("marked_by_user") for f in result.findings)


@pytest.mark.parametrize("module_name", ["launch_agent_audit", "launchd_persistence_audit"])
def test_changed_program_path_brings_the_warning_back(tmp_path, agents_dir, module_name):
    prog = _hidden_python(tmp_path)
    _write_task(agents_dir, prog)
    _mark(LABEL, prog, CODES[module_name])
    moved = _hidden_python(tmp_path, folder=".other")
    _write_task(agents_dir, moved)
    _, result = _run(module_name, agents_dir)
    assert any(f.severity == Severity.WARNING for f in _about(result))
    assert not any(f.data.get("marked_by_user") for f in result.findings)


def test_same_program_running_something_else_brings_the_warning_back(tmp_path, agents_dir):
    prog = _hidden_python(tmp_path)
    _write_task(agents_dir, prog)
    _mark(LABEL, prog)
    _write_task(agents_dir, prog, args=[prog, "/Users/me/.evil/payload.py"])
    _, result = _run("launch_agent_audit", agents_dir)
    assert any(f.severity == Severity.WARNING for f in _about(result))
    assert not any(f.data.get("marked_by_user") for f in result.findings)


@pytest.mark.parametrize("module_name", ["launch_agent_audit", "launchd_persistence_audit"])
def test_critical_is_never_downgraded_by_a_mark(tmp_path, agents_dir, module_name, request):
    tmp_dir = tempfile.mkdtemp(prefix="rescue-test-", dir="/tmp")
    request.addfinalizer(lambda: shutil.rmtree(tmp_dir, ignore_errors=True))
    prog = os.path.join(tmp_dir, "agent")
    Path(prog).write_text("x")
    _write_task(agents_dir, prog, args=[prog])
    _, before = _run(module_name, agents_dir)
    assert any(f.severity == Severity.CRITICAL for f in _about(before))
    _mark(LABEL, prog, CODES[module_name])
    _, after = _run(module_name, agents_dir)
    crit = [f for f in _about(after) if f.severity == Severity.CRITICAL]
    assert crit
    for f in crit:
        assert f.data.get("user_mark_ignored") is True
        assert not f.data.get("marked_by_user")
        assert "Background task you marked as yours" not in f.title


def test_known_malware_label_is_never_downgraded(tmp_path, agents_dir):
    prog = _hidden_python(tmp_path)
    _write_task(agents_dir, prog, label="com.pcv.helper")
    _mark("com.pcv.helper", prog, "security.launchd_persistence_audit.known_malware")
    _, result = _run("launchd_persistence_audit", agents_dir)
    crit = [f for f in _about(result, "com.pcv.helper") if f.data.get("check") == "known_malware"]
    assert crit and crit[0].severity == Severity.CRITICAL


# --- scan JSON ----------------------------------------------------------------


def test_scan_json_offers_markable_then_shows_marked(tmp_path, agents_dir):
    prog = _hidden_python(tmp_path)
    _write_task(agents_dir, prog)
    mod, check = _run("launch_agent_audit", agents_dir)
    doc = json.loads(checks_to_json([(mod, check)], "darwin"))
    offers = [f["markable"] for f in doc["modules"][0]["findings"] if "markable" in f]
    assert len(offers) == 1
    offer = offers[0]
    assert offer["label"] == LABEL and offer["program"] == prog and offer["code"] == LAA
    assert offer["kind"] == "background_task"
    assert "marked as yours" in offer["will_change"] and offer["how_to_undo"]
    # The offered id is exactly what the engine will pin from disk.
    assert offer["id"] == known_items.item_id(BACKGROUND_TASK, find_background_task(LABEL, prog, code=LAA))
    assert offer["content_sha256"]

    _mark(LABEL, prog)
    mod, check = _run("launch_agent_audit", agents_dir)
    doc = json.loads(checks_to_json([(mod, check)], "darwin"))
    findings = doc["modules"][0]["findings"]
    assert not any("markable" in f for f in findings)
    assert any(f["data"].get("marked_by_user") is True and f["severity"] == "info" for f in findings)


def test_markable_only_for_warnings_from_background_task_modules():
    data = {"arguments_sha256": "a" * 64, "content_sha256": CONTENT}
    assert known_items.markable(_warning(**data), "launch_agent_audit")
    assert known_items.markable(_warning(arguments_sha256="a" * 64), "launch_agent_audit") is None
    assert known_items.markable(_warning(**data), "some_other_module") is None
    assert known_items.markable(_warning(), "launch_agent_audit") is None  # no arguments hash
    assert known_items.markable(_warning(code=None, **data), "launch_agent_audit") is None
    crit = _warning(**data)
    crit.severity = Severity.CRITICAL
    assert known_items.markable(crit, "launch_agent_audit") is None
    assert known_items.markable(_warning(plist="", **data), "launch_agent_audit") is None


# --- CLI ----------------------------------------------------------------------


def _invoke(args, tty=False, input=None):
    with patch.object(cli_mod, "_stdin_is_tty", return_value=tty), \
         patch.object(cli_mod, "_run_startup_integrity_check"):
        return CliRunner().invoke(cli_mod.main, args, input=input)


def _add(prog, *extra, code=LAA):
    return ["known", "add", "--code", code, "--label", LABEL, "--program", prog, *extra]


def test_cli_add_refuses_without_a_person_at_the_keyboard(tmp_path, agents_dir):
    prog = _hidden_python(tmp_path)
    _write_task(agents_dir, prog)
    r = _invoke(_add(prog, "--json"))
    assert r.exit_code == 2
    assert json.loads(r.stdout)["status"] == "refused"
    assert KnownItemsStore().load() == []


def test_cli_add_needs_a_code(tmp_path, agents_dir):
    prog = _hidden_python(tmp_path)
    _write_task(agents_dir, prog)
    r = _invoke(["known", "add", "--label", LABEL, "--program", prog, "--json", "--i-understand"])
    assert r.exit_code != 0 and KnownItemsStore().load() == []


def test_cli_add_interactive_confirm(tmp_path, agents_dir):
    prog = _hidden_python(tmp_path)
    _write_task(agents_dir, prog)
    r = _invoke(_add(prog), tty=True, input="n\n")
    assert r.exit_code == 1 and KnownItemsStore().load() == []
    r = _invoke(_add(prog), tty=True, input="y\n")
    assert r.exit_code == 0, r.output
    items = KnownItemsStore().load()
    assert len(items) == 1 and items[0].marked_via == "confirmed in the terminal"


def test_cli_add_list_remove_json(tmp_path, agents_dir):
    prog = _hidden_python(tmp_path)
    plist = _write_task(agents_dir, prog)
    r = _invoke(_add(prog, "--plist", str(plist), "--json", "--i-understand"))
    assert r.exit_code == 0, r.output
    doc = json.loads(r.stdout)
    assert doc["status"] == "marked" and len(doc["id"]) == 12
    assert any(doc["id"] in step for step in doc["how_to_undo"])

    r = _invoke(["known", "list", "--json"])
    listed = json.loads(r.stdout)["items"]
    assert [i["id"] for i in listed] == [doc["id"]]
    assert listed[0]["identity"]["plist"] == str(plist)
    assert listed[0]["identity"]["code"] == LAA

    r = _invoke(["known", "list"])
    assert LABEL in r.stdout and prog in r.stdout and LAA in r.stdout

    r = _invoke(["known", "remove", doc["id"], "--json"])
    assert r.exit_code == 0 and json.loads(r.stdout)["status"] == "removed"
    assert KnownItemsStore().load() == []

    r = _invoke(["known", "remove", doc["id"], "--json"])
    assert r.exit_code == 1 and json.loads(r.stdout)["status"] == "not_found"
    r = _invoke(["known", "remove", "../etc", "--json"])
    assert r.exit_code == 2


def test_cli_add_refuses_a_task_that_does_not_match(tmp_path, agents_dir):
    prog = _hidden_python(tmp_path)
    _write_task(agents_dir, prog)
    r = _invoke(_add("/other/python", "--json", "--i-understand"))
    assert r.exit_code == 2 and json.loads(r.stdout)["status"] == "refused"
    assert KnownItemsStore().load() == []


def test_cli_expect_id_refuses_if_the_task_changed_since_the_scan(tmp_path, agents_dir):
    """What the app showed must be what is written: the engine re-reads the task."""
    prog = _hidden_python(tmp_path)
    _write_task(agents_dir, prog)
    mod, check = _run("launch_agent_audit", agents_dir)
    doc = json.loads(checks_to_json([(mod, check)], "darwin"))
    offer = next(f["markable"] for f in doc["modules"][0]["findings"] if "markable" in f)
    # The task is rewritten between the checkup and the click.
    _write_task(agents_dir, prog, args=[prog, "/Users/me/.evil/payload.py"])
    args = ["known", "add", "--code", offer["code"], "--label", offer["label"], "--program", offer["program"],
            "--plist", offer["plist"], "--expect-id", offer["id"], "--json", "--i-understand"]
    r = _invoke(args)
    assert r.exit_code == 2 and json.loads(r.stdout)["status"] == "refused"
    assert KnownItemsStore().load() == []
    # Same settings file, but the program's content changed: also refused.
    _write_task(agents_dir, prog)
    original = Path(prog).read_text()
    Path(prog).write_text("#!/bin/sh\necho swapped\n")
    r = _invoke(args)
    assert r.exit_code == 2 and json.loads(r.stdout)["status"] == "refused"
    assert KnownItemsStore().load() == []
    # Unchanged task: the same call saves exactly that id.
    Path(prog).write_text(original)
    r = _invoke(args)
    assert r.exit_code == 0, r.output
    assert [i.id for i in KnownItemsStore().load()] == [offer["id"]]


def test_cli_refuses_to_write_over_an_untrusted_list(tmp_path, agents_dir, _isolated_known_items):
    prog = _hidden_python(tmp_path)
    _write_task(agents_dir, prog)
    _isolated_known_items.write_text("{broken")
    os.chmod(_isolated_known_items, 0o600)
    r = _invoke(_add(prog, "--json", "--i-understand"))
    assert r.exit_code == 1 and json.loads(r.stdout)["status"] == "failed"
    assert _isolated_known_items.read_text() == "{broken"


def test_cli_mark_then_scan_end_to_end(tmp_path, agents_dir):
    """What the CLI pins must be exactly what the checks compute."""
    prog = _hidden_python(tmp_path)
    _write_task(agents_dir, prog)
    r = _invoke(["known", "add", "--code", CODES["launch_agent_audit"],
                 "--code", CODES["launchd_persistence_audit"],
                 "--label", LABEL, "--program", prog, "--json", "--i-understand"])
    assert r.exit_code == 0, r.output
    assert len(json.loads(r.stdout)["ids"]) == 2
    for name in ("launch_agent_audit", "launchd_persistence_audit"):
        _, result = _run(name, agents_dir)
        assert all(f.severity == Severity.INFO for f in _about(result))
        assert any(f.data.get("marked_by_user") for f in _about(result))


# --- one task reported by two checks ---------------------------------------------


def _scan_both(agents_dir):
    results = [_run(name, agents_dir) for name in ("launch_agent_audit", "launchd_persistence_audit")]
    return json.loads(checks_to_json(results, "darwin"))


def _offers(doc):
    return {
        f["markable"]["code"]: f["markable"]
        for m in doc["modules"] for f in m["findings"] if "markable" in f
    }


def _app_mark_args(offers, ids):
    """What desktop/engine-runner.js markArgs builds: one --code/--expect-id pair per mark."""
    first = next(iter(offers.values()))
    args = ["known", "add"]
    for code in offers:
        args += ["--code", code, "--expect-id", ids[code]]
    return args + ["--label", first["label"], "--program", first["program"], "--plist", first["plist"],
                   "--json", "--i-understand"]


def test_scan_groups_every_markable_warning_about_the_same_task(tmp_path, agents_dir):
    prog = _hidden_python(tmp_path)
    _write_task(agents_dir, prog)
    offers = _offers(_scan_both(agents_dir))
    assert set(offers) == set(CODES.values())
    ids = sorted(o["id"] for o in offers.values())
    for offer in offers.values():
        assert sorted(offer["ids"]) == ids
        assert "every warning about this task" in offer["will_change"]
        assert offer["will_change"].startswith(
            f"Device Rescue will stop warning you about the background task '{LABEL}'. This covers"
        )


def test_scan_does_not_group_different_tasks(tmp_path, agents_dir):
    prog = _hidden_python(tmp_path)
    other = _hidden_python(tmp_path, folder=".other")
    _write_task(agents_dir, prog)
    _write_task(agents_dir, other, label="ai.example.other")
    doc = _scan_both(agents_dir)
    offers = [f["markable"] for m in doc["modules"] for f in m["findings"] if "markable" in f]
    assert len(offers) == 4
    for offer in offers:
        siblings = {o["id"] for o in offers if o["label"] == offer["label"]}
        assert set(offer["ids"]) == siblings and len(siblings) == 2


def test_one_confirmation_marks_the_task_for_every_check(tmp_path, agents_dir):
    prog = _hidden_python(tmp_path)
    _write_task(agents_dir, prog)
    offers = _offers(_scan_both(agents_dir))
    r = _invoke(_app_mark_args(offers, {c: o["id"] for c, o in offers.items()}))
    assert r.exit_code == 0, r.output
    saved = json.loads(r.stdout)
    assert sorted(saved["ids"]) == sorted(o["id"] for o in offers.values())

    doc = _scan_both(agents_dir)
    about = [f for m in doc["modules"] for f in m["findings"] if f["data"].get("label") == LABEL]
    assert about and all(f["severity"] == "info" for f in about), "both checks' cards are quieted"
    marked = [f for f in about if f["data"].get("marked_by_user")]
    assert {f["code"] for f in marked} == set(CODES.values())
    for f in marked:
        assert sorted(f["marked_ids"]) == sorted(saved["ids"])
    assert not _offers(doc)

    # "Stop treating this as mine" removes the task's marks together.
    r = _invoke(["known", "remove", *saved["ids"], "--json"])
    assert r.exit_code == 0, r.output
    assert sorted(json.loads(r.stdout)["ids"]) == sorted(saved["ids"])
    assert KnownItemsStore().load() == []
    assert set(_offers(_scan_both(agents_dir))) == set(CODES.values())


def test_one_stale_id_refuses_every_mark(tmp_path, agents_dir):
    """If what one check showed no longer matches the disk, nothing is saved."""
    prog = _hidden_python(tmp_path)
    _write_task(agents_dir, prog)
    before = _offers(_scan_both(agents_dir))
    Path(prog).write_text("#!/bin/sh\necho updated\n")
    after = _offers(_scan_both(agents_dir))
    assert before[LAA]["id"] != after[LAA]["id"]
    lpa = CODES["launchd_persistence_audit"]
    mixed = {LAA: after[LAA]["id"], lpa: before[lpa]["id"]}
    r = _invoke(_app_mark_args(after, mixed))
    assert r.exit_code == 2 and json.loads(r.stdout)["status"] == "refused"
    assert KnownItemsStore().load() == []
    # The current ids for both still work.
    r = _invoke(_app_mark_args(after, {c: o["id"] for c, o in after.items()}))
    assert r.exit_code == 0, r.output
    assert len(KnownItemsStore().load()) == 2


@pytest.mark.parametrize("extra", [
    ["--expect-id", "abcdef012345"],  # one id for two codes
    ["--expect-id", "abcdef012345", "--expect-id", "abcdef012345"],  # the same id twice
    ["--expect-id", "abcdef012345", "--expect-id", "not-an-id"],
])
def test_cli_expect_ids_must_pair_with_codes(tmp_path, agents_dir, extra):
    prog = _hidden_python(tmp_path)
    _write_task(agents_dir, prog)
    args = ["known", "add", "--code", LAA, "--code", CODES["launchd_persistence_audit"],
            "--label", LABEL, "--program", prog, *extra, "--json", "--i-understand"]
    r = _invoke(args)
    assert r.exit_code == 2 and json.loads(r.stdout)["status"] == "refused"
    assert KnownItemsStore().load() == []


def test_add_many_is_all_or_nothing(tmp_path):
    store = KnownItemsStore()
    good = _ident()
    with pytest.raises(KnownItemsError):
        store.add_many(BACKGROUND_TASK, [good, _ident(program="")], via="test")
    assert store.load() == []
    saved = store.add_many(BACKGROUND_TASK, [good, _ident(code=CODES["launchd_persistence_audit"])], via="test")
    assert [c for _, c in saved] == [True, True] and len(store.load()) == 2
    again = store.add_many(BACKGROUND_TASK, [good], via="test")
    assert again[0][1] is False and len(store.load()) == 2


def test_only_markable_warnings_join_the_group():
    """A critical finding about the same task has no markable block, so it is never quieted."""
    offer = {"kind": BACKGROUND_TASK, "id": "a" * 12, "code": LAA, "label": LABEL, "plist": "/p",
             "program": "/x", "arguments_sha256": "s", "content_sha256": "c"}
    findings = [
        {"markable": offer, "data": {}},
        {"severity": "critical", "data": {"label": LABEL, "plist": "/p", "program": "/x"}},
    ]
    known_items.link_task_marks(findings)
    assert offer["ids"] == ["a" * 12]
    assert "markable" not in findings[1]
