# Checklists and Subset Marks Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a person mark some entries of a list finding as theirs (apps on one permission list, keys in one remote-login file), tick those entries in one shared checklist component in the desktop app, and pick several worries on the worry screen so the checkup runs the union of their profiles.

**Architecture:** The engine gains two per-entry mark kinds (`app_permission_entry`, `ssh_authorized_key`) next to the existing whole-list kinds, a `--item` flag on `rescue known add`, per-entry data on scan and export output, and a repeatable `--profile` that runs the union of several profiles. The desktop app gains one plain-script checklist component (`checklist.js` + `checklist.css`) used by the "It's mine" panel for list findings and by the worry screen; the main process stays the gatekeeper and only forwards item ids the scan offered. A pure `worries.js` turns several picked worries into one situation object that the existing app and game code can read.

**Tech Stack:** Python 3 (click, pytest via `uv run --extra dev pytest`), Electron renderer plain scripts and ES modules, `node:test`.

**Spec:** `docs/superpowers/specs/2026-10-18-teach-once-and-checklists-proposal.md` (Part 2, sections 2.1 to 2.4, and the two "Owner decisions" sections at the end). Executors read the spec, this plan and `AGENTS.md`.

## Global Constraints

- No time estimates, timelines or schedules anywhere: in code comments, copy, docs or commit messages.
- Copy is plain and calm. No "Apply" or "OK" on buttons; a primary button names the action and the number ("Mark 3 apps as mine").
- Checkboxes start **unticked everywhere** (owner decision 3). `Checklist.html` never writes `checked`, whatever the caller passes.
- Selection is memory only, never stored, and resets on every render. Pressing a primary button only opens a confirmation; nothing is sent before "Yes".
- Bulk "It's mine" for watching-capable lists happens **within a single finding only**, and the confirmation always shows the watching warning (`COULD_WATCH` and `ONLY_IF_YOURS`) (owner decision 6).
- Marking is a change the person makes. The CLI asks in a terminal (default No) and refuses without a terminal unless `--i-understand` is passed. Only the desktop app passes `--i-understand`, after its own confirmation. Tests, docs and agents never pass it for a person.
- Findings from `stalkerware_scan`, `mvt_spyware_scan` and `keylogger_indicators` can never be marked, per entry or whole.
- Whole-list marks keep working exactly as before. A whole-list mark that matches wins over entry marks.
- Rows in the "It's mine" panel are never dropped silently: if the engine's items and rows disagree, the panel shows the whole raw list with no checkboxes, as today.
- Desktop tests: `cd desktop && npm test` (`node --test "test/**/*.test.js"`). Engine tests: `uv run --extra dev pytest`.
- Any change under `rescue/` needs `uv run python scripts/generate_integrity_manifest.py` and the regenerated `rescue/security/integrity_manifest.json` committed in the same task. Two engine tasks running in parallel will both touch the manifest: after merging them, regenerate it once more and commit.
- No new finding codes are added, so the catalogs do not change. Each engine task still runs `uv run --extra dev pytest tests/test_remediation_catalog.py tests/test_generate_command_catalog.py tests/test_command_catalog_firewall.py` to prove it.
- Disk is tight: no new venvs, no new full clones. Use the existing `.venv` through `uv run`, and `git worktree add` for parallel tasks.
- Commit messages end with a blank line then `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. **An app whose maker can't be checked right now** (not found on disk, or the signature lookup ran out of budget). It must still appear as a row, disabled with a note, never vanish, and the CLI must refuse its id. Pinned by `test_an_entry_that_cannot_be_checked_now_is_listed_without_an_id` (Task 2) and `a row with no id is shown, disabled, with a note` (Task 8).
2. **The same bundle id twice in `data.apps`, or two apps with the same display name.** One row per distinct id; the counts still match, so the checklist is offered. Pinned by `test_one_row_per_distinct_app_even_when_the_list_repeats_one` (Task 1) and `two apps with the same name are two checklist rows` (Task 8).
3. **An old whole-list mark plus new entry marks on the same finding.** A matching whole-list mark wins; a stale whole-list mark keeps its "changed" note and the entry marks still apply. Pinned by `test_a_whole_list_mark_still_wins_and_entry_marks_wait` and `test_a_stale_whole_list_mark_lets_entry_marks_apply` (Task 1).
4. **A list that shrinks, or a check that couldn't look.** An entry mark is retired only when a clean run no longer lists that entry; a check that couldn't run, or a list too long to read entry by entry, retires nothing. Pinned by `test_an_entry_mark_is_retired_only_when_its_entry_is_gone` and `test_entry_marks_are_kept_when_the_check_could_not_look_or_the_list_cannot_be_read` (Task 1).
5. **The results list redraws while the checklist has focus** (a re-check changes the scan). Focus returns to the same row, selection resets, nothing is sent. Pinned by `preserveFocus puts focus back on the same row after a redraw` (Task 5) and the `renderResults` wrap in Task 8.

---

## File Structure

| File | Responsibility | Task |
| --- | --- | --- |
| `rescue/known_items.py` | Entry kinds, entry identity, applying and retiring entry marks, `markable.items`, `find_entries` | 1, 2 |
| `modules/security/session_revocation_scan/__init__.py` | Emits `data.keys` (one fingerprint per saved key, never the key) | 1 |
| `rescue/cli.py` | `known add --item`; repeatable `--profile` on `scan` and `export` | 2, 4 |
| `rescue/case.py` | Export drops key comments | 3 |
| `rescue/profiles.py` | `merge_profiles` (union of several profiles) | 4 |
| `docs/cli.md`, `AGENTS.md` | Document `--item`, entry kinds, data fields, repeatable `--profile` | 2, 4 |
| `tests/test_known_entries.py` | Entry marks: apply, stale, retire, ssh keys | 1 |
| `tests/test_known_entries_cli.py` | `known add --item`, offers, scan JSON | 2 |
| `tests/test_case_export.py` | Export test for entries and key comments | 3 |
| `tests/test_profile_union.py` | `merge_profiles` and the CLI | 4 |
| `desktop/renderer/checklist.js` (new) | The shared checklist component (`Checklist`) | 5 |
| `desktop/renderer/checklist.css` (new) | Its styles, plain and game themes | 5 |
| `desktop/test/checklist.test.js` (new) | Component tests | 5 |
| `desktop/test/stylesheets.test.js` | Adds `checklist.css` to the sheets checked | 5 |
| `desktop/mark-policy.js` | Remembers offered and marked entry ids; refuses forged ones | 6 |
| `desktop/engine-runner.js` | `--item` argv; `scanArgs` takes several profiles | 6 |
| `desktop/test/mark-entries.test.js` (new) | Policy and argv tests | 6 |
| `desktop/renderer/worries.js` (new) | Several worries as one situation (`Worries`) | 7 |
| `desktop/renderer/game/training.js`, `game/one-city.js` | Lessons and focus district for several worries | 7 |
| `desktop/test/worries.test.js` (new) | Worries tests, plus the two game helpers | 7 |
| `desktop/renderer/mark-flow.js` | Checklist in the "It's mine" panel for list findings; per-row undo | 8 |
| `desktop/main.js`, `desktop/preload.js` | Pass item ids through IPC | 8 |
| `desktop/renderer/index.html` | Load `checklist.css`, `checklist.js`, `worries.js`; worry screen markup | 8, 9 |
| `desktop/renderer/game/controller.js` | Link `checklist.css` in the shadow root; game theme; several worries | 8, 9 |
| `desktop/renderer/app.js` | Focus kept across result redraws; worry checklist; several worries everywhere | 8, 9 |
| `desktop/renderer/first-question.js` | "Watching me" among several worries still goes to city | 9 |
| `desktop/test/mark-entries-flow.test.js` (new) | Panel and flow tests | 8 |
| `desktop/test/page-harness.js`, `desktop/test/worry-checklist.test.js` (new), `desktop/test/first-question.test.js` | Worry checklist flow tests | 9 |

## Task order and what can run in parallel

| Task | Touches | Depends on | Waits for `reclaim-city` on main? | Runs in parallel with |
| --- | --- | --- | --- | --- |
| 1. Engine: entry kinds, apply, retire, ssh key data | `rescue/known_items.py`, `modules/security/session_revocation_scan/__init__.py`, `tests/test_known_entries.py`, manifest | nothing | no | 4, 5, 6, 7 |
| 2. Engine: offers and `known add --item` | `rescue/known_items.py`, `rescue/cli.py`, `docs/cli.md`, `AGENTS.md`, `tests/test_known_entries_cli.py`, manifest | 1 | no | 3, 5, 6, 7 (not 4: same `cli.py` and `docs/cli.md`) |
| 3. Engine: export shows entries, drops key comments | `rescue/case.py`, `tests/test_case_export.py`, manifest | 1 | no | 2, 4, 5, 6, 7 |
| 4. Engine: repeatable `--profile` (union) | `rescue/profiles.py`, `rescue/cli.py`, `docs/cli.md`, `AGENTS.md`, `tests/test_profile_union.py`, manifest | nothing | no | 1, 3, 5, 6, 7 (not 2) |
| 5. Desktop: checklist component | `desktop/renderer/checklist.js`, `checklist.css`, `desktop/test/checklist.test.js`, `desktop/test/stylesheets.test.js` | nothing | no | 1, 2, 3, 4, 6, 7 |
| 6. Desktop: mark policy and engine argv | `desktop/mark-policy.js`, `desktop/engine-runner.js`, `desktop/test/mark-entries.test.js` | nothing (uses the shape Task 2 emits) | no | 1, 2, 3, 4, 5, 7 |
| 7. Desktop: worries helper and game helpers | `desktop/renderer/worries.js`, `desktop/renderer/game/training.js`, `desktop/renderer/game/one-city.js`, `desktop/test/worries.test.js` | nothing | no | 1 to 6 |
| 8. Desktop: checklist in the "It's mine" panel | `desktop/renderer/mark-flow.js`, `desktop/main.js`, `desktop/preload.js`, `desktop/renderer/index.html`, `desktop/renderer/game/controller.js`, `desktop/renderer/app.js`, `desktop/test/mark-entries-flow.test.js` | 2, 5, 6 | **yes** | nothing (it edits `app.js`, `index.html`, `controller.js`) |
| 9. Desktop: worry screen as a checklist | `desktop/renderer/app.js`, `desktop/renderer/first-question.js`, `desktop/renderer/index.html`, `desktop/renderer/game/controller.js`, `desktop/test/page-harness.js`, `desktop/test/worry-checklist.test.js`, `desktop/test/first-question.test.js` | 4, 5, 6, 7, and 8 (same files) | **yes** | nothing |

Tasks 8 and 9 are written against the `reclaim-city` branch's versions of `app.js`, `first-question.js`, `index.html`, `controller.js` and `page-harness.js` (as of commit `d3a9e66`). The branch is being merged with main now. Before starting either task: confirm `git log main --oneline | grep -c "City mode"` is not 0 (the branch has landed), then re-read each "replace this" block below against the file on main. If a block no longer matches exactly, apply the same change to the code that replaced it; the intent of each edit is stated above its code.

---

### Task 1: Engine: entry kinds, applying and retiring entry marks, ssh key data

**Files:**
- Modify: `rescue/known_items.py` (import line near the top; after the `ITEM_KINDS` registration loop that ends `del _kind, _spec`; `apply_item_marks`; `marks_gone`)
- Modify: `modules/security/session_revocation_scan/__init__.py` (imports; `_authorized_keys_data`; new `_authorized_keys_entries` and module-level `_parse_key_line`)
- Create: `tests/test_known_entries.py`
- Regenerate: `rescue/security/integrity_manifest.json`

**Interfaces:**
- Consumes: existing `item_identity`, `item_id`, `base_identity`, `KnownItemsStore`, `stale_sentence`, `KINDS`, `ITEM_KINDS`, `NEVER_MARKABLE_MODULES`, `_text`, `app_rows` (all in `rescue/known_items.py` / `rescue/app_names.py`); `rescue.attribution.identify(subject: str, platform: str) -> MadeBy | None`.
- Produces (used by Tasks 2 and 3):
  - constants `APP_ENTRY = "app_permission_entry"`, `SSH_KEY_ENTRY = "ssh_authorized_key"`, `MAX_LIST_ENTRIES = 60`, `ENTRY_KINDS: dict[str, dict]`, `ENTRY_KIND_FOR: dict[str, str]` (list kind -> entry kind)
  - `app_signer(app: str) -> str | None` (`"team:<TEAMID>"`, `"apple"`, `"unsigned"`, or `None` when it can't be checked now)
  - `list_entries(list_kind: str, finding) -> list[dict] | None`; each dict has `entry`, `label`, `detail`, `shown` (and `line_sha256` for keys)
  - `entry_identity(entry_kind: str, code: str, entry: dict, signer_of=None) -> dict | None`
  - `apply_entry_marks(findings: list[Finding], items: list[KnownItem], signer_of=None) -> None`
  - finding data written: `data.partly_marked` (bool), `data.marked_items` / `data.stale_items` (lists of `{"id", "entry", "shown", "marked_at"}`), `data.unmarked` (list of entry strings), `data.entry_kind`; when every entry is marked also `marked_by_user`, `marked_at`, `original_severity`, `original_title` (no `known_item_id`)
  - `session_revocation_scan` data gains `keys: [{"type", "sha256", "line_sha256", "comment"}]` when every key line parses and the count matches.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_known_entries.py`:

```python
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run --extra dev pytest tests/test_known_entries.py -v`
Expected: FAIL at import with `ImportError: cannot import name 'ENTRY_KINDS' from 'rescue.known_items'`.

- [ ] **Step 3: Emit per-key data from the session scan**

In `modules/security/session_revocation_scan/__init__.py`, add `base64` and `unicodedata` to the imports (next to the existing `import hashlib`):

```python
import base64
import unicodedata
```

Add these module-level definitions directly below the line `_MAX_AUTHORIZED_KEYS_LINES = 500`:

```python
# Key types a line in authorized_keys can start its key with (after any options).
_KEY_TYPES = frozenset({
    "ssh-ed25519", "ssh-rsa", "ssh-dss",
    "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com",
})


def _parse_key_line(line: str) -> dict | None:
    """One saved key, as fingerprints: the SHA-256 of the decoded key (what
    `ssh-keygen -l` fingerprints) and of the whole line (so a change to its
    options or comment shows), its type and its comment. Never the key itself.
    None if the line isn't a key this can read."""
    tokens = line.split()
    for i, token in enumerate(tokens):
        if token not in _KEY_TYPES or i + 1 >= len(tokens):
            continue
        try:
            blob = base64.b64decode(tokens[i + 1], validate=True)
        except ValueError:
            return None
        if not blob:
            return None
        comment = " ".join(tokens[i + 2:])
        comment = "".join(ch for ch in comment if unicodedata.category(ch) not in ("Cc", "Cf"))[:128]
        return {
            "type": token,
            "sha256": hashlib.sha256(blob).hexdigest(),
            "line_sha256": hashlib.sha256(line.encode("utf-8", "replace")).hexdigest(),
            "comment": comment,
        }
    return None
```

Replace `_authorized_keys_data`:

```python
    def _authorized_keys_data(self, count: int) -> dict:
        data = {"check": "ssh_authorized_keys", "key_count": count}
        digest = self._authorized_keys_sha256()
        if digest:
            data["list_sha256"] = digest
        # One entry per key, so the person can say which keys are theirs.
        # Only when every line reads as a key: otherwise the list is offered whole.
        entries = self._authorized_keys_entries()
        if entries is not None and len(entries) == count:
            data["keys"] = entries
        return data

    def _authorized_keys_entries(self) -> list[dict] | None:
        """Every saved key as fingerprints (see _parse_key_line), or None if
        the file can't be read, is too long, or has a line that isn't a key."""
        path = self._authorized_keys_path()
        if not is_file_nofollow(path):
            return None
        entries = []
        try:
            with open(path, "r", errors="replace") as handle:
                for index, line in enumerate(handle):
                    if index >= _MAX_AUTHORIZED_KEYS_LINES:
                        return None
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    entry = _parse_key_line(stripped)
                    if entry is None:
                        return None
                    entries.append(entry)
        except OSError:
            return None
        return entries or None
```

- [ ] **Step 4: Add the entry kinds to `rescue/known_items.py`**

Change the import line `from rescue.app_names import app_rows` to:

```python
from rescue.app_names import app_rows, display_name
```

Add `import sys` to the standard-library imports at the top (after `import stat`).

Directly after the block that ends

```python
for _kind, _spec in ITEM_KINDS.items():
    assert not set(_spec["modules"]) & NEVER_MARKABLE_MODULES, _kind
    KINDS[_kind] = _spec
del _kind, _spec
```

insert:

```python
# --- one entry of a list -----------------------------------------------------
#
# A list finding (apps with Accessibility access, saved remote-login keys) can
# be marked one entry at a time. An entry mark pins the finding code and the
# entry, plus who signed the app (or the whole saved line of the key), so an
# app swapped for one from another maker makes only that mark stale. The
# whole-list kinds above keep working; a whole-list mark that matches wins.

APP_ENTRY = "app_permission_entry"
SSH_KEY_ENTRY = "ssh_authorized_key"
# Longer lists are offered whole only: each app's maker is checked by a
# signature lookup, and the scan must stay light.
MAX_LIST_ENTRIES = 60


def _app_entry_label(identity: dict) -> str:
    app = identity.get("app", "")
    try:
        name = display_name(app)
    except Exception:
        name = app
    return app if name == app else f"{name} · {app}"


ENTRY_KINDS: dict[str, dict] = {
    APP_ENTRY: {
        "keys": ("code", "app", "signer"),
        "evidence_keys": ("signer",),
        "list_kind": "app_permissions",
        "modules": ITEM_KINDS["app_permissions"]["modules"],
        "label_of": _app_entry_label,
        "title": ITEM_KINDS["app_permissions"]["title"],
        "noun": "app",
        "nouns": "apps",
        "changed": "who made it",
        "monitoring": True,
    },
    SSH_KEY_ENTRY: {
        "keys": ("code", "key_sha256", "line_sha256"),
        "evidence_keys": ("line_sha256",),
        "list_kind": "ssh_authorized_keys",
        "modules": ITEM_KINDS["ssh_authorized_keys"]["modules"],
        "label_of": lambda i: f"remote-login key {i.get('key_sha256', '')[:16]}…",
        "title": ITEM_KINDS["ssh_authorized_keys"]["title"],
        "noun": "remote-login key",
        "nouns": "remote-login keys",
        "changed": "the key's saved line",
        "monitoring": True,
    },
}
ENTRY_KIND_FOR: dict[str, str] = {spec["list_kind"]: kind for kind, spec in ENTRY_KINDS.items()}
for _kind, _spec in ENTRY_KINDS.items():
    assert not set(_spec["modules"]) & NEVER_MARKABLE_MODULES, _kind
    KINDS[_kind] = _spec
del _kind, _spec


def app_signer(app: str) -> str | None:
    """Who signed this app, as an entry mark pins it: "team:<Team ID>" for a
    verified Developer ID or App Store signature, "apple" for Apple's own,
    "unsigned" when no signature verifies. None when it can't be checked now
    (not found, or the lookup budget ran out): such an entry can't be marked
    on its own, and a mark on it shows as changed."""
    try:
        from rescue import attribution

        made = attribution.identify(app, sys.platform)
    except Exception:
        return None
    if made is None:
        return None
    if not made.verified:
        return "unsigned"
    if made.team:
        return f"team:{made.team}"
    if made.name == "Apple":
        return "apple"
    return None


def list_entries(list_kind: str, finding) -> list[dict] | None:
    """One dict per entry of a list finding, or None when the list can't be
    shown entry by entry (malformed, or longer than MAX_LIST_ENTRIES).

    Each dict: "entry" (the bundle id or path, or the key's SHA-256), "label"
    (the app's name, or the key type), "detail" (the bundle id, or the key's
    comment), "shown" (what text and exports may say: never a key comment),
    and for keys "line_sha256"."""
    data = getattr(finding, "data", None)
    if not isinstance(data, dict):
        return None
    if list_kind == "app_permissions":
        apps = data.get("apps")
        if not isinstance(apps, list) or not apps:
            return None
        if not all(isinstance(a, str) and a and "\0" not in a and len(a) <= 1024 for a in apps):
            return None
        rows = app_rows(apps)
        if not rows or len(rows) > MAX_LIST_ENTRIES:
            return None
        return [
            {"entry": r["id"], "label": r["name"], "detail": r["id"],
             "shown": r["id"] if r["name"] == r["id"] else f"{r['name']} · {r['id']}"}
            for r in rows
        ]
    if list_kind == "ssh_authorized_keys":
        keys = data.get("keys")
        count = data.get("key_count")
        if not isinstance(keys, list) or not keys or len(keys) > MAX_LIST_ENTRIES:
            return None
        if isinstance(count, bool) or count != len(keys):
            return None
        out = []
        for key in keys:
            if not isinstance(key, dict):
                return None
            sha = _text(key.get("sha256"), 64)
            line = _text(key.get("line_sha256"), 64)
            key_type = _text(key.get("type"), 64)
            if not (sha and line and key_type) or len(sha) != 64 or len(line) != 64:
                return None
            out.append({
                "entry": sha, "line_sha256": line, "label": f"{key_type} key",
                "detail": _text(key.get("comment"), 256) or "",
                "shown": f"{key_type} key {sha[:16]}…",
            })
        if len({e["entry"] for e in out}) != len(out):
            return None
        return out
    return None


def _entry_base(entry_kind: str, code: str, entry: dict) -> dict:
    """The entry's identity without its evidence: what says "the same entry"."""
    if entry_kind == APP_ENTRY:
        return {"code": code, "app": entry["entry"]}
    return {"code": code, "key_sha256": entry["entry"]}


def entry_identity(entry_kind: str, code: str, entry: dict, signer_of=None) -> dict | None:
    """The full pinned identity of one entry now, or None if it can't be pinned."""
    base = _entry_base(entry_kind, code, entry)
    if entry_kind == APP_ENTRY:
        signer = (signer_of or app_signer)(entry["entry"])
        if not isinstance(signer, str) or not signer:
            return None
        return dict(base, signer=signer)
    return dict(base, line_sha256=entry["line_sha256"])


def _entries_line(heading: str, shown: list[str]) -> str:
    return f"{heading} ({len(shown)}): " + ", ".join(shown)


def _entries_groups(marked, stale, fresh, entry_kind: str) -> str:
    parts = []
    if fresh:
        parts.append(_entries_line("Not marked as yours", [e["shown"] for e in fresh]))
    if stale:
        parts.append(_entries_line("Marked as yours before, but changed since", [e["shown"] for e, _ in stale]))
        parts.append(stale_sentence(stale[0][1], entry_kind))
    if marked:
        parts.append(_entries_line("Marked as yours", [e["shown"] for e, _ in marked]))
    return "\n".join(parts)


_ENTRY_UNDO = (
    "If you did not mark these, or you do not recognize them, undo a mark with "
    "\"rescue known remove <id>\" (\"rescue known list\" shows the ids) or with "
    "\"Stop treating this as mine\" in the app, and its warning comes back."
)


def apply_entry_marks(findings: list[Finding], items: list[KnownItem], signer_of=None) -> None:
    """Apply entry marks to list findings (in place).

    Runs after the whole-list marks, and leaves alone any finding a whole-list
    mark already covered. Every entry is checked: marked and unchanged,
    marked but changed (stale: it warns again, saying so), or not marked.
    Only when every entry is marked is the finding downgraded to info, as a
    whole-list mark would; otherwise it stays a warning about the rest.
    """
    for finding in findings:
        hit = item_identity(finding)
        if not hit:
            continue
        list_kind, list_identity = hit
        entry_kind = ENTRY_KIND_FOR.get(list_kind)
        data = finding.data
        if not entry_kind or data.get("marked_by_user") or data.get("user_mark_ignored"):
            continue
        marks = [i for i in items if i.kind == entry_kind and i.identity.get("code") == finding.code]
        if not marks:
            continue
        entries = list_entries(list_kind, finding)
        if entries is None:
            continue
        by_id = {i.id: i for i in marks}
        by_base: dict[str, KnownItem] = {}
        for i in marks:
            by_base.setdefault(i.base_id, i)
        marked, stale, fresh = [], [], []
        for entry in entries:
            near = by_base.get(item_id(entry_kind, _entry_base(entry_kind, finding.code, entry)))
            if near is None:
                fresh.append(entry)
                continue
            ident = entry_identity(entry_kind, finding.code, entry, signer_of)
            item = by_id.get(item_id(entry_kind, ident)) if ident else None
            if item is None:
                stale.append((entry, near))
            else:
                marked.append((entry, item))
        if not marked and not stale:
            continue
        spec = KINDS[entry_kind]
        data["entry_kind"] = entry_kind
        data["marked_items"] = [
            {"id": i.id, "entry": e["entry"], "shown": e["shown"], "marked_at": i.marked_at} for e, i in marked
        ]
        data["stale_items"] = [
            {"id": i.id, "entry": e["entry"], "shown": e["shown"], "marked_at": i.marked_at} for e, i in stale
        ]
        warn = fresh + [e for e, _ in stale]
        data["unmarked"] = [e["entry"] for e in warn]
        groups = _entries_groups(marked, stale, fresh, entry_kind)
        if finding.severity == Severity.CRITICAL:
            data["user_mark_ignored"] = True
            finding.description = (
                f"{finding.description}\n\n{groups}\n\nSome of these are marked as yours, but this "
                "finding is serious enough that a mark does not quiet it."
            )
            continue
        if not warn:
            when = max((i.marked_at for _, i in marked), default="") or "an unknown date"
            data.update({
                "marked_by_user": True,
                "marked_at": when,
                "original_severity": finding.severity.value,
                "original_title": finding.title,
            })
            finding.description = (
                f"You marked every {spec['noun']} on this list as yours (most recently on {when}), so it "
                "is no longer flagged. It stays on this list so that anyone helping you can see it.\n\n"
                f"What the check found before it was marked: {finding.title}\n\n{groups}\n\n{_ENTRY_UNDO}\n\n"
                f"Original details:\n{finding.description}"
            )
            finding.title = spec["title"].format(label=ITEM_KINDS[list_kind]["label_of"](list_identity))
            finding.severity = Severity.INFO
            continue
        data["partly_marked"] = True
        total = len(entries)
        finding.description = (
            f"{len(warn)} of {total} on this list are not marked as yours, so this is still a warning "
            f"about them.\n\n{groups}\n\n{_ENTRY_UNDO}\n\nOriginal details:\n{finding.description}"
        )
        finding.title = f"{finding.title} ({len(warn)} of {total} not marked as yours)"
```

- [ ] **Step 5: Call it from `apply_item_marks`**

In `apply_item_marks`, replace the final loop and return:

```python
    for kind in kinds:
        def identify(f, kind=kind):
            hit = item_identity(f)
            return hit[1] if hit and hit[0] == kind else None
        apply_marks(findings, kind, identify, items=items)
    return findings
```

with:

```python
    for kind in kinds:
        def identify(f, kind=kind):
            hit = item_identity(f)
            return hit[1] if hit and hit[0] == kind else None
        apply_marks(findings, kind, identify, items=items)
    # Entry marks after whole-list marks: a whole-list mark that matched wins.
    apply_entry_marks(findings, items)
    return findings
```

- [ ] **Step 6: Retire entry marks whose entry is gone**

Replace the whole `marks_gone` function with:

```python
def marks_gone(module_name: str, findings: list, items: list[KnownItem]) -> list[KnownItem]:
    """Marks on items (or list entries) this module reports that its findings no longer show.

    "Still there" means some finding (any severity) with the mark's code is
    about the same item: the same base identity, even if its evidence
    changed (that is a stale mark, not a gone one). An entry mark is still
    there while its entry is on that list; if a list can't be read entry by
    entry this time, no entry mark for that code is retired.
    """
    if module_name in NEVER_MARKABLE_MODULES:
        return []

    def mine(kinds) -> list[KnownItem]:
        return [
            i for i in items
            if i.kind in kinds and str(i.identity.get("code", "")).split(".")[1:2] == [module_name]
        ]

    whole = mine(ITEM_KINDS)
    entries = mine(ENTRY_KINDS)
    if not whole and not entries:
        return []
    present = set()
    unreadable_codes = set()
    for f in findings:
        hit = item_identity(f)
        if not hit:
            continue
        present.add(item_id(hit[0], base_identity(hit[0], hit[1])))
        entry_kind = ENTRY_KIND_FOR.get(hit[0])
        if entry_kind:
            rows = list_entries(hit[0], f)
            if rows is None:
                unreadable_codes.add(f.code)
                continue
            for row in rows:
                present.add(item_id(entry_kind, _entry_base(entry_kind, f.code, row)))
    gone = [i for i in whole if i.base_id not in present]
    gone += [
        i for i in entries
        if i.base_id not in present and i.identity.get("code") not in unreadable_codes
    ]
    return gone
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `uv run --extra dev pytest tests/test_known_entries.py tests/test_known_item_kinds.py tests/test_known_items.py -v`
Expected: PASS (all). `test_every_kind_has_a_case` still passes because the entry kinds live in `ENTRY_KINDS`, not `ITEM_KINDS`.

- [ ] **Step 8: Regenerate the integrity manifest and run the full suite**

Run: `uv run python scripts/generate_integrity_manifest.py && uv run --extra dev pytest`
Expected: the manifest file changes; every test PASSES. Then confirm the catalogs are untouched:
Run: `uv run --extra dev pytest tests/test_remediation_catalog.py tests/test_generate_command_catalog.py tests/test_command_catalog_firewall.py -v`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add rescue/known_items.py rescue/security/integrity_manifest.json modules/security/session_revocation_scan/__init__.py tests/test_known_entries.py
git commit -m "$(cat <<'EOF'
Engine: mark single entries of a list (apps, remote-login keys)

Entry marks pin the finding code and the entry, plus who signed the app or
the key's whole saved line. Partly marked lists stay a warning about the
rest; a new or changed entry warns on its own; marks retire per entry.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```

---
### Task 2: Engine: entry offers in `markable` and `rescue known add --item`

**Files:**
- Modify: `rescue/known_items.py` (new functions after `apply_entry_marks`; `item_markable`'s return; `find_item`)
- Modify: `rescue/cli.py` (`known_add` options and body; `_known_add_item`'s check runner; new `_fresh_check_runner` and `_known_add_entries`)
- Modify: `docs/cli.md` (the `rescue known` section), `AGENTS.md` (rule 1)
- Create: `tests/test_known_entries_cli.py`
- Regenerate: `rescue/security/integrity_manifest.json`

**Interfaces:**
- Consumes (Task 1): `APP_ENTRY`, `ENTRY_KIND_FOR`, `MAX_LIST_ENTRIES`, `KINDS`, `list_entries`, `entry_identity`, `app_signer`, `item_id`.
- Produces:
  - `markable.items` on a warning about a list, one per entry: `{"key": str, "label": str, "detail": str, "monitoring": True, "id": str | None, "marked"?: True, "stale"?: True}`. `id` is the entry's mark id now, `None` when it can't be pinned now; on an already-marked entry `id` is the saved mark id and `marked` is `True`. Plus `markable.items_will_change: str`. `markable.id` (the whole-list id) is unchanged.
  - `entries_will_change(entry_kind: str, chosen: int | None = None, total: int | None = None) -> str`
  - `entry_offers(finding, list_kind: str, signer_of=None) -> list[dict]`
  - `find_entries(code: str, expect_id: str, wanted: list[str], run_check, signer_of=None) -> tuple[str, list[tuple[dict, dict, str]], int]` (entry kind, `[(row, identity, item id)]` in the order asked, number of entries on the list)
  - CLI: `rescue known add --code C --expect-id ID --item I [--item I ...] [--json] [--i-understand]`. JSON doc on success: `status` `marked`/`already_marked`, `ids`, `id`, `label` (e.g. `"2 of 3 apps"`), `kind` (the entry kind), `how_to_undo`. Exit `2` for every refusal, `1` for cancelled/failed.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_known_entries_cli.py`:

```python
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run --extra dev pytest tests/test_known_entries_cli.py -v`
Expected: FAIL. `test_the_offer_lists_every_entry_with_its_own_id` fails with `KeyError: 'items'`; the CLI tests fail with exit code `2` and "No such option: --item".

- [ ] **Step 3: Add the offer and find helpers to `rescue/known_items.py`**

Directly after `apply_entry_marks` (from Task 1), add:

```python
def entries_will_change(entry_kind: str, chosen: int | None = None, total: int | None = None) -> str:
    """What marking entries does, in plain words. Without counts it is the
    app's text ("the ones you choose"); with them, the terminal's."""
    spec = KINDS[entry_kind]
    if chosen is None:
        which = f"the {spec['nouns']} you choose"
        rest = " The ones you leave unticked keep their warning."
    else:
        which = f"the {chosen} {spec['noun'] if chosen == 1 else spec['nouns']} you chose"
        rest = f" The other {total - chosen} on the list keep their warning." if total and chosen < total else ""
    return (
        f"The checkup will stop warning you about {which}. They will still be listed, as "
        "\"marked as yours\", on every checkup and in anything you export, so anyone helping "
        f"you can see them.{rest} Anything new on the list is flagged, and if {spec['changed']} "
        "changes for one of them, its warning comes back."
    )


def entry_offers(finding, list_kind: str, signer_of=None) -> list[dict]:
    """markable.items for a warning about a list: one row per entry, never
    dropped. A row's id is what `known add --item` takes; None when the entry
    can't be pinned now (its maker can't be checked). Rows already marked
    carry their mark id and "marked": True."""
    entry_kind = ENTRY_KIND_FOR.get(list_kind)
    rows = list_entries(list_kind, finding) if entry_kind else None
    if not rows:
        return []
    data = finding.data
    marked = {m["entry"]: m["id"] for m in data.get("marked_items") or [] if isinstance(m, dict)}
    stale = {m["entry"] for m in data.get("stale_items") or [] if isinstance(m, dict)}
    out = []
    for row in rows:
        offer = {"key": row["entry"], "label": row["label"], "detail": row["detail"], "monitoring": True}
        if row["entry"] in marked:
            offer.update(id=marked[row["entry"]], marked=True)
        else:
            ident = entry_identity(entry_kind, finding.code, row, signer_of)
            offer["id"] = item_id(entry_kind, ident) if ident else None
            if row["entry"] in stale:
                offer["stale"] = True
        out.append(offer)
    return out
```

Replace the whole `find_item` function with:

```python
def _find_fresh(code: str, expect_id: str, run_check: Callable[[str], list]) -> tuple[str, dict, Finding]:
    """(kind, identity, finding) of the item a fresh check reports under
    `code` whose mark id is `expect_id`. Raises KnownItemsError otherwise."""
    kind = item_kind_for(code)
    if kind is None:
        raise KnownItemsError(f"'{code}' is not a finding that can be marked as yours.")
    module_name = code.split(".")[1]
    try:
        findings = run_check(module_name)
    except Exception as exc:
        raise KnownItemsError(f"The check could not run again to confirm it ({exc}). Nothing was marked.") from exc
    for f in findings or []:
        if getattr(f, "code", None) != code or getattr(f, "severity", None) != Severity.WARNING:
            continue
        hit = item_identity(f)
        if hit and hit[0] == kind and item_id(kind, hit[1]) == expect_id:
            return hit[0], hit[1], f
    raise KnownItemsError(
        "This has changed since the checkup, or is no longer there, so nothing was marked. "
        "Run the checkup again."
    )


def find_item(code: str, expect_id: str, run_check: Callable[[str], list]) -> tuple[str, dict]:
    """(kind, identity) of the item a fresh check reports under `code` whose
    mark id is `expect_id`. Raises KnownItemsError otherwise.

    run_check(module_name) runs that check now and returns its findings, so a
    mark is only ever saved for what is on the computer at the moment of saving.
    """
    kind, identity, _finding = _find_fresh(code, expect_id, run_check)
    return kind, identity


def find_entries(code: str, expect_id: str, wanted: list[str], run_check: Callable[[str], list],
                 signer_of=None) -> tuple[str, list[tuple[dict, dict, str]], int]:
    """(entry kind, [(row, identity, item id)] in the order asked, entries on the list).

    The check runs again now: the list must still be the one the checkup
    showed (expect_id), and every wanted id must still be an entry on it,
    unchanged. Otherwise KnownItemsError, and nothing is saved.
    """
    kind, _identity, finding = _find_fresh(code, expect_id, run_check)
    entry_kind = ENTRY_KIND_FOR.get(kind)
    if entry_kind is None:
        raise KnownItemsError("This finding can only be marked as a whole, not one entry at a time. Nothing was marked.")
    rows = list_entries(kind, finding)
    if not rows:
        raise KnownItemsError(
            "This list can't be checked one entry at a time right now, so nothing was marked. "
            "You can still mark the whole list."
        )
    offered = {}
    for row in rows:
        ident = entry_identity(entry_kind, code, row, signer_of)
        if ident is not None:
            offered[item_id(entry_kind, ident)] = (row, ident)
    if not wanted or any(w not in offered for w in wanted):
        raise KnownItemsError(
            "This has changed since the checkup, or is no longer there, so nothing was marked. "
            "Run the checkup again."
        )
    return entry_kind, [(offered[w][0], offered[w][1], w) for w in wanted], len(rows)
```

- [ ] **Step 4: Offer the entries in `item_markable`**

In `item_markable`, replace the final `return { ... }` block (from `return {` through the closing `}` after `**({"apps": _apps_rows(finding)} if kind == "app_permissions" else {}),`) with:

```python
    out = {
        "kind": kind,
        # The engine refuses to save unless a fresh check still gives this id.
        "id": item_id(kind, identity),
        "code": identity["code"],
        "label": (spec.get("label_of") or (lambda i: ""))(identity),
        # The same item on another card has the same kind and group.
        "group": group_key(kind, identity),
        "monitoring": is_monitoring(kind, identity),
        "shows": shows,
        "will_change": item_will_change(kind, identity),
        "how_to_undo": list(MARK_HOW_TO_UNDO),
        **({"apps": _apps_rows(finding)} if kind == "app_permissions" else {}),
    }
    if kind in ENTRY_KIND_FOR:
        try:
            offers = entry_offers(finding, kind)
        except Exception:
            offers = []
        if offers:
            out["items"] = offers
            out["items_will_change"] = entries_will_change(ENTRY_KIND_FOR[kind])
    return out
```

- [ ] **Step 5: Add `--item` to the CLI**

In `rescue/cli.py`, add this option to `known add`, directly after the `--expect-id` option:

```python
@click.option(
    "--item", "item_ids", multiple=True,
    help=(
        "Mark only these entries of a list finding (apps on a permission list, remote-login keys): "
        "the ids from markable.items. Repeat for several. Needs exactly one --code and its --expect-id."
    ),
)
```

Change the signature line `def known_add(codes, label, program, plist, expect_id, as_json, acknowledged):` to:

```python
def known_add(codes, label, program, plist, expect_id, item_ids, as_json, acknowledged):
```

At the very start of the body of `known_add`, after the `from rescue.known_items import (...)` block and before `if label is None and program is None and plist is None:`, add:

```python
    if item_ids:
        if label is not None or program is not None or plist is not None:
            _emit_known(_known_doc(
                "refused", "--item is for lists of apps or keys, not background tasks. Nothing was marked.",
            ), as_json, 2)
            return
        _known_add_entries(list(codes), list(expect_id or ()), list(item_ids), as_json, acknowledged)
        return
```

Add this helper directly above `def _known_add_item(`:

```python
def _fresh_check_runner():
    """run_check(module_name) for find_item and find_entries: each check runs
    once, now, at write time; never trust what a scan said earlier."""
    by_name: dict = {}
    ran: dict = {}

    def run_check(module_name):
        from rescue.known_items import KnownItemsError

        if module_name not in ran:
            if not by_name:
                by_name.update({m.name: m for m in discover_modules(_get_modules_dir())})
            mod = by_name.get(module_name)
            if mod is None:
                raise KnownItemsError("that check was not found")
            ran[module_name] = _check_quietly(mod, gather_profile()).findings
        return ran[module_name]

    return run_check
```

In `_known_add_item`, replace:

```python
    kind = kinds.pop()
    by_name: dict = {}
    ran: dict = {}

    def run_check(module_name):
        # Each check runs once, now, at write time; never trust what a scan said earlier.
        if module_name not in ran:
            if not by_name:
                by_name.update({m.name: m for m in discover_modules(_get_modules_dir())})
            mod = by_name.get(module_name)
            if mod is None:
                raise KnownItemsError("that check was not found")
            ran[module_name] = _check_quietly(mod, gather_profile()).findings
        return ran[module_name]
```

with:

```python
    kind = kinds.pop()
    run_check = _fresh_check_runner()
```

Add this function directly below `_known_add_item`:

```python
def _known_add_entries(codes, expect_ids, item_ids, as_json, acknowledged) -> None:
    """`rescue known add --code C --expect-id ID --item I ...`: some entries of one list."""
    from rescue.known_items import (
        APP_ENTRY,
        KINDS,
        MARK_HOW_TO_UNDO,
        MAX_LIST_ENTRIES,
        KnownItemsError,
        KnownItemsStore,
        entries_will_change,
        find_entries,
    )

    if (
        len(codes) != 1
        or len(expect_ids) != 1
        or not re.fullmatch(r"[0-9a-f]{12}", expect_ids[0])
        or not item_ids
        or len(item_ids) > MAX_LIST_ENTRIES
        or len(set(item_ids)) != len(item_ids)
        or not all(re.fullmatch(r"[0-9a-f]{12}", i) for i in item_ids)
    ):
        _emit_known(_known_doc(
            "refused",
            "To mark some of a list, give one --code, its --expect-id (the list's mark id from the "
            "checkup), and one --item for each entry, each once. Nothing was marked.",
        ), as_json, 2)
        return
    code = codes[0]
    try:
        entry_kind, chosen, total = find_entries(code, expect_ids[0], item_ids, _fresh_check_runner())
    except KnownItemsError as exc:
        _emit_known(_known_doc("refused", str(exc)), as_json, 2)
        return
    spec = KINDS[entry_kind]
    label = f"{len(chosen)} of {total} {spec['nouns']}"
    if acknowledged:
        via = "confirmed in the app (--i-understand)"
    else:
        if not _stdin_is_tty():
            _emit_known(_known_doc(
                "refused",
                "Marking something as yours needs the person at the keyboard. Run this in a "
                "terminal and answer the question. Nothing was marked.",
                label=label,
            ), as_json, 2)
            return
        click.echo(entries_will_change(entry_kind, len(chosen), total), err=True)
        for row, ident, iid in chosen:
            click.echo(f"  {row['shown']}  (id {iid})", err=True)
            if entry_kind == APP_ENTRY:
                click.echo(f"    made by: {ident['signer']}", err=True)
        click.echo(f"  Finding: {code}", err=True)
        if not click.confirm("Are these yours, and do you want to stop being warned about them?", default=False, err=True):
            _emit_known(_known_doc("cancelled", "Nothing was marked.", label=label), as_json, 1)
            return
        via = "confirmed in the terminal"
    try:
        saved = KnownItemsStore().add_many(entry_kind, [ident for _, ident, _ in chosen], via=via)
    except (KnownItemsError, OSError) as exc:
        _emit_known(_known_doc("failed", f"Could not save the mark: {exc}", label=label), as_json, 1)
        return
    ids = [item.id for item, _ in saved]
    created = any(c for _, c in saved)
    undo = [s.replace("<id>", " ".join(ids)) for s in MARK_HOW_TO_UNDO]
    message = (
        f"Marked {label} as yours (id {', '.join(ids)}). They will show as \"marked as yours\" from the next checkup."
        if created else f"Those were already marked as yours (id {', '.join(ids)})."
    )
    _emit_known(_known_doc(
        "marked" if created else "already_marked", message,
        id=ids[0], ids=ids, label=label, kind=entry_kind, how_to_undo=undo,
    ), as_json)
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `uv run --extra dev pytest tests/test_known_entries_cli.py tests/test_known_entries.py tests/test_known_item_kinds.py tests/test_known_items.py -v`
Expected: PASS (all).

- [ ] **Step 7: Document it**

In `docs/cli.md`, in the `rescue known` console block, add this line after the second `rescue known add` line:

```console
$ rescue known add --code <finding code> --expect-id <list id> --item <entry id> [--item ...] [--json]
```

In the kinds table in that section, add these two rows directly below the `ssh_authorized_keys` row:

```markdown
| `app_permission_entry` | one app on an `app_permissions` list (same codes) | code, the app's bundle id or path, who signed it (`team:<Team ID>`, `apple` or `unsigned`) | who signed it changes, or it can't be checked |
| `ssh_authorized_key` | one key on the `ssh_authorized_keys` list | code, SHA-256 of the decoded key, SHA-256 of its whole saved line | the line changes (options or comment) |
```

Directly below the table (before "Nothing from `stalkerware_scan`…"), add:

```markdown
**Marking some entries of a list.** A warning about a list of apps or keys
carries `markable.items` in `rescue scan --json`: one row per entry, with
`key` (bundle id or path, or the key's SHA-256), `label`, `detail`, and `id`
(the entry's mark id, or `null` when its maker can't be checked now, so it
can't be marked on its own). Rows already marked have `"marked": true` and
their saved id. Pass the list's `markable.id` as `--expect-id` and one
`--item` per entry. The check runs again right then; if the list or any
chosen entry changed, nothing is saved. In a terminal the command lists each
entry by name and id and asks once, default No.

A partly marked list stays a warning. Its title ends "(N of M not marked as
yours)", the description lists the entries not marked first, and `data` has
`partly_marked: true`, `marked_items` and `stale_items` (each
`{id, entry, shown, marked_at}`), `unmarked` (the entries still flagged) and
`entry_kind`. When every entry is marked, the finding is downgraded to `info`
like a whole-list mark, with `marked_by_user: true` but no `known_item_id`
(the ids are in `marked_items`). A new entry, or one whose maker or saved
line changed, warns on its own. A key's comment is shown in the app only: it
is never in a description, and `rescue export` replaces it.
```

In the flags table of that section, add this row directly below the `--expect-id` row:

```markdown
| | `--item` (repeatable) | Mark only these entries of a list finding: ids from `markable.items`. Needs exactly one `--code` and its `--expect-id`. Not with `--label`, `--program` or `--plist`. Every one must still be on the list, unchanged, or nothing is saved. |
```

In `AGENTS.md`, rule 1, replace the sentence

```markdown
   `data.mark_stale: true` means it was marked but has changed since.
```

with:

```markdown
   `data.mark_stale: true` means it was marked but has changed since.
   `data.partly_marked: true` means some entries of a list were marked:
   `data.unmarked` lists the ones still flagged, and `data.marked_items` the
   ones marked.
```

- [ ] **Step 8: Regenerate the integrity manifest and run the full suite**

Run: `uv run python scripts/generate_integrity_manifest.py && uv run --extra dev pytest`
Expected: PASS (all). Then:
Run: `uv run --extra dev pytest tests/test_remediation_catalog.py tests/test_generate_command_catalog.py tests/test_command_catalog_firewall.py -v`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add rescue/known_items.py rescue/cli.py rescue/security/integrity_manifest.json docs/cli.md AGENTS.md tests/test_known_entries_cli.py
git commit -m "$(cat <<'EOF'
Engine: offer list entries in markable.items; rescue known add --item

The check runs again at write time and every chosen entry must still be
there, unchanged. In a terminal it lists each entry and asks once.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: Engine: the export shows marked entries and never a key comment

**Files:**
- Modify: `rescue/case.py` (`_entry_to_dict`; new `_without_key_comments`)
- Modify: `tests/test_case_export.py` (one new test at the end)
- Regenerate: `rescue/security/integrity_manifest.json`

**Interfaces:**
- Consumes (Task 1): finding `data.marked_items`, `data.keys[].comment`.
- Produces: `rescue export` JSON keeps `data.marked_items`, `data.stale_items`, `data.unmarked`; each `data.keys[].comment` becomes `"[redacted] key comment"`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_case_export.py`:

```python
def test_marked_entries_show_in_the_export_and_key_comments_never_do():
    keys = [{"type": "ssh-ed25519", "sha256": "a" * 64, "line_sha256": "b" * 64, "comment": "jo@laptop"}]
    marked = [{"id": "0123456789ab", "entry": "a" * 64, "shown": "ssh-ed25519 key aaaaaaaaaaaaaaaa…",
               "marked_at": "2026-10-18T00:00:00Z"}]
    case = _case_with_finding(
        code="security.session_revocation_scan.ssh_authorized_keys",
        description="Marked as yours (1): ssh-ed25519 key aaaaaaaaaaaaaaaa…",
        data={"check": "ssh_authorized_keys", "key_count": 1, "keys": keys,
              "marked_items": marked, "unmarked": []},
    )
    out = case_to_json(case)
    assert "jo@laptop" not in out
    assert "[redacted] key comment" in out
    data = case_to_dict(case)["modules"][0]["findings"][0]["data"]
    assert data["marked_items"][0]["id"] == "0123456789ab"
    assert data["keys"][0]["sha256"] == "a" * 64
    assert "Marked as yours (1)" in case_to_markdown(case)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run --extra dev pytest tests/test_case_export.py::test_marked_entries_show_in_the_export_and_key_comments_never_do -v`
Expected: FAIL with `AssertionError` on `"jo@laptop" not in out` (the comment has no TLD, so the email rule doesn't catch it).

- [ ] **Step 3: Drop key comments before redaction**

In `rescue/case.py`, add this function directly above `def _entry_to_dict(`:

```python
def _without_key_comments(data: Any) -> Any:
    """A saved remote-login key's comment is often user@host or an email
    address. It is shown on this computer only: an export never carries it."""
    if not isinstance(data, dict) or not isinstance(data.get("keys"), list):
        return data
    out = dict(data)
    out["keys"] = [
        dict(k, comment=f"{_REDACTED} key comment") if isinstance(k, dict) and k.get("comment") else k
        for k in data["keys"]
    ]
    return out
```

In `_entry_to_dict`, replace

```python
                "data": _redact_any(f.data, extra),
```

with

```python
                "data": _redact_any(_without_key_comments(f.data), extra),
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run --extra dev pytest tests/test_case_export.py -v`
Expected: PASS (all).

- [ ] **Step 5: Regenerate the integrity manifest and run the full suite**

Run: `uv run python scripts/generate_integrity_manifest.py && uv run --extra dev pytest`
Expected: PASS (all).

- [ ] **Step 6: Commit**

```bash
git add rescue/case.py rescue/security/integrity_manifest.json tests/test_case_export.py
git commit -m "$(cat <<'EOF'
Export: keep marked entries; never carry a saved key's comment

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: Engine: `--profile` repeatable on `scan` and `export` (the union)

**Files:**
- Modify: `rescue/profiles.py` (new `merge_profiles`)
- Modify: `rescue/cli.py` (`scan` and `export` options and bodies; new `_load_profiles_or_exit`; import line for `rescue.profiles`)
- Modify: `docs/cli.md` (scan and export sections), `AGENTS.md` ("Pick what to run" table)
- Create: `tests/test_profile_union.py`
- Regenerate: `rescue/security/integrity_manifest.json`

**Interfaces:**
- Consumes: `Profile`, `ProfileValidationError`, `discover_profiles`, `_load_profile_or_exit`, `discover_modules`.
- Produces:
  - `merge_profiles(profiles: list[Profile], module_names: list[str]) -> Profile`: `include_modules` is the union of what each selects, in `module_names` order; `exclude_modules` is `[]`; `module_config` merged per module (a key set differently by two profiles raises `ProfileValidationError` whose message contains "differently"); `name` is the names joined with `+`.
  - CLI: `rescue scan --json --profile A --profile B`, `rescue export --profile A --profile B [--stdout]`. One `--profile` behaves exactly as today. The export's `rescue_profile` is `"A+B"`.
  - Task 6 sends `--profile` once per name; Task 9 relies on it.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_profile_union.py`:

```python
"""Several profiles at once: the checkup runs every module any of them selects."""

import itertools
import json
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from rescue import cli as cli_mod
from rescue.models import Platform, SystemProfile
from rescue.profiles import Profile, ProfileValidationError, discover_profiles, merge_profiles
from rescue.registry import discover_modules

ROOT = Path(__file__).parent.parent
NAMES = ["a_mod", "b_mod", "c_mod", "d_mod"]


def P(name, include=(), exclude=(), config=None):
    return Profile(name=name, display_name=name.title(), description="",
                   include_modules=list(include), exclude_modules=list(exclude), module_config=config or {})


def test_union_of_the_modules_each_profile_selects_in_module_order():
    merged = merge_profiles([P("one", ["c_mod", "a_mod"]), P("two", ["b_mod", "a_mod"])], NAMES)
    assert merged.include_modules == ["a_mod", "b_mod", "c_mod"]
    assert merged.name == "one+two" and merged.exclude_modules == []


def test_a_profile_with_no_include_list_selects_everything_but_its_excludes():
    merged = merge_profiles([P("all", exclude=["d_mod"]), P("one", ["a_mod"])], NAMES)
    assert merged.include_modules == ["a_mod", "b_mod", "c_mod"]
    merged = merge_profiles([P("all", exclude=["d_mod"]), P("dee", ["d_mod"])], NAMES)
    assert merged.include_modules == NAMES


def test_settings_are_kept_and_a_conflict_is_refused():
    merged = merge_profiles([
        P("one", ["a_mod"], config={"a_mod": {"sensitivity": "elevated"}}),
        P("two", ["b_mod"], config={"b_mod": {"x": 1}}),
    ], NAMES)
    assert merged.module_config == {"a_mod": {"sensitivity": "elevated"}, "b_mod": {"x": 1}}
    with pytest.raises(ProfileValidationError, match="differently"):
        merge_profiles([
            P("one", ["a_mod"], config={"a_mod": {"sensitivity": "elevated"}}),
            P("two", ["a_mod"], config={"a_mod": {"sensitivity": "normal"}}),
        ], NAMES)


def test_no_profiles_is_refused():
    with pytest.raises(ProfileValidationError):
        merge_profiles([], NAMES)


def test_every_pair_of_shipped_profiles_can_run_together():
    profiles = discover_profiles(ROOT / "profiles")
    names = [m.name for m in discover_modules(ROOT / "modules")]
    for a, b in itertools.combinations(sorted(profiles), 2):
        merged = merge_profiles([profiles[a], profiles[b]], names)
        assert set(merged.include_modules) >= set(profiles[a].include_modules) | set(profiles[b].include_modules)


def _system():
    return SystemProfile(platform=Platform.DARWIN, os_name="macOS", os_version="15.0", architecture="arm64",
                         cpu_model="Test CPU", cpu_cores=4, ram_bytes=8 * 1024**3, hostname="test-host")


def _run(args):
    seen = {}

    class FakeOrchestrator:
        def __init__(self, modules_dir=None, profile=None):
            seen["profile"] = profile

        def run_checks(self, on_progress=None):
            return []

    with patch.object(cli_mod, "_run_startup_integrity_check"), \
         patch.object(cli_mod, "gather_profile", return_value=_system()), \
         patch.object(cli_mod, "Orchestrator", FakeOrchestrator):
        result = CliRunner().invoke(cli_mod.main, args)
    return result, seen.get("profile")


def test_scan_with_two_profiles_runs_their_union():
    r, prof = _run(["scan", "--json", "--profile", "digital_security_reset", "--profile", "home_network_intrusion"])
    assert r.exit_code == 0, r.output
    profiles = discover_profiles(ROOT / "profiles")
    want = set(profiles["digital_security_reset"].include_modules) | set(profiles["home_network_intrusion"].include_modules)
    assert set(prof.include_modules) == want
    assert prof.name == "digital_security_reset+home_network_intrusion"


def test_one_profile_is_unchanged_and_profile_with_module_is_still_refused():
    r, prof = _run(["scan", "--json", "--profile", "digital_security_reset"])
    assert r.exit_code == 0 and prof.name == "digital_security_reset"
    r, _ = _run(["scan", "--json", "--profile", "digital_security_reset", "--module", "disk_space"])
    assert r.exit_code == 2


def test_an_unknown_profile_among_several_exits_1():
    r, _ = _run(["scan", "--json", "--profile", "digital_security_reset", "--profile", "nope"])
    assert r.exit_code == 1


def test_export_names_both_profiles():
    r, _ = _run(["export", "--stdout", "--profile", "digital_security_reset", "--profile", "identity_theft_recovery"])
    assert r.exit_code == 0, r.output
    assert json.loads(r.stdout)["rescue_profile"] == "digital_security_reset+identity_theft_recovery"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run --extra dev pytest tests/test_profile_union.py -v`
Expected: FAIL at import with `ImportError: cannot import name 'merge_profiles'`.

- [ ] **Step 3: Add `merge_profiles` to `rescue/profiles.py`**

Append to `rescue/profiles.py`:

```python
def _selected(profile: Profile, module_names: list[str]) -> list[str]:
    out = [n for n in module_names if not profile.include_modules or n in profile.include_modules]
    return [n for n in out if n not in profile.exclude_modules]


def merge_profiles(profiles: list[Profile], module_names: list[str]) -> Profile:
    """One profile that runs every module any of `profiles` selects (the
    union), in `module_names` order, with each profile's module settings.

    Two profiles giving the same module setting different values is refused
    rather than guessed: ProfileValidationError.
    """
    if not profiles:
        raise ProfileValidationError("No profiles to combine.")
    chosen: set[str] = set()
    config: dict[str, dict[str, Any]] = {}
    set_by: dict[tuple[str, str], str] = {}
    for profile in profiles:
        chosen.update(_selected(profile, module_names))
        for module, settings in (profile.module_config or {}).items():
            merged = config.setdefault(module, {})
            for key, value in (settings or {}).items():
                if key in merged and merged[key] != value:
                    raise ProfileValidationError(
                        f"Profiles '{set_by[(module, key)]}' and '{profile.name}' set {module} "
                        f"{key} differently, so they can't run together."
                    )
                merged[key] = value
                set_by.setdefault((module, key), profile.name)
    return Profile(
        name="+".join(p.name for p in profiles),
        display_name=" + ".join(p.display_name for p in profiles),
        description="Every check any of these selects: " + ", ".join(p.display_name for p in profiles) + ".",
        include_modules=[n for n in module_names if n in chosen],
        exclude_modules=[],
        module_config=config,
        guides=list(dict.fromkeys(g for p in profiles for g in p.guides)),
    )
```

- [ ] **Step 4: Make `--profile` repeatable on `scan` and `export`**

In `rescue/cli.py`, change the import line

```python
from rescue.profiles import Profile, ProfileValidationError, discover_profiles, validate_profile_modules
```

to

```python
from rescue.profiles import Profile, ProfileValidationError, discover_profiles, merge_profiles, validate_profile_modules
```

Add this function directly below `_load_profile_or_exit`:

```python
def _load_profiles_or_exit(profile_names):
    """One profile, or the union of several (repeat --profile)."""
    names = list(dict.fromkeys(profile_names))
    if len(names) == 1:
        return _load_profile_or_exit(names[0])
    profiles = [_load_profile_or_exit(n) for n in names]
    try:
        return merge_profiles(profiles, [m.name for m in discover_modules(_get_modules_dir())])
    except ProfileValidationError as exc:
        click.echo(f"Invalid profiles: {exc}", err=True)
        raise SystemExit(1) from exc
```

On the `scan` command, replace

```python
@click.option("--profile", "profile_name", default=None, help="Only run the modules a profile selects.")
```

(the one directly above the `--module` option) with

```python
@click.option(
    "--profile", "profile_names", multiple=True,
    help="Only run the modules a profile selects. Repeat to run every module any of them selects.",
)
```

and replace the start of the `scan` function:

```python
def scan(as_json, profile_name, module_names, progress, trace, no_attribution):
    """Run read-only checks. With --json, print structured results to stdout."""
    from rescue.serialize import checks_to_json
    if profile_name and module_names:
        raise click.UsageError("Use --profile or --module, not both.")
    if module_names:
        threat_profile = _module_only_profile(module_names)
    else:
        threat_profile = _load_profile_or_exit(profile_name) if profile_name else None
```

with

```python
def scan(as_json, profile_names, module_names, progress, trace, no_attribution):
    """Run read-only checks. With --json, print structured results to stdout."""
    from rescue.serialize import checks_to_json
    if profile_names and module_names:
        raise click.UsageError("Use --profile or --module, not both.")
    if module_names:
        threat_profile = _module_only_profile(module_names)
    else:
        threat_profile = _load_profiles_or_exit(profile_names) if profile_names else None
```

On the `export` command, replace

```python
@click.option("--profile", "profile_name", default=None, help="Only run the modules a profile selects.")
```

(the one directly above `--output`) with

```python
@click.option(
    "--profile", "profile_names", multiple=True,
    help="Only run the modules a profile selects. Repeat to run every module any of them selects.",
)
```

and replace

```python
def export(profile_name, output_dir, to_stdout):
```

with

```python
def export(profile_names, output_dir, to_stdout):
```

and in its body replace

```python
    profile = _load_profile_or_exit(profile_name) if profile_name else None

    system_profile = gather_profile()
    orch = Orchestrator(modules_dir=_get_modules_dir(), profile=profile)
    case = RescueCase(
        profile=system_profile,
        profile_name=profile_name,
        started_at=_utc_now(),
    )
```

with

```python
    profile = _load_profiles_or_exit(profile_names) if profile_names else None

    system_profile = gather_profile()
    orch = Orchestrator(modules_dir=_get_modules_dir(), profile=profile)
    case = RescueCase(
        profile=system_profile,
        profile_name=profile.name if profile else None,
        started_at=_utc_now(),
    )
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `uv run --extra dev pytest tests/test_profile_union.py -v`
Expected: PASS (all).

- [ ] **Step 6: Document it**

In `docs/cli.md`, replace

```console
$ rescue scan [--json] [--profile <name> | --module <name> ...]
```

with

```console
$ rescue scan [--json] [--profile <name> ... | --module <name> ...]
```

and replace the scan table row

```markdown
| `--profile <name>` | Only run the modules the named profile selects. Exits `1` on an unknown or invalid profile. |
```

(the first one, under `rescue scan`) with

```markdown
| `--profile <name>` | Only run the modules the named profile selects. Repeat it to run every module any of the profiles selects, with each one's module settings; two profiles that set the same module setting differently are refused. Exits `1` on an unknown or invalid profile, or such a conflict. |
```

Replace

```console
$ rescue export [--profile <name>] [--output <dir>] [--stdout]
```

with

```console
$ rescue export [--profile <name> ...] [--output <dir>] [--stdout]
```

and replace the export table row (the `--profile <name>` row under `rescue export`) with

```markdown
| `--profile <name>` | Only run the modules the named profile selects. Repeat it to run every module any of them selects; the case's `rescue_profile` is the names joined with `+`. Exits `1` on an unknown or invalid profile, or a conflict between them. |
```

In `AGENTS.md`, in the "Pick what to run" table, add this row directly above the `| Linux machine |` row:

```markdown
| More than one of these at once | repeat the profile: `rescue export --profile digital_security_reset --profile home_network_intrusion --stdout` |
```

- [ ] **Step 7: Regenerate the integrity manifest and run the full suite**

Run: `uv run python scripts/generate_integrity_manifest.py && uv run --extra dev pytest`
Expected: PASS (all).

- [ ] **Step 8: Commit**

```bash
git add rescue/profiles.py rescue/cli.py rescue/security/integrity_manifest.json docs/cli.md AGENTS.md tests/test_profile_union.py
git commit -m "$(cat <<'EOF'
Engine: repeat --profile to run the union of several profiles

Each profile's module settings are kept; two that set the same setting
differently are refused rather than guessed.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```

---
### Task 5: Desktop: one shared checklist component

**Files:**
- Create: `desktop/renderer/checklist.js`
- Create: `desktop/renderer/checklist.css`
- Create: `desktop/test/checklist.test.js`
- Modify: `desktop/test/stylesheets.test.js` (the `SHEETS` list)

**Interfaces:**
- Consumes: nothing.
- Produces (global `Checklist` in the page, `window.Checklist` for the game, `module.exports` for Node):
  - `Checklist.html(opts) -> string`, where `opts = { id: string, legend: string, items: [{ key: string, label: string, detail?: string, evidenceHtml?: string, disabled?: boolean, note?: string }], actions: [{ id: string, verb: string, noun: [one, many], suffix?: string, min?: number }], selectAll?: boolean, theme?: 'plain' | 'game' }`. `evidenceHtml` must already be escaped by the caller; everything else is escaped here. Any `checked` on an item is ignored.
  - Markup contract (other tasks select on these): `fieldset[data-cl-list="<id>"]`, `input[type=checkbox][data-cl-item][data-cl-key="<key>"]`, `[data-cl-all]`, `[data-cl-none]`, `[data-cl-more]` rows, `[data-cl-more-show]`, `p[data-cl-count][aria-live=polite]`, `button[data-cl-action="<id>"]` with `data-cl-verb`, `data-cl-one`, `data-cl-many`, `data-cl-suffix`, `data-cl-min`.
  - `Checklist.attach(root, { onAction(listId: string, actionId: string, keys: string[]) }) -> { update(list), chosen(list) -> string[] }` (delegated `change`, `click` and `keydown` listeners on `root`).
  - `Checklist.actionLabel(action, n) -> string`, `Checklist.countText(n, total) -> string`, `Checklist.moveIndex(i, n, key) -> number | null`, `Checklist.preserveFocus(root, render) -> void`, `Checklist.SHOWN === 50`.

- [ ] **Step 1: Write the failing tests**

Create `desktop/test/checklist.test.js`:

```js
// The one checklist: real checkboxes, unticked, select all / none, a live
// count, and a primary button that says what it will do and to how many.
const test = require('node:test');
const assert = require('node:assert');
const Checklist = require('../renderer/checklist.js');
const { createDocument } = require('./mini-dom.js');

const MARK = { id: 'mark', verb: 'Mark', noun: ['app', 'apps'], suffix: 'as mine', min: 1 };
const items = (n) => Array.from({ length: n }, (_, i) => ({ key: `k${i}`, label: `App ${i}`, detail: `com.example.app${i}` }));

test('real checkboxes with real labels, inside a fieldset with a legend', () => {
  const html = Checklist.html({ id: 'apps-1', legend: 'Apps with Accessibility access', items: items(2), actions: [MARK], selectAll: true });
  assert.match(html, /<fieldset class="checklist checklist--plain" data-cl-list="apps-1"/);
  assert.match(html, /<legend class="checklist__legend">Apps with Accessibility access<\/legend>/);
  assert.strictEqual((html.match(/<input type="checkbox"/g) || []).length, 2);
  assert.match(html, /<input type="checkbox" id="apps-1-item-0" class="checklist__box" data-cl-item data-cl-key="k0">/);
  assert.match(html, /<label for="apps-1-item-0" class="checklist__label">/);
  assert.match(html, /<code class="checklist__detail">com\.example\.app0<\/code>/);
  assert.match(html, /data-cl-all>Select all<\/button>/);
  assert.match(html, /data-cl-none>Select none<\/button>/);
});

test('everything starts unticked, even if a caller asks otherwise', () => {
  const html = Checklist.html({ id: 'x', legend: 'L', items: [{ key: 'a', label: 'A', checked: true }], actions: [MARK] });
  assert.ok(!/\bchecked\b/.test(html));
});

test('the count and the button start at zero, and the button says so', () => {
  const html = Checklist.html({ id: 'x', legend: 'L', items: items(3), actions: [MARK] });
  assert.match(html, /<p class="checklist__count" data-cl-count aria-live="polite">0 of 3 selected<\/p>/);
  assert.match(html, /data-cl-action="mark"[^>]*disabled>Select at least one<\/button>/);
});

test('the primary button names the action and the number', () => {
  assert.strictEqual(Checklist.actionLabel(MARK, 3), 'Mark 3 apps as mine');
  assert.strictEqual(Checklist.actionLabel(MARK, 1), 'Mark 1 app as mine');
  assert.strictEqual(Checklist.actionLabel({ id: 'off', verb: 'Turn off', noun: ['startup item', 'startup items'] }, 2), 'Turn off 2 startup items');
  assert.strictEqual(Checklist.actionLabel(MARK, 0), 'Select at least one');
  assert.strictEqual(Checklist.countText(2, 7), '2 of 7 selected');
});

test('text is escaped and control characters are shown, not obeyed', () => {
  const html = Checklist.html({ id: 'x"><b', legend: '<i>L</i>', items: [{ key: 'a"b', label: 'Zoom‮exe.', note: '<b>n</b>' }], actions: [MARK] });
  assert.ok(!html.includes('<i>L</i>') && !html.includes('<b>n</b>'));
  assert.ok(!html.includes('‮'));
  assert.match(html, /Zoom\[U\+202E\]exe\./);
  assert.match(html, /data-cl-key="a&quot;b"/);
  assert.match(html, /data-cl-list="x___b"/);
});

test('a disabled row is shown, with its note, and not counted', () => {
  const html = Checklist.html({ id: 'x', legend: 'L', items: [{ key: 'a', label: 'A' }, { key: 'b', label: 'B', disabled: true, note: 'Can’t be checked on its own' }], actions: [MARK], selectAll: true });
  assert.match(html, /data-cl-key="b" disabled>/);
  assert.match(html, /<span class="checklist__note">Can’t be checked on its own<\/span>/);
  assert.match(html, /0 of 1 selected/);
  assert.ok(!html.includes('data-cl-all'), 'no "Select all" for a single choosable row');
});

test('long lists show 50, then "Show all", and the count counts all of them', () => {
  const html = Checklist.html({ id: 'x', legend: 'L', items: items(60), actions: [MARK], selectAll: true });
  assert.strictEqual((html.match(/data-cl-more hidden/g) || []).length, 10);
  assert.match(html, /data-cl-more-show>Show all 60<\/button>/);
  assert.match(html, /0 of 60 selected/);
});

test('the game theme is a class, nothing else', () => {
  const html = Checklist.html({ id: 'x', legend: 'L', items: items(1), actions: [MARK], theme: 'game' });
  assert.match(html, /class="checklist checklist--game"/);
});

// --- behaviour, on a small DOM built the way html() lays it out --------------

function build(keys, { disabled = [] } = {}) {
  const doc = createDocument();
  const root = doc.body.add('div');
  const list = root.add('fieldset', { 'data-cl-list': 'apps-1' });
  const boxes = keys.map((k) => {
    const row = list.add('li');
    const box = row.add('input', { 'data-cl-item': '', 'data-cl-key': k });
    box.checked = false;
    box.disabled = disabled.includes(k);
    box.focus = () => { doc.activeElement = box; };
    return box;
  });
  const all = list.add('button', { 'data-cl-all': '' });
  const none = list.add('button', { 'data-cl-none': '' });
  const count = list.add('p', { 'data-cl-count': '' });
  const action = list.add('button', { 'data-cl-action': 'mark', 'data-cl-verb': 'Mark', 'data-cl-one': 'app',
    'data-cl-many': 'apps', 'data-cl-suffix': 'as mine', 'data-cl-min': '1' });
  return { doc, root, list, boxes, all, none, count, action };
}

const fire = (root, type, event) => (root.listeners[type] || []).map((fn) => fn(event));

test('ticking updates the count and the button; select all and none skip disabled rows', async () => {
  const d = build(['a', 'b', 'c'], { disabled: ['c'] });
  const seen = [];
  Checklist.attach(d.root, { onAction: (listId, actionId, keys) => seen.push([listId, actionId, keys]) });
  d.boxes[0].checked = true;
  fire(d.root, 'change', { target: d.boxes[0] });
  assert.strictEqual(d.count.textContent, '1 of 2 selected');
  assert.strictEqual(d.action.textContent, 'Mark 1 app as mine');
  assert.strictEqual(d.action.disabled, false);
  await d.all.click();
  assert.deepStrictEqual(d.boxes.map((b) => b.checked), [true, true, false]);
  assert.strictEqual(d.action.textContent, 'Mark 2 apps as mine');
  await d.action.click();
  assert.deepStrictEqual(seen, [['apps-1', 'mark', ['a', 'b']]]);
  await d.none.click();
  assert.deepStrictEqual(d.boxes.map((b) => b.checked), [false, false, false]);
  assert.strictEqual(d.action.disabled, true);
  assert.strictEqual(d.action.textContent, 'Select at least one');
  await d.action.click();
  assert.strictEqual(seen.length, 1, 'nothing is sent with nothing ticked');
});

test('arrow keys, Home and End move between rows', () => {
  const d = build(['a', 'b', 'c']);
  Checklist.attach(d.root, {});
  let prevented = 0;
  const key = (box, k) => fire(d.root, 'keydown', { key: k, target: box, preventDefault: () => { prevented += 1; } });
  key(d.boxes[0], 'ArrowDown');
  assert.strictEqual(d.doc.activeElement, d.boxes[1]);
  key(d.boxes[1], 'End');
  assert.strictEqual(d.doc.activeElement, d.boxes[2]);
  key(d.boxes[2], 'ArrowDown');
  assert.strictEqual(d.doc.activeElement, d.boxes[2], 'stays on the last row');
  key(d.boxes[2], 'Home');
  assert.strictEqual(d.doc.activeElement, d.boxes[0]);
  key(d.boxes[0], 'x');
  assert.strictEqual(prevented, 4, 'other keys are left alone');
  assert.strictEqual(Checklist.moveIndex(0, 3, 'ArrowUp'), 0);
  assert.strictEqual(Checklist.moveIndex(-1, 3, 'ArrowDown'), null);
});

test('preserveFocus puts focus back on the same row after a redraw', () => {
  const d = build(['a', 'b']);
  d.doc.activeElement = d.boxes[1];
  let again;
  Checklist.preserveFocus(d.root, () => {
    d.root.removeChild(d.list);
    again = build(['a', 'b']);
    // The redraw replaces the elements; the new ones live in the same root.
    d.root.appendChild(again.list);
    again.boxes.forEach((b) => { b.focus = () => { d.doc.activeElement = b; }; });
  });
  assert.strictEqual(d.doc.activeElement, again.boxes[1]);
  assert.strictEqual(again.boxes[1].checked, false, 'the selection itself starts again');
});

test('preserveFocus does nothing when focus was elsewhere', () => {
  const d = build(['a']);
  d.doc.activeElement = null;
  let ran = false;
  Checklist.preserveFocus(d.root, () => { ran = true; });
  assert.ok(ran);
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd desktop && node --test test/checklist.test.js`
Expected: FAIL with `Cannot find module '../renderer/checklist.js'`.

- [ ] **Step 3: Write the component**

Create `desktop/renderer/checklist.js`:

```js
'use strict';

/*
 * One checklist for every list the app lets the person choose from: apps on a
 * permission list, saved keys, worries. Real checkboxes with real labels in a
 * fieldset, "Select all" and "Select none" as plain buttons, a live count,
 * and a primary button that says what it will do and to how many ("Mark 3
 * apps as mine"). Everything starts unticked. Ticking changes nothing: the
 * button only hands the ticked keys to the caller, which asks before it acts.
 * Selection lives in the page only and starts again on every redraw.
 *
 * Loaded as a plain script (global `Checklist`, also on window for the game's
 * ES modules) and required from Node by the tests.
 */
const Checklist = (function () {
  // Long lists show this many rows, then "Show all N".
  const SHOWN = 50;

  function esc(value) {
    return String(value == null ? '' : value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  // Control and format characters (bidi overrides, zero-width spaces) shown as
  // [U+XXXX], so text can't reorder or hide itself on screen.
  function visible(s) {
    return String(s == null ? '' : s).replace(/[\p{Cc}\p{Cf}]/gu, (c) => `[U+${c.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}]`);
  }

  // A list id usable inside an element id.
  function safeId(s) {
    return String(s == null ? '' : s).replace(/[^a-zA-Z0-9_-]/g, '_');
  }

  function nounFor(action, n) {
    const noun = Array.isArray(action.noun) && action.noun.length === 2 ? action.noun : ['item', 'items'];
    return n === 1 ? noun[0] : noun[1];
  }

  function minOf(action) {
    const m = Number(action && action.min);
    return Number.isInteger(m) && m > 0 ? m : 1;
  }

  // "Mark 3 apps as mine"; "Select at least one" below the minimum. Never "Apply".
  function actionLabel(action, n) {
    if (!n || n < minOf(action)) return 'Select at least one';
    return [action.verb, String(n), nounFor(action, n), action.suffix].filter((p) => p).join(' ');
  }

  function countText(n, total) {
    return `${n} of ${total} selected`;
  }

  function rowHtml(listId, it, i) {
    const boxId = `${listId}-item-${i}`;
    const more = i >= SHOWN ? ' data-cl-more hidden' : '';
    return `<li class="checklist__row"${more}>`
      + `<input type="checkbox" id="${boxId}" class="checklist__box" data-cl-item data-cl-key="${esc(it.key)}"${it.disabled ? ' disabled' : ''}>`
      + `<label for="${boxId}" class="checklist__label">`
      + `<span class="checklist__name">${esc(visible(it.label))}</span>`
      + (it.detail ? ` <code class="checklist__detail">${esc(visible(it.detail))}</code>` : '')
      + (it.evidenceHtml || '')
      + (it.note ? `<span class="checklist__note">${esc(visible(it.note))}</span>` : '')
      + '</label></li>';
  }

  function actionHtml(a) {
    const noun = Array.isArray(a.noun) && a.noun.length === 2 ? a.noun : ['item', 'items'];
    return `<button type="button" class="btn btn--primary btn--small" data-cl-action="${esc(a.id)}"`
      + ` data-cl-verb="${esc(a.verb)}" data-cl-one="${esc(noun[0])}" data-cl-many="${esc(noun[1])}"`
      + ` data-cl-suffix="${esc(a.suffix || '')}" data-cl-min="${minOf(a)}" disabled>${esc(actionLabel(a, 0))}</button>`;
  }

  function html(opts) {
    const o = opts || {};
    const listId = safeId(o.id);
    const items = Array.isArray(o.items) ? o.items.filter((it) => it && typeof it.key === 'string') : [];
    const actions = Array.isArray(o.actions) ? o.actions.filter((a) => a && typeof a.id === 'string') : [];
    const theme = o.theme === 'game' ? 'game' : 'plain';
    const choosable = items.filter((it) => !it.disabled).length;
    const bulk = o.selectAll && choosable > 1
      ? '<div class="checklist__bulk"><button type="button" class="link-button" data-cl-all>Select all</button> '
        + '<button type="button" class="link-button" data-cl-none>Select none</button></div>'
      : '';
    const more = items.length > SHOWN
      ? `<button type="button" class="link-button checklist__more" data-cl-more-show>Show all ${items.length}</button>`
      : '';
    return `<fieldset class="checklist checklist--${theme}" data-cl-list="${listId}">`
      + `<legend class="checklist__legend">${esc(visible(o.legend))}</legend>`
      + bulk
      + `<ul class="checklist__items">${items.map((it, i) => rowHtml(listId, it, i)).join('')}</ul>`
      + more
      + `<p class="checklist__count" data-cl-count aria-live="polite">${esc(countText(0, choosable))}</p>`
      + `<div class="checklist__actions">${actions.map(actionHtml).join('')}</div>`
      + '</fieldset>';
  }

  function isDisabled(el) {
    return el.disabled === true || (typeof el.hasAttribute === 'function' && el.hasAttribute('disabled') && el.disabled !== false);
  }

  function actionOf(btn) {
    const one = btn.getAttribute('data-cl-one') || 'item';
    const many = btn.getAttribute('data-cl-many') || 'items';
    return {
      id: btn.getAttribute('data-cl-action'),
      verb: btn.getAttribute('data-cl-verb') || '',
      noun: [one, many],
      suffix: btn.getAttribute('data-cl-suffix') || '',
      min: Number(btn.getAttribute('data-cl-min')) || 1,
    };
  }

  // Up/Left and Down/Right move one row; Home and End jump. null: not a move.
  function moveIndex(i, n, key) {
    if (n === 0 || i < 0) return null;
    if (key === 'ArrowDown' || key === 'ArrowRight') return Math.min(n - 1, i + 1);
    if (key === 'ArrowUp' || key === 'ArrowLeft') return Math.max(0, i - 1);
    if (key === 'Home') return 0;
    if (key === 'End') return n - 1;
    return null;
  }

  function attach(root, hooks) {
    const on = hooks || {};
    const listOf = (el) => (el && typeof el.closest === 'function' ? el.closest('[data-cl-list]') : null);
    const boxes = (list) => Array.from(list.querySelectorAll('[data-cl-item]')).filter((b) => !isDisabled(b));
    const chosen = (list) => boxes(list).filter((b) => b.checked === true).map((b) => b.getAttribute('data-cl-key'));

    function update(list) {
      const n = chosen(list).length;
      const count = list.querySelector('[data-cl-count]');
      if (count) count.textContent = countText(n, boxes(list).length);
      Array.from(list.querySelectorAll('[data-cl-action]')).forEach((btn) => {
        const action = actionOf(btn);
        btn.disabled = n < action.min;
        btn.textContent = actionLabel(action, n);
      });
    }

    root.addEventListener('change', (event) => {
      const t = event && event.target;
      if (!t || typeof t.hasAttribute !== 'function' || !t.hasAttribute('data-cl-item')) return;
      const list = listOf(t);
      if (list) update(list);
    });

    root.addEventListener('click', (event) => {
      const t = event && event.target && typeof event.target.closest === 'function'
        ? event.target.closest('[data-cl-all],[data-cl-none],[data-cl-action],[data-cl-more-show]')
        : null;
      const list = listOf(t);
      if (!t || !list) return undefined;
      if (t.hasAttribute('data-cl-all') || t.hasAttribute('data-cl-none')) {
        const tick = t.hasAttribute('data-cl-all');
        boxes(list).forEach((b) => { b.checked = tick; });
        update(list);
        return undefined;
      }
      if (t.hasAttribute('data-cl-more-show')) {
        Array.from(list.querySelectorAll('[data-cl-more]')).forEach((row) => { row.hidden = false; });
        t.hidden = true;
        return undefined;
      }
      const keys = chosen(list);
      if (keys.length < actionOf(t).min) return undefined;
      if (typeof on.onAction === 'function') return on.onAction(list.getAttribute('data-cl-list'), t.getAttribute('data-cl-action'), keys);
      return undefined;
    });

    root.addEventListener('keydown', (event) => {
      const t = event && event.target;
      if (!t || typeof t.hasAttribute !== 'function' || !t.hasAttribute('data-cl-item')) return;
      const list = listOf(t);
      if (!list) return;
      const rows = boxes(list).filter((b) => {
        const more = typeof b.closest === 'function' ? b.closest('[data-cl-more]') : null;
        return !(more && more.hidden);
      });
      const next = moveIndex(rows.indexOf(t), rows.length, event.key);
      if (next === null) return;
      if (typeof event.preventDefault === 'function') event.preventDefault();
      if (typeof rows[next].focus === 'function') rows[next].focus();
    });

    return { update, chosen };
  }

  // What has focus inside a checklist: its list, and the row or control.
  function focusKey(el) {
    if (!el || typeof el.getAttribute !== 'function' || typeof el.closest !== 'function') return null;
    const list = el.closest('[data-cl-list]');
    if (!list) return null;
    const listId = list.getAttribute('data-cl-list');
    for (const attr of ['data-cl-key', 'data-cl-action']) {
      const value = el.getAttribute(attr);
      if (value !== null) return { listId, attr, value };
    }
    for (const attr of ['data-cl-all', 'data-cl-none', 'data-cl-more-show']) {
      if (el.hasAttribute(attr)) return { listId, attr, value: null };
    }
    return null;
  }

  function activeIn(root) {
    const node = root && typeof root.getRootNode === 'function' ? root.getRootNode() : null;
    if (node && node.activeElement) return node.activeElement;
    const doc = root && root.ownerDocument;
    return doc ? doc.activeElement || null : null;
  }

  // Redraw `root` with render(), then put focus back on the same row or
  // control of the same list, if it is still there. Works in a shadow root.
  function preserveFocus(root, render) {
    const key = focusKey(activeIn(root));
    render();
    if (!key || !root || typeof root.querySelectorAll !== 'function') return;
    const list = Array.from(root.querySelectorAll('[data-cl-list]')).find((l) => l.getAttribute('data-cl-list') === key.listId);
    if (!list) return;
    const target = Array.from(list.querySelectorAll(`[${key.attr}]`))
      .find((el) => key.value === null || el.getAttribute(key.attr) === key.value);
    if (target && typeof target.focus === 'function') target.focus();
  }

  return { SHOWN, html, attach, actionLabel, countText, moveIndex, preserveFocus, focusKey, esc, visible };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = Checklist;
}
// A top-level const isn't a window property; game mode's ES modules read it from window.
if (typeof window !== 'undefined') {
  window.Checklist = Checklist;
}
```

Note on the `disabled` test in `isDisabled`: in the browser, `el.disabled` reflects the attribute; in the test DOM the property is set directly. Both paths read the same answer.

- [ ] **Step 4: Add the styles**

Create `desktop/renderer/checklist.css`:

```css
/* The shared checklist (checklist.js). Plain view uses styles.css tokens;
   the game's shadow root links this file too and adds .checklist--game. */
.checklist {
  border: 1px solid var(--border, #d0d4dc);
  border-radius: var(--radius-md, 8px);
  padding: 12px 16px;
  margin: 12px 0;
  min-width: 0;
}
.checklist__legend {
  font-weight: 600;
  padding: 0 4px;
}
.checklist__bulk {
  display: flex;
  gap: 12px;
  margin: 4px 0 8px;
}
.checklist__items {
  list-style: none;
  margin: 0;
  padding: 0;
}
.checklist__row {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 6px 0;
  border-top: 1px solid var(--surface-muted, #eef0f4);
}
.checklist__row:first-child {
  border-top: 0;
}
.checklist__box {
  margin-top: 3px;
  width: 18px;
  height: 18px;
  flex: none;
}
.checklist__box:focus-visible {
  outline: 2px solid var(--brand, #2f5bd3);
  outline-offset: 2px;
}
.checklist__label {
  display: flex;
  flex-wrap: wrap;
  gap: 4px 8px;
  min-width: 0;
  overflow-wrap: anywhere;
}
.checklist__detail {
  color: var(--text-muted, #5b6170);
  overflow-wrap: anywhere;
}
.checklist__note {
  flex-basis: 100%;
  color: var(--text-muted, #5b6170);
  font-size: 0.9em;
}
.checklist__count {
  margin: 8px 0;
  color: var(--text-muted, #5b6170);
}
.checklist__actions {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}
.checklist__more {
  margin-top: 6px;
}
.checklist--game {
  border-color: var(--line, currentColor);
  color: inherit;
}
.checklist--game .checklist__row {
  border-top-color: var(--line, currentColor);
}
.checklist--game .checklist__detail,
.checklist--game .checklist__note,
.checklist--game .checklist__count {
  color: var(--dim, inherit);
}
.checklist--game .checklist__box:focus-visible {
  outline-color: var(--cyan, currentColor);
}
```

In `desktop/test/stylesheets.test.js`, replace

```js
const SHEETS = ['renderer/styles.css', 'renderer/game/game.css', 'renderer/game-fonts.css'];
```

with

```js
const SHEETS = ['renderer/styles.css', 'renderer/game/game.css', 'renderer/game-fonts.css', 'renderer/checklist.css'];
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd desktop && node --test test/checklist.test.js test/stylesheets.test.js`
Expected: PASS (all).

- [ ] **Step 6: Run the whole desktop suite**

Run: `cd desktop && npm test`
Expected: PASS (all). Nothing loads `checklist.js` yet outside its own test.

- [ ] **Step 7: Commit**

```bash
git add desktop/renderer/checklist.js desktop/renderer/checklist.css desktop/test/checklist.test.js desktop/test/stylesheets.test.js
git commit -m "$(cat <<'EOF'
Desktop: one shared checklist component

Real checkboxes, unticked, select all and none, a live count, a button that
names the action and the number, arrow keys, and focus kept across redraws.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```

---
### Task 6: Desktop: the main process allows only entry ids the scan offered

**Files:**
- Modify: `desktop/mark-policy.js` (whole file replaced below)
- Modify: `desktop/engine-runner.js` (`scanArgs`; `markArgs`; new `entryMarkArgs`)
- Create: `desktop/test/mark-entries.test.js`

**Interfaces:**
- Consumes: the scan document's `markable.items` (Task 2 shape: `{key, label, detail, id: string|null, marked?: true, stale?: true}`) and `data.marked_items` (`[{id, entry, shown, marked_at}]`).
- Produces (used by Task 8's `main.js`):
  - `createMarkPolicy()` now also has `itemsFor(id: string, itemIds: string[]) -> string[] | null` (the validated, de-duplicated ids, or null).
  - `handleMark(id, { policy, runMark }, itemIds?)`: with `itemIds`, `runMark` receives `{ kind, id, code, group, marks: [{ code, id }], chosen: string[] }`.
  - `handleUnmark(idOrIds: string | string[], { policy, runUnmark })`: every id must be allowed; `runUnmark` receives the de-duplicated list.
  - `markArgs(target)` with `target.chosen`: `['known', 'add', '--code', C, '--expect-id', ID, '--item', I1, ..., '--json', '--i-understand']`.
  - `scanArgs(profile)` accepts `null`, a name, or an array of 1 to 8 names: one `--profile` per distinct name, in order.

- [ ] **Step 1: Write the failing tests**

Create `desktop/test/mark-entries.test.js`:

```js
// "It's mine" for some entries of one list: the main process sends the engine
// only entry ids its own last scan offered on that finding, never names.
const test = require('node:test');
const assert = require('node:assert');
const { createMarkPolicy, handleMark, handleUnmark } = require('../mark-policy');
const { markArgs, scanArgs } = require('../engine-runner');

const LIST = 'aaaaaaaaaaaa';
const OTHER_LIST = 'bbbbbbbbbbbb';
const E1 = '111111111111';
const E2 = '222222222222';
const E3 = '333333333333';
const DONE = '444444444444';
const ACC = 'security.app_permissions.accessibility_access';

const listMarkable = (id = LIST, items = [
  { key: 'com.example.one', label: 'One', detail: 'com.example.one', id: E1, monitoring: true },
  { key: 'com.example.two', label: 'Two', detail: 'com.example.two', id: E2, monitoring: true },
  { key: 'com.example.gone', label: 'Gone', detail: 'com.example.gone', id: null, monitoring: true },
  { key: 'com.example.done', label: 'Done', detail: 'com.example.done', id: DONE, marked: true, monitoring: true },
]) => ({
  kind: 'app_permissions', id, code: ACC, group: '0123456789ab', monitoring: true,
  shows: [['Apps', 'One, Two'], ['How many', String(items.length)]], items,
  will_change: 'w', how_to_undo: ['u'],
});

const scan = (...findings) => ({ modules: [{ name: 'app_permissions', findings }] });

test('only ids the scan offered on that finding, each once, can be sent', async () => {
  const policy = createMarkPolicy();
  policy.remember(scan({ title: 'x', markable: listMarkable() }));
  assert.deepStrictEqual(policy.itemsFor(LIST, [E1, E2]), [E1, E2]);
  assert.strictEqual(policy.itemsFor(LIST, [E3]), null, 'a forged id');
  assert.strictEqual(policy.itemsFor(LIST, [E1, E1]), null, 'a repeat');
  assert.strictEqual(policy.itemsFor(LIST, []), null);
  assert.strictEqual(policy.itemsFor(LIST, [DONE]), null, 'already marked');
  assert.strictEqual(policy.itemsFor(LIST, ['"><x']), null);
  assert.strictEqual(policy.itemsFor(LIST, 'x'), null);
  assert.strictEqual(policy.itemsFor(OTHER_LIST, [E1]), null, 'another finding');
  assert.strictEqual(policy.itemsFor(LIST, Array.from({ length: 61 }, () => E1)), null);
});

test('handleMark with items sends only this finding, never the other checks', async () => {
  const policy = createMarkPolicy();
  policy.remember(scan({ title: 'x', markable: { ...listMarkable(), ids: [LIST, OTHER_LIST] } },
    { title: 'y', markable: { ...listMarkable(OTHER_LIST), code: 'security.privacy_permissions_audit.excessive_camera', ids: [LIST, OTHER_LIST] } }));
  let got;
  const result = await handleMark(LIST, { policy, runMark: async (t) => { got = t; return { status: 'marked', ids: [E2] }; } }, [E2]);
  assert.strictEqual(result.status, 'marked');
  assert.deepStrictEqual(got.chosen, [E2]);
  assert.deepStrictEqual(got.marks, [{ code: ACC, id: LIST }]);
  assert.deepStrictEqual(markArgs(got), ['known', 'add', '--code', ACC, '--expect-id', LIST, '--item', E2, '--json', '--i-understand']);
});

test('a forged item id over IPC is refused and nothing runs', async () => {
  const policy = createMarkPolicy();
  policy.remember(scan({ title: 'x', markable: listMarkable() }));
  let ran = false;
  const result = await handleMark(LIST, { policy, runMark: async () => { ran = true; return {}; } }, [E1, E3]);
  assert.strictEqual(result.status, 'refused');
  assert.strictEqual(ran, false);
});

test('entries saved now, and entries marked on the scan, can be unmarked one by one', async () => {
  const policy = createMarkPolicy();
  policy.remember(scan({ title: 'x', markable: listMarkable(), data: { marked_items: [{ id: DONE, entry: 'com.example.done', shown: 'Done' }] } }));
  assert.ok(policy.isUnmarkAllowed(DONE));
  assert.deepStrictEqual(policy.unmarkIdsFor(DONE), [DONE]);
  assert.ok(!policy.isUnmarkAllowed(E1));
  await handleMark(LIST, { policy, runMark: async () => ({ status: 'marked', ids: [E1, E3] }) }, [E1]);
  assert.ok(policy.isUnmarkAllowed(E1));
  assert.ok(!policy.isUnmarkAllowed(E3), 'only ids that were asked for');
  let sent;
  const r = await handleUnmark([E1, DONE, E1], { policy, runUnmark: async (ids) => { sent = ids; return { status: 'removed', ids } } });
  assert.strictEqual(r.status, 'removed');
  assert.deepStrictEqual(sent, [E1, DONE]);
  const refused = await handleUnmark([E1, E3], { policy, runUnmark: async () => { throw new Error('must not run'); } });
  assert.strictEqual(refused.status, 'refused');
});

test('a fully marked list from the scan can be unmarked all at once', async () => {
  const policy = createMarkPolicy();
  policy.remember(scan({ title: 'x', data: { marked_by_user: true, marked_items: [{ id: E1, entry: 'a', shown: 'a' }, { id: E2, entry: 'b', shown: 'b' }] } }));
  let sent;
  await handleUnmark([E1, E2], { policy, runUnmark: async (ids) => { sent = ids; return { status: 'removed' }; } });
  assert.deepStrictEqual(sent, [E1, E2]);
});

test('the monitoring-software checks never offer entries', () => {
  const policy = createMarkPolicy();
  policy.remember({ modules: [{ name: 'stalkerware_scan', findings: [{ markable: listMarkable(), data: { marked_items: [{ id: DONE }] } }] }] });
  assert.strictEqual(policy.itemsFor(LIST, [E1]), null);
  assert.ok(!policy.isUnmarkAllowed(DONE));
});

test('entry argv is checked again where it is built', () => {
  const t = { kind: 'app_permissions', id: LIST, code: ACC, chosen: [E1] };
  assert.deepStrictEqual(markArgs(t), ['known', 'add', '--code', ACC, '--expect-id', LIST, '--item', E1, '--json', '--i-understand']);
  assert.throws(() => markArgs({ ...t, kind: 'sharing_service' }));
  assert.throws(() => markArgs({ ...t, chosen: [] }));
  assert.throws(() => markArgs({ ...t, chosen: [E1, E1] }));
  assert.throws(() => markArgs({ ...t, chosen: ['--json'] }));
  assert.throws(() => markArgs({ ...t, chosen: [LIST] }));
  assert.throws(() => markArgs({ ...t, code: 'security.stalkerware_scan.x' }));
});

test('scanArgs takes one profile or several, and refuses anything else', () => {
  assert.deepStrictEqual(scanArgs(null), ['scan', '--json']);
  assert.deepStrictEqual(scanArgs('digital_security_reset'), ['scan', '--json', '--profile', 'digital_security_reset']);
  assert.deepStrictEqual(scanArgs(['digital_security_reset', 'home_network_intrusion', 'digital_security_reset']),
    ['scan', '--json', '--profile', 'digital_security_reset', '--profile', 'home_network_intrusion']);
  assert.throws(() => scanArgs([]));
  assert.throws(() => scanArgs(['ok_name', '--yes']));
  assert.throws(() => scanArgs(Array.from({ length: 9 }, (_, i) => `p${i}`)));
  assert.throws(() => scanArgs([null]));
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd desktop && node --test test/mark-entries.test.js`
Expected: FAIL with `TypeError: policy.itemsFor is not a function` and the `scanArgs` array cases throwing `invalid profile name`.

- [ ] **Step 3: Replace `desktop/mark-policy.js`**

Replace the whole file with:

```js
// Gatekeeping for "It's mine" (mark-mine / unmark-mine IPC channels).
//
// The engine says which findings may be marked, as a `markable` block on each
// one. For a background task that is {kind, id, code, label, program, plist,
// arguments_sha256}; for a setting or installed item (a sharing service, a
// proxy, an extension...) it is {kind, id, code, group}. The id is the
// engine's hash over everything the mark pins.
//
// The renderer sends ONLY that id. The main process looks up the target it
// stored from the scan it ran itself and passes that to the engine, so the
// renderer can never confirm one thing and have another written. The engine
// then re-reads the item from disk (or runs the check again) and refuses
// unless it still hashes to the same id (--expect-id), so something that
// changed after the checkup is never marked. Everything goes to the engine
// as argv, never through a shell.
//
// One item reported by several checks is marked as one: the stored target
// carries every {code, id} the scan offered for that same item, the engine
// re-checks each id and saves all of them or none. "Stop treating this as
// mine" likewise removes every mark the scan showed for that item, or that
// this app saved since.
//
// Some entries of one list (apps on one permission list, keys in one file):
// the renderer sends the finding's id and the ticked entry ids. Each entry id
// must be one this same scan offered on that same finding, not already
// marked, each once. Only that finding's own {code, id} goes to the engine:
// never the other checks' lists. Each entry mark can be removed on its own.

const MARK_ID = /^[0-9a-f]{12}$/;
const CODE = /^[a-z0-9_]+\.[a-z0-9_]+\.[a-z0-9_]+$/;
const SHA256 = /^[0-9a-f]{64}$/;
const BACKGROUND_TASK = 'background_task';
// Settings and installed items (rescue/known_items.py ITEM_KINDS).
const ITEM_KINDS = new Set([
  'sharing_service', 'network_proxy', 'system_extension', 'browser_extension',
  'app_permissions', 'ssh_authorized_keys', 'ai_tooling',
]);
// Lists that can be marked entry by entry (rescue/known_items.py ENTRY_KIND_FOR).
const ENTRY_LIST_KINDS = new Set(['app_permissions', 'ssh_authorized_keys']);
// rescue/known_items.py MAX_LIST_ENTRIES.
const MAX_ENTRIES = 60;
// Checks for monitoring software: never markable, whatever the engine says.
const NEVER_MARKABLE_MODULES = new Set(['stalkerware_scan', 'mvt_spyware_scan', 'keylogger_indicators']);

function isCleanString(s, max = 1024) {
  return typeof s === 'string' && s.length > 0 && s.length < max && !s.includes('\0');
}

function moduleOfCode(code) {
  return String(code).split('.')[1];
}

// The validated target from a markable block, or null.
function markTarget(markable) {
  const m = markable;
  if (!m || typeof m !== 'object') return null;
  if (typeof m.id !== 'string' || !MARK_ID.test(m.id)) return null;
  if (typeof m.code !== 'string' || !CODE.test(m.code)) return null;
  if (NEVER_MARKABLE_MODULES.has(moduleOfCode(m.code))) return null;
  if (ITEM_KINDS.has(m.kind)) {
    if (typeof m.group !== 'string' || !MARK_ID.test(m.group)) return null;
    return { kind: m.kind, id: m.id, code: m.code, group: m.group };
  }
  if (m.kind !== BACKGROUND_TASK) return null;
  if (typeof m.arguments_sha256 !== 'string' || !SHA256.test(m.arguments_sha256)) return null;
  if (!isCleanString(m.label, 256) || m.label.startsWith('-')) return null;
  if (!isCleanString(m.program) || !(m.program.startsWith('/') || m.program.startsWith('~'))) return null;
  if (!isCleanString(m.plist) || !m.plist.startsWith('/')) return null;
  return { kind: m.kind, id: m.id, code: m.code, label: m.label, program: m.program, plist: m.plist };
}

function isValidMarkId(id) {
  return typeof id === 'string' && MARK_ID.test(id);
}

// What makes two findings "the same item". Two offers group only if every
// one of these matches; the engine's `ids` list is never trusted on its own.
function itemKey(m) {
  if (ITEM_KINDS.has(m.kind)) return JSON.stringify([m.kind, m.group]);
  return JSON.stringify([m.kind, m.label, m.plist, m.program, m.arguments_sha256,
    typeof m.content_sha256 === 'string' ? m.content_sha256 : '']);
}

function markedKey(data) {
  if (ITEM_KINDS.has(data.marked_kind) && isValidMarkId(data.marked_key)) {
    return JSON.stringify([data.marked_kind, data.marked_key]);
  }
  return JSON.stringify([data.label, data.plist, data.program, data.arguments_sha256]);
}

function idList(value) {
  return Array.isArray(value) ? value.filter(isValidMarkId) : [];
}

// Entry ids a list finding offers to mark now (not already marked).
function offeredEntryIds(m) {
  if (!m || !ENTRY_LIST_KINDS.has(m.kind) || !Array.isArray(m.items) || m.items.length > MAX_ENTRIES) return [];
  return [...new Set(m.items.filter((i) => i && i.marked !== true && isValidMarkId(i.id)).map((i) => i.id))];
}

// Entry marks the scan shows on a finding: in data.marked_items, or as marked rows.
function markedEntryIds(f) {
  const out = [];
  const d = f && f.data;
  if (d && Array.isArray(d.marked_items)) {
    for (const m of d.marked_items) if (m && isValidMarkId(m.id)) out.push(m.id);
  }
  const items = f && f.markable && Array.isArray(f.markable.items) ? f.markable.items : [];
  for (const i of items) if (i && i.marked === true && isValidMarkId(i.id)) out.push(i.id);
  return out;
}

function createMarkPolicy() {
  let markable = new Map(); // id -> target, from the last scan only
  let marked = new Map(); // id -> every marked id for the same item, from the last scan (or saved since)
  let entryMarked = new Set(); // entry mark ids from the last scan, or saved since
  return {
    // Replace (not merge) with what the latest scan offered.
    //
    // One item is often reported by more than one check, each with its own
    // mark id. The engine lists them together (markable.ids); a sibling is
    // kept only if this same scan offered it as markable for the same item,
    // so one confirmation can never reach a different item.
    remember(doc) {
      const offered = new Map(); // id -> { target, key, ids, entries }
      const markedSeen = new Map(); // id -> { key, ids }
      const entriesSeen = new Set();
      const modules = doc && Array.isArray(doc.modules) ? doc.modules : [];
      for (const mod of modules) {
        if (!mod || !Array.isArray(mod.findings)) continue;
        if (NEVER_MARKABLE_MODULES.has(mod.name)) continue;
        for (const f of mod.findings) {
          const t = f && markTarget(f.markable);
          if (t && !offered.has(t.id)) {
            offered.set(t.id, { target: t, key: itemKey(f.markable), ids: idList(f.markable.ids), entries: offeredEntryIds(f.markable) });
          }
          const data = f && f.data;
          if (data && data.marked_by_user === true && isValidMarkId(data.known_item_id) && !markedSeen.has(data.known_item_id)) {
            markedSeen.set(data.known_item_id, { key: markedKey(data), ids: idList(f.marked_ids) });
          }
          for (const id of markedEntryIds(f)) entriesSeen.add(id);
        }
      }
      const nextMarkable = new Map();
      for (const [id, o] of offered) {
        const group = [id, ...o.ids.filter((other) => other !== id
          && offered.has(other) && offered.get(other).key === o.key)];
        const marks = [...new Set(group)]
          .map((gid) => ({ code: offered.get(gid).target.code, id: gid }))
          .sort((a, b) => (a.code < b.code ? -1 : a.code > b.code ? 1 : 0));
        // Two ids for one code would mean two different items: keep only this one.
        const codes = new Set(marks.map((m) => m.code));
        nextMarkable.set(id, {
          ...o.target,
          marks: codes.size === marks.length ? marks : [{ code: o.target.code, id }],
          ...(o.entries.length ? { items: o.entries } : {}),
        });
      }
      const nextMarked = new Map();
      for (const [id, m] of markedSeen) {
        const group = [id, ...m.ids.filter((other) => other !== id
          && markedSeen.has(other) && markedSeen.get(other).key === m.key)];
        nextMarked.set(id, [...new Set(group)].sort());
      }
      markable = nextMarkable;
      marked = nextMarked;
      entryMarked = entriesSeen;
    },
    // The stored target for an id the last scan offered, or null. Its `marks`
    // are every {code, id} the same item was offered under in that scan.
    targetFor(id) {
      return isValidMarkId(id) && markable.has(id) ? markable.get(id) : null;
    },
    // The entry ids to send for this finding, or null: each one this scan
    // offered on this finding, not already marked, each once.
    itemsFor(id, itemIds) {
      const t = this.targetFor(id);
      if (!t || !Array.isArray(t.items) || !Array.isArray(itemIds)) return null;
      if (!itemIds.length || itemIds.length > MAX_ENTRIES) return null;
      if (new Set(itemIds).size !== itemIds.length) return null;
      if (!itemIds.every((x) => isValidMarkId(x) && t.items.includes(x))) return null;
      return [...itemIds];
    },
    // After the engine saved marks for `target`: those ids may be unmarked
    // ("Undo") in this session. Only ids this target asked for count.
    rememberMarked(target, result) {
      if (!target || !result || (result.status !== 'marked' && result.status !== 'already_marked')) return;
      if (Array.isArray(target.chosen)) {
        const saved = Array.isArray(result.ids) ? result.ids.filter((x) => isValidMarkId(x) && target.chosen.includes(x)) : [];
        for (const id of saved) entryMarked.add(id);
        return;
      }
      const asked = new Set((target.marks || [{ id: target.id }]).map((m) => m.id));
      const saved = Array.isArray(result.ids) ? result.ids.filter((x) => isValidMarkId(x) && asked.has(x)) : [];
      const ids = saved.length ? saved : (isValidMarkId(result.id) && asked.has(result.id) ? [result.id] : []);
      const group = [...new Set(ids)].sort();
      for (const id of group) marked.set(id, group);
    },
    isUnmarkAllowed(id) {
      return isValidMarkId(id) && (marked.has(id) || entryMarked.has(id));
    },
    // Every marked id for the same item as `id` ([] if none). An entry mark is its own.
    unmarkIdsFor(id) {
      if (!isValidMarkId(id)) return [];
      if (marked.has(id)) return [...marked.get(id)];
      return entryMarked.has(id) ? [id] : [];
    },
  };
}

function refusal(error, message) {
  return { status: 'refused', error, message, id: null, label: null, how_to_undo: [] };
}

// Pure handler behind ipcMain.handle('mark-mine'). Takes only ids. Never throws.
// With itemIds: some entries of this one list finding.
async function handleMark(id, { policy, runMark }, itemIds) {
  const target = policy.targetFor(id);
  if (!target) {
    return refusal('not_allowed', 'This item can’t be marked from the app. Nothing was changed.');
  }
  let run = target;
  if (itemIds !== undefined && itemIds !== null) {
    const chosen = typeof policy.itemsFor === 'function' ? policy.itemsFor(id, itemIds) : null;
    if (!chosen) {
      return refusal('not_allowed', 'Those can’t be marked from the app. Nothing was changed.');
    }
    // One finding only: never the other checks' marks for a similar list.
    run = { kind: target.kind, id: target.id, code: target.code, group: target.group,
      marks: [{ code: target.code, id: target.id }], chosen };
  }
  try {
    const result = await runMark(run);
    if (typeof policy.rememberMarked === 'function') policy.rememberMarked(run, result);
    return result;
  } catch (err) {
    return refusal('engine_error', `We could not save that: ${err && err.message ? err.message : err}`);
  }
}

// Pure handler behind ipcMain.handle('unmark-mine'). One id or several. Never throws.
async function handleUnmark(idOrIds, { policy, runUnmark }) {
  const asked = Array.isArray(idOrIds) ? idOrIds : [idOrIds];
  if (!asked.length || asked.length > MAX_ENTRIES || !asked.every((x) => policy.isUnmarkAllowed(x))) {
    return refusal('not_allowed', 'That item isn’t marked as yours in this checkup. Nothing was changed.');
  }
  try {
    // Every mark for the same item, so all of its warnings come back.
    const ids = [...new Set(asked.flatMap((x) => (typeof policy.unmarkIdsFor === 'function' ? policy.unmarkIdsFor(x) : [x])))];
    return await runUnmark(ids.length ? ids : [...new Set(asked)]);
  } catch (err) {
    return refusal('engine_error', `We could not save that: ${err && err.message ? err.message : err}`);
  }
}

module.exports = {
  createMarkPolicy, handleMark, handleUnmark, markTarget, isValidMarkId, ITEM_KINDS, ENTRY_LIST_KINDS,
  NEVER_MARKABLE_MODULES,
};
```

- [ ] **Step 4: Build `--item` argv and several `--profile` flags in `desktop/engine-runner.js`**

Replace `scanArgs`:

```js
function scanArgs(profile) {
  const args = ['scan', '--json'];
  if (profile == null) return args;
  if (typeof profile !== 'string' || !PROFILE_NAME.test(profile)) {
    throw new Error(`invalid profile name: ${profile}`);
  }
  return args.concat(['--profile', profile]);
}
```

with:

```js
// Several worries run the union of their profiles: one --profile each.
const MAX_PROFILES = 8;

function scanArgs(profile) {
  const args = ['scan', '--json'];
  if (profile == null) return args;
  const names = Array.isArray(profile) ? profile : [profile];
  if (names.length === 0 || names.length > MAX_PROFILES) throw new Error('invalid profile list');
  for (const name of names) {
    if (typeof name !== 'string' || !PROFILE_NAME.test(name)) {
      throw new Error(`invalid profile name: ${name}`);
    }
  }
  return args.concat(...[...new Set(names)].map((name) => ['--profile', name]));
}
```

Directly above `function markArgs(target) {`, add:

```js
// Lists that can be marked entry by entry, and how many entries at most
// (rescue/known_items.py ENTRY_KIND_FOR and MAX_LIST_ENTRIES).
const ENTRY_LIST_KINDS = new Set(['app_permissions', 'ssh_authorized_keys']);
const MAX_ENTRIES = 60;

// Some entries of one list: the list's own code and id, then one --item each.
function entryMarkArgs(t) {
  if (!ENTRY_LIST_KINDS.has(t.kind)) throw new Error('not a list');
  if (typeof t.code !== 'string' || !MARK_CODE.test(t.code)) throw new Error('invalid code');
  if (NEVER_MARKABLE_MODULES.has(t.code.split('.')[1])) throw new Error('not markable');
  if (typeof t.id !== 'string' || !MARK_ID.test(t.id)) throw new Error('invalid id');
  const chosen = Array.isArray(t.chosen) ? t.chosen : [];
  if (!chosen.length || chosen.length > MAX_ENTRIES) throw new Error('invalid items');
  if (new Set(chosen).size !== chosen.length) throw new Error('invalid items');
  if (!chosen.every((x) => typeof x === 'string' && MARK_ID.test(x)) || chosen.includes(t.id)) throw new Error('invalid items');
  // The person confirmed in the app. The engine runs the check again and
  // saves none of them unless every entry is still there, unchanged.
  return ['known', 'add', '--code', t.code, '--expect-id', t.id,
    ...chosen.flatMap((x) => ['--item', x]), '--json', '--i-understand'];
}
```

In `markArgs`, replace its first two lines

```js
function markArgs(target) {
  const t = target || {};
```

with

```js
function markArgs(target) {
  const t = target || {};
  if (t.chosen !== undefined) return entryMarkArgs(t);
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd desktop && node --test test/mark-entries.test.js test/mark-items.test.js test/mark-policy.test.js test/situations.test.js test/engine-runner.test.js`
Expected: PASS (all).

- [ ] **Step 6: Run the whole desktop suite**

Run: `cd desktop && npm test`
Expected: PASS (all).

- [ ] **Step 7: Commit**

```bash
git add desktop/mark-policy.js desktop/engine-runner.js desktop/test/mark-entries.test.js
git commit -m "$(cat <<'EOF'
Desktop: allow only list entries the scan offered; several profiles per scan

The main process checks each ticked entry id against its own last scan,
sends only that finding's code and id with one --item each, and lets each
entry mark be removed on its own.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```

---
### Task 7: Desktop: several worries as one situation, and the game helpers that read it

**Files:**
- Create: `desktop/renderer/worries.js`
- Modify: `desktop/renderer/game/training.js` (`orderLessons`; new export `worryIdsOf`)
- Modify: `desktop/renderer/game/one-city.js` (`focusFor`)
- Create: `desktop/test/worries.test.js`

**Interfaces:**
- Consumes: `SITUATIONS` from `desktop/renderer/app.js` (each `{ id, icon, title, sub, profile, guide, safety? }`).
- Produces (global `Worries` in the page; `module.exports` for Node):
  - `Worries.CHECKLIST_IDS = ['hacked', 'watched', 'wifi', 'identity', 'sketchy', 'helping']`, `Worries.ON_THEIR_OWN = ['unsure', 'phone']`
  - `Worries.combine(ids: string[], situations) -> situation | null`. One id: a frozen copy of that entry plus `ids: [id]`. Several (all from `CHECKLIST_IDS`): `{ id: 'several', ids, icon: '', sub: '', title, profiles, profile, guide, guides, safety }`. Any id from `ON_THEIR_OWN` mixed with others, or nothing known, gives `null`.
  - `Worries.idsOf(situation) -> string[]`, `Worries.has(situation, id) -> boolean`, `Worries.key(situation) -> string`, `Worries.firstWith(situation, table) -> any`, `Worries.scanProfile(situation) -> null | string | string[]` (a string when exactly one distinct profile, as today).
  - `training.js`: `orderLessons(lessons, worry)` and `lessonsByDistrict(lessons, worry)` accept one id or an array of ids; new `worryIdsOf(situation) -> string[]`.
  - `one-city.js`: `focusFor(situation)` uses the first of `situation.ids` (in `SITUATIONS` order) that has a focus district.

- [ ] **Step 1: Write the failing tests**

Create `desktop/test/worries.test.js`:

```js
// Several worries at once: one situation the rest of the app can read. The
// checkup runs the union of their profiles; "watching me" among them counts.
const test = require('node:test');
const assert = require('node:assert');
const Worries = require('../renderer/worries.js');
const { SITUATIONS } = require('../renderer/app.js');

const profileOf = (id) => SITUATIONS.find((s) => s.id === id).profile;

test('every worry is either in the checklist or runs on its own', () => {
  const all = [...Worries.CHECKLIST_IDS, ...Worries.ON_THEIR_OWN].sort();
  assert.deepStrictEqual(all, SITUATIONS.map((s) => s.id).sort());
});

test('one worry is that worry, with its ids', () => {
  const s = Worries.combine(['wifi'], SITUATIONS);
  assert.strictEqual(s.id, 'wifi');
  assert.deepStrictEqual(s.ids, ['wifi']);
  assert.strictEqual(Worries.scanProfile(s), profileOf('wifi'));
  assert.ok(Object.isFrozen(s));
  assert.strictEqual(Worries.combine(['phone'], SITUATIONS).id, 'phone');
  assert.strictEqual(Worries.scanProfile(Worries.combine(['unsure'], SITUATIONS)), null);
});

test('several worries run the union of their profiles, in the list order', () => {
  const s = Worries.combine(['wifi', 'hacked'], SITUATIONS);
  assert.strictEqual(s.id, 'several');
  assert.deepStrictEqual(s.ids, ['hacked', 'wifi']);
  assert.deepStrictEqual(Worries.scanProfile(s), [profileOf('hacked'), profileOf('wifi')]);
  assert.strictEqual(s.title, `${SITUATIONS[0].title} and ${SITUATIONS.find((x) => x.id === 'wifi').title}`);
  assert.strictEqual(s.guide, SITUATIONS[0].guide);
  assert.strictEqual(s.safety, false);
});

test('two worries with the same profile run it once', () => {
  const s = Worries.combine(['hacked', 'watched'], SITUATIONS);
  assert.strictEqual(Worries.scanProfile(s), 'digital_security_reset');
  assert.strictEqual(s.safety, true, '"watching me" among several still counts');
  assert.ok(Worries.has(s, 'watched'));
});

test('"check everything" and the iPhone check never mix with others', () => {
  assert.strictEqual(Worries.combine(['hacked', 'unsure'], SITUATIONS), null);
  assert.strictEqual(Worries.combine(['phone', 'wifi'], SITUATIONS), null);
  assert.strictEqual(Worries.combine([], SITUATIONS), null);
  assert.strictEqual(Worries.combine(['nope'], SITUATIONS), null);
  assert.strictEqual(Worries.combine(['nope', 'wifi'], SITUATIONS).id, 'wifi');
});

test('helpers read a single entry, a combined one, or nothing', () => {
  const one = SITUATIONS.find((s) => s.id === 'identity');
  assert.deepStrictEqual(Worries.idsOf(one), ['identity']);
  assert.deepStrictEqual(Worries.idsOf(null), []);
  assert.ok(!Worries.has(null, 'watched'));
  const two = Worries.combine(['identity', 'hacked'], SITUATIONS);
  assert.strictEqual(Worries.key(two), Worries.key(Worries.combine(['hacked', 'identity'], SITUATIONS)));
  assert.notStrictEqual(Worries.key(two), Worries.key(one));
  assert.strictEqual(Worries.firstWith(two, { identity: 'I', hacked: 'H' }), 'H');
  assert.strictEqual(Worries.firstWith(two, { wifi: 'W' }), undefined);
  assert.strictEqual(Worries.scanProfile(null), null);
});

test('the game recommends lessons for any of the worries', async () => {
  const { orderLessons, worryIdsOf } = await import('../renderer/game/training.js');
  const L = (id, recommendedFor = []) => ({ id, title: id, recommendedFor, modules: [], questions: [] });
  const lessons = [L('password-asker'), L('a', ['wifi']), L('b', ['identity']), L('c', [])];
  const both = orderLessons(lessons, ['wifi', 'identity']);
  assert.deepStrictEqual(both.recommended.map((l) => l.id), ['password-asker', 'a', 'b']);
  assert.deepStrictEqual(both.other.map((l) => l.id), ['c']);
  assert.deepStrictEqual(orderLessons(lessons, 'wifi').recommended.map((l) => l.id), ['password-asker', 'a']);
  assert.deepStrictEqual(worryIdsOf({ id: 'several', ids: ['hacked', 'wifi'] }), ['hacked', 'wifi']);
  assert.deepStrictEqual(worryIdsOf({ id: 'wifi' }), ['wifi']);
  assert.deepStrictEqual(worryIdsOf(null), []);
});

test('the game\'s starting district follows the first worry that has one', async () => {
  const { focusFor } = await import('../renderer/game/one-city.js');
  assert.strictEqual(focusFor({ id: 'several', ids: ['wifi', 'identity'] }), 'reclamation');
  assert.strictEqual(focusFor({ id: 'several', ids: ['hacked', 'identity'] }), 'master-keys');
  assert.strictEqual(focusFor({ id: 'several', ids: ['wifi', 'sketchy'] }), 'computer');
  assert.strictEqual(focusFor({ id: 'hacked' }), 'master-keys');
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd desktop && node --test test/worries.test.js`
Expected: FAIL with `Cannot find module '../renderer/worries.js'`.

- [ ] **Step 3: Write `desktop/renderer/worries.js`**

```js
'use strict';

/*
 * The worry screen is a checklist: the person ticks everything that sounds
 * close, and the checkup runs every check any of those worries would run.
 * This turns the ticked worries into one situation object, shaped like a
 * SITUATIONS entry, so the rest of the app and the game read it as before.
 * "Check everything" and the iPhone check run on their own: the first
 * already covers every worry, and the second reads a large phone backup.
 *
 * Nothing here is stored. Loaded as a plain script (global `Worries`) and
 * required from Node by the tests.
 */
const Worries = (function () {
  const CHECKLIST_IDS = Object.freeze(['hacked', 'watched', 'wifi', 'identity', 'sketchy', 'helping']);
  const ON_THEIR_OWN = Object.freeze(['unsure', 'phone']);

  function idsOf(situation) {
    if (!situation) return [];
    if (Array.isArray(situation.ids)) return situation.ids.filter((x) => typeof x === 'string');
    return typeof situation.id === 'string' ? [situation.id] : [];
  }

  function has(situation, id) {
    return idsOf(situation).includes(id);
  }

  // The same worries in any order are the same checkup.
  function key(situation) {
    return [...idsOf(situation)].sort().join('+');
  }

  // The value for the first worry (in the list's order) that has one in `table`.
  function firstWith(situation, table) {
    for (const id of idsOf(situation)) {
      if (table && Object.prototype.hasOwnProperty.call(table, id)) return table[id];
    }
    return undefined;
  }

  function joinTitles(titles) {
    if (titles.length < 2) return titles[0] || '';
    return `${titles.slice(0, -1).join(', ')} and ${titles[titles.length - 1]}`;
  }

  function combine(ids, situations) {
    const list = Array.isArray(situations) ? situations : [];
    const wanted = new Set(Array.isArray(ids) ? ids : []);
    const picked = list.filter((s) => s && wanted.has(s.id));
    if (!picked.length) return null;
    if (picked.length === 1) {
      const s = picked[0];
      return Object.freeze({ ...s, ids: [s.id], profiles: s.profile ? [s.profile] : [] });
    }
    if (picked.some((s) => ON_THEIR_OWN.includes(s.id))) return null;
    const profiles = [...new Set(picked.map((s) => s.profile).filter((p) => typeof p === 'string' && p))];
    return Object.freeze({
      id: 'several',
      ids: picked.map((s) => s.id),
      icon: '',
      sub: '',
      title: joinTitles(picked.map((s) => s.title)),
      profiles,
      profile: profiles[0] || null,
      guide: picked[0].guide,
      guides: [...new Set(picked.map((s) => s.guide))],
      safety: picked.some((s) => !!s.safety),
    });
  }

  // What runScan takes: null (every check), one profile name, or several.
  function scanProfile(situation) {
    if (!situation) return null;
    const profiles = Array.isArray(situation.profiles)
      ? situation.profiles
      : (situation.profile ? [situation.profile] : []);
    if (!profiles.length) return null;
    return profiles.length === 1 ? profiles[0] : [...profiles];
  }

  return { CHECKLIST_IDS, ON_THEIR_OWN, idsOf, has, key, firstWith, combine, scanProfile };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = Worries;
}
```

- [ ] **Step 4: Let the game helpers take several worries**

In `desktop/renderer/game/training.js`, replace:

```js
export function orderLessons(lessons, worryId) {
  const list = Array.isArray(lessons) ? lessons : [];
  const first = list.filter((l) => l.id === FIRST_LESSON);
  const rest = list.filter((l) => l.id !== FIRST_LESSON);
  const fits = (l) => (l.recommendedFor || []).includes(worryId);
  return { recommended: [...first, ...rest.filter(fits)], other: rest.filter((l) => !fits(l)) };
}
```

with:

```js
// The worries a situation stands for: one SITUATIONS entry, or several picked together.
export function worryIdsOf(situation) {
  if (!situation) return [];
  if (Array.isArray(situation.ids)) return situation.ids.filter((x) => typeof x === 'string');
  return typeof situation.id === 'string' ? [situation.id] : [];
}

// `worry`: one worry id, or a list of them; a lesson fits if it is recommended for any.
export function orderLessons(lessons, worry) {
  const list = Array.isArray(lessons) ? lessons : [];
  const worries = Array.isArray(worry) ? worry : [worry];
  const first = list.filter((l) => l.id === FIRST_LESSON);
  const rest = list.filter((l) => l.id !== FIRST_LESSON);
  const fits = (l) => (l.recommendedFor || []).some((w) => worries.includes(w));
  return { recommended: [...first, ...rest.filter(fits)], other: rest.filter((l) => !fits(l)) };
}
```

(`lessonsByDistrict(lessons, worryId)` passes its second argument straight to `orderLessons`, so it accepts a list too without a change.)

In `desktop/renderer/game/one-city.js`, replace:

```js
export function focusFor(situation) {
  return (situation && FOCUS[situation.id]) || 'computer';
}
```

with:

```js
// Several worries: the first one (in the worry list's order) that has a district.
export function focusFor(situation) {
  if (!situation) return 'computer';
  const ids = Array.isArray(situation.ids) ? situation.ids : [situation.id];
  for (const id of ids) if (FOCUS[id]) return FOCUS[id];
  return 'computer';
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd desktop && node --test test/worries.test.js test/game-training.test.js test/game-one-city.test.js test/game-lessons.test.js`
Expected: PASS (all).

- [ ] **Step 6: Run the whole desktop suite**

Run: `cd desktop && npm test`
Expected: PASS (all).

- [ ] **Step 7: Commit**

```bash
git add desktop/renderer/worries.js desktop/renderer/game/training.js desktop/renderer/game/one-city.js desktop/test/worries.test.js
git commit -m "$(cat <<'EOF'
Desktop: several worries as one situation; game lessons and focus read all

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```

---
### Task 8: Desktop: the checklist in the "It's mine" panel for list findings

**Waits for `reclaim-city` to land on main** (it edits `app.js`, `index.html` and `game/controller.js`, and the person running `reclaim-city` named `mark-flow.js` as in flight). Re-read each "replace" block against main first.

**Files:**
- Modify: `desktop/renderer/mark-flow.js` (constants; `showsHtml`; new entry helpers; `markControlsHtml`; new `itemsResultHtml`; `CLICK_TARGETS` and `attach`; the returned object)
- Modify: `desktop/preload.js` (`markMine`, `unmarkMine`)
- Modify: `desktop/main.js` (the `mark-mine` and `unmark-mine` handlers)
- Modify: `desktop/renderer/index.html` (stylesheet and script tags)
- Modify: `desktop/renderer/game/controller.js` (shadow root stylesheet; `markControlsHtml` calls)
- Modify: `desktop/renderer/app.js` (`renderResults`: keep focus across the redraw)
- Create: `desktop/test/mark-entries-flow.test.js`

**Interfaces:**
- Consumes: `Checklist.html`, `Checklist.attach`, `Checklist.preserveFocus` (Task 5); `markable.items`, `markable.items_will_change`, `data.marked_items` (Task 2); `handleMark(id, deps, itemIds)` and `handleUnmark(idOrIds, deps)` (Task 6).
- Produces:
  - `MarkFlow.markControlsHtml(finding, { watched?, theme? })`: for a list finding whose `items` line up with its rows, a card `[data-mark-card][data-mark-entries]` with an "Already marked as yours" list, a "Some of these … are mine" button, a checklist (`data-cl-list="mark-<id>"`), a confirmation block, and a list of just-marked rows. A fully entry-marked finding gets `[data-mark-card][data-mark-entries-done]` with per-row undo and "Stop treating all of these as mine".
  - The renderer bridge: `window.rescue.markMine(id, itemIds?)`, `window.rescue.unmarkMine(idOrIds)`.
  - New exports: `MarkFlow.ENTRY_REASON`, `MarkFlow.CANT_ALONE`, `MarkFlow.STALE_ROW`, `MarkFlow.ENTRY_BUTTON`.

- [ ] **Step 1: Write the failing tests**

Create `desktop/test/mark-entries-flow.test.js`:

```js
// "It's mine" for some entries of a list: a checklist of the apps (or keys),
// unticked, inside one finding. The confirmation lists exactly the ticked
// rows, always with the watching warning, and nothing is sent before "Yes".
const test = require('node:test');
const assert = require('node:assert');
const MarkFlow = require('../renderer/mark-flow.js');
const { createDocument } = require('./mini-dom.js');

const CARD = 'aaaaaaaaaaaa';
const ID_1 = '111111111111';
const ID_2 = '222222222222';
const DONE = '444444444444';
const ACC = 'security.app_permissions.accessibility_access';

const apps = (rows) => rows.map((r) => ({ id: r.key, name: r.label }));
const entries = (rows) => ({
  kind: 'app_permissions', id: CARD, code: ACC, group: '0123456789ab', label: `${rows.length} apps`, monitoring: true,
  shows: [['Apps', rows.map((r) => r.label).join(', ')], ['How many', String(rows.length)]],
  apps: apps(rows),
  items: rows,
  will_change: 'The checkup will stop warning you about this list of apps.',
  items_will_change: 'The checkup will stop warning you about the apps you choose.',
  how_to_undo: ['Choose "Stop treating this as mine" on the item in this app'],
});
const ROWS = [
  { key: 'com.example.one', label: 'One', detail: 'com.example.one', id: ID_1, monitoring: true },
  { key: 'com.example.two', label: 'Two', detail: 'com.example.two', id: ID_2, monitoring: true },
];
const finding = (markable, extra = {}) => ({ module: 'app_permissions', markable, ...extra });

test('a list finding shows a checklist of its apps, unticked, and no whole-list answer', () => {
  const html = MarkFlow.markControlsHtml(finding(entries(ROWS), {
    made_by: [{ subject: 'com.example.one', name: 'Example Ltd', verified: true }],
  }));
  assert.match(html, /data-mark-entries/);
  assert.match(html, new RegExp(`data-cl-list="mark-${CARD}"`));
  assert.strictEqual((html.match(/<input type="checkbox"/g) || []).length, 2);
  assert.ok(!/\bchecked\b/.test(html));
  assert.match(html, /<code class="checklist__detail">com\.example\.one<\/code>/);
  assert.match(html, /Made by Example Ltd \(verified\)/);
  assert.match(html, /Some of these apps are mine/);
  assert.match(html, /Select at least one/);
  assert.ok(!html.includes(MarkFlow.NOT_SURE_LIST), 'no "leave the whole list" line');
  assert.ok(!html.includes('Yes, it’s mine'));
});

test('the confirmation always carries the watching warning, even without "watched"', () => {
  const html = MarkFlow.markControlsHtml(finding(entries(ROWS)));
  const confirm = html.slice(html.indexOf('data-mark-items-confirm'));
  assert.ok(confirm.includes(MarkFlow.ONLY_IF_YOURS));
  assert.ok(confirm.includes(MarkFlow.COULD_WATCH));
  assert.ok(confirm.includes(MarkFlow.ENTRY_REASON));
  assert.ok(confirm.includes('The checkup will stop warning you about the apps you choose.'));
});

test('a row with no id is shown, disabled, with a note', () => {
  const rows = [...ROWS, { key: 'com.example.gone', label: 'Gone', detail: 'com.example.gone', id: null, monitoring: true }];
  const html = MarkFlow.markControlsHtml(finding(entries(rows)));
  assert.match(html, /data-cl-key="none-2" disabled>/);
  assert.ok(html.includes(MarkFlow.CANT_ALONE));
  assert.match(html, /data-mark-selectable="2"/);
});

test('rows already marked are listed with their own undo, never as checkboxes', () => {
  const rows = [...ROWS, { key: 'com.example.done', label: 'Done', detail: 'com.example.done', id: DONE, marked: true, monitoring: true }];
  const html = MarkFlow.markControlsHtml(finding(entries(rows)));
  assert.match(html, /Already marked as yours \(1\)/);
  assert.match(html, new RegExp(`data-unmark-item="${DONE}"`));
  assert.ok(!html.includes(`data-cl-key="${DONE}"`));
  assert.strictEqual((html.match(/<input type="checkbox"/g) || []).length, 2);
});

test('two apps with the same name are two checklist rows', () => {
  const rows = [
    { key: 'us.zoom.xos', label: 'Zoom', detail: 'us.zoom.xos', id: ID_1, monitoring: true },
    { key: 'com.fake.zoom', label: 'Zoom', detail: 'com.fake.zoom', id: ID_2, monitoring: true },
  ];
  const html = MarkFlow.markControlsHtml(finding(entries(rows)));
  assert.strictEqual((html.match(/<input type="checkbox"/g) || []).length, 2);
  assert.ok(html.includes('us.zoom.xos') && html.includes('com.fake.zoom'));
});

test('if the items and the rows disagree, the whole raw list is shown as before', () => {
  const m = entries(ROWS);
  const html = MarkFlow.markControlsHtml(finding({ ...m, items: [ROWS[0]] }));
  assert.ok(!html.includes('data-mark-entries'));
  assert.match(html, /Yes, these are mine/);
  assert.ok(html.includes(MarkFlow.NOT_SURE_LIST));
  const forged = MarkFlow.markControlsHtml(finding({ ...m, items: [ROWS[0], { ...ROWS[1], id: '"><x' }] }));
  assert.ok(!forged.includes('data-mark-entries') && !forged.includes('"><x'));
});

test('saved remote-login keys get the same checklist', () => {
  const sha = (c) => c.repeat(64);
  const keys = {
    kind: 'ssh_authorized_keys', id: CARD, code: 'security.session_revocation_scan.ssh_authorized_keys', group: '0123456789ab',
    monitoring: true, shows: [['Saved keys', '2'], ['Fingerprint of the list', 'abcd…']],
    items: [
      { key: sha('a'), label: 'ssh-ed25519 key', detail: 'me@laptop', id: ID_1, monitoring: true },
      { key: sha('b'), label: 'ssh-rsa key', detail: '', id: ID_2, monitoring: true },
    ],
    will_change: 'w', items_will_change: 'The checkup will stop warning you about the remote-login keys you choose.', how_to_undo: ['u'],
  };
  const html = MarkFlow.markControlsHtml({ module: 'session_revocation_scan', markable: keys });
  assert.match(html, /Some of these keys are mine/);
  assert.match(html, /<code class="checklist__detail">me@laptop<\/code>/);
  assert.strictEqual((html.match(/<input type="checkbox"/g) || []).length, 2);
});

test('a list marked entry by entry offers undo per row and for all of them', () => {
  const html = MarkFlow.markControlsHtml({ module: 'app_permissions', data: { marked_by_user: true, marked_items: [
    { id: ID_1, entry: 'com.example.one', shown: 'One · com.example.one' },
    { id: ID_2, entry: 'com.example.two', shown: 'Two · com.example.two' },
  ] } });
  assert.match(html, /data-mark-entries-done/);
  assert.match(html, /Marked as yours \(2\)/);
  assert.match(html, new RegExp(`data-unmark-item="${ID_1}"`));
  assert.match(html, new RegExp(`data-unmark-items="${ID_1} ${ID_2}"`));
  assert.strictEqual(MarkFlow.markControlsHtml({ module: 'stalkerware_scan', data: { marked_by_user: true, marked_items: [{ id: ID_1, shown: 'x' }] } }), '');
});

test('the test card below uses the same hooks the panel renders', () => {
  const html = MarkFlow.markControlsHtml(finding(entries(ROWS)));
  for (const attr of ['data-mark-entries', 'data-mark-selectable', 'data-mark-items-pick', 'data-mark-items-confirm',
    'data-mark-items-head', 'data-mark-items-row', 'data-mark-items-yes', 'data-mark-items-back',
    'data-mark-items-done', 'data-mark-items-done-row', 'data-unmark-item', 'data-unmark-item-status',
    'data-cl-action="mark"', 'data-cl-item', 'data-mark-open', 'data-mark-cancel', 'data-mark-panel', 'data-mark-status']) {
    assert.ok(html.includes(attr), attr);
  }
});

// --- the flow, on a small DOM laid out like the panel ------------------------

function entryCard({ selectable = [ID_1, ID_2] } = {}) {
  const doc = createDocument();
  const root = doc.body.add('div');
  const card = root.add('div', { 'data-mark-card': '', 'data-mark-entries': '', 'data-mark-id': CARD,
    'data-mark-group': CARD, 'data-mark-selectable': String(selectable.length), 'data-mark-kind': 'app_permissions' });
  const open = card.add('button', { 'data-mark-open': '' });
  const panel = card.add('div', { 'data-mark-panel': '', hidden: '' });
  const pick = panel.add('div', { 'data-mark-items-pick': '' });
  const list = pick.add('fieldset', { 'data-cl-list': `mark-${CARD}` });
  const boxes = selectable.map((k) => { const b = list.add('input', { 'data-cl-item': '', 'data-cl-key': k }); b.checked = false; b.disabled = false; return b; });
  list.add('p', { 'data-cl-count': '' });
  const action = list.add('button', { 'data-cl-action': 'mark', 'data-cl-verb': 'Mark', 'data-cl-one': 'app',
    'data-cl-many': 'apps', 'data-cl-suffix': 'as mine', 'data-cl-min': '1' });
  const cancel = pick.add('button', { 'data-mark-cancel': '' });
  const confirm = panel.add('div', { 'data-mark-items-confirm': '', hidden: '' });
  const head = confirm.add('strong', { 'data-mark-items-head': '' });
  const confirmRows = selectable.map((k) => confirm.add('li', { 'data-mark-items-row': k, hidden: '' }));
  const yes = confirm.add('button', { 'data-mark-items-yes': '' });
  const back = confirm.add('button', { 'data-mark-items-back': '' });
  const status = card.add('div', { 'data-mark-status': '', hidden: '' });
  const done = card.add('ul', { 'data-mark-items-done': '', hidden: '' });
  const doneRows = selectable.map((k) => {
    const li = done.add('li', { 'data-mark-entry': k, 'data-mark-items-done-row': k, hidden: '' });
    li.add('button', { 'data-unmark-item': k });
    li.add('span', { 'data-unmark-item-status': '', hidden: '' });
    return li;
  });
  return { doc, root, card, open, panel, pick, boxes, action, cancel, confirm, head, confirmRows, yes, back, status, done, doneRows };
}

const tick = (c, i) => {
  c.boxes[i].checked = true;
  (c.root.listeners.change || []).forEach((fn) => fn({ target: c.boxes[i] }));
};

test('tick, then the button: the confirmation shows exactly the ticked rows; nothing is sent until Yes', async () => {
  const c = entryCard();
  const sent = [];
  const marked = [];
  MarkFlow.attach(c.root, { markMine: async (id, ids) => { sent.push([id, ids]); return { status: 'marked', ids, how_to_undo: ['u'] }; } },
    { onMarked: (cards) => marked.push(cards) });
  await c.open.click();
  assert.strictEqual(c.panel.hidden, false);
  tick(c, 1);
  await c.action.click();
  assert.strictEqual(c.pick.hidden, true);
  assert.strictEqual(c.confirm.hidden, false);
  assert.deepStrictEqual(c.confirmRows.map((r) => r.hidden), [true, false]);
  assert.strictEqual(c.head.textContent, 'You’re saying this one is yours:');
  assert.deepStrictEqual(sent, [], 'nothing before Yes');
  await c.yes.click();
  assert.deepStrictEqual(sent, [[CARD, [ID_2]]]);
  assert.match(c.status.innerHTML, /Marked 1 as yours\./);
  assert.match(c.status.innerHTML, /The other 1 keep their warning\./);
  assert.strictEqual(c.done.hidden, false);
  assert.deepStrictEqual(c.doneRows.map((r) => r.hidden), [true, false]);
  assert.deepStrictEqual(marked, [], 'one of two: the card stays on the list');
});

test('ticking every row and saying yes clears the card', async () => {
  const c = entryCard();
  const marked = [];
  MarkFlow.attach(c.root, { markMine: async (id, ids) => ({ status: 'marked', ids }) }, { onMarked: (cards) => marked.push(cards) });
  await c.open.click();
  tick(c, 0);
  tick(c, 1);
  await c.action.click();
  assert.strictEqual(c.head.textContent, 'You’re saying these 2 are yours:');
  await c.yes.click();
  assert.deepStrictEqual(marked, [[c.card]]);
});

test('Back returns to the list, and Escape closes the panel', async () => {
  const c = entryCard();
  MarkFlow.attach(c.root, { markMine: async () => { throw new Error('must not send'); } });
  await c.open.click();
  tick(c, 0);
  await c.action.click();
  await c.back.click();
  assert.strictEqual(c.pick.hidden, false);
  assert.strictEqual(c.confirm.hidden, true);
  await c.action.click();
  (c.root.listeners.keydown || []).forEach((fn) => fn({ key: 'Escape', target: c.yes }));
  assert.strictEqual(c.panel.hidden, true);
  await c.yes.click();
  assert.strictEqual(c.status.hidden, true, 'a closed confirmation sends nothing');
});

test('a refused answer says so and offers the button again', async () => {
  const c = entryCard();
  MarkFlow.attach(c.root, { markMine: async () => ({ status: 'refused', message: 'It changed since the checkup.' }) });
  await c.open.click();
  tick(c, 0);
  await c.action.click();
  await c.yes.click();
  assert.match(c.status.innerHTML, /We couldn’t mark this one\./);
  assert.strictEqual(c.open.hidden, false);
  assert.strictEqual(c.done.hidden, true);
});

test('keys the panel never showed are ignored', async () => {
  const c = entryCard({ selectable: [ID_1] });
  const sent = [];
  MarkFlow.attach(c.root, { markMine: async (id, ids) => { sent.push(ids); return { status: 'marked', ids }; } });
  await c.open.click();
  c.boxes[0].setAttribute('data-cl-key', ID_2); // something rewrote the row
  tick(c, 0);
  await c.action.click();
  assert.strictEqual(c.confirm.hidden, true);
  await c.yes.click();
  assert.deepStrictEqual(sent, []);
});

test('undo on one row removes only that mark', async () => {
  const c = entryCard();
  const sent = [];
  MarkFlow.attach(c.root, { unmarkMine: async (ids) => { sent.push(ids); return { status: 'removed', ids }; } });
  const btn = c.doneRows[0].querySelector('[data-unmark-item]');
  await btn.click();
  assert.deepStrictEqual(sent, [[ID_1]]);
  assert.strictEqual(btn.hidden, true);
  assert.match(c.doneRows[0].querySelector('[data-unmark-item-status]').textContent, /No longer marked as yours/);
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd desktop && node --test test/mark-entries-flow.test.js`
Expected: FAIL. The first test fails on `/data-mark-entries/` (the panel still renders the whole-list version).

- [ ] **Step 3: Add the entry constants and helpers to `desktop/renderer/mark-flow.js`**

Directly below the `BUTTON` object (the line `  };` that closes it), add:

```js
  // Lists that can be marked entry by entry (rescue/known_items.py ENTRY_KIND_FOR).
  const ENTRY_LIST_KINDS = new Set(['app_permissions', 'ssh_authorized_keys']);
  const ENTRY_NOUNS = { app_permissions: ['app', 'apps'], ssh_authorized_keys: ['key', 'keys'] };
  const ENTRY_BUTTON = { app_permissions: 'Some of these apps are mine', ssh_authorized_keys: 'Some of these keys are mine' };
  const ENTRY_LEGEND = { app_permissions: 'Tick the apps you know and use', ssh_authorized_keys: 'Tick the keys you added yourself' };
  const ENTRY_REASON = 'We ask so the list stays accurate: anything you leave unticked, or that appears later, keeps its warning.';
  const CANT_ALONE = 'We couldn’t check who made this one just now, so it can’t be marked on its own.';
  const STALE_ROW = 'Marked as yours before, but it has changed since.';
  // The shared checklist (checklist.js): a global in the page, required in Node.
  const CL = typeof Checklist !== 'undefined' ? Checklist
    : (typeof require === 'function' ? require('./checklist.js') : null);
```

Replace `showsHtml`'s first lines

```js
  function showsHtml(m, finding) {
    const rows = Array.isArray(m.shows)
      ? m.shows.filter((r) => Array.isArray(r) && r.length === 2 && typeof r[0] === 'string' && typeof r[1] === 'string')
      : [];
```

with

```js
  function shownRowsOf(m) {
    return Array.isArray(m.shows)
      ? m.shows.filter((r) => Array.isArray(r) && r.length === 2 && typeof r[0] === 'string' && typeof r[1] === 'string')
      : [];
  }

  function showsHtml(m, finding) {
    const rows = shownRowsOf(m);
```

Directly above the comment `// opts.watched: the person said "I think someone is watching me".` (the one above `markControlsHtml`), add:

```js
  // One row of the engine's markable.items, or false if anything is off.
  function validEntry(it) {
    if (!it || typeof it !== 'object') return false;
    if (typeof it.key !== 'string' || !it.key || it.key.length > MAX_APP_ID || it.key.includes('\0')) return false;
    if (typeof it.label !== 'string' || !it.label.trim()) return false;
    if (it.label !== it.key && (it.label.length > MAX_APP_NAME || CONTROL_OR_FORMAT.test(it.label))) return false;
    if (it.detail != null && (typeof it.detail !== 'string' || it.detail.length > MAX_APP_ID || it.detail.includes('\0'))) return false;
    if (it.marked === true) return typeof it.id === 'string' && MARK_ID.test(it.id);
    return it.id === null || (typeof it.id === 'string' && MARK_ID.test(it.id));
  }

  // The engine's entries for a list, or null when the panel must show the
  // whole list as before: no checklist component, a malformed row, a repeat,
  // or rows that don't line up with the apps (or keys) the engine counted.
  function entryRowsOf(m, rows) {
    if (!CL || !m || !ENTRY_LIST_KINDS.has(m.kind) || !Array.isArray(m.items) || !m.items.length) return null;
    if (!m.items.every(validEntry)) return null;
    const keys = m.items.map((i) => i.key);
    if (new Set(keys).size !== keys.length) return null;
    const ids = m.items.map((i) => i.id).filter((x) => x);
    if (new Set(ids).size !== ids.length || ids.includes(m.id)) return null;
    if (m.kind === 'app_permissions') {
      const appRows = appRowsOf(m, rows);
      if (!appRows || appRows.length !== keys.length || !appRows.every((a) => keys.includes(a.id))) return null;
    } else {
      const count = (rows.find(([k]) => k === 'Saved keys') || [])[1];
      if (!/^\d+$/.test(count || '') || Number(count) !== keys.length) return null;
    }
    return m.items;
  }

  function rowText(e) {
    return e.detail && e.detail !== e.label ? `${e.label} · ${e.detail}` : e.label;
  }

  // The maker line and the name/maker flag for one app row (none for keys).
  function entryEvidence(m, finding, e) {
    if (m.kind !== 'app_permissions') return '';
    const maker = makerEntry(finding && finding.made_by, e.key);
    const text = makerText(maker);
    return (text ? `<span class="mark-apps__maker">${esc(visible(text))}</span>` : '')
      + (nameContradictsMaker(e.label, maker) ? `<span class="mark-apps__flag">${esc(NAME_MAKER_MISMATCH)}</span>` : '');
  }

  // A row with its own "Stop treating this as mine".
  function unmarkRowHtml(id, text, attrs) {
    return `<li class="mark-apps__row" data-mark-entry="${esc(id)}"${attrs || ''}>`
      + `<span class="mark-apps__who">${esc(visible(text))}</span>`
      + `<button type="button" class="btn btn--secondary btn--small" data-unmark-item="${esc(id)}">Stop treating this as mine</button>`
      + '<span class="fix-status" data-unmark-item-status role="status" aria-live="polite" hidden></span></li>';
  }

  function entryControlsHtml(m, finding, entries, opts) {
    const noun = ENTRY_NOUNS[m.kind];
    const marked = entries.filter((e) => e.marked === true);
    const open = entries.filter((e) => e.marked !== true);
    const selectable = open.filter((e) => e.id);
    const checklist = CL.html({
      id: `mark-${m.id}`,
      legend: `${ENTRY_LEGEND[m.kind]} (${open.length} not marked as yours yet)`,
      items: open.map((e, i) => ({
        key: e.id || `none-${i}`,
        label: e.label,
        detail: e.detail && e.detail !== e.label ? e.detail : '',
        evidenceHtml: entryEvidence(m, finding, e),
        disabled: !e.id,
        note: !e.id ? CANT_ALONE : (e.stale ? STALE_ROW : ''),
      })),
      actions: [{ id: 'mark', verb: 'Mark', noun, suffix: 'as mine', min: 1 }],
      selectAll: true,
      theme: opts && opts.theme === 'game' ? 'game' : 'plain',
    });
    const already = marked.length
      ? `<p class="fix-panel__line"><strong>Already marked as yours (${marked.length}):</strong></p>
          <ul class="mark-apps">${marked.map((e) => unmarkRowHtml(e.id, rowText(e))).join('')}</ul>`
      : '';
    const confirmRows = selectable.map((e) => `<li class="mark-apps__row" data-mark-items-row="${esc(e.id)}" hidden>`
      + `<span class="mark-apps__who">${esc(visible(rowText(e)))}</span>${entryEvidence(m, finding, e)}</li>`).join('');
    const doneRows = selectable.map((e) => unmarkRowHtml(e.id, rowText(e), ` data-mark-items-done-row="${esc(e.id)}" hidden`)).join('');
    return `
      <div class="mark-mine" data-mark-card data-mark-entries data-mark-kind="${esc(m.kind)}" data-mark-id="${esc(m.id)}" data-mark-group="${esc(m.id)}" data-mark-selectable="${selectable.length}">
        ${already}
        ${selectable.length ? `<button type="button" class="btn btn--secondary btn--small" data-mark-open>${esc(ENTRY_BUTTON[m.kind])}</button>` : ''}
        <div class="fix-panel" data-mark-panel hidden role="group" aria-label="Choose which are yours">
          <div data-mark-items-pick>
            ${checklist}
            <p class="muted fix-panel__note">Ticking changes nothing. You’ll see what you picked before anything is saved.</p>
            <div class="fix-panel__actions"><button type="button" class="btn btn--secondary btn--small" data-mark-cancel>Cancel</button></div>
          </div>
          <div data-mark-items-confirm hidden>
            <p class="fix-panel__line"><strong data-mark-items-head>You’re saying these are yours:</strong></p>
            <ul class="mark-apps">${confirmRows}</ul>
            <p class="fix-panel__line"><strong>This will:</strong> ${esc(m.items_will_change || m.will_change)}</p>
            <p class="fix-panel__line"><strong>To undo later:</strong></p>
            ${undoListHtml(m.how_to_undo)}
            <p class="fix-panel__line fix-panel__warning"><strong>${esc(ONLY_IF_YOURS)}</strong></p>
            <p class="fix-panel__line">${esc(COULD_WATCH)}</p>
            <p class="fix-panel__line">${esc(ENTRY_REASON)}</p>
            <p class="muted fix-panel__note">Nothing on your computer is changed or turned off.</p>
            <div class="fix-panel__actions">
              <button type="button" class="btn btn--primary btn--small" data-mark-items-yes>Yes, these are mine</button>
              <button type="button" class="btn btn--secondary btn--small" data-mark-items-back>Back</button>
            </div>
          </div>
        </div>
        <div class="fix-status" data-mark-status role="status" aria-live="polite" hidden></div>
        <ul class="mark-apps" data-mark-items-done hidden>${doneRows}</ul>
      </div>`;
  }

  // A list marked entry by entry (every entry): data.marked_items, or null.
  function markedEntriesOf(finding) {
    const d = finding && finding.data;
    if (!d || d.marked_by_user !== true || !Array.isArray(d.marked_items) || !d.marked_items.length) return null;
    if (NEVER_MARKABLE_MODULES.has(finding.module)) return null;
    const ok = d.marked_items.every((x) => x && typeof x.id === 'string' && MARK_ID.test(x.id)
      && typeof x.shown === 'string' && x.shown.trim() !== '' && x.shown.length <= 1200 && !x.shown.includes('\0'));
    return ok ? d.marked_items : null;
  }

  function markedEntriesHtml(list) {
    const ids = list.map((x) => x.id);
    return `
      <div class="mark-mine" data-mark-card data-mark-entries-done>
        <p class="fix-panel__line"><strong>Marked as yours (${list.length}):</strong></p>
        <ul class="mark-apps">${list.map((x) => unmarkRowHtml(x.id, x.shown)).join('')}</ul>
        ${list.length > 1 ? `<button type="button" class="btn btn--secondary btn--small" data-unmark-items="${esc(ids.join(' '))}">Stop treating all of these as mine</button>` : ''}
        <div class="fix-status" data-mark-status role="status" aria-live="polite" hidden></div>
      </div>`;
  }
```

- [ ] **Step 4: Route list findings to the checklist in `markControlsHtml`**

In `markControlsHtml`, replace the opening lines

```js
  function markControlsHtml(finding, opts) {
    const m = markableOf(finding);
    if (m) {
      const group = groupOf(m.id, m.ids);
```

with

```js
  function markControlsHtml(finding, opts) {
    const m = markableOf(finding);
    if (m) {
      const entries = entryRowsOf(m, shownRowsOf(m));
      if (entries) return entryControlsHtml(m, finding, entries, opts);
      const group = groupOf(m.id, m.ids);
```

and replace its tail

```js
    const id = markedIdOf(finding);
    if (id) {
```

with

```js
    const done = markedEntriesOf(finding);
    if (done) return markedEntriesHtml(done);
    const id = markedIdOf(finding);
    if (id) {
```

Directly below `siblingHtml` (after its closing `}`), add:

```js
  // After some entries were marked: how many, and what happens to the rest.
  function itemsResultHtml(n, rest, undo) {
    const detail = rest > 0
      ? `The other ${rest} keep their warning. From your next checkup, the ones you marked are listed as “marked as yours”.`
      : 'From your next checkup the whole list is listed as “marked as yours” instead of being flagged.';
    return `
      <div class="fix-status--success fix-status__box">
        <p class="fix-status__headline"><strong>${esc(`Marked ${n} as yours.`)}</strong></p>
        <p class="fix-status__detail">${esc(detail)}</p>
        ${undo && undo.length ? `<p class="fix-status__detail"><strong>To undo later:</strong></p>${undoListHtml(undo)}` : ''}
      </div>`;
  }
```

- [ ] **Step 5: Replace `CLICK_TARGETS` and `attach`**

Replace everything from the line `  const CLICK_TARGETS = '[data-mark-open],[data-mark-confirm],[data-mark-cancel],[data-unmark]';` down to (and including) the closing `  }` of `attach` (the line before `  return {`) with:

```js
  const CLICK_TARGETS = '[data-mark-open],[data-mark-confirm],[data-mark-cancel],[data-unmark],'
    + '[data-unmark-items],[data-unmark-item],[data-mark-items-yes],[data-mark-items-back]';

  function splitIds(value) {
    return String(value || '').split(/\s+/).filter((x) => MARK_ID.test(x));
  }

  // Delegated handlers on a container that survives re-renders. `api` is the
  // preload bridge: api.markMine(id, itemIds?), api.unmarkMine(idOrIds). `hooks` (optional):
  // onMarked(cards) and onUnmarked(cards) after the engine saved or removed
  // marks, with every card the answer covered. Returns {unmark(card)} so the
  // "Cleared" list can offer Undo.
  // onResult({kind, result, described}) after the engine answers (game mode).
  function attach(root, api, hooks) {
    const onResult = hooks && typeof hooks.onResult === 'function' ? hooks.onResult : null;
    const state = new WeakMap(); // card -> 'confirming' | 'confirming-items' | 'running'
    const rowState = new WeakMap(); // entry row -> true while its undo runs
    const on = hooks || {};

    function cardOf(el) {
      return el && el.closest ? el.closest('[data-mark-card]') : null;
    }

    function showPick(card) {
      const pick = card.querySelector('[data-mark-items-pick]');
      const confirm = card.querySelector('[data-mark-items-confirm]');
      if (pick) pick.hidden = false;
      if (confirm) confirm.hidden = true;
    }

    function closePanel(card) {
      const panel = card.querySelector('[data-mark-panel]');
      if (panel) panel.hidden = true;
      showPick(card);
      state.delete(card);
    }

    function setButtons(card, hidden) {
      card.querySelectorAll('[data-mark-open],[data-unmark]').forEach((b) => { b.hidden = hidden; });
    }

    // A card that was just marked can be unmarked again ("Undo"): it learns
    // the ids the engine saved for it.
    function becomeMarked(card, ids) {
      const own = card.getAttribute('data-mark-id');
      if (!own || !ids.includes(own)) return;
      card.setAttribute('data-unmark-id', own);
      card.setAttribute('data-unmark-group', [own, ...ids.filter((x) => x !== own)].join(' '));
      card.setAttribute('data-marked-now', '');
    }

    // After an unmark, a card that was marked in this session offers the button again.
    function becomeUnmarked(card) {
      if (!card.hasAttribute || !card.hasAttribute('data-marked-now')) return;
      card.removeAttribute('data-marked-now');
      card.removeAttribute('data-unmark-id');
      card.removeAttribute('data-unmark-group');
      setButtons(card, false);
    }

    // The same item is often reported by more than one check, so it has more
    // than one card. Once the engine has saved (or removed) the marks for all
    // of them, the other cards say so instead of offering the button again.
    function updateSiblings(card, kind, result) {
      if (typeof root.querySelectorAll !== 'function') return [];
      const ownAttr = kind === 'marked' ? 'data-mark-id' : 'data-unmark-id';
      const groupAttr = kind === 'marked' ? 'data-mark-group' : 'data-unmark-group';
      const own = card.getAttribute(ownAttr);
      let ids = idsAttr(card, groupAttr).filter((x) => x !== own);
      // When the engine lists what it saved or removed, only those.
      if (result && Array.isArray(result.ids)) ids = ids.filter((x) => result.ids.includes(x));
      if (!ids.length) return [];
      const touched = [];
      for (const other of Array.from(root.querySelectorAll(`[${ownAttr}]`))) {
        if (other === card || !ids.includes(other.getAttribute(ownAttr))) continue;
        if (state.get(other) === 'running') continue;
        closePanel(other);
        setButtons(other, true);
        const status = other.querySelector('[data-mark-status]');
        if (status) { status.hidden = false; status.innerHTML = siblingHtml(kind); }
        other.setAttribute('data-mark-handled-by-other', '');
        if (kind === 'marked') becomeMarked(other, [own, ...ids]);
        else becomeUnmarked(other);
        touched.push(other);
      }
      return touched;
    }

    // kind: 'marked', 'removed', or 'marked-items' (some entries; `chosen` are their ids).
    async function send(card, call, kind, chosen) {
      state.set(card, 'running');
      const panel = card.querySelector('[data-mark-panel]');
      const status = card.querySelector('[data-mark-status]');
      if (panel) panel.hidden = true;
      setButtons(card, true);
      status.hidden = false;
      status.innerHTML = '<p class="fix-status__headline fix-status--running">Saving…</p>';
      let d;
      try {
        const result = await call();
        status.innerHTML = resultHtml(result);
        d = describeMarkResult(result);
        if (onResult) { try { onResult({ kind, result, described: d }); } catch (_) { /* never break a mark */ } }
        const r = result || {};
        if (kind === 'marked' && (r.status === 'marked' || r.status === 'already_marked')) {
          const own = card.getAttribute('data-mark-id');
          const saved = Array.isArray(r.ids) ? r.ids.filter((x) => MARK_ID.test(x)) : [own];
          const others = updateSiblings(card, kind, r);
          becomeMarked(card, saved.length ? saved : [own]);
          if (typeof on.onMarked === 'function') on.onMarked([card, ...others]);
        }
        if (kind === 'marked-items' && (r.status === 'marked' || r.status === 'already_marked')) {
          const saved = Array.isArray(r.ids) ? r.ids.filter((x) => MARK_ID.test(x) && (chosen || []).includes(x)) : [];
          const open = Number(card.getAttribute('data-mark-selectable')) || 0;
          status.innerHTML = itemsResultHtml(saved.length, Math.max(0, open - saved.length), d.undo);
          const done = card.querySelector('[data-mark-items-done]');
          if (done) done.hidden = saved.length === 0;
          card.querySelectorAll('[data-mark-items-done-row]').forEach((row) => {
            row.hidden = !saved.includes(row.getAttribute('data-mark-items-done-row'));
          });
          // Every entry it could mark is now marked: the card leaves the list, as a whole mark would.
          if (saved.length && saved.length === open && typeof on.onMarked === 'function') on.onMarked([card]);
        }
        if (kind === 'removed' && r.status === 'removed') {
          const others = updateSiblings(card, kind, r);
          state.delete(card);
          becomeUnmarked(card);
          if (card.hasAttribute && card.hasAttribute('data-mark-entries-done')) {
            card.querySelectorAll('[data-unmark-items],[data-unmark-item]').forEach((b) => { b.hidden = true; });
          }
          if (typeof on.onUnmarked === 'function') on.onUnmarked([card, ...others]);
        }
      } catch (_) {
        status.innerHTML = resultHtml(null);
        d = { done: false };
      }
      state.delete(card);
      if (!d.done) setButtons(card, false);
    }

    function unmark(card) {
      if (!card || state.get(card) === 'running') return undefined;
      const id = card.getAttribute('data-unmark-id');
      if (typeof id !== 'string' || !MARK_ID.test(id)) return undefined;
      return send(card, () => api.unmarkMine(id), 'removed');
    }

    // "Stop treating this as mine" on one entry: only that entry's mark.
    async function unmarkItem(btn) {
      const row = btn.closest ? btn.closest('[data-mark-entry]') : null;
      const id = btn.getAttribute('data-unmark-item');
      if (!row || rowState.get(row) || typeof id !== 'string' || !MARK_ID.test(id)) return undefined;
      rowState.set(row, true);
      const status = row.querySelector('[data-unmark-item-status]');
      btn.hidden = true;
      if (status) { status.hidden = false; status.textContent = 'Saving…'; }
      let ok = false;
      try {
        const r = await api.unmarkMine([id]);
        ok = !!r && r.status === 'removed';
        if (status) status.textContent = ok ? 'No longer marked as yours. Its warning comes back on your next checkup.' : describeMarkResult(r).headline;
      } catch (_) {
        if (status) status.textContent = describeMarkResult(null).headline;
      }
      rowState.delete(row);
      if (!ok) btn.hidden = false;
      return undefined;
    }

    // The checklist's button: show exactly the ticked rows the panel rendered, and ask.
    function openItemsConfirm(card, keys) {
      const rows = Array.from(card.querySelectorAll('[data-mark-items-row]'));
      const allowed = new Set(rows.map((r) => r.getAttribute('data-mark-items-row')));
      const ids = [...new Set(keys)].filter((k) => MARK_ID.test(k) && allowed.has(k));
      const confirm = card.querySelector('[data-mark-items-confirm]');
      if (!ids.length || !confirm) return;
      rows.forEach((row) => { row.hidden = !ids.includes(row.getAttribute('data-mark-items-row')); });
      const head = card.querySelector('[data-mark-items-head]');
      if (head) head.textContent = ids.length === 1 ? 'You’re saying this one is yours:' : `You’re saying these ${ids.length} are yours:`;
      const yes = card.querySelector('[data-mark-items-yes]');
      if (yes) yes.textContent = ids.length === 1 ? 'Yes, this one is mine' : `Yes, these ${ids.length} are mine`;
      confirm.setAttribute('data-mark-items-chosen', ids.join(' '));
      const pick = card.querySelector('[data-mark-items-pick]');
      if (pick) pick.hidden = true;
      confirm.hidden = false;
      state.set(card, 'confirming-items');
    }

    // The checklist listens first: some callers' roots keep only the last click handler.
    if (CL) {
      CL.attach(root, {
        onAction(listId, actionId, keys) {
          if (actionId !== 'mark' || typeof listId !== 'string' || !listId.startsWith('mark-')) return;
          const id = listId.slice('mark-'.length);
          const card = Array.from(root.querySelectorAll('[data-mark-entries]')).find((c) => c.getAttribute('data-mark-id') === id);
          if (card && state.get(card) === 'confirming') openItemsConfirm(card, keys);
        },
      });
    }

    root.addEventListener('click', (event) => {
      const target = event.target && event.target.closest ? event.target.closest(CLICK_TARGETS) : null;
      if (target && target.hasAttribute('data-unmark-item')) return unmarkItem(target);
      const card = cardOf(target);
      if (!target || !card || state.get(card) === 'running') return undefined;
      if (target.hasAttribute('data-mark-open')) {
        const panel = card.querySelector('[data-mark-panel]');
        const status = card.querySelector('[data-mark-status]');
        if (status) { status.hidden = true; status.innerHTML = ''; }
        showPick(card);
        if (panel) panel.hidden = false;
        state.set(card, 'confirming');
        return undefined;
      }
      if (target.hasAttribute('data-mark-cancel')) {
        closePanel(card);
        return undefined;
      }
      if (target.hasAttribute('data-unmark')) return unmark(card);
      if (target.hasAttribute('data-unmark-items')) {
        const ids = splitIds(target.getAttribute('data-unmark-items'));
        return ids.length ? send(card, () => api.unmarkMine(ids), 'removed') : undefined;
      }
      if (target.hasAttribute('data-mark-items-back')) {
        if (state.get(card) === 'confirming-items') { showPick(card); state.set(card, 'confirming'); }
        return undefined;
      }
      if (target.hasAttribute('data-mark-items-yes')) {
        if (state.get(card) !== 'confirming-items') return undefined;
        const confirm = card.querySelector('[data-mark-items-confirm]');
        const ids = splitIds(confirm && confirm.getAttribute('data-mark-items-chosen'));
        const id = card.getAttribute('data-mark-id');
        if (!ids.length || typeof id !== 'string' || !MARK_ID.test(id)) return undefined;
        // The finding's id and the ticked entry ids only; main checks each against its scan.
        return send(card, () => api.markMine(id, ids), 'marked-items', ids);
      }
      if (!target.hasAttribute('data-mark-confirm') || state.get(card) !== 'confirming') return undefined;
      // Only the engine's id is sent; the main process looks up what it showed.
      const id = card.getAttribute('data-mark-id');
      if (typeof id !== 'string' || !MARK_ID.test(id)) return undefined;
      return send(card, () => api.markMine(id), 'marked');
    });

    root.addEventListener('keydown', (event) => {
      if (event.key !== 'Escape') return;
      const card = cardOf(event.target);
      const s = card && state.get(card);
      if (s === 'confirming' || s === 'confirming-items') closePanel(card);
    });

    return { unmark };
  }
```

Replace the returned object

```js
  return {
    ONLY_IF_YOURS, COULD_WATCH, LIST_REASON, NOT_SURE_LIST, NAME_MAKER_MISMATCH, MAX_APP_NAME, BUTTON, NEVER_MARKABLE_MODULES, groupOf, markableOf, markedIdOf,
    needsStrongConfirm, markControlsHtml, describeMarkResult, resultHtml, attach, esc,
  };
```

with

```js
  return {
    ONLY_IF_YOURS, COULD_WATCH, LIST_REASON, NOT_SURE_LIST, NAME_MAKER_MISMATCH, MAX_APP_NAME, BUTTON, NEVER_MARKABLE_MODULES,
    ENTRY_REASON, CANT_ALONE, STALE_ROW, ENTRY_BUTTON, groupOf, markableOf, markedIdOf,
    needsStrongConfirm, markControlsHtml, describeMarkResult, resultHtml, attach, esc,
  };
```

- [ ] **Step 6: Run the mark-flow tests**

Run: `cd desktop && node --test test/mark-entries-flow.test.js test/mark-flow.test.js test/mark-apps.test.js test/mark-items.test.js test/clear-list.test.js`
Expected: PASS (all). The existing whole-list tests pass unchanged: their markable blocks have no `items`.

- [ ] **Step 7: Pass item ids through IPC**

In `desktop/preload.js`, replace

```js
  markMine: (id) => ipcRenderer.invoke('mark-mine', id),
  unmarkMine: (id) => ipcRenderer.invoke('unmark-mine', id),
```

with

```js
  // itemIds: some entries of one list finding (main checks each against its scan).
  markMine: (id, itemIds) => ipcRenderer.invoke('mark-mine', id, itemIds),
  unmarkMine: (idOrIds) => ipcRenderer.invoke('unmark-mine', idOrIds),
```

In `desktop/main.js`, replace

```js
  ipcMain.handle('mark-mine', (_e, id) =>
    handleMark(id, { policy: markPolicy, runMark }));
  ipcMain.handle('unmark-mine', (_e, id) =>
    handleUnmark(id, { policy: markPolicy, runUnmark }));
```

with

```js
  ipcMain.handle('mark-mine', (_e, id, itemIds) =>
    handleMark(id, { policy: markPolicy, runMark }, itemIds));
  ipcMain.handle('unmark-mine', (_e, idOrIds) =>
    handleUnmark(idOrIds, { policy: markPolicy, runUnmark }));
```

- [ ] **Step 8: Load the component in the page and in the game**

In `desktop/renderer/index.html`, directly below `<link rel="stylesheet" href="styles.css" />`, add:

```html
  <link rel="stylesheet" href="checklist.css" />
```

and directly above `<script src="mark-flow.js"></script>`, add:

```html
  <script src="checklist.js"></script>
```

In `desktop/renderer/game/controller.js`, replace

```js
  shadow.innerHTML = '<link rel="stylesheet" href="rc/style.css"><link rel="stylesheet" href="game/game.css"><div class="frame" id="frame"></div>';
```

with

```js
  shadow.innerHTML = '<link rel="stylesheet" href="rc/style.css"><link rel="stylesheet" href="game/game.css"><link rel="stylesheet" href="checklist.css"><div class="frame" id="frame"></div>';
```

Then find every call: `grep -n "MarkFlow.markControlsHtml(" desktop/renderer/game/controller.js`. Each call with one argument, e.g.

```js
win.MarkFlow.markControlsHtml(m.primary)
```

becomes

```js
win.MarkFlow.markControlsHtml(m.primary, { theme: 'game' })
```

and a call that already passes an options object gets `theme: 'game'` added to that object. (On `reclaim-city` at `d3a9e66` there is one call, in the mission controls; main's Signal or Noise view may add a second, `win.MarkFlow.markControlsHtml(sig.finding)`, which becomes `win.MarkFlow.markControlsHtml(sig.finding, { theme: 'game' })`.)

- [ ] **Step 9: Keep focus across the results redraw**

In `desktop/renderer/app.js`, inside the `if (typeof document !== 'undefined') {` block, directly above `function renderResults(doc) {`, add:

```js
    // A re-check redraws the list; focus stays on the same checklist row.
    const keepFocus = (root, render) => (typeof Checklist !== 'undefined' ? Checklist.preserveFocus(root, render) : render());
```

and in `renderResults`, replace

```js
      groupsEl.innerHTML = SEVERITY_ORDER.map((sev) => renderSeverityGroup(sev, groups[sev])).join('')
        + ClearList.sectionHtml();
```

with

```js
      keepFocus(groupsEl, () => {
        groupsEl.innerHTML = SEVERITY_ORDER.map((sev) => renderSeverityGroup(sev, groups[sev])).join('')
          + ClearList.sectionHtml();
      });
```

- [ ] **Step 10: Run the whole desktop suite**

Run: `cd desktop && npm test`
Expected: PASS (all).

- [ ] **Step 11: Check it in the real app**

Run the app against a source engine: `cd desktop && RESCUE_ENGINE=../.venv/bin/rescue npm start`. Pick "I'm not sure — check everything", wait for the results, open a warning about apps with Accessibility (or camera/microphone) access, press "Some of these apps are mine", tick one app with Space, move with the arrow keys, press "Mark 1 app as mine", check the confirmation lists only that app and shows the watching warning, then press **Back** and **Cancel** (do not mark anything on a real machine unless it really is yours). Confirm with the keyboard alone that Tab reaches the list, Space ticks, and Escape closes the panel.

- [ ] **Step 12: Commit**

```bash
git add desktop/renderer/mark-flow.js desktop/preload.js desktop/main.js desktop/renderer/index.html desktop/renderer/game/controller.js desktop/renderer/app.js desktop/test/mark-entries-flow.test.js
git commit -m "$(cat <<'EOF'
Desktop: tick the apps (or keys) that are yours, inside one finding

The "It's mine" panel for a list is now a checklist. The confirmation lists
exactly the ticked rows, always with the watching warning; each marked row
has its own undo. Rows that don't line up fall back to the whole list.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```

---
### Task 9: Desktop: the worry screen as a checklist, and several worries everywhere

**Waits for `reclaim-city` to land on main, and for Task 8** (both edit `app.js`, `index.html` and `game/controller.js`). The "replace" blocks below are from `reclaim-city` at `d3a9e66`; re-read each against main first.

**Files:**
- Modify: `desktop/renderer/index.html` (worry screen markup; `worries.js` script tag)
- Modify: `desktop/renderer/app.js` (`WorryPick`; `mayBeWatched`; `gameOfferedFor`; `learnMoreFor`; `leaveGame`; `renderSituations`; the `runScan` call)
- Modify: `desktop/renderer/first-question.js` (`afterWorry`)
- Modify: `desktop/renderer/game/controller.js` (import `worryIdsOf`; two call sites)
- Modify: `desktop/test/page-harness.js` (`El` parser, `querySelectorAll`, `getAttribute`; `pick`)
- Modify: `desktop/test/first-question.test.js` (one new test)
- Create: `desktop/test/worry-checklist.test.js`

**Interfaces:**
- Consumes: `Worries.combine`, `Worries.has`, `Worries.key`, `Worries.firstWith`, `Worries.scanProfile`, `Worries.CHECKLIST_IDS`, `Worries.ON_THEIR_OWN` (Task 7); `worryIdsOf`, `orderLessons`/`lessonsByDistrict` with a list, `focusFor` with `ids` (Task 7); `Checklist.html`, `Checklist.attach` (Task 5); `scanArgs` with an array (Task 6); engine `--profile` repeatable (Task 4).
- Produces: the worry screen: `#situations` holds `Checklist.html({ id: 'worries', ... })` with one row per `Worries.CHECKLIST_IDS` entry and the action `data-cl-action="start"` ("Start the checkup for 2 worries"); `#situations-alone` holds one `button[data-situation]` each for "check everything" and the iPhone check. The page harness's `pick(...ids)` ticks the ids and presses start, or clicks the one on its own.

- [ ] **Step 1: Teach the page harness the checklist, and write the failing tests**

In `desktop/test/page-harness.js`, replace the `El` methods

```js
  // The buttons the page makes from HTML: one per data-situation or data-answer.
  set innerHTML(html) {
    this._html = String(html);
    this.kids = [...this._html.matchAll(/data-(situation|answer)="([^"]+)"/g)].map((m) => {
      const b = new El(this.doc); b.dataset[m[1]] = m[2]; return b;
    });
  }
```

with

```js
  // The controls the page makes from HTML: one per data-situation or
  // data-answer button, per worry checkbox (data-cl-key) and per checklist
  // button (data-cl-action).
  set innerHTML(html) {
    this._html = String(html);
    this.kids = [...this._html.matchAll(/data-(situation|answer|cl-key|cl-action)="([^"]+)"/g)].map((m) => {
      const b = new El(this.doc); b.dataset[m[1]] = m[2]; b.attrs = { [`data-${m[1]}`]: m[2] }; return b;
    });
  }
```

replace

```js
  querySelectorAll(sel) {
    const m = /^\[data-(situation|answer)\]$/.exec(sel);
    return m ? this.kids.filter((k) => m[1] in k.dataset) : [];
  }
  querySelector() { return null; }
  getAttribute() { return null; }
```

with

```js
  querySelectorAll(sel) {
    const m = /^\[data-(situation|answer|cl-key|cl-action)\]$/.exec(sel);
    return m ? this.kids.filter((k) => m[1] in k.dataset) : [];
  }
  querySelector() { return null; }
  getAttribute(name) { return this.attrs && name in this.attrs ? this.attrs[name] : null; }
```

and replace

```js
  const pick = (id) => byId('situations').kids.find((b) => b.dataset.situation === id).click();
```

with

```js
  // "Check everything" and the iPhone check are buttons of their own; the
  // other worries are ticked, then "Start the checkup" is pressed.
  const pick = (...ids) => {
    const alone = ids.length === 1 ? byId('situations-alone').kids.find((b) => b.dataset.situation === ids[0]) : null;
    if (alone) return alone.click();
    const kids = byId('situations').kids;
    for (const id of ids) {
      const box = kids.find((b) => b.dataset['cl-key'] === id);
      box.checked = true;
      (box.listeners.change || []).forEach((fn) => fn({ target: box }));
    }
    return kids.find((b) => 'cl-action' in b.dataset).click();
  };
```

Create `desktop/test/worry-checklist.test.js`:

```js
// The worry screen is a checklist: tick everything that sounds close, and the
// checkup runs every check any of them would run. "Watching me" among them
// means city mode, without asking. Nothing is ticked to start with.
const test = require('node:test');
const assert = require('node:assert');
const { SITUATIONS } = require('../renderer/app.js');
const { page } = require('./page-harness.js');

const KEY = 'device-rescue.display';
const modeWrites = (p) => p.storage.writes.filter(([k]) => k === KEY);
const profileOf = (id) => SITUATIONS.find((s) => s.id === id).profile;

test('the worry screen is a checklist of worries, with two on their own', () => {
  const p = page();
  const html = p.byId('situations').innerHTML;
  assert.match(html, /<fieldset class="checklist checklist--plain" data-cl-list="worries"/);
  for (const id of ['hacked', 'watched', 'wifi', 'identity', 'sketchy', 'helping']) {
    assert.match(html, new RegExp(`data-cl-key="${id}"`), id);
  }
  assert.ok(!/\bchecked\b/.test(html), 'nothing is ticked to start with');
  assert.match(html, /Select at least one/);
  const alone = p.byId('situations-alone').innerHTML;
  assert.match(alone, /data-situation="unsure"/);
  assert.match(alone, /data-situation="phone"/);
});

test('two worries run the union of their profiles in one scan', () => {
  const p = page();
  p.byId('btn-get-started').click();
  p.pick('hacked', 'wifi');
  assert.deepStrictEqual(p.shown(), ['scan']);
  p.byId('btn-run-scan').click();
  assert.deepStrictEqual(p.calls.scans, [[profileOf('hacked'), profileOf('wifi')]]);
});

test('"watching me" among several worries goes straight to city mode, without asking', () => {
  const p = page({ store: {} });
  p.byId('btn-get-started').click();
  p.pick('hacked', 'watched');
  assert.ok(!p.shown().includes('question'));
  assert.deepStrictEqual(modeWrites(p), [[KEY, 'city']]);
  assert.deepStrictEqual(p.calls.game, ['newWorry', 'showBoss']);
  assert.deepStrictEqual(p.calls.scans, ['digital_security_reset'], 'one profile, run once');
});

test('nothing ticked starts nothing', () => {
  const p = page();
  p.byId('btn-get-started').click();
  p.byId('situations').kids.find((b) => 'cl-action' in b.dataset).click();
  assert.deepStrictEqual(p.shown(), ['worry']);
  assert.deepStrictEqual(p.calls.scans, []);
});

test('"check everything" is a button of its own and runs every check', () => {
  const p = page();
  p.byId('btn-get-started').click();
  p.pick('unsure');
  p.byId('btn-run-scan').click();
  assert.deepStrictEqual(p.calls.scans, [null]);
});
```

Append to `desktop/test/first-question.test.js`:

```js
test('"watching me" among several worries still goes straight to city', () => {
  for (const mode of [null, 'standard', 'city']) {
    assert.strictEqual(FQ.afterWorry({ id: 'several', ids: ['hacked', 'watched'] }, mode), 'city');
  }
  assert.strictEqual(FQ.afterWorry({ id: 'several', ids: ['hacked', 'wifi'] }, 'standard'), 'standard');
  assert.strictEqual(FQ.afterWorry({ id: 'several', ids: ['hacked', 'wifi'] }, null), 'ask');
});
```

(`FQ` is the name `first-question.test.js` already gives `require('../renderer/first-question.js')`; if main's copy names it differently, use that name.)

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd desktop && node --test test/worry-checklist.test.js test/first-question.test.js`
Expected: FAIL. `worry-checklist` fails on the fieldset match (the screen still renders buttons); the new first-question test fails with `'ask' !== 'city'` for `mode: null`.

- [ ] **Step 3: "Watching me" among several worries in `desktop/renderer/first-question.js`**

Replace

```js
  function afterWorry(situation, mode) {
    if (situation && situation.id === STRAIGHT_TO_CITY) return 'city';
```

with

```js
  // Several worries can be ticked together; their ids are in situation.ids.
  function idsOf(situation) {
    if (!situation) return [];
    return Array.isArray(situation.ids) ? situation.ids : [situation.id];
  }

  // "Watching me" among the worries goes straight to 'city', whatever else was ticked.
  function afterWorry(situation, mode) {
    if (idsOf(situation).includes(STRAIGHT_TO_CITY)) return 'city';
```

- [ ] **Step 4: The worry screen markup in `desktop/renderer/index.html`**

Replace

```html
          <p class="lede">Pick the one that sounds closest. You can come back and choose another afterward.</p>
          <ul id="situations" class="situations"></ul>
```

with

```html
          <p class="lede">Tick everything that sounds close. You can come back and choose again afterward.</p>
          <div id="situations" class="situations-checklist"></div>
          <p class="muted">Or one of these, on its own:</p>
          <ul id="situations-alone" class="situations"></ul>
```

and directly above `<script src="app.js"></script>`, add:

```html
  <script src="worries.js"></script>
```

- [ ] **Step 5: Several worries in `desktop/renderer/app.js`**

Directly below the closing `];` of `const SITUATIONS = [ ... ];`, add:

```js
// worries.js loads before app.js in the page; the Node tests require it.
const WorryPick = typeof Worries !== 'undefined' ? Worries : require('./worries.js');
```

In `mayBeWatched`, replace

```js
  if (situation && (situation.safety || situation.id === 'phone')) return true;
```

with

```js
  if (situation && (situation.safety || WorryPick.has(situation, 'phone'))) return true;
```

Replace `gameOfferedFor`'s body line

```js
  return !!situation && situation.id !== 'phone';
```

with

```js
  return !!situation && !WorryPick.has(situation, 'phone');
```

In `learnMoreFor`, replace

```js
  const entry = LEARN_MORE[situation.id];
```

with

```js
  // Several worries: the first one (in the list's order) that has a suggestion.
  const entry = WorryPick.firstWith(situation, LEARN_MORE);
```

In `leaveGame`, replace

```js
        if (lastScanDoc && !scanRunning && lastScanSituation === situation) showScreen('results');
```

with

```js
        if (lastScanDoc && !scanRunning && WorryPick.key(lastScanSituation) === WorryPick.key(situation)) showScreen('results');
```

Replace the whole `renderSituations` function

```js
    function renderSituations() {
      const list = document.getElementById('situations');
      list.innerHTML = SITUATIONS.map(
        (s) => `
          <li>
            <button type="button" class="situation" data-situation="${escapeHtml(s.id)}">
              <span class="situation__icon" aria-hidden="true">${escapeHtml(s.icon)}</span>
              <span class="situation__text">
                <span class="situation__title">${escapeHtml(s.title)}</span>
                <span class="situation__sub">${escapeHtml(s.sub)}</span>
              </span>
            </button>
          </li>`
      ).join('');
      list.querySelectorAll('[data-situation]').forEach((btn) => {
        btn.addEventListener('click', () => {
          situation = SITUATIONS.find((s) => s.id === btn.dataset.situation) || null;
          const next = FirstQuestion.afterWorry(situation, mode);
          if (next === 'ask') { ask('first', startWorry); return; }
          if (next !== mode) setMode(next);
          startWorry();
        });
      });
    }
```

with

```js
    // The worries: a checklist of the ones that combine, unticked, and a
    // button each for the two that run on their own ("check everything" and
    // the iPhone check). Ticking changes nothing until "Start the checkup".
    function renderSituations() {
      const list = document.getElementById('situations');
      const alone = document.getElementById('situations-alone');
      list.innerHTML = Checklist.html({
        id: 'worries',
        legend: 'What’s worrying you?',
        items: SITUATIONS.filter((s) => WorryPick.CHECKLIST_IDS.includes(s.id))
          .map((s) => ({ key: s.id, label: s.title, note: s.sub })),
        actions: [{ id: 'start', verb: 'Start the checkup for', noun: ['worry', 'worries'], min: 1 }],
        selectAll: false,
      });
      alone.innerHTML = SITUATIONS.filter((s) => WorryPick.ON_THEIR_OWN.includes(s.id)).map(
        (s) => `
          <li>
            <button type="button" class="situation" data-situation="${escapeHtml(s.id)}">
              <span class="situation__icon" aria-hidden="true">${escapeHtml(s.icon)}</span>
              <span class="situation__text">
                <span class="situation__title">${escapeHtml(s.title)}</span>
                <span class="situation__sub">${escapeHtml(s.sub)}</span>
              </span>
            </button>
          </li>`
      ).join('');
      // The count, the button's words and the arrow keys.
      Checklist.attach(list, {});
      const start = list.querySelectorAll('[data-cl-action]')[0];
      if (start) {
        start.addEventListener('click', () => {
          const ids = Array.from(list.querySelectorAll('[data-cl-key]'))
            .filter((box) => box.checked === true)
            .map((box) => box.getAttribute('data-cl-key'));
          const picked = WorryPick.combine(ids, SITUATIONS);
          if (picked) chooseWorry(picked);
        });
      }
      alone.querySelectorAll('[data-situation]').forEach((btn) => {
        btn.addEventListener('click', () => {
          const picked = WorryPick.combine([btn.dataset.situation], SITUATIONS);
          if (picked) chooseWorry(picked);
        });
      });
    }

    // One worry or several: the display preference first, then the scan.
    function chooseWorry(picked) {
      situation = picked;
      const next = FirstQuestion.afterWorry(situation, mode);
      if (next === 'ask') { ask('first', startWorry); return; }
      if (next !== mode) setMode(next);
      startWorry();
    }
```

In `runCheckup`, replace

```js
        const doc = await window.rescue.runScan(situation ? situation.profile : null);
```

with

```js
        // One profile, the union of several (one --profile each), or null for every check.
        const doc = await window.rescue.runScan(WorryPick.scanProfile(situation));
```

- [ ] **Step 6: Several worries in the game's controller**

In `desktop/renderer/game/controller.js`, replace the import

```js
import { loadLessons, orderLessons, lessonForModule, afterScanDone, lessonsByDistrict, districtLesson } from './training.js';
```

with

```js
import { loadLessons, orderLessons, lessonForModule, afterScanDone, lessonsByDistrict, districtLesson, worryIdsOf } from './training.js';
```

Replace

```js
    const by = lessonsByDistrict(s.lessons, s.situation && s.situation.id);
```

with

```js
    const by = lessonsByDistrict(s.lessons, worryIdsOf(s.situation));
```

and replace

```js
      return renderTraining({ ordered: orderLessons(s.lessons, s.situation && s.situation.id), progress: s.progress,
```

with

```js
      return renderTraining({ ordered: orderLessons(s.lessons, worryIdsOf(s.situation)), progress: s.progress,
```

Then confirm nothing else in the game reads a single worry id:

Run: `grep -rn "situation\.id\|situation && s.situation.id" desktop/renderer/game desktop/renderer/app.js`
Expected: no lines from `desktop/renderer/game`; in `app.js`, none outside comments. (`focusFor` reads `ids` since Task 7; `worryTitle` reads `title`, which a combined situation has.)

- [ ] **Step 7: Run the tests to verify they pass**

Run: `cd desktop && node --test test/worry-checklist.test.js test/first-question.test.js test/first-question-flow.test.js test/game-worry-scan.test.js test/learn-more.test.js test/situations.test.js test/game-gate.test.js test/game-flow-gate.test.js`
Expected: PASS (all). The existing flow tests call `p.pick('wifi')`, which now ticks and presses start; `p.pick('phone')` and `p.pick('unsure')` click their own buttons.

- [ ] **Step 8: Run the whole desktop suite**

Run: `cd desktop && npm test`
Expected: PASS (all).

- [ ] **Step 9: Check it in the real app**

Run: `cd desktop && RESCUE_ENGINE=../.venv/bin/rescue npm start`. On the worry screen: nothing is ticked; the button says "Select at least one"; tick "I think I've been hacked" and "Someone is on my Wi-Fi…" with the keyboard (Tab, Space, arrow keys); the button reads "Start the checkup for 2 worries" and the count "2 of 6 selected". Press it, answer the one question, and on the scan screen confirm it reads "Checking for: … and …". Go back and tick "I think someone is watching me" with another worry: no question is asked and the app goes to the city. Do not run the full scan unless you mean to; Back is enough.

- [ ] **Step 10: Commit**

```bash
git add desktop/renderer/index.html desktop/renderer/app.js desktop/renderer/first-question.js desktop/renderer/game/controller.js desktop/test/page-harness.js desktop/test/worry-checklist.test.js desktop/test/first-question.test.js
git commit -m "$(cat <<'EOF'
Desktop: tick every worry that fits; the checkup runs all their checks

"Check everything" and the iPhone check stay buttons of their own. "Watching
me" among the ticked worries still goes straight to city mode. Lessons,
the starting district and the Reclaim City link read every worry.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```

---

## Ambiguities resolved in this plan

- **Startup items (L7b) are not in this plan.** They aren't markable at all today, and the spec ties per-item startup marks and fixes to Phase 3 (3b). This plan covers the two lists that are markable now: apps per permission and remote-login keys.
- **An app's maker is pinned as `team:<Team ID>`, `apple`, or `unsigned`**, from the same verified signature check "Who made it?" uses, run only for list entries (at most 60 per finding). When it can't be checked now, the row is shown without a checkbox and its mark (if any) shows as changed. The spec named the field `signer`; this fixes its values.
- **`data.marked_items` holds objects (`{id, entry, shown, marked_at}`)**, not bare ids as the spec sketched, so the app can list and undo each one without a second lookup. A list marked entry by entry has `marked_by_user: true` but no `known_item_id`; that field stays for whole-list marks.
- **A key's comment is shown in the app only.** It is in `data.keys` for the checklist, never in a description or a `shown` label, and `rescue export` replaces it, because comments are often user@host or an email address the email rule may miss.
- **Bulk marking stays inside one finding.** `handleMark` with items sends only that finding's `{code, id}`, never the other checks' lists for the same apps.
- **"Check everything" and the iPhone check are not in the worry checklist.** The first already covers every worry; the second reads a large phone backup and must not start alongside another scan (AGENTS.md rule 5). They stay buttons of their own below the checklist.
- **Several worries are one engine scan.** The engine takes `--profile` more than once and runs the union, keeping each profile's module settings; two profiles that set the same setting differently are refused (no shipped pair does, and a test pins that). The app does not merge module lists itself.
- **A combined worry links the first chosen worry's guide** and the first Reclaim City suggestion that applies, in the worry list's order.
- **The plain fallback (`NOT_SURE_LIST`, "Yes, these are mine") stays** for lists whose rows don't line up, for lists too long to show entry by entry, and for older engines that send no `items`.

## Self-review

**1. Spec coverage.**
- 2.2 "Selection never changes anything", memory only, confirmation lists every ticked item with evidence, `ONLY_IF_YOURS` once at the top: Tasks 5 and 8 (`openItemsConfirm`, the confirm block). Bulk "It's mine" inside one finding, never for monitoring checks: Tasks 6 and 8; `NEVER_MARKABLE_MODULES` checked in Tasks 1, 2, 6, 8. Bulk fix and game tags: not in scope (Phase 3b and the missions plan).
- 2.3.1 per-item identity for apps (with `signer`) and keys (with `data.keys` from `session_revocation_scan`, comments redacted in export): Tasks 1 and 3. Startup items: out of scope (see Ambiguities).
- 2.3.2 `markable.items` with the whole-list `id` kept: Task 2.
- 2.3.3 partial marks keep the warning, engine-count title, `marked_items`/`unmarked`, unmarked listed first, marked entries never dropped, stale entries, new entries, criticals never downgraded: Task 1.
- 2.3.4 retiring per entry: Task 1.
- 2.3.5 CLI `--item`, fresh check, all-or-none, terminal prompt listing each item, default No, refuses without a terminal, list id alone is today's mark: Task 2.
- 2.3.6 undo per item, `known list` one line per mark, "Stop treating this as mine" per row: Tasks 2, 6, 8.
- 2.3.7 desktop plumbing (`remember` stores items, renderer sends ids only, main checks each, `--item` argv, rows never dropped): Tasks 6 and 8.
- 2.3.8 tests listed in the spec (partial keeps warning, new entry, signer change, `--item` not in fresh check, no TTY, monitoring refuse, forged IPC id, confirmation lists exactly the ticked rows): Tasks 1, 2, 6, 8.
- 2.4 component (fieldset/legend, real labels, escaped and `visible()`, select all/none as buttons, disabled skipped, live count, named primary button, "Select at least one", keyboard, Escape via the panels, nothing before Yes, memory-only selection, 50 then "Show all"): Task 5 (Escape is the panel's, Task 8). Its use in the "It's mine" panel: Task 8. The other uses in the 2.4 table (result cards, info group, couldn't-check, step lists, deck): other plans.
- Owner decisions 3 (unticked), 6 (bulk within one finding, with the watching warning), 7 (worry checklist, union of profiles): Tasks 5, 8, 9 and 4.
- Game: lessons, focus district, the safety gate and stealth for several worries: Tasks 7 and 9 (`orderLessons`, `focusFor`, `mayBeWatched` via combined `safety`, `afterWorry`).

**2. Placeholder scan.** No "TBD", "TODO", "similar to Task N", or steps without code. The two places that depend on main after the `reclaim-city` merge (controller call sites, the `FQ` name) give the exact before/after text and a grep to find them.

**3. Type consistency.** `ENTRY_KIND_FOR`, `list_entries`, `entry_identity`, `entry_offers`, `entries_will_change`, `find_entries` and `app_signer` are spelled the same in Tasks 1 and 2. `markable.items[]` fields (`key`, `label`, `detail`, `id`, `marked`, `stale`) match between Task 2 (engine), Task 6 (`offeredEntryIds`, `markedEntryIds`) and Task 8 (`validEntry`). `target.chosen` is set in Task 6's `handleMark` and read by `markArgs`/`entryMarkArgs` and `rememberMarked`. `api.markMine(id, ids)` / `api.unmarkMine(ids)` match Task 8's preload and main. `Worries.*` names match between Tasks 7 and 9; `worryIdsOf` is exported by Task 7 and imported in Task 9. The checklist's `data-cl-*` attributes match between Task 5 (`html`, `attach`), Task 8 (tests and `onAction`) and Task 9 (harness and `renderSituations`).

**4. Review Focus.** Each of the five lines names its pinning test and the task that owns it; all five tests appear in those tasks' Step 1.

## Execution handoff

Plan complete and saved to `docs/superpowers/plans/2026-10-18-checklists-and-subset-marks.md`. Please review the plan. Which execution approach would you prefer?

- **Subagent-driven**: a fresh subagent implements each task and a fresh reviewer checks it before the next one starts, then a whole-branch review at the end. Most thorough; costs a fresh context per task and per review.
- **Native**: one session implements every task, then one fresh reviewer on the most capable model checks the whole branch. Cheapest and fastest; no independent review until the end.

For this plan I recommend **subagent-driven**, because Tasks 1 to 7 are independent enough to run in parallel worktrees now, Tasks 8 and 9 depend on exact interfaces from four earlier tasks and on a branch still being merged, and a mistake here (a mark that covers more than the person ticked) is the kind of thing a fresh reviewer should catch before it ships.
