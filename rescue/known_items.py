"""Items the person at the keyboard has said are theirs ("marked as mine").

A scan flags things it cannot tell apart from unwanted software, such as a
background task that runs from a hidden folder. On a developer's machine that
can be their own tool, flagged on every scan. This lets the person say "I know
this one" without anyone shipping a name-based exception that an attacker
could copy.

The rules that keep it from becoming a way to hide stalkerware:

* A mark pins identity, not a name, and covers one kind of finding. For a
  background task that is the finding code (which names the check), the
  label, the plist path, the program path, and a hash of the full
  ProgramArguments. Every field must match exactly; if any changes, the mark
  stops matching and the original finding comes back.
* A marked finding is never hidden. It is downgraded to info, retitled
  "... you marked as yours", and carries ``data["marked_by_user"] = True``
  plus when it was marked, so a helper reviewing the scan or an export sees it.
* A critical finding (for example a known virus) is never downgraded.
* Adding a mark needs the person: an interactive confirmation in the terminal,
  or the app's own confirmation (which passes ``--i-understand``).
* The list lives in the person's home folder, outside the install. It is
  opened without following symlinks; if it (or its folder) is not owned by
  this user, or other users can write to it, or it cannot be read, no mark
  applies and the scan says so. Any malformed entry matches nothing.

Storage: ``~/.rescue/known_items.json`` (override with ``$RESCUE_KNOWN_ITEMS``,
which the test suite always sets).

Only background tasks are wired up today. Another module adopts this by
building an identity for each item it reports (a dict of strings, under a new
kind in KINDS), and calling :func:`apply_marks` on its findings.
"""

from __future__ import annotations

import hashlib
import json
import os
import plistlib
import stat
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable

from rescue.models import Finding, Severity

ENV_PATH = "RESCUE_KNOWN_ITEMS"
SCHEMA_VERSION = 1

BACKGROUND_TASK = "background_task"

# kind -> (identity keys, modules whose findings honour it, marked title)
KINDS: dict[str, dict] = {
    BACKGROUND_TASK: {
        "keys": ("code", "label", "plist", "program", "arguments_sha256"),
        "modules": ("launch_agent_audit", "launchd_persistence_audit"),
        "title": "Background task you marked as yours: {label}",
        "noun": "background task",
    },
}

MARK_WILL_CHANGE = (
    "Device Rescue will stop warning you about the background task '{label}'. "
    "It will still be listed, as \"marked as yours\", on every checkup and in "
    "anything you export, so anyone helping you can see it. If the task's "
    "program or settings file ever changes, the warning comes back."
)
MARK_HOW_TO_UNDO = [
    "Choose \"Stop treating this as mine\" on the item in Device Rescue",
    "Or run: rescue known remove <id> (rescue known list shows the id)",
]


class KnownItemsError(Exception):
    """The list could not be read or written. The message is plain language."""


def default_path() -> Path:
    override = os.environ.get(ENV_PATH)
    if override:
        return Path(override).expanduser()
    return Path.home() / ".rescue" / "known_items.json"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def item_id(kind: str, identity: dict) -> str:
    blob = json.dumps({"kind": kind, "identity": identity}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:12]


@dataclass
class KnownItem:
    kind: str
    identity: dict[str, str]
    marked_at: str = ""
    marked_via: str = ""
    id: str = field(default="")

    def __post_init__(self):
        if not self.id:
            self.id = item_id(self.kind, self.identity)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "kind": self.kind,
            "identity": dict(self.identity),
            "marked_at": self.marked_at,
            "marked_via": self.marked_via,
        }

    @classmethod
    def from_dict(cls, data) -> "KnownItem | None":
        """None for anything malformed: a bad entry never turns into a match."""
        if not isinstance(data, dict):
            return None
        kind = data.get("kind")
        identity = data.get("identity")
        spec = KINDS.get(kind)
        if spec is None or not isinstance(identity, dict):
            return None
        if set(identity) != set(spec["keys"]):
            return None
        if not all(isinstance(identity[k], str) and identity[k] for k in spec["keys"]):
            return None
        # The id is always recomputed, so editing it in the file cannot make an
        # entry match something else.
        return cls(
            kind=kind,
            identity={k: identity[k] for k in spec["keys"]},
            marked_at=str(data.get("marked_at") or ""),
            marked_via=str(data.get("marked_via") or ""),
        )


def _untrusted_reason(st, what: str) -> str | None:
    if not hasattr(os, "getuid"):
        return None
    if st.st_uid != os.getuid():
        return f"{what} belongs to a different user"
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        return f"other users can change {what}"
    return None


def _read_trusted(path: Path) -> str:
    """The file's text, read without following a symlink, after checking that
    it and its folder belong to this user and nobody else can write them.

    Raises KnownItemsError with a plain-language reason otherwise.
    """
    try:
        parent = os.lstat(path.parent)
    except OSError as exc:
        raise KnownItemsError(f"Could not read the folder holding {path}: {exc}") from exc
    if stat.S_ISLNK(parent.st_mode):
        raise KnownItemsError(f"The folder holding {path} is a shortcut (symlink), so the list was not used.")
    reason = _untrusted_reason(parent, "the folder holding the list")
    if reason:
        raise KnownItemsError(f"{path} was not used: {reason}.")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise KnownItemsError(
            f"{path} could not be opened (a shortcut/symlink is never followed): {exc}"
        ) from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise KnownItemsError(f"{path} is not an ordinary file, so it was not used.")
        reason = _untrusted_reason(st, "the list")
        if reason:
            raise KnownItemsError(f"{path} was not used: {reason}.")
        fh = os.fdopen(fd, "r", encoding="utf-8")
        fd = -1
        with fh:
            return fh.read(1_000_000)
    finally:
        if fd >= 0:
            os.close(fd)


class KnownItemsStore:
    def __init__(self, path: Path | None = None):
        self.path = Path(path) if path is not None else default_path()

    def exists(self) -> bool:
        return os.path.lexists(self.path)

    def load(self) -> list[KnownItem]:
        """Every valid entry. Missing file = empty.

        Raises KnownItemsError if the file is unreadable, not JSON, the wrong
        shape, a symlink, or owned/writable by someone else. Malformed entries
        are dropped, so they can never match anything.
        """
        if not self.exists():
            return []
        text = _read_trusted(self.path)
        try:
            data = json.loads(text)
        except ValueError as exc:
            raise KnownItemsError(f"{self.path} is damaged (not valid JSON), so it was not used.") from exc
        entries = data.get("items") if isinstance(data, dict) else None
        if not isinstance(entries, list):
            raise KnownItemsError(f"{self.path} is not a list of marked items, so it was not used.")
        items = [KnownItem.from_dict(e) for e in entries]
        return [i for i in items if i is not None]

    def load_for_scan(self) -> tuple[list[KnownItem], str | None]:
        """(marks a check may honour, why the list was ignored or None).

        Any doubt means no marks, so every finding shows as it normally would.
        """
        try:
            return self.load(), None
        except KnownItemsError as exc:
            return [], str(exc)
        except Exception as exc:  # never let the list break a check
            return [], f"{self.path} could not be read: {exc}"

    def _save(self, items: list[KnownItem]) -> None:
        directory = self.path.parent
        directory.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(directory, 0o700)
        except OSError:
            pass
        doc = {"schema_version": SCHEMA_VERSION, "items": [i.to_dict() for i in items]}
        fd, tmp = tempfile.mkstemp(prefix=".known_items.", dir=str(directory))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(doc, fh, indent=2)
                fh.write("\n")
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def add(self, kind: str, identity: dict, via: str = "") -> tuple[KnownItem, bool]:
        # load() refuses an untrusted or damaged list, so nothing is written on top of one.
        """(item, created). Adding the same identity twice is a no-op."""
        item = KnownItem(kind=kind, identity=dict(identity), marked_at=_now(), marked_via=via)
        if KnownItem.from_dict(item.to_dict()) is None:
            raise KnownItemsError("That item is missing part of what identifies it.")
        items = self.load()
        for existing in items:
            if existing.id == item.id:
                return existing, False
        items.append(item)
        self._save(items)
        return item, True

    def remove(self, wanted_id: str) -> KnownItem | None:
        items = self.load()
        keep = [i for i in items if i.id != wanted_id]
        if len(keep) == len(items):
            return None
        self._save(keep)
        return next(i for i in items if i.id == wanted_id)


# --- background tasks ---------------------------------------------------------


def arguments_sha256(arguments: Iterable[str]) -> str:
    """Hash of the full ProgramArguments. The interpreter path alone (a venv's
    python) says nothing about which script it runs; the arguments do."""
    blob = json.dumps([str(a) for a in arguments], separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def background_task_identity(
    label: str, program: str, plist: str, arguments: Iterable[str], code: str | None = None
) -> dict | None:
    """The pinned identity of one background task. Without `code` it is the item
    alone (what a check knows before it has findings); apply_marks adds the code
    of each finding before matching."""
    if not (label and program and plist):
        return None
    ident = {
        "label": str(label),
        "plist": str(plist),
        "program": str(program),
        "arguments_sha256": arguments_sha256(arguments or []),
    }
    if code is not None:
        ident["code"] = str(code)
    return ident


def code_is_markable(kind: str, code) -> bool:
    """Only codes emitted by a module that honours this kind of mark."""
    spec = KINDS.get(kind)
    if spec is None or not isinstance(code, str):
        return False
    parts = code.split(".")
    return len(parts) == 3 and all(parts) and parts[1] in spec["modules"]


def launchd_dirs() -> list[Path]:
    """Folders a background task's plist may live in."""
    return [
        Path.home() / "Library" / "LaunchAgents",
        Path("/Library/LaunchAgents"),
        Path("/Library/LaunchDaemons"),
    ]


def read_launchd_plist(plist_path) -> tuple[str, str, list[str]]:
    """(label, program, arguments) read exactly as the background-task checks read them.

    Raises KnownItemsError if the file cannot be read as a plist.
    """
    path = Path(plist_path)
    try:
        with open(path, "rb") as fh:
            data = plistlib.load(fh)
    except Exception as exc:
        raise KnownItemsError(f"{path} could not be read as a settings (plist) file.") from exc
    if not isinstance(data, dict):
        raise KnownItemsError(f"{path} is not a background task settings file.")
    label = data.get("Label")
    if not isinstance(label, str) or not label:
        label = path.stem
    args = data.get("ProgramArguments")
    if isinstance(args, str):
        args = [args]
    arguments = [str(a) for a in args] if isinstance(args, (list, tuple)) else []
    program = data.get("Program")
    if isinstance(program, (list, tuple)):
        program = " ".join(str(a) for a in program)
    elif program and not isinstance(program, str):
        program = str(program)
    if not program:
        program = arguments[0] if arguments else ""
    return label, program.strip().strip("\"'"), arguments


def find_background_task(label: str, program: str, plist: str | None = None, code: str | None = None) -> dict:
    """Identity of the background task on disk with this label and program.

    With `code`, the identity is pinned to that finding code (needed to save a mark).

    The plist must be an ordinary file directly inside one of launchd_dirs().
    Raises KnownItemsError with a plain-language reason otherwise.
    """
    allowed = {Path(os.path.realpath(d)) for d in launchd_dirs()}
    if plist:
        raw = os.path.expanduser(str(plist))
        if "\0" in raw or not os.path.isabs(raw):
            raise KnownItemsError("The settings file must be given as a full path.")
        candidates = [Path(raw)]
    else:
        candidates = []
        for d in launchd_dirs():
            try:
                candidates.extend(sorted(d.glob("*.plist")))
            except OSError:
                continue
    matches = []
    for cand in candidates:
        try:
            st = os.lstat(cand)
        except OSError:
            if plist:
                raise KnownItemsError(f"{cand} does not exist.") from None
            continue
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            if plist:
                raise KnownItemsError(f"{cand} is not an ordinary file.")
            continue
        if Path(os.path.realpath(cand)).parent not in allowed:
            raise KnownItemsError(
                f"{cand} is not in a background task folder "
                "(~/Library/LaunchAgents, /Library/LaunchAgents or /Library/LaunchDaemons)."
            )
        try:
            found_label, found_program, arguments = read_launchd_plist(cand)
        except KnownItemsError:
            if plist:
                raise
            continue
        if found_label == label and found_program == program:
            matches.append((cand, arguments))
        elif plist:
            raise KnownItemsError(
                f"{cand} is for '{found_label}', running {found_program or '(nothing)'}, "
                "which is not what you named. Nothing was marked."
            )
    if not matches:
        raise KnownItemsError(
            f"No background task named '{label}' that runs {program} was found. Nothing was marked."
        )
    if len(matches) > 1:
        raise KnownItemsError(
            f"More than one background task is named '{label}'. Name the one you mean with --plist."
        )
    cand, arguments = matches[0]
    if code is not None and not code_is_markable(BACKGROUND_TASK, code):
        raise KnownItemsError(f"'{code}' is not a background-task finding that can be marked.")
    return background_task_identity(label, program, str(cand), arguments, code)


# --- applying marks to findings ----------------------------------------------


def marked_description(finding: Finding, item: KnownItem, noun: str) -> str:
    when = item.marked_at or "an unknown date"
    return (
        f"You marked this {noun} as yours on {when}, so it is no longer flagged. "
        "It stays on this list so that anyone helping you can see it.\n\n"
        f"What the check found before it was marked: {finding.title}\n\n"
        f"If you did not mark it, or you do not recognize it, undo the mark with "
        f"\"rescue known remove {item.id}\" (or \"Stop treating this as mine\" in the app) "
        "and the warning comes back.\n\n"
        f"Original details:\n{finding.description}"
    )


def apply_marks(
    findings: list[Finding],
    kind: str,
    identify: Callable[[Finding], dict | None],
    items: list[KnownItem] | None = None,
) -> list[Finding]:
    """Downgrade findings that match a mark (in place); returns the same list.

    identify(finding) gives the identity of the item a finding is about
    (without the code), or None. The finding's own code is added, so a mark
    covers only the kind of finding it was made for. A match is an exact match
    of every pinned field (the id is a hash over all of them); anything else,
    including a missing or empty field, matches nothing. Critical findings are
    never downgraded; they are tagged instead.

    If the list exists but was not used (unreadable, symlink, wrong owner,
    writable by others), an info finding says so.
    """
    spec = KINDS[kind]
    if items is None:
        items, problem = KnownItemsStore().load_for_scan()
        if problem and findings:
            findings.append(Finding(
                title="Your \"marked as yours\" list was not used",
                description=(
                    f"{problem}\n\nNothing on this checkup was treated as marked, so "
                    "everything is shown as it normally would be. If you did not "
                    "change this file, someone or something else may have."
                ),
                severity=Severity.INFO,
                category=findings[0].category,
                data={"check": "known_items_ignored", "path": str(default_path())},
            ))
    by_id = {i.id: i for i in items if i.kind == kind}
    if not by_id:
        return findings
    for finding in findings:
        code = getattr(finding, "code", None)
        if not code_is_markable(kind, code):
            continue
        try:
            identity = identify(finding)
        except Exception:
            identity = None
        if not isinstance(identity, dict):
            continue
        identity = dict(identity, code=code)
        if set(identity) != set(spec["keys"]) or not all(
            isinstance(identity[k], str) and identity[k] for k in spec["keys"]
        ):
            continue
        item = by_id.get(item_id(kind, identity))
        if item is None:
            continue
        if finding.severity == Severity.CRITICAL:
            finding.data["user_mark_ignored"] = True
            finding.data["known_item_id"] = item.id
            finding.description = (
                f"{finding.description}\n\nYou marked this {spec['noun']} as yours, but this "
                "finding is serious enough that a mark does not quiet it."
            )
            continue
        finding.data.update(
            {
                "marked_by_user": True,
                "known_item_id": item.id,
                "marked_at": item.marked_at,
                "original_severity": finding.severity.value,
                "original_title": finding.title,
            }
        )
        finding.description = marked_description(finding, item, spec["noun"])
        finding.title = spec["title"].format(label=identity.get("label", ""))
        finding.severity = Severity.INFO
    return findings


def markable(finding: Finding, module_name: str) -> dict | None:
    """The `markable` block the app may offer on a finding, or None.

    Only warnings from a module that honours background-task marks, about a
    task whose label, program and plist are known, and not already marked.
    """
    spec = KINDS[BACKGROUND_TASK]
    if module_name not in spec["modules"]:
        return None
    if getattr(finding, "severity", None) != Severity.WARNING:
        return None
    data = getattr(finding, "data", None)
    if not isinstance(data, dict) or data.get("marked_by_user"):
        return None
    code = getattr(finding, "code", None)
    if not code_is_markable(BACKGROUND_TASK, code):
        return None
    fields = {k: data.get(k) for k in ("label", "program", "plist", "arguments_sha256")}
    if not all(isinstance(v, str) and v and "\0" not in v for v in fields.values()):
        return None
    if not fields["plist"].startswith("/") or not fields["program"].startswith(("/", "~")):
        return None
    identity = {**fields, "code": code}
    return {
        "kind": BACKGROUND_TASK,
        # The engine refuses to save unless the task on disk still hashes to this.
        "id": item_id(BACKGROUND_TASK, identity),
        "code": code,
        **fields,
        "will_change": MARK_WILL_CHANGE.replace("{label}", fields["label"]),
        "how_to_undo": list(MARK_HOW_TO_UNDO),
    }
