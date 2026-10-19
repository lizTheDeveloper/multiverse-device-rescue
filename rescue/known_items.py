"""Items the person at the keyboard has said are theirs ("marked as mine").

A scan flags things it cannot tell apart from unwanted software, such as a
background task that runs from a hidden folder. On a developer's machine that
can be their own tool, flagged on every scan. This lets the person say "I know
this one" without anyone shipping a name-based exception that an attacker
could copy.

The rules that keep it from becoming a way to hide stalkerware:

* A mark pins identity, not a name, and covers one kind of finding. For a
  background task that is the finding code (which names the check), the
  label, the plist path, the program path, a hash of the full
  ProgramArguments, and a hash of the CONTENT of what runs: the program file
  (and its resolved path, so a symlink swap shows) plus any script file the
  arguments name in the home folder or a hidden folder. Every field must match
  exactly. If only the content changed, the finding is shown again with a note
  saying so ("mark_stale"); a person who updated their own tool can mark it
  again. For people being watched we prefer that noise to a mark that keeps
  covering a program someone swapped out. Content that cannot be hashed
  (missing, unreadable, over 200 MB) cannot be marked and never matches.
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

Two families of kinds:

* Background tasks (``background_task``): the checks call
  :func:`apply_background_task_marks` themselves, because the identity needs a
  hash of files on disk.
* Settings and installed items (``ITEM_KINDS``: a sharing service, a proxy, a
  VPN, a certificate, an extension...): the identity is read from the
  finding's own evidence (``data``), every pinned field is a non-empty string,
  and the orchestrator applies marks to every module's findings after its
  check ran (:func:`apply_item_marks`). Each kind names "evidence" fields: if
  the item is the same (same code and the same base fields) but its evidence
  differs, the mark is stale and the finding comes back with a sentence
  saying it changed. When a mark is saved the engine runs the check again and
  refuses unless the item still hashes to the id the person saw.

Findings from checks for monitoring software (stalkerware, iPhone spyware,
keyloggers) can never be marked: see NEVER_MARKABLE_MODULES.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import plistlib
import stat
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable

from rescue.app_names import app_rows, display_name
from rescue.models import Finding, Severity

logger = logging.getLogger(__name__)

ENV_PATH = "RESCUE_KNOWN_ITEMS"
SCHEMA_VERSION = 1

BACKGROUND_TASK = "background_task"

# kind -> (identity keys, modules whose findings honour it, marked title)
KINDS: dict[str, dict] = {
    BACKGROUND_TASK: {
        "keys": ("code", "label", "plist", "program", "arguments_sha256", "content_sha256"),
        # Matched separately, so a content change can be reported as "changed".
        "content_key": "content_sha256",
        "modules": ("launch_agent_audit", "launchd_persistence_audit"),
        "title": "Background task you marked as yours: {label}",
        "noun": "background task",
    },
}

MARK_WILL_CHANGE = (
    "The checkup will stop warning you about the background task '{label}'. "
    "It will still be listed, as \"marked as yours\", on every checkup and in "
    "anything you export, so anyone helping you can see it. If the task's "
    "program, the script it runs, or its settings file ever changes, the "
    "warning comes back."
)
# The app's confirmation: one "Yes, it's mine" marks the task under every
# check that warned about it in that checkup (see link_task_marks).
MARK_COVERS_TASK = (
    "This covers every warning about this task on this checkup."
)
MARK_HOW_TO_UNDO = [
    "Choose \"Stop treating this as mine\" on the item in this app",
]
# The same, for a tech helper at the command line. Kept apart from the steps
# above so the app shows it only under "For tech helpers".
MARK_HOW_TO_UNDO_CLI = "rescue known remove <id> (rescue known list shows the id)"


class KnownItemsError(Exception):
    """The list could not be read or written. The message is plain language."""


def default_path() -> Path:
    override = os.environ.get(ENV_PATH)
    if override:
        return Path(override).expanduser()
    return Path.home() / ".rescue" / "known_items.json"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _evidence_keys(kind: str) -> set:
    spec = KINDS.get(kind, {})
    keys = set(spec.get("evidence_keys", ()))
    if spec.get("content_key"):
        keys.add(spec["content_key"])
    return keys


def base_identity(kind: str, identity: dict) -> dict:
    """The identity without the fields that may change while it is still the
    same item (a content hash, a proxy's server...). Used only to say "it changed"."""
    drop = _evidence_keys(kind)
    return {k: v for k, v in identity.items() if k not in drop}


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

    @property
    def base_id(self) -> str:
        return item_id(self.kind, base_identity(self.kind, self.identity))

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
        Called once per scan, so it also starts a fresh program-hashing budget.
        """
        reset_hash_budget()
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
        """(item, created). Adding the same identity twice is a no-op."""
        return self.add_many(kind, [identity], via=via)[0]

    def add_many(self, kind: str, identities: list[dict], via: str = "") -> list[tuple[KnownItem, bool]]:
        """[(item, created)] for each identity, written in one save: all or none.

        load() refuses an untrusted or damaged list, so nothing is written on top of one.
        """
        now = _now()
        wanted = []
        for identity in identities:
            item = KnownItem(kind=kind, identity=dict(identity), marked_at=now, marked_via=via)
            if KnownItem.from_dict(item.to_dict()) is None:
                raise KnownItemsError("That item is missing part of what identifies it.")
            wanted.append(item)
        if not wanted:
            raise KnownItemsError("Nothing to mark.")
        items = self.load()
        by_id = {i.id: i for i in items}
        out = []
        for item in wanted:
            existing = by_id.get(item.id)
            if existing is not None:
                out.append((existing, False))
                continue
            items.append(item)
            by_id[item.id] = item
            out.append((item, True))
        if any(created for _, created in out):
            self._save(items)
        return out

    def remove(self, wanted_id: str) -> KnownItem | None:
        removed = self.remove_many([wanted_id])
        return removed[0] if removed else None

    def remove_many(self, wanted_ids: Iterable[str]) -> list[KnownItem]:
        """Remove every listed id that is marked, in one save. Returns what was removed."""
        wanted = set(wanted_ids)
        items = self.load()
        keep = [i for i in items if i.id not in wanted]
        if len(keep) == len(items):
            return []
        self._save(keep)
        return [i for i in items if i.id in wanted]


# --- background tasks ---------------------------------------------------------


def arguments_sha256(arguments: Iterable[str]) -> str:
    """Hash of the full ProgramArguments. The interpreter path alone (a venv's
    python) says nothing about which script it runs; the arguments do."""
    blob = json.dumps([str(a) for a in arguments], separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


MAX_HASH_BYTES = 200 * 1024 * 1024
# Arguments that are files of these kinds are scripts the program runs. Other
# files (logs, configs) change on their own and are not pinned.
SCRIPT_SUFFIXES = {
    ".py", ".pyc", ".pyz", ".sh", ".bash", ".zsh", ".command", ".js", ".mjs", ".cjs",
    ".ts", ".rb", ".pl", ".php", ".lua", ".jar", ".scpt", ".applescript", ".swift", ".tcl",
}
_HASH_CACHE: dict[tuple, str] = {}


class _CannotPin(Exception):
    pass


def _sha256_file(path: str) -> tuple[str, str]:
    """(resolved path, sha256) of a regular file, read without following a
    symlink at the final step. Raises _CannotPin if it cannot be hashed."""
    try:
        real = os.path.realpath(os.path.expanduser(path))
        fd = os.open(real, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError as exc:
        raise _CannotPin(str(exc)) from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_HASH_BYTES:
            raise _CannotPin("not an ordinary file, or too large")
        key = (real, st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)
        cached = _HASH_CACHE.get(key)
        if cached is not None:
            return real, cached
        h = hashlib.sha256()
        read = 0
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            read += len(chunk)
            if read > MAX_HASH_BYTES:
                raise _CannotPin("too large")
            h.update(chunk)
        digest = h.hexdigest()
        if len(_HASH_CACHE) > 256:
            _HASH_CACHE.clear()
        _HASH_CACHE[key] = digest
        return real, digest
    except OSError as exc:
        raise _CannotPin(str(exc)) from exc
    finally:
        os.close(fd)


def _script_argument(arg: str) -> bool:
    """An argument naming a script file in the home folder or a hidden folder."""
    a = str(arg).strip().strip("\"'")
    if not a.startswith(("/", "~")) or "\0" in a:
        return False
    expanded = os.path.expanduser(a)
    real = os.path.realpath(expanded)
    if not os.path.isfile(real):
        return False
    home = os.path.realpath(os.path.expanduser("~")) + os.sep
    in_home = real.startswith(home) or os.path.normpath(expanded).startswith(home)
    hidden = any(p.startswith(".") and p not in (".", "..") for p in (expanded + "/" + real).split("/"))
    if not (in_home or hidden):
        return False
    try:
        executable = bool(os.stat(real).st_mode & 0o111)
    except OSError:
        executable = False
    return executable or Path(real).suffix.lower() in SCRIPT_SUFFIXES


def content_sha256(program: str, arguments: Iterable[str]) -> str | None:
    """Hash of what a background task runs, or None if it cannot be pinned.

    Covers the program file and every script file the arguments name (see
    _script_argument), each with its given and resolved path. Cached per file
    (path, inode, size, mtime) so a scan hashes each file once.
    """
    if not isinstance(program, str) or not program.startswith(("/", "~")):
        return None
    entries = []
    seen = set()
    try:
        for i, path in enumerate([program, *[str(a) for a in (arguments or [])]]):
            if path in seen:
                continue
            if i > 0 and not _script_argument(path):
                continue
            seen.add(path)
            real, digest = _sha256_file(path)
            entries.append([path, real, digest])
    except _CannotPin:
        return None
    blob = json.dumps(entries, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def background_task_identity(
    label: str, program: str, plist: str, arguments: Iterable[str], code: str | None = None,
    with_content: bool = False,
) -> dict | None:
    """The pinned identity of one background task. Without `code` it is the item
    alone (what a check knows before it has findings); apply_marks adds the code
    of each finding before matching. With `with_content`, the content hash is
    included ("" if it cannot be pinned, which never matches or saves)."""
    if not (label and program and plist):
        return None
    ident = {
        "label": str(label),
        "plist": str(plist),
        "program": str(program),
        "arguments_sha256": arguments_sha256(arguments or []),
    }
    if with_content:
        ident["content_sha256"] = content_sha256(program, arguments) or ""
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
    ident = background_task_identity(label, program, str(cand), arguments, code, with_content=True)
    if not ident["content_sha256"]:
        raise KnownItemsError(
            f"The program '{program}' (or a script it runs) could not be read, or is too large "
            "to check, so Reclaim City cannot tell later whether it changed. Nothing was marked."
        )
    return ident


# --- settings and installed items (ITEM_KINDS) ---------------------------------

# Checks whose findings are themselves monitoring software. Nothing they report
# can ever be marked as "mine": for someone being watched, a mark is exactly
# what the person doing the watching would want.
NEVER_MARKABLE_MODULES = frozenset({"stalkerware_scan", "mvt_spyware_scan", "keylogger_indicators"})


def _text(value, limit: int = 512) -> str | None:
    """A pinned field: a non-empty string without NUL, or None."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        value = str(value)
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or "\0" in value or len(value) > limit:
        return None
    return value


def list_sha256(values) -> str | None:
    """SHA-256 of a list of strings, order and repeats ignored. None if it is not one."""
    if not isinstance(values, (list, tuple)) or not values:
        return None
    if not all(isinstance(v, str) and v and "\0" not in v for v in values):
        return None
    blob = json.dumps(sorted(set(values)), separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


# remote_login_check calls Remote Login "ssh"; the other checks say remote_login.
_SERVICE_ALIASES = {"ssh": "remote_login"}
_SERVICE_NAMES = {
    "screen_sharing": "Screen Sharing",
    "file_sharing": "File Sharing",
    "remote_login": "Remote Login",
    "remote_management": "Remote Management",
    "remote_apple_events": "Remote Apple Events",
    "printer_sharing": "Printer Sharing",
    "airdrop": "AirDrop open to everyone",
}
# Sharing services that let someone else see, control or log in to this Mac.
_MONITORING_SERVICES = {"screen_sharing", "remote_login", "remote_management", "remote_apple_events"}


def _sharing_identity(finding) -> dict | None:
    data = finding.data
    service = _text(data.get("service"), 64)
    if service is None and str(finding.code or "").endswith(".airdrop_everyone"):
        service = "airdrop"
    service = _SERVICE_ALIASES.get(service, service)
    if service not in _SERVICE_NAMES:
        return None
    # The finding exists only while the service is on.
    return {"service": service, "state": "on"}


def _proxy_identity(finding) -> dict | None:
    data = finding.data
    interface = _text(data.get("interface"), 64)
    servers = data.get("proxy_servers")
    if interface is None or not isinstance(servers, list) or not servers:
        return None
    if not all(_text(s, 300) for s in servers):
        return None
    return {"interface": interface, "proxies": ", ".join(sorted(set(servers)))}


def _dns_profile_identity(finding) -> dict | None:
    data = finding.data
    provider = _text(data.get("provider"), 128)
    servers = data.get("servers")
    if provider is None or not isinstance(servers, list) or not servers:
        return None
    if not all(_text(s, 64) for s in servers):
        return None
    return {"provider": provider, "servers": ", ".join(sorted(set(servers)))}


def _system_extension_identity(finding) -> dict | None:
    data = finding.data
    bundle_id = _text(data.get("name"), 256)
    team_id = _text(data.get("team_id"), 64)
    state = _text(data.get("state"), 128)
    if not (bundle_id and team_id and state) or "unknown" in (bundle_id.lower(), team_id.lower()):
        return None
    return {"bundle_id": bundle_id, "team_id": team_id, "state": state}


def _browser_extension_identity(finding) -> dict | None:
    data = finding.data
    browser = _text(data.get("browser"), 64)
    ext_id = _text(data.get("extension_id"), 256)
    name = _text(data.get("extension"), 256)
    perms = data.get("permissions")
    if not (browser and ext_id and name) or not isinstance(perms, list) or not perms:
        return None
    if not all(isinstance(p, str) and p and "\0" not in p for p in perms):
        return None
    return {"browser": browser, "extension_id": ext_id, "name": name,
            "permissions": ", ".join(sorted(set(perms)))}


def _app_list_identity(finding) -> dict | None:
    apps = finding.data.get("apps")
    digest = list_sha256(apps)
    if digest is None:
        return None
    return {"apps_sha256": digest, "app_count": str(len(set(apps)))}


def _ssh_keys_identity(finding) -> dict | None:
    data = finding.data
    digest = _text(data.get("list_sha256"), 64)
    count = data.get("key_count")
    if digest is None or len(digest) != 64 or isinstance(count, bool) or not isinstance(count, int) or count < 1:
        return None
    return {"list_sha256": digest, "key_count": str(count)}


def _ai_tooling_identity(finding) -> dict | None:
    data = finding.data
    if data.get("check") == "ai_api_key_found":
        name = _text(data.get("key_name"), 128)
        return {"what": "key_name", "value": name} if name else None
    if data.get("check") == "cron_ai_call":
        digest = _text(data.get("entry_sha256"), 64)
        return {"what": "cron_entry_sha256", "value": digest} if digest and len(digest) == 64 else None
    return None


def _show_sharing(ident, finding):
    return [["Setting", _SERVICE_NAMES.get(ident["service"], ident["service"])], ["Now", "On"]]


def _show_proxy(ident, finding):
    return [["Connection", ident["interface"]], ["Proxy", ident["proxies"]]]


def _show_dns_profile(ident, finding):
    return [["Provider", ident["provider"]], ["DNS servers", ident["servers"]]]


def _show_sysext(ident, finding):
    return [["Extension", ident["bundle_id"]], ["Developer (team ID)", ident["team_id"]], ["State", ident["state"]]]


def _show_browser_ext(ident, finding):
    return [["Extension", ident["name"]], ["Browser", ident["browser"]], ["Extension ID", ident["extension_id"]],
            ["Access it has", ident["permissions"]]]


def _show_apps(ident, finding):
    # Every app, by the name it shows and always with its bundle id: an app
    # picks its own name, so "Zoom" alone could be anything. Never merged by
    # name; this list is what the panel falls back to, so it must be complete.
    shown = []
    for row in app_rows(finding.data.get("apps") or []):
        shown.append(row["id"] if row["name"] == row["id"] else f"{row['name']} · {row['id']}")
    return [["Apps", ", ".join(shown)], ["How many", ident["app_count"]]]


def _show_ssh(ident, finding):
    return [["Saved keys", ident["key_count"]], ["Fingerprint of the list", ident["list_sha256"][:16] + "…"]]


def _show_ai(ident, finding):
    if ident["what"] == "key_name":
        return [["Key name", ident["value"]]]
    entry = finding.data.get("cron_entry") or ""
    return [["Scheduled task", str(entry)[:120]]]


# kind -> spec. "keys" are what a mark pins (with "code"); "evidence_keys" may
# change while it is still the same item, and a change makes the mark stale
# (the warning comes back, saying so) rather than silently matching.
# "monitoring": could this be used to watch someone (True, False, or a
# callable on the identity)? The app then asks for the stronger confirmation.
ITEM_KINDS: dict[str, dict] = {
    "sharing_service": {
        "keys": ("code", "service", "state"),
        "evidence_keys": ("state",),
        "modules": ("sharing_services", "sharing_preferences_audit", "remote_login_check", "airdrop_config"),
        "identify": _sharing_identity,
        "label_of": lambda i: _SERVICE_NAMES.get(i.get("service", ""), i.get("service", "")),
        "title": "Sharing setting you marked as yours: {label}",
        "noun": "sharing setting",
        "what": "{label} being on",
        "changed": "this setting",
        "monitoring": lambda i: i.get("service") in _MONITORING_SERVICES,
        "show": _show_sharing,
    },
    "network_proxy": {
        "keys": ("code", "interface", "proxies"),
        "evidence_keys": ("proxies",),
        "modules": ("network_proxy",),
        "identify": _proxy_identity,
        "label_of": lambda i: f"{i.get('interface', '')} through {i.get('proxies', '')}",
        "title": "Proxy you marked as yours: {label}",
        "noun": "proxy setting",
        "what": "your {label} proxy setting",
        "changed": "the proxy server",
        "monitoring": True,
        "show": _show_proxy,
    },
    "dns_profile": {
        # A NextDNS / Control D / AdGuard profile: its owner sees every name
        # looked up, so it counts as able to watch someone.
        "keys": ("code", "provider", "servers"),
        "evidence_keys": ("servers",),
        "modules": ("dns_poisoning_check",),
        "identify": _dns_profile_identity,
        "label_of": lambda i: f"{i.get('provider', '')} ({i.get('servers', '')})",
        "title": "DNS profile you marked as yours: {label}",
        "noun": "DNS profile",
        "what": "your {label} DNS profile",
        "changed": "the DNS servers",
        "monitoring": True,
        "show": _show_dns_profile,
    },
    "system_extension": {
        "keys": ("code", "bundle_id", "team_id", "state"),
        "evidence_keys": ("team_id", "state"),
        "modules": ("system_extensions",),
        "identify": _system_extension_identity,
        "label_of": lambda i: i.get("bundle_id", ""),
        "title": "System extension you marked as yours: {label}",
        "noun": "system extension",
        "what": "the system extension {label}",
        "changed": "its developer or its state",
        "monitoring": True,
        "show": _show_sysext,
    },
    "browser_extension": {
        "keys": ("code", "browser", "extension_id", "name", "permissions"),
        "evidence_keys": ("name", "permissions"),
        "modules": ("browser_extension_audit",),
        "identify": _browser_extension_identity,
        "label_of": lambda i: f"{i.get('name', '')} ({i.get('browser', '')})",
        "title": "Browser extension you marked as yours: {label}",
        "noun": "browser extension",
        "what": "the extension {label}",
        "changed": "its name or the access it has",
        "monitoring": True,
        "show": _show_browser_ext,
    },
    "app_permissions": {
        "keys": ("code", "apps_sha256", "app_count"),
        "evidence_keys": ("apps_sha256", "app_count"),
        "modules": ("app_permissions", "privacy_permissions_audit", "accessibility_permissions"),
        "identify": _app_list_identity,
        "label_of": lambda i: f"{i.get('app_count', '')} apps",
        "title": "Apps you marked as yours: {label}",
        "noun": "list of apps",
        "what": "this list of {label}",
        "changed": "the list of apps",
        "monitoring": True,
        "show": _show_apps,
    },
    "ssh_authorized_keys": {
        "keys": ("code", "list_sha256", "key_count"),
        "evidence_keys": ("list_sha256", "key_count"),
        "modules": ("session_revocation_scan",),
        "identify": _ssh_keys_identity,
        "label_of": lambda i: f"{i.get('key_count', '')} saved remote-login key(s)",
        "title": "Remote-login keys you marked as yours: {label}",
        "noun": "list of remote-login keys",
        "what": "these {label}",
        "changed": "the list of keys",
        "monitoring": True,
        "show": _show_ssh,
    },
    "ai_tooling": {
        "keys": ("code", "what", "value"),
        "evidence_keys": (),
        "modules": ("ai_threat_indicators",),
        "identify": _ai_tooling_identity,
        "label_of": lambda i: i.get("value", "") if i.get("what") == "key_name" else "a scheduled AI task",
        "title": "AI tool setting you marked as yours: {label}",
        "noun": "AI tool setting",
        "what": "{label}",
        "changed": "it",
        "monitoring": False,
        "show": _show_ai,
    },
}
# Only these codes are offered: warnings about one thing the person may have set up.
ITEM_CODES: dict[str, str] = {
    "security.sharing_services.screen_sharing": "sharing_service",
    "security.sharing_services.file_sharing": "sharing_service",
    "security.sharing_services.remote_login": "sharing_service",
    "security.sharing_services.remote_management": "sharing_service",
    "security.sharing_services.printer_sharing": "sharing_service",
    "security.sharing_preferences_audit.screen_sharing": "sharing_service",
    "security.sharing_preferences_audit.file_sharing": "sharing_service",
    "security.sharing_preferences_audit.remote_login": "sharing_service",
    "security.sharing_preferences_audit.remote_management": "sharing_service",
    "security.sharing_preferences_audit.printer_sharing": "sharing_service",
    "security.sharing_preferences_audit.airdrop_everyone": "sharing_service",
    "security.remote_login_check.ssh_enabled": "sharing_service",
    "security.remote_login_check.screen_sharing_enabled": "sharing_service",
    "security.remote_login_check.remote_management_enabled": "sharing_service",
    "security.remote_login_check.remote_apple_events_enabled": "sharing_service",
    "security.airdrop_config.airdrop_everyone": "sharing_service",
    "security.network_proxy.proxy_enabled": "network_proxy",
    "security.dns_poisoning_check.dns_filtering_profile": "dns_profile",
    "security.system_extensions.unusual_state": "system_extension",
    "security.browser_extension_audit.excessive_permissions": "browser_extension",
    "security.app_permissions.accessibility_access": "app_permissions",
    "security.privacy_permissions_audit.excessive_camera": "app_permissions",
    "security.privacy_permissions_audit.excessive_microphone": "app_permissions",
    "security.privacy_permissions_audit.camera_microphone_combo": "app_permissions",
    "security.privacy_permissions_audit.screen_accessibility_combo": "app_permissions",
    "security.accessibility_permissions.suspicious_accessibility": "app_permissions",
    "security.session_revocation_scan.ssh_authorized_keys": "ssh_authorized_keys",
    "security.ai_threat_indicators.ai_api_key_found": "ai_tooling",
    "security.ai_threat_indicators.cron_ai_call": "ai_tooling",
}
for _kind, _spec in ITEM_KINDS.items():
    assert not set(_spec["modules"]) & NEVER_MARKABLE_MODULES, _kind
    KINDS[_kind] = _spec
del _kind, _spec

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


_MAX_PROGRAM_BYTES = 128 * 1024 * 1024
_SCAN_HASH_BYTES = 1024 * 1024 * 1024
# git's "racy" rule: a file changed this close to when it was hashed may change
# again within one tick of a coarse ctime clock, so its hash is never cached.
_RACY_NS = 1_000_000_000
_hash_state = {"spent": 0, "cache": {}}
# Entry offers check each app's maker with their own small lookup budget, so
# they never use up the one that "made by" attribution relies on.
ENTRY_MAX_LOOKUPS = 60
ENTRY_BUDGET_SECONDS = 20.0
_entry_state: dict = {"attributor": None}


def reset_hash_budget() -> None:
    """Start a scan: forget what was hashed and looked up, and spend nothing yet."""
    _hash_state["spent"] = 0
    _hash_state["cache"] = {}
    _entry_state["attributor"] = None


def _entry_attributor():
    """This scan's attributor for entry offers (made on first use, so its
    time budget starts then)."""
    att = _entry_state["attributor"]
    if att is None:
        from rescue import attribution

        att = _entry_state["attributor"] = attribution.Attributor(
            sys.platform, max_lookups=ENTRY_MAX_LOOKUPS, budget_seconds=ENTRY_BUDGET_SECONDS)
    return att


def _hash_regular_file(path: str) -> str | None:
    """SHA-256 of a regular file, read at most _MAX_PROGRAM_BYTES. The file is
    opened without blocking and checked on the open handle, so a pipe or device
    swapped in after a check can't hang the scan. None if it isn't a regular
    file, is too big (now or by the time it is read), or the scan's total
    hashing budget is spent."""
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > _MAX_PROGRAM_BYTES:
            return None
        # Keyed only on the open handle's fstat: a program can restore mtime
        # after a same-size rewrite, but not ctime, which the rewrite changes.
        # A file changed in the last second is never cached (see _RACY_NS).
        key = (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
        cache = _hash_state["cache"]
        if key in cache:
            return cache[key]
        if _hash_state["spent"] + st.st_size > _SCAN_HASH_BYTES:
            return None
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            total += len(chunk)
            if total > _MAX_PROGRAM_BYTES:
                return None
            digest.update(chunk)
        _hash_state["spent"] += total
        result = digest.hexdigest()
        if time.time_ns() - max(st.st_mtime_ns, st.st_ctime_ns) >= _RACY_NS:
            cache[key] = result
        return result
    finally:
        os.close(fd)


def _program_sha256(app: str) -> str | None:
    """SHA-256 of an app's main program file (read-only), or None if it can't
    be found, isn't a plain file, is too large, or the scan's hashing budget is
    spent: such an entry isn't offered for marking, and is never a match."""
    try:
        from rescue import attribution

        path = attribution.resolve_app(app, sys.platform, attributor=_entry_attributor())
        if not path:
            return None
        path = os.path.realpath(path)
        if os.path.isdir(path):
            with open(os.path.join(path, "Contents", "Info.plist"), "rb") as handle:
                exe = plistlib.load(handle).get("CFBundleExecutable")
            if not isinstance(exe, str) or not exe or "/" in exe or exe.startswith("."):
                return None
            path = os.path.realpath(os.path.join(path, "Contents", "MacOS", exe))
        return _hash_regular_file(path)
    except Exception:
        return None


def app_signer(app: str) -> str | None:
    """Who signed this app, as an entry mark pins it: "team:<Team ID>" for a
    verified Developer ID or App Store signature, "apple" for Apple's own,
    "unsigned:<SHA-256 of its program>" when no signature verifies. None when it can't be checked now
    (not found, or the lookup budget ran out): such an entry can't be marked
    on its own, and a mark on it shows as not checked this time (never as
    changed: nothing says it changed)."""
    try:
        from rescue import attribution

        made = attribution.identify(app, sys.platform, attributor=_entry_attributor())
    except Exception:
        return None
    if made is None:
        return None
    if not made.verified:
        # Nothing vouches for who made it, so pin the program itself: another
        # unsigned app, or this one changed, must not inherit the mark.
        digest = _program_sha256(app)
        return f"unsigned:{digest}" if digest else None
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
            # A key with options (cert-authority, command=, restrict...) works
            # differently from a plain one, so the checklist says it has some.
            with_options = " (with options)" if key.get("options") is True else ""
            out.append({
                "entry": sha, "line_sha256": line, "label": f"{key_type} key{with_options}",
                "detail": _text(key.get("comment"), 256) or "",
                "shown": f"{key_type} key{with_options} {sha[:16]}…",
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


def _entries_groups(marked, stale, fresh, entry_kind: str, unchecked=()) -> str:
    parts = []
    if fresh:
        parts.append(_entries_line("Not marked as yours", [e["shown"] for e in fresh]))
    if unchecked:
        parts.append(_entries_line("Marked as yours before, but not checked this time",
                                   [e["shown"] for e, _ in unchecked]))
        parts.append(UNCHECKED_ONE if len(unchecked) == 1 else UNCHECKED_MANY)
    if stale:
        parts.append(_entries_line("Marked as yours before, but changed since", [e["shown"] for e, _ in stale]))
        if len(stale) == 1:
            parts.append(stale_sentence(stale[0][1], entry_kind))
        else:
            dates = sorted(i.marked_at for _, i in stale if i.marked_at)
            when = f" (the earliest on {dates[0]})" if dates else ""
            changed = KINDS.get(entry_kind, {}).get("changed", "it")
            parts.append(
                f"You marked these as yours{when}, but {changed} has changed on each since you marked "
                "them, so they are shown again. If you changed them yourself, you can mark them again."
            )
    if marked:
        parts.append(_entries_line("Marked as yours", [e["shown"] for e, _ in marked]))
    return "\n".join(parts)


# A mark whose item couldn't be checked this time (the maker lookup or the
# scan's hashing budget ran out): its warning is back, but nothing says it
# changed, and saying so would frighten someone for no reason.
UNCHECKED_ONE = "We couldn't check this one this time, so its warning is back. That doesn't mean it changed."
UNCHECKED_MANY = (
    "We couldn't check these this time, so their warnings are back. That doesn't mean they changed."
)


def unchecked_sentence(item: KnownItem) -> str:
    when = item.marked_at or "an unknown date"
    return (
        f"You marked this as yours on {when}. {UNCHECKED_ONE} The next checkup will try again."
    )


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
        marked, stale, fresh, unchecked = [], [], [], []
        for entry in entries:
            near = by_base.get(item_id(entry_kind, _entry_base(entry_kind, finding.code, entry)))
            if near is None:
                fresh.append(entry)
                continue
            ident = entry_identity(entry_kind, finding.code, entry, signer_of)
            if ident is None:
                # Its maker couldn't be looked up now: not checked, not changed.
                unchecked.append((entry, near))
                continue
            item = by_id.get(item_id(entry_kind, ident))
            if item is None:
                stale.append((entry, near))
            else:
                marked.append((entry, item))
        if not marked and not stale and not unchecked:
            continue
        spec = KINDS[entry_kind]
        data["entry_kind"] = entry_kind
        data["marked_items"] = [
            {"id": i.id, "entry": e["entry"], "shown": e["shown"], "marked_at": i.marked_at} for e, i in marked
        ]
        data["stale_items"] = [
            {"id": i.id, "entry": e["entry"], "shown": e["shown"], "marked_at": i.marked_at} for e, i in stale
        ]
        data["unchecked_items"] = [
            {"id": i.id, "entry": e["entry"], "shown": e["shown"], "marked_at": i.marked_at} for e, i in unchecked
        ]
        warn = fresh + [e for e, _ in stale] + [e for e, _ in unchecked]
        data["unmarked"] = [e["entry"] for e in warn]
        groups = _entries_groups(marked, stale, fresh, entry_kind, unchecked)
        if finding.severity == Severity.CRITICAL:
            data["user_mark_ignored"] = True
            note = (
                "\n\nSome of these are marked as yours, but this finding is serious enough that a "
                "mark does not quiet it." if marked else ""
            )
            finding.description = f"{finding.description}\n\n{groups}{note}"
            continue
        if not warn:
            # A stale whole-list mark gave way to the entry marks: keep it out of the
            # top level so nothing (an undo, say) is aimed at the wrong mark.
            if data.get("mark_stale") and isinstance(data.get("known_item_id"), str):
                old = next((i for i in items if i.id == data["known_item_id"]), None)
                data["stale_list_mark"] = {"id": data.pop("known_item_id")}
                data.pop("mark_stale", None)
                data.pop("mark_unchecked", None)
                if old is not None:
                    for said in (stale_sentence(old, list_kind), unchecked_sentence(old)):
                        finding.description = finding.description.replace(f"\n\n{said}", "")
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
    unchecked = {m["entry"] for m in data.get("unchecked_items") or [] if isinstance(m, dict)}
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
            elif row["entry"] in unchecked:
                offer["unchecked"] = True
        out.append(offer)
    return out


def item_kind_for(code) -> str | None:
    """The ITEM_KINDS kind a finding code can be marked under, or None."""
    if not isinstance(code, str):
        return None
    kind = ITEM_CODES.get(code)
    if kind is None or not code_is_markable(kind, code):
        return None
    if code.split(".")[1] in NEVER_MARKABLE_MODULES:
        return None
    return kind


def item_identity(finding) -> tuple[str, dict] | None:
    """(kind, identity including the code) of a finding about one item, or None."""
    kind = item_kind_for(getattr(finding, "code", None))
    if kind is None or not isinstance(getattr(finding, "data", None), dict):
        return None
    try:
        ident = ITEM_KINDS[kind]["identify"](finding)
    except Exception:
        return None
    if not isinstance(ident, dict):
        return None
    ident = dict(ident, code=finding.code)
    keys = ITEM_KINDS[kind]["keys"]
    if set(ident) != set(keys) or not all(isinstance(ident[k], str) and ident[k] for k in keys):
        return None
    return kind, ident


def group_key(kind: str, identity: dict) -> str:
    """Same item, whichever check reported it: a hash of the identity without the code."""
    return item_id(kind, {k: v for k, v in identity.items() if k != "code"})


def is_monitoring(kind: str, identity: dict) -> bool:
    flag = KINDS.get(kind, {}).get("monitoring", True)
    try:
        return bool(flag(identity)) if callable(flag) else bool(flag)
    except Exception:
        return True


def apply_item_marks(module_name: str, findings: list[Finding], items: list[KnownItem] | None = None,
                     problem: str | None = None) -> list[Finding]:
    """Apply settings/installed-item marks to one module's findings (in place).

    Called by the orchestrator after each check. `items`/`problem` come from
    one load_for_scan() per scan; without them the list is read here.
    """
    if module_name in NEVER_MARKABLE_MODULES or not findings:
        return findings
    kinds = sorted({k for f in findings if (k := item_kind_for(getattr(f, "code", None)))})
    if not kinds:
        return findings
    if items is None:
        items, problem = KnownItemsStore().load_for_scan()
    if problem:
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
        return findings
    for kind in kinds:
        def identify(f, kind=kind):
            hit = item_identity(f)
            return hit[1] if hit and hit[0] == kind else None
        apply_marks(findings, kind, identify, items=items)
    # Entry marks after whole-list marks: a whole-list mark that matched wins.
    apply_entry_marks(findings, items)
    return findings


# --- retiring marks for items that are gone -----------------------------------
#
# A mark on a setting or item covers it only while it stays. If a check that
# reports it runs cleanly and no longer sees it (the service was turned off,
# the proxy, extension, key list or app list is gone), the mark is removed.
# If the thing comes back later, it is flagged again and the person decides
# again. Without this, a mark on "Screen Sharing is on" would also quietly
# cover someone turning Screen Sharing back on after the person turned it off.
#
# This is the one thing a scan writes: it only ever REMOVES entries from
# Reclaim City's own list, through the same trusted read and atomic write as
# `rescue known remove`. If the list is untrusted or damaged nothing is
# written (and no mark applied anyway). A check that wrongly reports nothing
# can only make a warning come back, never hide one.

ITEM_MODULES = frozenset(m for spec in ITEM_KINDS.values() for m in spec["modules"])


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


def retire_marks(gone: list[KnownItem], store: "KnownItemsStore | None" = None) -> list[KnownItem]:
    """Remove these marks from the list. Returns what was removed ([] if the
    list could not be trusted or written: nothing is changed then)."""
    if not gone:
        return []
    try:
        return (store or KnownItemsStore()).remove_many(i.id for i in gone)
    except (KnownItemsError, OSError):
        return []


def retired_notice(item: KnownItem) -> Finding:
    spec = KINDS.get(item.kind, {})
    try:
        label = str(spec["label_of"](item.identity))
    except Exception:
        label = item.kind
    when = item.marked_at or "an earlier checkup"
    return Finding(
        title=f"No longer marked as yours: {label}",
        description=(
            f"On {when} you marked {label} as yours. This checkup didn't find it any more "
            "(it is turned off, or gone), so Reclaim City removed that mark. If it comes "
            "back, you'll be warned about it again and can decide again."
        ),
        severity=Severity.INFO,
        category="security",
        data={
            "check": "known_item_retired",
            "known_item_id": item.id,
            "kind": item.kind,
            "marked_at": item.marked_at,
            "finding_code": item.identity.get("code"),
        },
    )


def item_will_change(kind: str, identity: dict) -> str:
    spec = KINDS[kind]
    label = (spec.get("label_of") or (lambda i: ""))(identity)
    what = spec["what"].replace("{label}", label)
    return (
        f"The checkup will stop warning you about {what}. It will still be listed, as "
        "\"marked as yours\", on every checkup and in anything you export, so anyone "
        f"helping you can see it. If {spec['changed']} changes, the warning comes back."
    )


def item_markable(finding: Finding, module_name: str) -> dict | None:
    """The `markable` block for a warning about one setting or installed item, or None."""
    if module_name in NEVER_MARKABLE_MODULES:
        return None
    if getattr(finding, "severity", None) != Severity.WARNING:
        return None
    data = getattr(finding, "data", None)
    if not isinstance(data, dict) or data.get("marked_by_user"):
        return None
    hit = item_identity(finding)
    if hit is None:
        return None
    kind, identity = hit
    if identity["code"].split(".")[1] != module_name:
        return None
    spec = KINDS[kind]
    try:
        shows = [[str(a), str(b)] for a, b in spec["show"](identity, finding)]
    except Exception:
        shows = []
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
        "tech_undo": MARK_HOW_TO_UNDO_CLI,
        **({"apps": _apps_rows(finding)} if kind == "app_permissions" else {}),
    }
    if kind in ENTRY_KIND_FOR:
        try:
            offers = entry_offers(finding, kind)
        except Exception as exc:
            # Fail safe: the list is still offered whole.
            logger.debug("entry offers for %s skipped: %r", identity["code"], exc)
            offers = []
        if offers:
            out["items"] = offers
            out["items_will_change"] = entries_will_change(ENTRY_KIND_FOR[kind])
    return out


def _apps_rows(finding) -> list[dict]:
    """Each app on a marked list: its bundle id (or path) and the name to show."""
    try:
        return app_rows(finding.data.get("apps") or [])
    except Exception:
        return []


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


def stale_sentence(item: KnownItem, kind: str = BACKGROUND_TASK) -> str:
    when = item.marked_at or "an unknown date"
    if kind == BACKGROUND_TASK:
        return (
            f"You marked this as yours on {when}, but the program it runs has changed since "
            "then, so it's shown again. If you updated it yourself, you can mark it again."
        )
    changed = KINDS.get(kind, {}).get("changed", "it")
    return (
        f"You marked this as yours on {when}, but {changed} has changed since you marked it, "
        "so it's shown again. If you changed it yourself, you can mark it again."
    )


def apply_marks(
    findings: list[Finding],
    kind: str,
    identify: Callable[[Finding], dict | None],
    items: list[KnownItem] | None = None,
    content_of: Callable[[Finding], str | None] | None = None,
) -> list[Finding]:
    """Downgrade findings that match a mark (in place); returns the same list.

    identify(finding) gives the identity of the item a finding is about
    (without the code), or None. The finding's own code is added, so a mark
    covers only the kind of finding it was made for. A match is an exact match
    of every pinned field (the id is a hash over all of them); anything else,
    including a missing or empty field, matches nothing. Critical findings are
    never downgraded; they are tagged instead.

    content_of(finding) gives the content hash of what the item runs (only
    asked for findings that already match a mark on everything else, so a scan
    hashes a handful of files). If it differs from the mark's, the finding is
    not downgraded: it gets data["mark_stale"] and a sentence saying it
    changed. If it cannot be computed (unreadable, or the scan's hashing
    budget is spent), it is not downgraded either, and also gets
    data["mark_unchecked"] and a sentence saying it couldn't be checked this
    time, never that it changed.

    If the list exists but was not used (unreadable, symlink, wrong owner,
    writable by others), an info finding says so.
    """
    spec = KINDS[kind]
    label_of = spec.get("label_of") or (lambda ident: ident.get("label", ""))
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
    by_base: dict[str, KnownItem] = {}
    for i in by_id.values():
        by_base.setdefault(i.base_id, i)
    content_key = spec.get("content_key")
    base_keys = [k for k in spec["keys"] if k != content_key]
    for finding in findings:
        code = getattr(finding, "code", None)
        if not code_is_markable(kind, code):
            continue
        if not isinstance(getattr(finding, "data", None), dict):
            continue
        try:
            identity = identify(finding)
        except Exception:
            identity = None
        if not isinstance(identity, dict):
            continue
        identity = {k: v for k, v in identity.items() if k != content_key}
        identity["code"] = code
        if set(identity) != set(base_keys) or not all(
            isinstance(identity[k], str) and identity[k] for k in base_keys
        ):
            continue
        near = by_base.get(item_id(kind, base_identity(kind, identity)))
        if near is None:
            continue
        item = None
        unchecked = False
        if content_key:
            try:
                content = content_of(finding) if content_of else None
            except Exception:
                content = None
            if isinstance(content, str) and content:
                item = by_id.get(item_id(kind, dict(identity, **{content_key: content})))
            else:
                unchecked = True
        else:
            item = by_id.get(item_id(kind, identity))
        if item is None and unchecked:
            # Couldn't be checked this time: the warning is back, but nothing says it changed.
            finding.data["mark_stale"] = True
            finding.data["mark_unchecked"] = True
            finding.data["known_item_id"] = near.id
            finding.description = f"{finding.description}\n\n{unchecked_sentence(near)}"
            continue
        if item is None:
            # Same item, but what it runs (or its evidence) changed, or cannot be checked.
            finding.data["mark_stale"] = True
            finding.data["known_item_id"] = near.id
            finding.description = f"{finding.description}\n\n{stale_sentence(near, kind)}"
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
        if kind != BACKGROUND_TASK:
            # Groups the marks for one item reported by several checks (link_task_marks).
            finding.data["marked_kind"] = kind
            finding.data["marked_key"] = group_key(kind, identity)
        finding.description = marked_description(finding, item, spec["noun"])
        finding.title = spec["title"].format(label=label_of(identity))
        finding.severity = Severity.INFO
    return findings


def markable(finding: Finding, module_name: str) -> dict | None:
    """The `markable` block the app may offer on a finding, or None.

    Only warnings from a module that honours background-task marks, about a
    task whose label, program and plist are known, and not already marked.
    """
    spec = KINDS[BACKGROUND_TASK]
    if module_name not in spec["modules"]:
        return item_markable(finding, module_name)
    if getattr(finding, "severity", None) != Severity.WARNING:
        return None
    data = getattr(finding, "data", None)
    if not isinstance(data, dict) or data.get("marked_by_user"):
        return None
    code = getattr(finding, "code", None)
    if not code_is_markable(BACKGROUND_TASK, code):
        return None
    fields = {k: data.get(k) for k in ("label", "program", "plist", "arguments_sha256", "content_sha256")}
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
        "will_change": MARK_WILL_CHANGE.replace(
            "'{label}'. ", "'{label}'. " + MARK_COVERS_TASK + " ", 1
        ).replace("{label}", fields["label"]),
        "how_to_undo": list(MARK_HOW_TO_UNDO),
        "tech_undo": MARK_HOW_TO_UNDO_CLI,
    }


def apply_background_task_marks(findings: list[Finding], tasks: dict) -> list[Finding]:
    """Wire-up for the background-task checks.

    tasks: {plist path: (label, program, arguments)} for every item the check
    read. Each finding names its item with data["plist"]. Applies marks, then
    records the content hash on warnings that could be marked, so the app can
    offer "It's mine" with an id covering exactly what runs now.
    """
    def item_of(f):
        return tasks.get(f.data.get("plist")) if isinstance(f.data, dict) else None

    def identify(f):
        t = item_of(f)
        return background_task_identity(t[0], t[1], f.data.get("plist"), t[2]) if t else None

    def content_of(f):
        t = item_of(f)
        return content_sha256(t[1], t[2]) if t else None

    apply_marks(findings, BACKGROUND_TASK, identify, content_of=content_of)
    for f in findings:
        if (
            f.severity == Severity.WARNING
            and not f.data.get("marked_by_user")
            and code_is_markable(BACKGROUND_TASK, f.code)
            and item_of(f)
        ):
            content = content_of(f)
            if content:
                f.data["content_sha256"] = content
    return findings


# --- one task, several findings ------------------------------------------------

_TASK_FIELDS = ("label", "plist", "program", "arguments_sha256")


def link_task_marks(findings: list[dict]) -> list[dict]:
    """Group the scan's output by background task (or by setting/item), after every module ran.

    The same task is often reported by more than one check (one finding code
    each). A person who says "this is mine" means the task, so:

    * every `markable` block gets ``ids``: the mark ids of every markable
      finding about the same task in this scan (same label, plist, program,
      arguments and content), its own included, ordered by code. One
      confirmation saves all of them, and the engine re-checks each.
    * every finding already marked as yours gets ``marked_ids``: the marks
      about the same task shown in this scan, so "Stop treating this as mine"
      removes them all.

    Works on the serialized finding dicts; changes them in place.
    """
    offers: dict[tuple, list[dict]] = {}
    marked: dict[tuple, list[dict]] = {}
    for f in findings:
        m = f.get("markable")
        if isinstance(m, dict) and m.get("kind") == BACKGROUND_TASK:
            key = tuple(m.get(k) for k in (*_TASK_FIELDS, "content_sha256"))
            if all(isinstance(v, str) and v for v in key) and isinstance(m.get("id"), str):
                offers.setdefault(key, []).append(m)
        elif isinstance(m, dict) and m.get("kind") in ITEM_KINDS:
            # A setting or item: the same one on several cards has the same group.
            key = (m["kind"], m.get("group"))
            if isinstance(key[1], str) and key[1] and isinstance(m.get("id"), str):
                offers.setdefault(key, []).append(m)
        data = f.get("data")
        if (
            isinstance(data, dict)
            and data.get("marked_by_user") is True
            and isinstance(data.get("known_item_id"), str)
        ):
            if data.get("marked_kind") in ITEM_KINDS:
                key = (data["marked_kind"], data.get("marked_key"))
            else:
                key = tuple(data.get(k) for k in _TASK_FIELDS)
            if all(isinstance(v, str) and v for v in key):
                marked.setdefault(key, []).append(f)
    for group in offers.values():
        ordered = sorted(group, key=lambda m: (str(m.get("code") or ""), m["id"]))
        ids = list(dict.fromkeys(m["id"] for m in ordered))
        for m in group:
            m["ids"] = list(ids)
    for group in marked.values():
        ids = sorted({f["data"]["known_item_id"] for f in group})
        for f in group:
            f["marked_ids"] = list(ids)
    return findings
