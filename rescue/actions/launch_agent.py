"""Turn off one background job (a user LaunchAgent) and undo it.

disable() stops the job and MOVES its plist into a quarantine folder. Nothing is
deleted. restore() puts it back and starts it again. Every path is validated
here, at execution time; the scan that suggested the action is never trusted.

All commands go through rescue.command.run as list argv. macOS only.
"""

from __future__ import annotations

import hashlib
import json
import os
import plistlib
import re
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path

from rescue.command import run

ACTION = "disable_launch_agent"
UNDO_ACTION = "undo_disable_launch_agent"
MODULES_OFFERING = (
    "launchd_persistence_audit",
    "launch_agent_audit",
    "scheduled_tasks_audit",
    "ai_worm_persistence",
    "ai_threat_indicators",
)
_SAFE_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,200}$")
QUARANTINE_ID = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[A-Za-z0-9][A-Za-z0-9._-]{0,200}$")
# launchctl bootout exit codes / text meaning "that job is not loaded".
_NOT_LOADED_CODES = {3, 113}
_NOT_LOADED_TEXT = ("no such process", "could not find service", "not found")
_ALREADY_LOADED_TEXT = ("already",)
NOT_SUPPORTED = "This is only supported on a Mac."
UNDO_STEPS = [
    "Open Reclaim City and choose Undo on this item",
    "Or move the file from ~/Library/Application Support/Device Rescue/Quarantine back to "
    "~/Library/LaunchAgents and log out and back in",
]
_EXIT = {"fixed": 0, "restored": 0, "nothing_to_fix": 0, "refused": 2, "unsupported": 3}


class Refused(Exception):
    """The request is not safe to act on. The message is plain language."""


def _uid() -> int:
    return os.getuid()


def _home() -> Path:
    return Path(os.path.expanduser("~"))


def launch_agents_dir() -> Path:
    return _home() / "Library" / "LaunchAgents"


def quarantine_dir() -> Path:
    return _home() / "Library" / "Application Support" / "Device Rescue" / "Quarantine"


def _supported() -> bool:
    return sys.platform == "darwin"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate(plist_path) -> dict:
    """Return {"path": Path, "label": str}. Raises Refused with the reason."""
    if not isinstance(plist_path, (str, os.PathLike)) or not str(plist_path).strip() or "\0" in str(plist_path):
        raise Refused("No file was named.")
    raw = os.path.expanduser(str(plist_path))
    if not os.path.isabs(raw):
        raise Refused("That is not a full file path.")
    try:
        st = os.lstat(raw)
    except OSError:
        raise Refused("That file does not exist.") from None
    if stat.S_ISLNK(st.st_mode):
        raise Refused("That file is a shortcut (symbolic link), so we will not touch it.")
    if not stat.S_ISREG(st.st_mode):
        raise Refused("That is not an ordinary file.")
    real = Path(os.path.realpath(raw))
    if real.parent != Path(os.path.realpath(launch_agents_dir())):
        raise Refused("That file is not directly inside your own LaunchAgents folder.")
    if st.st_uid != _uid():
        raise Refused("That file belongs to a different user.")
    if real.suffix != ".plist":
        raise Refused("That is not a .plist file.")
    try:
        with open(real, "rb") as fh:
            data = plistlib.load(fh)
    except Exception:
        raise Refused("That file could not be read as a settings (plist) file.") from None
    label = data.get("Label") if isinstance(data, dict) else None
    if not isinstance(label, str) or not label:
        raise Refused("That settings file has no Label.")
    if label != real.stem:
        raise Refused("The file's Label does not match its file name.")
    if not _SAFE_LABEL.match(label):
        raise Refused("The Label contains characters we will not act on.")
    return {"path": real, "label": label}


def offer_target(data, severity: str, module: str):
    """{"target", "label"} for a scan finding that may be offered this action, else None.

    Read-only and never raises: any doubt means no offer.
    """
    try:
        if module not in MODULES_OFFERING or severity not in ("warning", "critical"):
            return None
        if not isinstance(data, dict):
            return None
        candidates = []
        named = False
        for key in ("plist", "plist_path"):
            if isinstance(data.get(key), str) and data[key].strip():
                named = True
                candidates.append(data[key])
        # Guess the file from the label only when the finding did not say which
        # file it came from. A finding about /Library/LaunchDaemons/x.plist must
        # never turn into an offer to move a different ~/Library/LaunchAgents/x.plist.
        label = data.get("label")
        if not named and isinstance(label, str) and _SAFE_LABEL.match(label):
            candidates.append(str(launch_agents_dir() / f"{label}.plist"))
        for cand in candidates:
            try:
                info = validate(cand)
            except Refused:
                continue
            return {"target": os.path.expanduser(cand), "label": info["label"]}
    except Exception:
        return None
    return None


def _doc(action: str, **fields) -> dict:
    doc = {
        "module": action,
        "action": action,
        "applied": False,
        "message": "",
        "changes": [],
        "how_to_undo": [],
        "verified": False,
        "status": "refused",
    }
    doc.update(fields)
    return doc


def exit_code(doc: dict) -> int:
    """Same exit codes as `rescue fix`: 0 done, 1 not done, 2 refused, 3 unsupported."""
    return _EXIT.get(doc.get("status"), 1)


def _manifest_path(qid: str) -> Path:
    return quarantine_dir() / f"{qid}.json"



def _move_no_clobber(src: Path, dst: Path, expect_sha256: str | None = None) -> None:
    """Move a regular file without following or replacing anything.

    ``os.link`` with ``follow_symlinks=False`` fails if *anything* (a file, a
    symlink, a directory) already exists at ``dst``, atomically, so there is no
    check-then-move window. Afterwards the new name must be the very same
    regular file (same inode) and, when given, have the validated contents;
    otherwise the new name is removed and nothing else is touched.
    """
    before = os.lstat(src)
    if not stat.S_ISREG(before.st_mode):
        raise OSError("not a regular file any more")
    os.link(src, dst, follow_symlinks=False)
    after = os.lstat(dst)
    same = stat.S_ISREG(after.st_mode) and (after.st_ino, after.st_dev) == (before.st_ino, before.st_dev)
    if not same or (expect_sha256 is not None and _sha256(dst) != expect_sha256):
        os.unlink(dst)
        raise OSError("the file changed while it was being moved")
    os.unlink(src)

def _already_gone(plist_path):
    """The quarantine id (or "") if plist_path is a .plist that USED to be in the
    user's LaunchAgents folder and is not there now; None otherwise.

    This is what happens when the same background job is listed on more than one
    card and the person already turned it off from another card, or removed it
    themselves since the scan. That is not a refusal: there is nothing left to do.
    """
    if not isinstance(plist_path, (str, os.PathLike)) or "\0" in str(plist_path):
        return None
    raw = os.path.expanduser(str(plist_path))
    if not os.path.isabs(raw) or not raw.endswith(".plist"):
        return None
    path = Path(os.path.normpath(raw))
    try:
        if os.path.realpath(path.parent) != os.path.realpath(launch_agents_dir()):
            return None
        if os.path.lexists(path):
            return None
    except OSError:
        return None
    qid = ""
    try:
        for manifest in sorted(quarantine_dir().glob("*.json"), reverse=True):
            try:
                entry = json.loads(manifest.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if (
                isinstance(entry, dict)
                and not entry.get("restored_at")
                and isinstance(entry.get("id"), str)
                and QUARANTINE_ID.match(entry["id"])
                and entry.get("original_path") in (str(plist_path), raw, str(path))
            ):
                qid = entry["id"]
                break
    except OSError:
        pass
    return qid


def disable(plist_path) -> dict:
    if not _supported():
        return _doc(ACTION, status="unsupported", error="unsupported_platform", message=NOT_SUPPORTED)
    gone = _already_gone(plist_path)
    if gone is not None:
        fields = {
            "status": "nothing_to_fix",
            "error": None,
            "verified": True,
            "target": os.path.expanduser(str(plist_path)),
        }
        if gone:
            fields.update(
                message="This background job is already turned off, and its settings file is "
                "in Reclaim City's quarantine folder. Nothing was changed.",
                how_to_undo=list(UNDO_STEPS),
                quarantine_id=gone,
            )
        else:
            fields["message"] = "This background job is already gone. Nothing was changed."
        return _doc(ACTION, **fields)
    try:
        info = validate(plist_path)
    except Refused as exc:
        return _doc(ACTION, error="not_allowed", message=f"We changed nothing. {exc}")
    path, label = info["path"], info["label"]
    original = os.path.expanduser(str(plist_path))
    undo = list(UNDO_STEPS)

    stamp = datetime.now(timezone.utc)
    qid = f"{stamp.strftime('%Y%m%dT%H%M%SZ')}-{label}"
    qdir = quarantine_dir()
    dest = qdir / f"{qid}.plist"
    manifest = _manifest_path(qid)
    try:
        qdir.mkdir(parents=True, exist_ok=True)
        os.chmod(qdir, 0o700)
        if dest.exists() or manifest.exists():
            return _doc(ACTION, error="exists", message="We changed nothing. That item is already in quarantine.")
        digest = _sha256(path)
    except OSError as exc:
        return _doc(ACTION, status="failed", error="io", message=f"We changed nothing. {exc}")

    res = run(["launchctl", "bootout", f"gui/{_uid()}/{label}"])
    was_loaded = res.ok
    if not res.ok:
        text = f"{res.stdout} {res.stderr}".lower()
        not_loaded = res.returncode in _NOT_LOADED_CODES or any(t in text for t in _NOT_LOADED_TEXT)
        if res.timed_out or res.returncode is None or not not_loaded:
            return _doc(
                ACTION,
                status="failed",
                error="stop_failed",
                message="We could not stop that background job, so we changed nothing.",
            )

    entry = {
        "id": qid,
        "label": label,
        "original_path": original,
        "quarantine_path": str(dest),
        "quarantined_at": stamp.isoformat(),
        "sha256": digest,
        "was_loaded": was_loaded,
    }
    try:
        manifest.write_text(json.dumps(entry, indent=2), encoding="utf-8")
        _move_no_clobber(Path(path), Path(dest), expect_sha256=digest)
    except OSError as exc:
        try:
            manifest.unlink()
        except OSError:
            pass
        return _doc(
            ACTION,
            status="failed",
            error="move_failed",
            message=f"The job was stopped, but its settings file could not be moved ({exc}). It may start again when you log in.",
            how_to_undo=undo,
        )

    verified = not os.path.lexists(path) and dest.is_file() and _sha256(dest) == digest
    return _doc(
        ACTION,
        applied=True,
        verified=verified,
        status="fixed" if verified else "not_fixed",
        message="Done. Nothing was deleted." if verified else "We moved the file but could not confirm it.",
        changes=[{
            "title": f"Turned off '{label}'",
            "description": f"Stopped the job and moved {original} to {dest}",
            "success": True,
            "error": None,
        }],
        how_to_undo=undo,
        target=original,
        label=label,
        quarantine_id=qid,
    )


def restore(quarantine_id) -> dict:
    if not _supported():
        return _doc(UNDO_ACTION, status="unsupported", error="unsupported_platform", message=NOT_SUPPORTED)
    if not isinstance(quarantine_id, str) or not QUARANTINE_ID.match(quarantine_id):
        return _doc(UNDO_ACTION, error="not_allowed", message="That is not a valid undo id. We changed nothing.")
    qid = quarantine_id
    try:
        entry = json.loads(_manifest_path(qid).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return _doc(UNDO_ACTION, status="failed", error="unknown_item", message="We could not find that item to put back.")
    if not isinstance(entry, dict) or entry.get("id") != qid or entry.get("restored_at"):
        return _doc(UNDO_ACTION, error="not_allowed", message="That item was already put back or is not valid. We changed nothing.")
    label = entry.get("label")
    # The manifest is only a record: the destination is rebuilt from the label so
    # an edited manifest cannot aim the move somewhere else.
    if not isinstance(label, str) or not _SAFE_LABEL.match(label) or not qid.endswith("-" + label):
        return _doc(UNDO_ACTION, error="not_allowed", message="That record looks damaged. We changed nothing.")
    src = quarantine_dir() / f"{qid}.plist"
    orig = launch_agents_dir() / f"{label}.plist"
    if src.is_symlink() or not src.is_file():
        return _doc(UNDO_ACTION, status="failed", error="missing", message="The saved file is missing, so we changed nothing.")
    if _sha256(src) != entry.get("sha256"):
        return _doc(UNDO_ACTION, error="tampered", message="The saved file has changed since it was set aside, so we did not put it back.")
    if os.path.lexists(orig):
        return _doc(
            UNDO_ACTION,
            error="exists",
            message="Something already exists where this file belongs, so we did not put it back. Nothing was changed.",
        )
    try:
        orig.parent.mkdir(parents=True, exist_ok=True)
        _move_no_clobber(Path(src), Path(orig), expect_sha256=entry.get("sha256"))
        entry["restored_at"] = datetime.now(timezone.utc).isoformat()
        _manifest_path(qid).write_text(json.dumps(entry, indent=2), encoding="utf-8")
    except OSError as exc:
        return _doc(UNDO_ACTION, status="failed", error="move_failed", message=f"We could not put the file back: {exc}")

    res = run(["launchctl", "bootstrap", f"gui/{_uid()}", str(orig)])
    started = res.ok or any(t in f"{res.stdout} {res.stderr}".lower() for t in _ALREADY_LOADED_TEXT)
    message = (
        "Put back, and the background job is on again."
        if started
        else "Put back. The job will start again the next time you log out and back in."
    )
    return _doc(
        UNDO_ACTION,
        applied=True,
        verified=orig.is_file(),
        status="restored",
        message=message,
        changes=[{"title": f"Put back '{label}'", "description": f"Moved it back to {orig}", "success": True, "error": None}],
        target=str(orig),
        label=label,
        quarantine_id=qid,
        started=started,
    )
