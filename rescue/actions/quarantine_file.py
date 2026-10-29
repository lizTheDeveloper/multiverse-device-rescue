"""Move one file a malware scan matched into quarantine, and put it back.

quarantine() MOVES the file into Reclaim City's quarantine folder, renamed so
it can't be opened by a double-click, with its permissions set to read-only
(nothing can run it), and records where it came from in a manifest next to it:
the original path, its sha256, its permissions and the time. Nothing is
deleted. restore() puts it back with its permissions as they were.

Every path is validated here, at execution time; the scan that suggested the
action is never trusted. Never moved: the operating system's own files
(System Integrity Protection on a Mac), a file with an immutable flag, a file
that belongs to another account, a symbolic link.

macOS and Linux. On Windows, Defender keeps its own quarantine (Windows
Security > Protection history), and that's where its finds belong.
"""

from __future__ import annotations

import errno
import json
import os
import re
import shutil
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path

from rescue import file_scan

ACTION = "quarantine_file"
UNDO_ACTION = "undo_quarantine_file"
MODULES_OFFERING = ("malware_file_scan", "clamav_scanner")
# Fits the app's quarantine-id pattern; "-file-" tells it apart from a background job's.
QUARANTINE_ID = re.compile(r"^[0-9]{8}T[0-9]{6}Z-file-[0-9a-f]{16}\Z")
SUFFIX = ".quarantined"
NOT_SUPPORTED = (
    "Reclaim City's quarantine works on a Mac and on Linux. On Windows, use Windows "
    "Security's own quarantine: Virus & threat protection > Protection history."
)
UNDO_STEPS = [
    "Open Reclaim City and choose Undo on this item",
    "Or, in Terminal: rescue quarantine list, then rescue undo --quarantine-id <the id it shows>",
]
_EXIT = {"fixed": 0, "restored": 0, "nothing_to_fix": 0, "refused": 2, "unsupported": 3}


class Refused(Exception):
    """The request is not safe to act on. The message is plain language."""


def _uid() -> int:
    return os.getuid()


def _home() -> Path:
    return Path(os.path.expanduser("~"))


def _supported() -> bool:
    return sys.platform == "darwin" or sys.platform.startswith("linux")


def _platform() -> str:
    return "darwin" if sys.platform == "darwin" else "linux"


def quarantine_dir() -> Path:
    if sys.platform == "darwin":
        return _home() / "Library" / "Application Support" / "Device Rescue" / "Quarantine" / "Files"
    data = os.environ.get("XDG_DATA_HOME") or str(_home() / ".local" / "share")
    return Path(data) / "device-rescue" / "quarantine" / "files"


def _inside(path: str, folder: Path) -> bool:
    real = os.path.realpath(folder)
    return path == real or path.startswith(real + os.sep)


def validate(path) -> dict:
    """{"path": str, "stat": os.stat_result}. Raises Refused with the reason."""
    if not isinstance(path, (str, os.PathLike)) or not str(path).strip() or "\0" in str(path):
        raise Refused("No file was named.")
    raw = os.path.expanduser(str(path))
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
    real = os.path.realpath(raw)
    if file_scan.is_protected(real, _platform()) or file_scan.is_protected(raw, _platform()):
        raise Refused(
            "That file is part of the operating system, which protects it (on a Mac, System "
            "Integrity Protection). Reclaim City never moves system files. Apple's own XProtect "
            "deals with malware there, and keeping macOS up to date keeps it current."
        )
    if _inside(real, quarantine_dir()):
        raise Refused("That file is already in Reclaim City's quarantine folder.")
    if st.st_uid != _uid():
        raise Refused(
            "That file belongs to another account or to the system, so moving it needs an "
            "administrator. Reclaim City doesn't do that for you; the steps on this item say how."
        )
    if not os.access(os.path.dirname(real), os.W_OK):
        raise Refused("The folder it's in can't be changed from your account, so we left it alone.")
    return {"path": real, "stat": st}


def offer_target(data, severity: str, module: str):
    """{"target", "name", "monitoring"} for a finding that may be offered this action, else None.

    Read-only and never raises: any doubt means no offer.
    """
    try:
        if not _supported() or module not in MODULES_OFFERING or severity != "critical":
            return None
        if not isinstance(data, dict) or not isinstance(data.get("path"), str):
            return None
        info = validate(data["path"])
        return {
            "target": data["path"],
            "name": os.path.basename(info["path"]),
            "monitoring": bool(data.get("monitoring_name")),
        }
    except Exception:
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


def _held_path(qid: str) -> Path:
    return quarantine_dir() / f"{qid}{SUFFIX}"


def is_file_quarantine_id(qid) -> bool:
    return isinstance(qid, str) and bool(QUARANTINE_ID.match(qid))


def _same_file(a: os.stat_result, b: os.stat_result) -> bool:
    return (a.st_ino, a.st_dev, a.st_size, a.st_mtime_ns) == (b.st_ino, b.st_dev, b.st_size, b.st_mtime_ns)


def _move(src: str, dst: str, expect_sha256: str, before: os.stat_result) -> None:
    """Move a regular file to a new name without replacing anything.

    On the same disk, ``os.link`` (which fails if anything already exists at
    ``dst``) then unlink. Across disks, a copy into a file created with
    O_EXCL, checked against the sha256, then unlink. Either way the original
    must still be the very file that was checked, or nothing is removed.
    """
    try:
        os.link(src, dst, follow_symlinks=False)
    except OSError as exc:
        if exc.errno != errno.EXDEV:
            raise
        fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with open(src, "rb") as fin, os.fdopen(fd, "wb") as fout:
                shutil.copyfileobj(fin, fout)
                fout.flush()
                os.fsync(fout.fileno())
        except OSError:
            os.unlink(dst)
            raise
    now = os.lstat(src)
    if not _same_file(before, now) or file_scan.sha256_file(dst) != expect_sha256:
        os.unlink(dst)
        raise OSError("the file changed while it was being moved")
    os.unlink(src)


def _gone_already(path):
    """The quarantine id (or "") if `path` names a file that isn't there now; None otherwise.

    The same file is often reported by more than one check; once one card moved
    it, the others have nothing left to do.
    """
    if not isinstance(path, (str, os.PathLike)) or "\0" in str(path):
        return None
    raw = os.path.expanduser(str(path))
    if not os.path.isabs(raw) or os.path.lexists(raw):
        return None
    try:
        for manifest in sorted(quarantine_dir().glob("*.json"), reverse=True):
            try:
                entry = json.loads(manifest.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if (
                isinstance(entry, dict)
                and not entry.get("restored_at")
                and is_file_quarantine_id(entry.get("id"))
                and raw in (entry.get("original_path"), entry.get("named_path"))
            ):
                return entry["id"]
    except OSError:
        pass
    return ""


def quarantine(path, *, module: str | None = None, detail: str | None = None) -> dict:
    if not _supported():
        return _doc(ACTION, status="unsupported", error="unsupported_platform", message=NOT_SUPPORTED)
    gone = _gone_already(path)
    if gone:
        return _doc(
            ACTION, status="nothing_to_fix", error=None, verified=True, target=str(path),
            message="This file is already in Reclaim City's quarantine folder. Nothing was changed.",
            how_to_undo=list(UNDO_STEPS), quarantine_id=gone,
        )
    if gone == "":
        return _doc(
            ACTION, status="nothing_to_fix", error=None, verified=True, target=str(path),
            message="This file is already gone. Nothing was changed.",
        )
    try:
        info = validate(path)
    except Refused as exc:
        return _doc(ACTION, error="not_allowed", message=f"We changed nothing. {exc}")
    real, before = info["path"], info["stat"]
    try:
        digest = file_scan.sha256_file(real)
    except OSError as exc:
        return _doc(ACTION, status="failed", error="io", message=f"We changed nothing. The file couldn't be read ({exc}).")

    stamp = datetime.now(timezone.utc)
    qid = f"{stamp.strftime('%Y%m%dT%H%M%SZ')}-file-{digest[:16]}"
    qdir = quarantine_dir()
    dest = _held_path(qid)
    manifest = _manifest_path(qid)
    entry = {
        "id": qid,
        "original_path": real,
        "named_path": os.path.expanduser(str(path)),
        "quarantine_path": str(dest),
        "quarantined_at": stamp.isoformat(),
        "sha256": digest,
        "size": before.st_size,
        "mode": stat.S_IMODE(before.st_mode),
        "module": module,
        "detail": detail,
    }
    try:
        qdir.mkdir(parents=True, exist_ok=True)
        os.chmod(qdir, 0o700)
        if os.path.lexists(dest) or manifest.exists():
            return _doc(ACTION, error="exists", message="We changed nothing. That file is already in quarantine.")
        manifest.write_text(json.dumps(entry, indent=2), encoding="utf-8")
        _move(real, str(dest), digest, before)
        # Read-only for you, nothing for anyone else, and never runnable.
        os.chmod(dest, 0o400)
    except OSError as exc:
        for leftover in (manifest,):
            try:
                leftover.unlink()
            except OSError:
                pass
        return _doc(ACTION, status="failed", error="move_failed", message=f"We changed nothing. The file couldn't be moved ({exc}).")

    verified = (
        not os.path.lexists(real)
        and dest.is_file()
        and not (os.lstat(dest).st_mode & 0o111)
        and file_scan.sha256_file(dest) == digest
    )
    return _doc(
        ACTION,
        applied=True,
        verified=verified,
        status="fixed" if verified else "not_fixed",
        message="Done. The file is in quarantine, where it can't run. Nothing was deleted."
        if verified else "We moved the file but could not confirm it.",
        changes=[{
            "title": f"Quarantined '{os.path.basename(real)}'",
            "description": f"Moved {real} to {dest} and made it read-only",
            "success": True,
            "error": None,
        }],
        how_to_undo=list(UNDO_STEPS),
        target=real,
        sha256=digest,
        quarantine_id=qid,
    )


def _check_destination(original: str) -> None:
    """Raises Refused when putting a file back at `original` isn't safe."""
    if not isinstance(original, str) or not os.path.isabs(original) or "\0" in original:
        raise Refused("That record looks damaged. We changed nothing.")
    parent = os.path.dirname(original)
    if file_scan.is_protected(original, _platform()) or file_scan.is_system_path(parent + os.sep, _platform()):
        raise Refused("That record points into a system folder. We changed nothing.")
    if _inside(os.path.realpath(parent), quarantine_dir()):
        raise Refused("That record looks damaged. We changed nothing.")
    try:
        pst = os.stat(parent)
    except OSError:
        raise Refused("The folder it came from isn't there any more, so we did not put it back.") from None
    if not stat.S_ISDIR(pst.st_mode) or not os.access(parent, os.W_OK):
        raise Refused("The folder it came from can't be changed from your account, so we did not put it back.")
    if os.path.lexists(original):
        raise Refused("Something already exists where this file belongs, so we did not put it back. Nothing was changed.")


def restore(quarantine_id) -> dict:
    if not _supported():
        return _doc(UNDO_ACTION, status="unsupported", error="unsupported_platform", message=NOT_SUPPORTED)
    if not is_file_quarantine_id(quarantine_id):
        return _doc(UNDO_ACTION, error="not_allowed", message="That is not a valid undo id. We changed nothing.")
    qid = quarantine_id
    try:
        entry = json.loads(_manifest_path(qid).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return _doc(UNDO_ACTION, status="failed", error="unknown_item", message="We could not find that item to put back.")
    if not isinstance(entry, dict) or entry.get("id") != qid or entry.get("restored_at"):
        return _doc(UNDO_ACTION, error="not_allowed", message="That item was already put back or is not valid. We changed nothing.")
    digest = entry.get("sha256")
    # The held file's name is rebuilt from the id, never read from the manifest.
    src = _held_path(qid)
    original = entry.get("original_path")
    if not isinstance(digest, str) or not file_scan.SHA256_RE.match(digest) or not qid.endswith(digest[:16]):
        return _doc(UNDO_ACTION, error="not_allowed", message="That record looks damaged. We changed nothing.")
    if src.is_symlink() or not src.is_file():
        return _doc(UNDO_ACTION, status="failed", error="missing", message="The saved file is missing, so we changed nothing.")
    if file_scan.sha256_file(src) != digest:
        return _doc(UNDO_ACTION, error="tampered", message="The saved file has changed since it was set aside, so we did not put it back.")
    try:
        _check_destination(original)
    except Refused as exc:
        return _doc(UNDO_ACTION, error="exists" if "already exists" in str(exc) else "not_allowed", message=str(exc))
    mode = entry.get("mode")
    # Its permissions come back as they were, minus set-user/group-id bits.
    mode = mode & 0o777 if isinstance(mode, int) else 0o644
    try:
        os.chmod(src, 0o600)
        _move(str(src), original, digest, os.lstat(src))
        os.chmod(original, mode)
        entry["restored_at"] = datetime.now(timezone.utc).isoformat()
        _manifest_path(qid).write_text(json.dumps(entry, indent=2), encoding="utf-8")
    except OSError as exc:
        try:
            if src.exists():
                os.chmod(src, 0o400)
        except OSError:
            pass
        return _doc(UNDO_ACTION, status="failed", error="move_failed", message=f"We could not put the file back: {exc}")
    return _doc(
        UNDO_ACTION,
        applied=True,
        verified=os.path.isfile(original) and file_scan.sha256_file(original) == digest,
        status="restored",
        message="Put back where it was. It can run again, so only do this if you're sure it's safe.",
        changes=[{"title": f"Put back '{os.path.basename(original)}'", "description": f"Moved it back to {original}",
                  "success": True, "error": None}],
        target=original,
        quarantine_id=qid,
    )


def list_items() -> list[dict]:
    """Everything in the file quarantine that hasn't been put back, newest first."""
    out = []
    try:
        manifests = sorted(quarantine_dir().glob("*.json"), reverse=True)
    except OSError:
        return out
    for manifest in manifests:
        try:
            entry = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(entry, dict) and is_file_quarantine_id(entry.get("id")) and not entry.get("restored_at"):
            out.append({k: entry.get(k) for k in ("id", "original_path", "sha256", "quarantined_at", "module", "detail")})
    return out
