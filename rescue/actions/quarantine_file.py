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
import hashlib
import json
import os
import re
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


def _same_inode(a: os.stat_result, b: os.stat_result) -> bool:
    return (a.st_ino, a.st_dev) == (b.st_ino, b.st_dev)


# Every file and folder this action touches is reached through descriptors
# opened without following links, and acted on relative to its folder's
# descriptor (link/unlink/open with dir_fd, fchmod on an open descriptor), so
# nothing can be swapped for a symbolic link between a check and the change.
_DIR_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
_FILE_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
_NEW_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)


def _open_dir(path: str) -> int:
    """A descriptor for folder `path`, opened one part at a time from / without following any link.

    Raises OSError (ELOOP/ENOTDIR) when any part of the path is a symbolic link.
    """
    if not os.path.isabs(path):
        raise OSError(errno.EINVAL, "not a full path")
    fd = os.open("/", _DIR_FLAGS)
    try:
        for part in [p for p in path.split("/") if p]:
            if part in (".", ".."):
                raise OSError(errno.EINVAL, "path has . or ..")
            nxt = os.open(part, _DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = nxt
    except BaseException:
        os.close(fd)
        raise
    return fd


def _hash_fd(fd: int) -> str:
    digest = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    while True:
        block = os.read(fd, 1024 * 1024)
        if not block:
            break
        digest.update(block)
    return digest.hexdigest()


def _copy_fd(src_fd: int, name: str, dir_fd: int) -> os.stat_result:
    """Copy an open file into a new file `name` in `dir_fd` (never replacing anything); its stat."""
    out = os.open(name, _NEW_FLAGS, 0o600, dir_fd=dir_fd)
    try:
        os.lseek(src_fd, 0, os.SEEK_SET)
        while True:
            block = os.read(src_fd, 1024 * 1024)
            if not block:
                break
            os.write(out, block)
        os.fsync(out)
        return os.fstat(out)
    except BaseException:
        os.close(out)
        os.unlink(name, dir_fd=dir_fd)
        raise
    finally:
        try:
            os.close(out)
        except OSError:
            pass


def _transfer(src_name: str, src_dir: int, src_fd: int, dst_name: str, dst_dir: int,
              expect: os.stat_result, expect_sha256: str, mode: int) -> None:
    """Move one regular file between two folders held open, then set its permissions.

    `src_fd` is the source opened without following links and checked against
    `expect`. Same disk: a hard link (fails if anything is at `dst_name`).
    Across disks: a copy into a new O_EXCL file. The new name is then opened
    without following links and must be the file just made (same inode); its
    contents must match `expect_sha256`; only then are its permissions set
    (fchmod on that descriptor) and the old name removed, after checking the
    old name is still the very file that was checked.
    """
    try:
        os.link(src_name, dst_name, src_dir_fd=src_dir, dst_dir_fd=dst_dir, follow_symlinks=False)
        made = os.fstat(src_fd)
    except OSError as exc:
        if exc.errno != errno.EXDEV:
            raise
        made = _copy_fd(src_fd, dst_name, dst_dir)
    try:
        dfd = os.open(dst_name, _FILE_FLAGS, dir_fd=dst_dir)
    except OSError:
        raise OSError("the new file couldn't be opened") from None
    try:
        now = os.fstat(dfd)
        if not stat.S_ISREG(now.st_mode) or not _same_inode(now, made) or _hash_fd(dfd) != expect_sha256:
            raise OSError("the file changed while it was being moved")
        os.fchmod(dfd, mode)
    except BaseException:
        os.close(dfd)
        _unlink_if_same(dst_name, dst_dir, made)
        raise
    os.close(dfd)
    old = os.lstat(src_name, dir_fd=src_dir)
    if not _same_file(old, expect):
        _unlink_if_same(dst_name, dst_dir, made)
        raise OSError("the file changed while it was being moved")
    os.unlink(src_name, dir_fd=src_dir)


def _unlink_if_same(name: str, dir_fd: int, expect: os.stat_result) -> None:
    try:
        if _same_inode(os.lstat(name, dir_fd=dir_fd), expect):
            os.unlink(name, dir_fd=dir_fd)
    except OSError:
        pass


def _open_quarantine() -> int:
    """The quarantine folder, made if needed, opened without links, yours, and closed to others."""
    qdir = quarantine_dir()
    qdir.mkdir(parents=True, exist_ok=True)
    fd = _open_dir(os.path.realpath(qdir))
    st = os.fstat(fd)
    if st.st_uid != _uid():
        os.close(fd)
        raise OSError("the quarantine folder belongs to another account")
    os.fchmod(fd, 0o700)
    return fd


def _write_manifest(qfd: int, qid: str, entry: dict, new: bool) -> None:
    flags = (_NEW_FLAGS if new else os.O_WRONLY | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0))
    fd = os.open(f"{qid}.json", flags, 0o600, dir_fd=qfd)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, indent=2))


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
    parent, name = os.path.split(real)

    pfd = sfd = qfd = None
    try:
        try:
            pfd = _open_dir(parent)
            sfd = os.open(name, _FILE_FLAGS, dir_fd=pfd)
        except OSError:
            return _doc(ACTION, error="not_allowed",
                        message="We changed nothing. The file or its folder changed (a shortcut appeared), so we left it alone.")
        if not _same_file(os.fstat(sfd), before):
            return _doc(ACTION, error="not_allowed", message="We changed nothing. The file changed since it was checked.")
        try:
            digest = _hash_fd(sfd)
        except OSError as exc:
            return _doc(ACTION, status="failed", error="io", message=f"We changed nothing. The file couldn't be read ({exc}).")

        stamp = datetime.now(timezone.utc)
        qid = f"{stamp.strftime('%Y%m%dT%H%M%SZ')}-file-{digest[:16]}"
        dest = _held_path(qid)
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
            qfd = _open_quarantine()
            try:
                _write_manifest(qfd, qid, entry, new=True)
            except FileExistsError:
                return _doc(ACTION, error="exists", message="We changed nothing. That file is already in quarantine.")
            try:
                # Read-only for you, nothing for anyone else, and never runnable.
                _transfer(name, pfd, sfd, dest.name, qfd, before, digest, 0o400)
            except OSError:
                try:
                    os.unlink(f"{qid}.json", dir_fd=qfd)
                except OSError:
                    pass
                raise
        except OSError as exc:
            return _doc(ACTION, status="failed", error="move_failed", message=f"We changed nothing. The file couldn't be moved ({exc}).")

        try:
            os.lstat(name, dir_fd=pfd)
            source_gone = False
        except FileNotFoundError:
            source_gone = True
        held = os.lstat(dest.name, dir_fd=qfd)
        verified = source_gone and stat.S_ISREG(held.st_mode) and not (held.st_mode & 0o111)
    finally:
        for fd in (sfd, pfd, qfd):
            if fd is not None:
                os.close(fd)
    return _doc(
        ACTION,
        applied=True,
        verified=verified,
        status="fixed" if verified else "not_fixed",
        message="Done. The file is in quarantine, where it can't run. Nothing was deleted."
        if verified else "We moved the file but could not confirm it.",
        changes=[{
            "title": f"Quarantined '{name}'",
            "description": f"Moved {real} to {dest} and made it read-only",
            "success": True,
            "error": None,
        }],
        how_to_undo=list(UNDO_STEPS),
        target=real,
        sha256=digest,
        quarantine_id=qid,
    )


def _check_destination(original) -> None:
    """Raises Refused when the recorded place isn't one a file may be put back into (by its path)."""
    if not isinstance(original, str) or not os.path.isabs(original) or "\0" in original \
            or any(ord(c) < 32 or ord(c) == 127 for c in original):
        raise Refused("That record looks damaged. We changed nothing.")
    parent = os.path.dirname(original)
    if file_scan.is_protected(original, _platform()) or file_scan.is_system_path(parent + os.sep, _platform()):
        raise Refused("That record points into a system folder. We changed nothing.")
    if _inside(os.path.realpath(parent), quarantine_dir()):
        raise Refused("That record looks damaged. We changed nothing.")


def _check_parent(pfd: int) -> None:
    """Raises Refused unless the folder held open is yours and not open for anyone to write in."""
    st = os.fstat(pfd)
    if not stat.S_ISDIR(st.st_mode):
        raise Refused("The place it came from isn't a folder any more, so we did not put it back.")
    if st.st_uid != _uid():
        raise Refused(
            "The folder it came from belongs to another account or the system (a shared or temporary "
            "folder, for example), so we did not put it back. The file stays safe in quarantine."
        )
    if st.st_mode & stat.S_IWOTH and not st.st_mode & stat.S_ISVTX:
        raise Refused("Anyone can change the folder it came from, so we did not put it back. The file stays safe in quarantine.")


def restore(quarantine_id) -> dict:
    if not _supported():
        return _doc(UNDO_ACTION, status="unsupported", error="unsupported_platform", message=NOT_SUPPORTED)
    if not is_file_quarantine_id(quarantine_id):
        return _doc(UNDO_ACTION, error="not_allowed", message="That is not a valid undo id. We changed nothing.")
    qid = quarantine_id
    try:
        qfd = _open_dir(os.path.realpath(quarantine_dir()))
    except OSError:
        return _doc(UNDO_ACTION, status="failed", error="unknown_item", message="We could not find that item to put back.")
    pfd = hfd = None
    try:
        try:
            mfd = os.open(f"{qid}.json", _FILE_FLAGS, dir_fd=qfd)
            with os.fdopen(mfd, "r", encoding="utf-8") as fh:
                entry = json.loads(fh.read())
        except (OSError, ValueError):
            return _doc(UNDO_ACTION, status="failed", error="unknown_item", message="We could not find that item to put back.")
        if not isinstance(entry, dict) or entry.get("id") != qid or entry.get("restored_at"):
            return _doc(UNDO_ACTION, error="not_allowed", message="That item was already put back or is not valid. We changed nothing.")
        digest = entry.get("sha256")
        original = entry.get("original_path")
        if not isinstance(digest, str) or not file_scan.SHA256_RE.match(digest) or not qid.endswith(digest[:16]):
            return _doc(UNDO_ACTION, error="not_allowed", message="That record looks damaged. We changed nothing.")
        try:
            _check_destination(original)
        except Refused as exc:
            return _doc(UNDO_ACTION, error="not_allowed", message=str(exc))
        # The held file's name is rebuilt from the id, never read from the manifest.
        held_name = f"{qid}{SUFFIX}"
        try:
            hfd = os.open(held_name, _FILE_FLAGS, dir_fd=qfd)
        except OSError:
            return _doc(UNDO_ACTION, status="failed", error="missing", message="The saved file is missing, so we changed nothing.")
        held = os.fstat(hfd)
        if not stat.S_ISREG(held.st_mode) or _hash_fd(hfd) != digest:
            return _doc(UNDO_ACTION, error="tampered", message="The saved file has changed since it was set aside, so we did not put it back.")
        parent, name = os.path.split(original)
        try:
            pfd = _open_dir(parent)
        except OSError:
            return _doc(UNDO_ACTION, error="not_allowed",
                        message="The folder it came from isn't there any more, or is now a shortcut, so we did not put it back.")
        try:
            _check_parent(pfd)
        except Refused as exc:
            return _doc(UNDO_ACTION, error="not_allowed", message=str(exc))
        try:
            os.lstat(name, dir_fd=pfd)
            return _doc(
                UNDO_ACTION, error="exists",
                message="Something already exists where this file belongs, so we did not put it back. Nothing was changed.",
            )
        except FileNotFoundError:
            pass
        mode = entry.get("mode")
        # Its permissions come back as they were, minus set-user/group-id bits.
        mode = mode & 0o777 if isinstance(mode, int) else 0o644
        try:
            _transfer(held_name, qfd, hfd, name, pfd, held, digest, mode)
            entry["restored_at"] = datetime.now(timezone.utc).isoformat()
            _write_manifest(qfd, qid, entry, new=False)
        except OSError as exc:
            return _doc(UNDO_ACTION, status="failed", error="move_failed", message=f"We could not put the file back: {exc}")
        back = os.lstat(name, dir_fd=pfd)
    finally:
        for fd in (hfd, pfd, qfd):
            if fd is not None:
                os.close(fd)
    return _doc(
        UNDO_ACTION,
        applied=True,
        verified=stat.S_ISREG(back.st_mode),
        status="restored",
        message="Put back where it was. It can run again, so only do this if you're sure it's safe.",
        changes=[{"title": f"Put back '{name}'", "description": f"Moved it back to {original}",
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
