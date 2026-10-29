"""Run Apple's own malware rules (XProtect's YARA files) over a list of files.

Every Mac carries the rules XProtect uses to recognise known Mac malware:

    /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.yara
    .../XPScripts.yr   (rules for scripts: AppleScript, shell, Python)

Apple keeps them up to date with the system's own background updates. This
module compiles them with YARA-X (VirusTotal's YARA engine, the ``yara-x``
package, BSD-3-Clause) and scans files with them. Nothing is downloaded and
nothing is changed: files are only read.

It lives in ``rescue/`` rather than in the check module so the frozen app's
build sees the ``yara_x`` import and bundles it (check modules ship as data).
"""

from __future__ import annotations

import hashlib
import os
import plistlib
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rescue import file_scan

XPROTECT_BUNDLE = Path("/Library/Apple/System/Library/CoreServices/XProtect.bundle")
# (rule set, file name). The rule set becomes the YARA namespace.
APPLE_RULE_FILES = (("XProtect", "XProtect.yara"), ("XPScripts", "XPScripts.yr"))
# How long YARA may spend on one file before moving on.
PER_FILE_TIMEOUT = 10


class EngineMissing(Exception):
    """The YARA engine isn't available in this copy of Reclaim City."""


class RulesMissing(Exception):
    """Apple's rule files aren't on this Mac, or the engine couldn't read them."""


@dataclass
class Match:
    path: str
    rule: str
    rule_set: str
    # The rule's own description, e.g. "MACOS.ADLOAD.B" (family = "ADLOAD").
    description: str
    family: str
    # sha256 of the very bytes that were scanned.
    sha256: str = ""


@dataclass
class ScanStats:
    scanned: int = 0
    scanned_bytes: int = 0
    unreadable: int = 0
    timed_out: int = 0
    # Files left unscanned because the time or byte budget ran out.
    left: int = 0
    left_bytes: int = 0
    stopped_by: str | None = None  # "time" | "bytes" | None
    seconds: float = 0.0
    matched_files: list[str] = field(default_factory=list)


def load_engine():
    try:
        import yara_x  # noqa: PLC0415 - optional at import time; the check says if it's missing
    except Exception as exc:  # ImportError, or a wheel built for a newer macOS
        raise EngineMissing(str(exc)[:200]) from exc
    return yara_x


def xprotect_version(bundle: Path = XPROTECT_BUNDLE) -> str | None:
    try:
        with open(bundle / "Contents" / "Info.plist", "rb") as fh:
            info = plistlib.load(fh)
    except Exception:
        return None
    version = info.get("CFBundleShortVersionString") if isinstance(info, dict) else None
    return version if isinstance(version, str) else None


def compile_apple_rules(bundle: Path = XPROTECT_BUNDLE, engine: Any = None) -> tuple[Any, int]:
    """(compiled rules, how many rule sets were read). Raises RulesMissing or EngineMissing."""
    yara_x = engine or load_engine()
    compiler = yara_x.Compiler()
    loaded = 0
    for rule_set, name in APPLE_RULE_FILES:
        path = bundle / "Contents" / "Resources" / name
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        compiler.new_namespace(rule_set)
        try:
            compiler.add_source(source)
        except Exception as exc:
            raise RulesMissing(f"{name}: {str(exc)[:300]}") from exc
        loaded += 1
    if not loaded:
        raise RulesMissing("no XProtect rule files found")
    return compiler.build(), loaded


_SCRIPT_KINDS = frozenset({"OSASCRIPT", "PYTHON", "SHELL", "BASH", "ZSH", "PERL", "SCRIPT", "JXA"})


def _family(description: str) -> str:
    """"MACOS.ADLOAD.B" -> "ADLOAD"; "OSX.OpinionSpy.B" -> "OpinionSpy"."""
    parts = [p for p in description.split(".") if p]
    if len(parts) >= 3 and parts[1].upper() in _SCRIPT_KINDS:
        return parts[2]  # "MACOS.OSASCRIPT.COTABR" -> "COTABR"
    if len(parts) >= 2 and parts[0].upper() in ("MACOS", "OSX"):
        return parts[1]
    return parts[0] if parts else ""


def scan_files(
    rules: Any,
    paths: list,
    *,
    time_budget: float,
    max_total_bytes: int,
    engine: Any = None,
    clock=time.monotonic,
) -> tuple[list[Match], ScanStats]:
    """Scan listed files (file_scan.Target, or (path, size) pairs) in order until done or a budget runs out.

    Each file is read once, from a descriptor opened without following a link
    and checked to be the file that was listed; the bytes read are the bytes
    scanned and the bytes hashed, so a match can't be pinned on another file.

    When the time runs out the scan stops; a file that would go over the byte
    budget is left out and the scan goes on with the smaller ones after it.
    """
    yara_x = engine or load_engine()
    scanner = yara_x.Scanner(rules)
    scanner.set_timeout(PER_FILE_TIMEOUT)
    matches: list[Match] = []
    stats = ScanStats()
    start = clock()
    for index, item in enumerate(paths):
        target = item if isinstance(item, file_scan.Target) else file_scan.Target(path=item[0], size=item[1], place="")
        path, size = target.path, target.size
        if clock() - start >= time_budget:
            stats.stopped_by = "time"
            stats.left += len(paths) - index
            break
        if stats.scanned_bytes + size > max_total_bytes:
            stats.stopped_by = stats.stopped_by or "bytes"
            stats.left += 1
            stats.left_bytes += size
            continue
        data = file_scan.read_target(target, size)  # grown since it was listed: not the file listed
        if data is None:
            stats.unreadable += 1
            continue
        try:
            results = scanner.scan(data)
        except yara_x.TimeoutError:
            stats.timed_out += 1
            continue
        except Exception:
            # Gone since it was listed, no permission, or not readable as a file.
            stats.unreadable += 1
            continue
        stats.scanned += 1
        stats.scanned_bytes += size
        found = False
        digest = hashlib.sha256(data).hexdigest() if results.matching_rules else ""
        for rule in results.matching_rules:
            meta = dict(rule.metadata or ())
            description = str(meta.get("description") or rule.identifier)
            matches.append(Match(
                path=os.fspath(path), rule=rule.identifier, rule_set=rule.namespace,
                description=description, family=_family(description), sha256=digest,
            ))
            found = True
        if found:
            stats.matched_files.append(os.fspath(path))
    stats.seconds = round(clock() - start, 2)
    return matches, stats
