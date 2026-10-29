"""knockknock_scan: everything set to start on its own on a Mac, using KnockKnock.

KnockKnock (Objective-See, GPL-3.0) lists what is installed to run
automatically: launch agents and daemons, background tasks macOS manages,
login items, kernel and system extensions, browser extensions, cron jobs,
authorization plugins, library inserts, login hooks, Spotlight and Quick Look
plugins, startup and periodic scripts, and shell start-up files. For every
program it records the code signature. This module runs only its
command-line scan:

    KnockKnock -whosthere -skipVT

``-skipVT`` keeps it off VirusTotal; with no ``-key`` it never queries
VirusTotal anyway, and nothing is sent anywhere. Without ``-apple`` it leaves
out what is part of macOS (signed by Apple, or files it knows by their hash).

KnockKnock hashes every item it finds (Apple's too), so a scan reads a lot of
files and is slow. It is opt-in: a plain checkup only says it's
available. A profile turns it on with ``module_config: {knockknock_scan:
{run_scan: true}}`` (the deep_startup_check and infected_device profiles).

An installed copy (/Applications/KnockKnock.app) is used when its signature
checks out. Otherwise the pinned release is downloaded once from GitHub into
the user cache folder, checked against its published sha256, unpacked with
ditto, and kept only if its signature satisfies Objective-See's Developer ID
(team VBG97UB4TA), notarized. That signature is checked again right before and
right after every run. Downloads follow the same switches as ai_agent_audit:
``--no-downloads`` / ``RESCUE_NO_DOWNLOADS=1`` / ``{downloads: false}``. It never
runs with administrator rights. KnockKnock needs Full Disk Access for the app
running it; without it, it stops and this check says it couldn't run.

What becomes a finding (what the light startup checks already list is not
repeated; docs/trust-and-safety.md says why):

- a program that starts on its own and is unsigned, ad-hoc signed, has a
  signature that doesn't check out, or couldn't be read: one lead each;
- anything at all in a rarely used place (library inserts, authorization
  plugins, login hooks...): one lead each;
- signed third-party items: one inventory note, with counts of what was left
  out (part of macOS, listed twice, or covered by another check).
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import tempfile
import threading
import zipfile
from pathlib import Path
from typing import Any

from rescue.command import run
from rescue.models import (
    CheckResult,
    Finding,
    FixResult,
    Mode,
    Platform,
    RiskLevel,
    Severity,
    SystemProfile,
)
from rescue.module_base import ModuleBase

KK_VERSION = "4.1.0"
KK_URL = (
    "https://github.com/objective-see/KnockKnock/releases/download/"
    f"v{KK_VERSION}/KnockKnock_{KK_VERSION}.zip"
)
# Published with the release (and checked against GitHub's own asset digest).
KK_ZIP_SHA256 = "98eae6cda5a7e122e6c7e68622617c00d6533a909f505f002c93dd90941a3f9e"
KK_ZIP_MAX_BYTES = 20 * 1024 * 1024
DOWNLOAD_HOST = "github.com"
TEAM_ID = "VBG97UB4TA"
BUNDLE_ID = "com.objective-see.KnockKnock"
# Objective-See's Developer ID, notarized: what a genuine KnockKnock satisfies.
REQUIREMENT = (
    f'identifier "{BUNDLE_ID}" and anchor apple generic'
    " and certificate 1[field.1.2.840.113635.100.6.2.6] exists"
    " and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
    f' and certificate leaf[subject.OU] = "{TEAM_ID}" and notarized'
)
APP_NAME = "KnockKnock.app"
EXECUTABLE = Path("Contents") / "MacOS" / "KnockKnock"
RESOLVE_TIMEOUT = 5.0
DOWNLOAD_TIMEOUT = 120
UNPACK_TIMEOUT = 60
VERIFY_TIMEOUT = 30
SCAN_TIMEOUT = 300
# Stand-ins filled in at run time (shown as "…" in docs/commands.md).
_KK = object()
_ZIP = object()
_DEST = object()
_APP = object()

CURL_ARGS = [
    "/usr/bin/curl", "--fail", "--silent", "--show-error", "--location",
    "--proto", "=https", "--proto-redir", "=https",
    "--max-filesize", str(KK_ZIP_MAX_BYTES), "--max-time", str(DOWNLOAD_TIMEOUT),
    "--output", _ZIP, KK_URL,
]
DITTO_ARGS = ["/usr/bin/ditto", "-x", "-k", _ZIP, _DEST]
VERIFY_ARGS = ["/usr/bin/codesign", "--verify", "--strict", "--deep",
               f"-R={REQUIREMENT}", "--", _APP]
SCAN_ARGS = [_KK, "-whosthere", "-skipVT"]

# Where a person may have installed KnockKnock themselves (~ is the home folder).
INSTALLED_APPS = ("/Applications/KnockKnock.app", "~/Applications/KnockKnock.app")

# KnockKnock's signer numbers (consts.h: enum Signer{None, Apple, AppStore, DevID, AdHoc}).
SIGNER_APPLE, SIGNER_APP_STORE, SIGNER_DEV_ID, SIGNER_AD_HOC = 1, 2, 3, 4
ERR_UNSIGNED = -67062  # errSecCSUnsigned
# 100000 + errno (kPOSIXErrorBase): the file couldn't be opened, e.g. 100013 permission denied.
_POSIX_BASE = 100000

# KnockKnock's group names. Items in these are covered by another check in the
# light checkup, so they are counted here, not repeated.
COVERED_ELSEWHERE = {
    "Cron Jobs": "cron_jobs_audit",
    "Browser Extensions": "browser_extension_audit",
    "Shell Configuration Files": "ai_worm_persistence",
}
# Places very few genuine programs use. Anything here that isn't part of
# macOS is a lead, signed or not.
RARE_PLACES = {
    "Library Inserts", "Library Proxies", "Authorization Plugins", "Login/Logout Hooks",
    "Dir. Services Plugins", "Event Rules", "Periodic Scripts", "Startup Scripts",
}
# Of those, the ones that put code inside other programs or the login window.
INJECTION_PLACES = {"Library Inserts", "Library Proxies", "Authorization Plugins",
                    "Login/Logout Hooks"}
# Group names as a person would say them.
PLACE_WORDS = {
    "Launch Items": "a launch agent or daemon",
    "Background Managed Tasks": "a background item macOS manages",
    "Login Items": "a login item",
    "Kernel Extensions": "a kernel extension",
    "System Extensions": "a system extension",
    "Extensions and Widgets": "an app extension or widget",
    "Dock Tiles Plugins": "a Dock plugin",
    "Quicklook Plugins": "a Quick Look plugin",
    "Spotlight Importers": "a Spotlight plugin",
    "Library Inserts": "a library inserted into other programs",
    "Library Proxies": "a library that stands in for another one",
    "Authorization Plugins": "a plugin in the login and password prompts",
    "Login/Logout Hooks": "a login or logout hook",
    "Dir. Services Plugins": "a directory services plugin",
    "Event Rules": "an event rule",
    "Periodic Scripts": "a periodic script",
    "Startup Scripts": "a startup script",
}
# The sealed system volume: macOS checks it at every start, and nothing can
# change it while System Integrity Protection is on. KnockKnock sometimes can't
# read a file there (permission denied); it is still macOS's own.
_SEALED_PREFIXES = ("/System/", "/usr/bin/", "/usr/sbin/", "/usr/lib/", "/usr/libexec/",
                    "/usr/share/", "/bin/", "/sbin/")
# The group a merged item is described by, when it was listed in several.
_GROUP_ORDER = ("Launch Items", "Login Items", "Kernel Extensions", "System Extensions")
# Developer tools whose programs are usually ad-hoc signed or unsigned.
_HOMEBREW_PREFIXES = ("/opt/homebrew/", "/usr/local/Cellar/", "/usr/local/opt/")
MAX_LEADS = 40
MAX_INVENTORY = 60

_COULD_NOT_CHECK = {
    "elevated": (
        "This check was run with administrator rights. Reclaim City doesn't run "
        "KnockKnock that way, because its copy lives in a folder any program "
        "running as you can change. Run the checkup the normal way (no sudo)."
    ),
    "downloads_off": (
        "This check uses a free tool called KnockKnock, which Reclaim City "
        "downloads the first time it's needed. Downloads are turned off for this "
        "scan, so it didn't run. Run the scan without --no-downloads to include it, "
        "or install KnockKnock yourself from https://objective-see.org."
    ),
    "kept_offline": (
        "This checkup is for a computer you're keeping off the internet, so "
        "Reclaim City didn't download KnockKnock, the free tool this check needs, "
        "and the check didn't run. If KnockKnock is installed in Applications, "
        "it's used instead."
    ),
    "offline": (
        "This check uses a free tool called KnockKnock, which Reclaim City "
        "downloads the first time it's needed. This computer isn't connected to "
        "the internet, so it wasn't downloaded and the check didn't run."
    ),
    "fetch_failed": (
        "This check uses a free tool called KnockKnock, which Reclaim City "
        "downloads from GitHub the first time it's needed. The download didn't "
        "finish, so the check didn't run. Run the checkup again later."
    ),
    "download_mismatch": (
        "Reclaim City downloaded KnockKnock, but the file wasn't the one "
        "Objective-See published, so it wasn't kept or run. Run the checkup again "
        "later. If this keeps happening, your network may be changing downloads; "
        "try another network."
    ),
    "signature_mismatch": (
        "The copy of KnockKnock on this computer isn't signed by Objective-See, "
        "the company that makes it, so it wasn't run."
    ),
    "unpack_failed": (
        "Reclaim City couldn't unpack KnockKnock (the disk may be full), so the "
        "check didn't run. Run the checkup again after freeing some space."
    ),
    "no_full_disk_access": (
        "KnockKnock needs Full Disk Access to see everything that starts on its "
        "own, and the app running this checkup doesn't have it, so the check "
        "didn't run. To include it: open System Settings > Privacy & Security > "
        "Full Disk Access, turn on Reclaim City (or Terminal, if you ran the "
        "checkup from there), quit and reopen it, and run this check again."
    ),
    "timed_out": (
        "KnockKnock took too long, so we stopped it. Run the check again to try "
        "once more."
    ),
    "tool_failed": (
        "KnockKnock stopped with an error before it finished, so we couldn't read "
        "what it found."
    ),
    "bad_output": (
        "KnockKnock finished, but its answer wasn't in a form we could read, so "
        "we didn't use it."
    ),
}


def host_resolves(host: str = DOWNLOAD_HOST, timeout: float = RESOLVE_TIMEOUT) -> bool:
    """Whether ``host`` resolves within ``timeout`` seconds. Never raises."""
    answer: list[bool] = []

    def lookup() -> None:
        try:
            answer.append(bool(socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)))
        except Exception:
            answer.append(False)

    worker = threading.Thread(target=lookup, name="knockknock-resolves", daemon=True)
    worker.start()
    worker.join(timeout)
    return bool(answer and answer[0])


def user_cache_dir() -> Path:
    override = os.environ.get("RESCUE_CACHE_DIR")
    return Path(override) if override else Path.home() / "Library" / "Caches"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _fill(template: list, **values: Any) -> list[str]:
    stand_ins = {id(_KK): "kk", id(_ZIP): "zip", id(_DEST): "dest", id(_APP): "app"}
    return [str(values[stand_ins[id(a)]]) if id(a) in stand_ins else a for a in template]


def _zip_is_plain(path: Path) -> bool:
    """Every entry sits inside KnockKnock.app, with no absolute or '..' parts."""
    try:
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
    except (OSError, zipfile.BadZipFile):
        return False
    for name in names:
        parts = Path(name).parts
        if name.startswith("/") or ".." in parts or not parts:
            return False
        if parts[0] != APP_NAME and not parts[0].startswith("__MACOSX"):
            return False
    return bool(names)


class _CouldNotCheck(Exception):
    def __init__(self, reason: str, **data: Any):
        super().__init__(reason)
        self.reason = reason
        self.data = data


class _ChangedDuringRun(Exception):
    """KnockKnock's signature stopped checking out while it ran."""


def signature_state(item: dict) -> str:
    """'apple', 'signed', 'ad_hoc', 'unsigned', 'broken', 'unreadable' or 'none' (not code)."""
    sig = item.get("signature(s)")
    if "command" in item or "browser" in item:
        return "none"
    if not isinstance(sig, dict):
        return "unreadable"
    status = sig.get("signatureStatus")
    signer = sig.get("signatureSigner")
    if not isinstance(status, int):
        return "unreadable"
    if status == ERR_UNSIGNED:
        return "unsigned"
    if status >= _POSIX_BASE:
        return "unreadable"
    if status != 0:
        return "broken"
    if signer == SIGNER_APPLE:
        return "apple"
    ident = sig.get("signatureIdentifier")
    if signer == SIGNER_APP_STORE and isinstance(ident, str) and ident.startswith("com.apple."):
        return "apple"
    if signer == SIGNER_AD_HOC:
        return "ad_hoc"
    if signer in (SIGNER_APP_STORE, SIGNER_DEV_ID):
        return "signed"
    return "unsigned"


def _team_of(item: dict) -> str | None:
    sig = item.get("signature(s)")
    auths = sig.get("signatureAuthorities") if isinstance(sig, dict) else None
    if isinstance(auths, list) and auths and isinstance(auths[0], str):
        # App Store apps are signed by Apple on the developer's behalf.
        return "Mac App Store" if auths[0] == "Apple Mac OS Application Signing" else auths[0]
    return None


def merge_items(doc: dict) -> tuple[list[dict], dict[str, int]]:
    """One entry per (program, settings file), with every group it showed up in.

    Returns the merged entries and how many listings were folded away as
    duplicates or left to another check.
    """
    merged: dict[tuple, dict] = {}
    counts = {"duplicates": 0, "covered_elsewhere": 0}
    for group, items in doc.items():
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            if group in COVERED_ELSEWHERE:
                counts["covered_elsewhere"] += 1
                continue
            path = item.get("path") if "path" in item else item.get("file")
            path = path if isinstance(path, str) else ""
            plist = item.get("plist") if isinstance(item.get("plist"), str) else ""
            plist = "" if plist in ("n/a", "unknown") else plist
            key = (path, plist)
            if key in merged:
                counts["duplicates"] += 1
                if group not in merged[key]["groups"]:
                    merged[key]["groups"].append(group)
                continue
            merged[key] = {"item": item, "path": path, "plist": plist, "groups": [group]}
    return list(merged.values()), counts


class Module(ModuleBase):
    name = "knockknock_scan"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 58
    depends_on = []
    estimated_duration = "off unless a profile turns it on; slow when on (first run downloads 2.5 MB)"

    emits_codes = [
        "security.knockknock_scan.unsigned_autostart",
        "security.knockknock_scan.broken_signature",
        "security.knockknock_scan.unreadable_autostart",
        "security.knockknock_scan.rare_autostart_place",
        "security.knockknock_scan.signed_inventory",
        "security.knockknock_scan.not_run",
        "security.knockknock_scan.could_not_check",
        "security.knockknock_scan.changed_during_run",
    ]

    # Off by default: a scan hashes every startup item, Apple's too.
    run_scan: bool = False
    downloads_allowed: bool = True
    scan_timeout: int = SCAN_TIMEOUT
    # Seams for tests: None = the real defaults.
    installed_apps: tuple[str, ...] | None = None
    elevated: bool | None = None
    host_resolves: Any = None

    def configure(self, config: dict[str, Any]) -> None:
        config = config or {}
        self.run_scan = bool(config.get("run_scan", False))
        self.downloads_allowed = config.get("downloads", True) is not False
        if "scan_timeout" in config:
            self.scan_timeout = int(config["scan_timeout"])
        if self.run_scan:
            # Room for a first download, the run and the two signature checks.
            self.check_timeout = (DOWNLOAD_TIMEOUT + UNPACK_TIMEOUT + 3 * VERIFY_TIMEOUT
                                  + self.scan_timeout + 30)

    def check(self, profile: SystemProfile) -> CheckResult:
        self._stderr_notes: list[str] = []
        if not self.run_scan:
            return CheckResult(module_name=self.name, findings=[self._not_run_finding()])
        try:
            doc, app, source = self._scan()
        except _CouldNotCheck as exc:
            return CheckResult(module_name=self.name, findings=[self._could_not_check(exc)])
        except _ChangedDuringRun:
            return CheckResult(module_name=self.name, findings=[self._changed_during_run()])
        return CheckResult(module_name=self.name, findings=self._findings(doc, app, source))

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        # Removing a startup item is the launch-agent fix or the person's own
        # choice in System Settings; nothing is changed from here.
        return FixResult(module_name=self.name, actions=[])

    # --- getting a verified KnockKnock ----------------------------------------

    def _is_elevated(self) -> bool:
        if self.elevated is not None:
            return bool(self.elevated)
        geteuid = getattr(os, "geteuid", None)
        return bool(geteuid is not None and geteuid() == 0)

    def _install_dir(self) -> Path:
        return user_cache_dir() / "ReclaimCity" / f"knockknock-{KK_VERSION}"

    def _verified(self, app: Path) -> bool:
        if app.is_symlink() or not (app / EXECUTABLE).is_file():
            return False
        res = run(_fill(VERIFY_ARGS, app=app), timeout=VERIFY_TIMEOUT)
        return res.ok

    def _find_app(self) -> tuple[Path, str]:
        """A KnockKnock whose signature checks out: installed, saved, or freshly fetched."""
        candidates = self.installed_apps if self.installed_apps is not None else INSTALLED_APPS
        installed_but_wrong = False
        for raw in candidates:
            app = Path(os.path.expanduser(raw))
            if not app.exists():
                continue
            if self._verified(app):
                return app, "installed"
            installed_but_wrong = True
        saved = self._install_dir() / APP_NAME
        if saved.exists():
            if self._verified(saved):
                return saved, "downloaded"
            shutil.rmtree(self._install_dir(), ignore_errors=True)
        if os.environ.get("RESCUE_NO_DOWNLOADS") == "1":
            raise _CouldNotCheck("downloads_off", installed_but_wrong=installed_but_wrong)
        if not self.downloads_allowed:
            raise _CouldNotCheck("kept_offline", installed_but_wrong=installed_but_wrong)
        resolves = self.host_resolves if self.host_resolves is not None else host_resolves
        if not resolves():
            raise _CouldNotCheck("offline")
        return self._fetch(), "downloaded"

    def _fetch(self) -> Path:
        install = self._install_dir()
        install.parent.mkdir(parents=True, exist_ok=True)
        work = Path(tempfile.mkdtemp(prefix=".knockknock-", dir=install.parent))
        try:
            archive = work / f"KnockKnock_{KK_VERSION}.zip"
            res = run(_fill(CURL_ARGS, zip=archive), timeout=DOWNLOAD_TIMEOUT + 10)
            if not res.ok or not archive.is_file():
                raise _CouldNotCheck("fetch_failed", detail=(res.stderr or res.error or "")[:200])
            if archive.stat().st_size > KK_ZIP_MAX_BYTES or _sha256(archive) != KK_ZIP_SHA256:
                raise _CouldNotCheck("download_mismatch")
            if not _zip_is_plain(archive):
                raise _CouldNotCheck("download_mismatch")
            unpacked = work / "unpacked"
            res = run(_fill(DITTO_ARGS, zip=archive, dest=unpacked), timeout=UNPACK_TIMEOUT)
            app = unpacked / APP_NAME
            if not res.ok or not app.is_dir():
                raise _CouldNotCheck("unpack_failed", detail=(res.stderr or res.error or "")[:200])
            shutil.rmtree(install, ignore_errors=True)
            install.mkdir(parents=True)
            os.replace(app, install / APP_NAME)
            # Checked where it will run from, right before the run.
            if not self._verified(install / APP_NAME):
                shutil.rmtree(install, ignore_errors=True)
                raise _CouldNotCheck("signature_mismatch")
        except OSError as exc:
            raise _CouldNotCheck("unpack_failed", detail=str(exc)[:200]) from exc
        finally:
            shutil.rmtree(work, ignore_errors=True)
        return install / APP_NAME

    # --- running it -----------------------------------------------------------------

    def _scan(self) -> tuple[dict, Path, str]:
        if self._is_elevated():
            raise _CouldNotCheck("elevated")
        app, source = self._find_app()
        env = {k: v for k, v in os.environ.items() if k in ("HOME", "PATH", "LANG", "TMPDIR", "USER")}
        res = run(_fill(SCAN_ARGS, kk=app / EXECUTABLE), timeout=self.scan_timeout,
                  max_output=32 * 1024 * 1024, env=env)
        # A genuine KnockKnock's signature can't stop checking out mid-run;
        # if it did, something swapped files and its answer can't be trusted.
        if not self._verified(app):
            if source == "downloaded":
                shutil.rmtree(self._install_dir(), ignore_errors=True)
            raise _ChangedDuringRun()
        if res.timed_out:
            raise _CouldNotCheck("timed_out", seconds=self.scan_timeout)
        if "Full Disk Access" in (res.stderr or ""):
            raise _CouldNotCheck("no_full_disk_access")
        if res.returncode != 0:
            raise _CouldNotCheck("tool_failed", detail=(res.stderr or res.error or "")[:200])
        try:
            doc = json.loads(res.stdout)
        except ValueError:
            doc = None
        if not isinstance(doc, dict) or "ERROR" in doc or res.truncated:
            raise _CouldNotCheck("bad_output")
        self._stderr_notes = [line.strip()[:200] for line in (res.stderr or "").splitlines()
                              if line.startswith("ERROR: plugin")][:10]
        return doc, app, source

    # --- findings -------------------------------------------------------------------

    @staticmethod
    def _tilde(path: str) -> str:
        home = str(Path.home())
        return "~" + path[len(home):] if path == home or path.startswith(home + "/") else path

    def _findings(self, doc: dict, app: Path, source: str) -> list[Finding]:
        entries, counts = merge_items(doc)
        leads: list[Finding] = []
        signed: list[dict] = []
        apple = 0
        for entry in entries:
            state = signature_state(entry["item"])
            rare = any(g in RARE_PLACES for g in entry["groups"])
            if state == "apple" or (state == "unreadable"
                                    and entry["path"].startswith(_SEALED_PREFIXES)):
                apple += 1
                continue
            if rare:
                leads.append(self._rare_finding(entry, state))
            elif state in ("unsigned", "ad_hoc", "none"):
                leads.append(self._unsigned_finding(entry, state))
            elif state == "broken":
                leads.append(self._broken_finding(entry))
            elif state == "unreadable":
                leads.append(self._unreadable_finding(entry))
            else:
                signed.append(entry)
        leads.sort(key=lambda f: 0 if f.severity == Severity.CRITICAL else 1)
        more = max(0, len(leads) - MAX_LEADS)
        findings = leads[:MAX_LEADS]
        findings.append(self._inventory(signed, apple, counts, len(leads), more, app, source))
        return findings

    def _where(self, entry: dict) -> str:
        groups = sorted(entry["groups"], key=lambda g: _GROUP_ORDER.index(g)
                        if g in _GROUP_ORDER else len(_GROUP_ORDER))
        return PLACE_WORDS.get(groups[0], groups[0].lower()) if groups else "something that starts on its own"

    def _item_data(self, entry: dict, state: str) -> dict:
        item = entry["item"]
        sig = item.get("signature(s)") if isinstance(item.get("signature(s)"), dict) else {}
        data = {
            "path": entry["path"],
            "name": item.get("name") if isinstance(item.get("name"), str) else Path(entry["path"]).name,
            "knockknock_groups": entry["groups"],
            "signature": state,
            "signature_status": sig.get("signatureStatus"),
            "signing_identifier": sig.get("signatureIdentifier"),
            "signed_by": _team_of(item),
            "notarized": bool(sig.get("notarized")),
        }
        if entry["plist"]:
            data["plist"] = entry["plist"]
        hashes = item.get("hashes")
        if isinstance(hashes, dict) and isinstance(hashes.get("sha256"), str):
            data["sha256"] = hashes["sha256"].lower()
        return data

    def _file_lines(self, entry: dict) -> str:
        lines = f"The program: {self._tilde(entry['path'])}"
        if entry["plist"]:
            lines += f"\nStarted by: {self._tilde(entry['plist'])}"
        return lines

    def _unsigned_finding(self, entry: dict, state: str) -> Finding:
        data = self._item_data(entry, state)
        name = data["name"]
        how = ("carries only an ad-hoc signature, which doesn't name a maker"
               if state == "ad_hoc" else "isn't signed")
        homebrew = entry["path"].startswith(_HOMEBREW_PREFIXES)
        source_note = (
            "It's in Homebrew's folder, so it was most likely installed with Homebrew, "
            "a tool developers use to install programs; those are usually signed this way. "
            if homebrew else
            "Scripts and programs people write or build for themselves are often "
            "unsigned. So is a lot of malware. "
        )
        return Finding(
            title=f"Starts on its own, and nothing says who made it: {name}",
            description=(
                f"{name} is set up as {self._where(entry)}, so it runs without "
                f"anyone opening it. Its program {how}, so macOS can't tell who "
                f"made it. {source_note}On its own this doesn't mean anything is "
                "wrong.\n\n"
                f"{self._file_lines(entry)}\n\n"
                "What to do: If you know what this is (you set it up, or someone who "
                "helps you did), there's nothing to do. If you don't, don't delete it yet: "
                "search for its name, or ask someone who helps you with computers. "
                "The steps below go through it."
            ),
            severity=Severity.WARNING,
            category=self.category,
            code="security.knockknock_scan.unsigned_autostart",
            data=data,
            confidence=0.5,
        )

    def _broken_finding(self, entry: dict) -> Finding:
        data = self._item_data(entry, "broken")
        name = data["name"]
        return Finding(
            title=f"Starts on its own, and its signature doesn't check out: {name}",
            description=(
                f"{name} is set up as {self._where(entry)}. It carries a signature, "
                "but the signature doesn't match the program any more: the file was "
                "changed after it was signed. Apps that update themselves "
                "sometimes cause this for a moment; a program someone tampered with "
                "looks the same.\n\n"
                f"{self._file_lines(entry)}\n\n"
                "What to do: Update or reinstall the app it belongs to, from its "
                "maker's website or the App Store, and run this check again. If it "
                "still doesn't check out, or you don't know what it is, ask someone "
                "who helps you with computers before removing it."
            ),
            severity=Severity.WARNING,
            category=self.category,
            code="security.knockknock_scan.broken_signature",
            data=data,
            confidence=0.6,
        )

    def _unreadable_finding(self, entry: dict) -> Finding:
        data = self._item_data(entry, "unreadable")
        name = data["name"]
        return Finding(
            title=f"Starts on its own, and we couldn't read it to check who made it: {name}",
            description=(
                f"{name} is set up as {self._where(entry)}, but its program couldn't "
                "be opened to check its signature (usually because only the system "
                "account can read it, or the file is missing). That doesn't mean "
                "anything is wrong; it means this one wasn't checked.\n\n"
                f"{self._file_lines(entry)}\n\n"
                "What to do: If the name matches an app you use (it often starts "
                "with the maker's name), it's most likely that app's helper. If you "
                "don't recognise it, ask someone who helps you with computers."
            ),
            severity=Severity.WARNING,
            category=self.category,
            code="security.knockknock_scan.unreadable_autostart",
            data=data,
            confidence=0.3,
        )

    def _rare_finding(self, entry: dict, state: str) -> Finding:
        data = self._item_data(entry, state)
        name = data["name"]
        injects = any(g in INJECTION_PLACES for g in entry["groups"])
        unverified = state in ("unsigned", "ad_hoc", "broken", "unreadable", "none")
        signed_note = (
            "It isn't signed by a maker macOS can check."
            if unverified else
            f"It is signed ({data['signed_by'] or 'by a registered developer'}), which "
            "says who made it, not that it belongs here."
        )
        what = (
            "Code put here runs inside other programs or the login window, where it "
            "can see what's typed, including passwords. Some security and "
            "company-management tools use it; so does malware."
            if injects else
            "Very few genuine apps use this place; it's an old way to make "
            "something run that macOS still honours."
        )
        return Finding(
            title=f"Something is set up in a rarely used startup place: {name}",
            description=(
                f"{name} is set up as {self._where(entry)}. {what} {signed_note}\n\n"
                f"{self._file_lines(entry)}\n\n"
                "What to do: If this computer belongs to a workplace or school, ask "
                "its IT team whether it's theirs. If not, and you didn't install a "
                "security or remote-support tool, ask someone who helps you with "
                "computers before removing it. If you think someone close to you "
                "may have put monitoring software on this Mac, removing it can alert "
                "them; read the safety note in the steps below first."
            ),
            severity=Severity.CRITICAL if (injects and unverified) else Severity.WARNING,
            category=self.category,
            code="security.knockknock_scan.rare_autostart_place",
            data=data,
            confidence=0.6 if unverified else 0.4,
        )

    def _inventory(self, signed: list[dict], apple: int, counts: dict, leads: int,
                   more: int, app: Path, source: str) -> Finding:
        items = []
        for entry in signed[:MAX_INVENTORY]:
            item = entry["item"]
            items.append({
                "name": item.get("name") if isinstance(item.get("name"), str) else Path(entry["path"]).name,
                "path": entry["path"],
                **({"plist": entry["plist"]} if entry["plist"] else {}),
                "signed_by": _team_of(item),
                "knockknock_groups": entry["groups"],
            })
        total = len(signed) + leads
        text = (
            f"KnockKnock looked at everything set to start on its own. Besides what "
            f"is part of macOS, it found {total} item(s). {len(signed)} are "
            "signed by a maker macOS could check (the list is in the details); "
            f"{leads} are listed above as worth a look."
        )
        if more:
            text += (f" {more} more like those weren't listed separately; run "
                     "KnockKnock yourself to see them all.")
        text += (
            f"\n\nLeft out: {apple} item(s) that run a program that's part of macOS "
            f"(often a script started with bash or python), {counts['duplicates']} listed "
            f"twice, and {counts['covered_elsewhere']} cron job(s), browser "
            "extension(s) and shell start-up file(s), which other checks cover.\n\n"
            "Signed doesn't mean safe; it means the maker is known. Read the list "
            "for anything you don't remember installing."
        )
        data = {
            "items": items,
            "signed_count": len(signed),
            "lead_count": leads,
            "not_listed_leads": more,
            "apple_run_count": apple,
            "duplicates": counts["duplicates"],
            "covered_elsewhere": counts["covered_elsewhere"],
            "knockknock_version": KK_VERSION if source == "downloaded" else None,
            "knockknock_source": source,
            "knockknock_app": self._tilde(str(app)),
        }
        if self._stderr_notes:
            data["incomplete"] = self._stderr_notes
            text += ("\n\nKnockKnock couldn't finish one or more of its own checks, so "
                     "this list may be missing something.")
        return Finding(
            title=f"What starts on its own, from KnockKnock ({total} items besides macOS's own)",
            description=text,
            severity=Severity.INFO,
            category=self.category,
            code="security.knockknock_scan.signed_inventory",
            data=data,
        )

    def _not_run_finding(self) -> Finding:
        return Finding(
            title="Deeper startup check is available (not run in this checkup)",
            description=(
                "A free tool called KnockKnock, from Objective-See, can list everything "
                "set to start on its own on this Mac, in more places than this checkup "
                "looks, and check who signed each one. It reads a lot of files, so it "
                "isn't part of this checkup and nothing was checked by it. To run it, "
                "choose the deep startup check (rescue scan --profile "
                "deep_startup_check). The first run downloads KnockKnock (2.5 MB) "
                "from GitHub."
            ),
            severity=Severity.INFO,
            category=self.category,
            code="security.knockknock_scan.not_run",
            data={"reason": "not_enabled"},
        )

    def _could_not_check(self, exc: _CouldNotCheck) -> Finding:
        text = _COULD_NOT_CHECK[exc.reason]
        if exc.data.get("installed_but_wrong"):
            text += ("\n\nThere is a copy of KnockKnock in Applications, but it isn't "
                     "signed by Objective-See, so it wasn't used.")
        return Finding(
            title="Couldn't run the deeper startup check (KnockKnock)",
            description=(
                f"{text}\n\nThis means KnockKnock didn't look at what starts on its own; "
                "it doesn't mean everything is fine or that something is wrong. The "
                "rest of the checkup's startup checks still ran."
            ),
            severity=Severity.INFO,
            category=self.category,
            code="security.knockknock_scan.could_not_check",
            data={"reason": exc.reason, **exc.data},
        )

    def _changed_during_run(self) -> Finding:
        return Finding(
            title="The startup checker's files changed while it was running",
            description=(
                "Right after KnockKnock (the free tool this check uses) ran, its "
                "signature no longer checked out. A genuine copy can't change like "
                "that. It may mean another program on this computer swapped in its "
                "own code, which would then have run with Reclaim City's permissions. "
                "We threw its results away and deleted the downloaded copy.\n\n"
                "What to do: Run the checkup again and look closely at what starts on "
                "its own. If this happens again, treat this Mac as possibly "
                "compromised: change important passwords from a different device, and "
                "ask someone you trust who helps you with computers."
            ),
            severity=Severity.WARNING,
            category=self.category,
            code="security.knockknock_scan.changed_during_run",
            data={"reason": "changed_during_run"},
        )

