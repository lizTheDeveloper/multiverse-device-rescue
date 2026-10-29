"""clamav_scanner: is ClamAV here, and (when asked) a ClamAV scan of the places malware lands.

ClamAV is a free, open-source virus scanner (Cisco Talos, GPL-2.0). Reclaim
City never installs it; the person can, from https://www.clamav.net/downloads
(an installer for Mac and Windows), their Linux package manager, or Homebrew.

By default this check only looks: is ClamAV installed, how old its virus list
is, whether its background scanner runs. Reading files with it is opt-in
(``module_config: {clamav_scanner: {scan_files: true}}``, which the
deep_virus_scan profile sets), because loading ClamAV's virus list takes a lot
of memory and a scan reads many files. The scan:

* runs ``clamscan`` on the same places as malware_file_scan (rescue/file_scan.py),
  every kind of file there, archives and disk images included, with a cap on
  each file's size and on the total, and a time limit;
* uses ClamAV's own virus list when it is less than a week old; otherwise, the
  first time, downloads a fresh one (about 115 MB, from ClamAV's own servers,
  with ClamAV's own ``freshclam``) into Reclaim City's cache folder. That
  download honours ``--no-downloads`` / ``RESCUE_NO_DOWNLOADS=1`` and a
  profile's ``downloads: false``, and never runs with administrator rights.

A match is reported; moving the file into quarantine is a separate action the
person agrees to (rescue/actions/quarantine_file.py).
"""

from __future__ import annotations

import os
import re
import shutil
import socket
import tempfile
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from rescue import file_scan
from rescue.command import run
from rescue.models import (
    Action,
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

MB = 1024 * 1024
CLAMAV_DOWNLOADS = "https://www.clamav.net/downloads"
MIRROR_HOST = "database.clamav.net"
DB_DOWNLOAD_SIZE = "about 115 MB"
# A virus list older than this is refreshed before a scan (when downloads are allowed).
FRESH_DAYS = 7
# Older than this, the "is it installed" check calls the list out of date.
OUTDATED_DAYS = 30
VERSION_TIMEOUT = 15
FRESHCLAM_TIMEOUT = 900
RESOLVE_TIMEOUT = 5.0
# ClamAV's own folders for its virus list, per platform.
_DB_DIRS = {
    "darwin": ["/opt/homebrew/var/lib/clamav", "/usr/local/var/lib/clamav", "/usr/local/clamav/share/clamav",
               "~/.clamav"],
    "linux": ["/var/lib/clamav", "/usr/local/share/clamav", "/var/clamav"],
    "win32": ["C:\\Program Files\\ClamAV\\database", "C:\\Program Files\\ClamAV"],
}
# Where the installers put clamscan, when it isn't on PATH.
_BIN_DIRS = {
    "darwin": ["/usr/local/clamav/bin", "/opt/homebrew/bin", "/usr/local/bin"],
    "linux": ["/usr/bin", "/usr/local/bin"],
    "win32": ["C:\\Program Files\\ClamAV"],
}
_DB_FILES = ("main.cvd", "main.cld", "daily.cvd", "daily.cld")
# "<path>: <signature> FOUND", one per infected file (clamscan --infected).
_FOUND_RE = re.compile(r"^(?P<path>.+?): (?P<sig>\S+) FOUND$")

_GET_IT = {
    "darwin": (
        "If you'd like a second opinion, ClamAV is free: download the macOS installer (the "
        f".pkg file) from {CLAMAV_DOWNLOADS}. If you already use Homebrew, 'brew install "
        "clamav' works too. You don't need it: Apple's own protection and Reclaim City's "
        "file check already run."
    ),
    "win32": (
        "Windows already has a virus scanner built in (Windows Security). If you'd like ClamAV "
        f"too, download the Windows installer (the .msi file) from {CLAMAV_DOWNLOADS}."
    ),
    "linux": (
        "If you'd like it, install the clamav package from your system's software app or "
        "package manager (on Ubuntu or Debian: sudo apt install clamav clamav-freshclam)."
    ),
}

# Why the deep scan couldn't run, in plain words. Keys are data.reason.
_COULD_NOT_SCAN = {
    "not_installed": "ClamAV isn't installed, so the ClamAV scan didn't run.",
    "downloads_off": (
        "ClamAV needs an up-to-date virus list, and this one is missing or more than a week "
        f"old. Getting a fresh one is a download ({DB_DOWNLOAD_SIZE}), and downloads are "
        "turned off for this scan, so the ClamAV scan didn't run. Run it without "
        "--no-downloads to include it."
    ),
    "kept_offline": (
        "This checkup is for a computer you're keeping off the internet, so Reclaim City "
        f"didn't download ClamAV's virus list ({DB_DOWNLOAD_SIZE}) and the ClamAV scan didn't run."
    ),
    "offline": (
        "ClamAV's virus list is missing or more than a week old, and this computer isn't "
        "connected to the internet, so a fresh one couldn't be downloaded. The ClamAV scan "
        "didn't run."
    ),
    "no_freshclam": (
        "ClamAV's virus list is missing or old, and ClamAV's updater (freshclam) isn't "
        "installed, so we couldn't get a fresh one. The ClamAV scan didn't run. Reinstalling "
        f"ClamAV from {CLAMAV_DOWNLOADS} puts the updater back."
    ),
    "fetch_failed": (
        "We tried to download ClamAV's virus list from ClamAV's servers, but it didn't finish "
        "(the connection may have dropped, or ClamAV's servers asked us to wait). The ClamAV "
        "scan didn't run. Try again later."
    ),
    "elevated": (
        "Reclaim City is running with administrator rights, and it doesn't download anything "
        "with those rights, so ClamAV's virus list wasn't fetched and the ClamAV scan didn't "
        "run. Run the checkup the normal way, without sudo or \u201cRun as administrator\u201d."
    ),
    "scan_failed": "ClamAV started but stopped with an error before it could report, so nothing was checked.",
    "nothing_to_scan": "We found no files in the places this scan looks, so ClamAV had nothing to check.",
}


def _resolves(host: str = MIRROR_HOST, timeout: float = RESOLVE_TIMEOUT) -> bool:
    """Whether ClamAV's download server's name resolves. Never raises."""
    answer: list[bool] = []

    def lookup() -> None:
        try:
            answer.append(bool(socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)))
        except Exception:
            answer.append(False)

    worker = threading.Thread(target=lookup, name="clamav-resolves", daemon=True)
    worker.start()
    worker.join(timeout)
    return bool(answer and answer[0])


class _CouldNotScan(Exception):
    def __init__(self, reason: str, **data: Any):
        super().__init__(reason)
        self.reason = reason
        self.data = data


class Module(ModuleBase):
    name = "clamav_scanner"
    category = "security"
    platforms = [Platform.DARWIN, Platform.LINUX, Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 56
    depends_on = []
    estimated_duration = "2s; the deep virus scan reads many files"

    emits_codes = [
        "security.clamav_scanner.clamav_not_installed",
        "security.clamav_scanner.clamav_version",
        "security.clamav_scanner.freshclam_not_installed",
        "security.clamav_scanner.clamav_definitions",
        "security.clamav_scanner.clamav_outdated_definitions",
        "security.clamav_scanner.clamd_not_running",
        "security.clamav_scanner.clamd_running",
        "security.clamav_scanner.deep_scan_available",
        "security.clamav_scanner.virus_found",
        "security.clamav_scanner.monitoring_found",
        "security.clamav_scanner.scan_clean",
        "security.clamav_scanner.scan_incomplete",
        "security.clamav_scanner.could_not_scan",
    ]

    # Off by default: the deep_virus_scan profile turns it on.
    scan_files: bool = False
    max_file_bytes: int = 100 * MB
    max_total_bytes: int = 4096 * MB
    max_files: int = 50000
    scan_timeout: float = 1800.0
    downloads_allowed: bool = True
    # Seams for tests.
    home: Path | None = None
    runner: Any = None
    which: Any = None
    elevated: bool | None = None
    mirror_resolves: Any = None
    cache_dir: Path | None = None
    db_dirs: list[str] | None = None
    clock: Any = None

    def configure(self, config: dict[str, Any]) -> None:
        config = config or {}
        if "scan_files" in config:
            self.scan_files = bool(config["scan_files"])
        for key in ("max_file_bytes", "max_total_bytes", "max_files"):
            if key in config:
                setattr(self, key, int(config[key]))
        if "scan_timeout" in config:
            self.scan_timeout = float(config["scan_timeout"])
        self.downloads_allowed = config.get("downloads", True) is not False
        if self.scan_files:
            # The orchestrator reads check_timeout: room for the download and the scan.
            self.check_timeout = FRESHCLAM_TIMEOUT + self.scan_timeout + 120

    # --- check ------------------------------------------------------------------

    def check(self, profile: SystemProfile) -> CheckResult:
        platform = profile.platform.value
        findings: list[Finding] = []
        clamscan = self._find("clamscan", platform)
        freshclam = self._find("freshclam", platform)

        if not clamscan:
            findings.append(Finding(
                title="ClamAV (a free extra virus scanner) isn't installed",
                description="ClamAV is a free virus scanner you can add. It isn't on this computer. "
                            + _GET_IT[platform],
                severity=Severity.INFO,
                category=self.category,
                code="security.clamav_scanner.clamav_not_installed",
                data={"check": "clamav_not_installed", "download_page": CLAMAV_DOWNLOADS},
            ))
            if self.scan_files:
                findings.append(self._could_not_scan(_CouldNotScan("not_installed")))
            return CheckResult(module_name=self.name, findings=findings)

        version = self._get_clamav_version(clamscan)
        if version:
            findings.append(Finding(
                title=f"Antivirus software installed: ClamAV {version}",
                description=(
                    f"ClamAV version {version} is installed. It's a free, open-source virus "
                    "scanner. It only checks files when it's asked to."
                ),
                severity=Severity.INFO,
                category=self.category,
                code="security.clamav_scanner.clamav_version",
                data={"check": "clamav_version", "version": version, "clamscan": clamscan},
            ))

        if not freshclam:
            findings.append(Finding(
                title="ClamAV cannot update its virus list",
                description=(
                    "ClamAV needs its updater, freshclam, to get new virus lists. It isn't "
                    "installed, so ClamAV's list will get old and miss new threats.\n\n"
                    f"What to do: Reinstall ClamAV from {CLAMAV_DOWNLOADS} (or the same way you "
                    "installed it); that puts the updater back."
                ),
                severity=Severity.WARNING,
                category=self.category,
                code="security.clamav_scanner.freshclam_not_installed",
                data={"check": "freshclam_not_installed"},
            ))

        db_dir, def_age = self._newest_database(platform)
        if db_dir is not None:
            def_version = self._get_definition_version(db_dir, platform)
            findings.append(Finding(
                title=f"ClamAV's virus list is {def_age} days old",
                description=(
                    f"ClamAV's list of known viruses{f' (version {def_version})' if def_version else ''} "
                    f"was last updated {def_age} days ago."
                ),
                severity=Severity.INFO,
                category=self.category,
                code="security.clamav_scanner.clamav_definitions",
                data={"check": "clamav_definitions", "def_version": def_version, "def_age": def_age,
                      "database_dir": db_dir},
            ))
            if def_age > OUTDATED_DAYS:
                findings.append(Finding(
                    title=f"ClamAV's virus list is {def_age} days old",
                    description=(
                        "ClamAV recognises viruses from a list, and new ones appear all the time. "
                        f"This list is {def_age} days old, so ClamAV may miss recent threats.\n\n"
                        "What to do: Run ClamAV's updater (freshclam), or let the deep virus scan "
                        "fetch a fresh list of its own. If you don't use ClamAV, you can ignore this."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.clamav_scanner.clamav_outdated_definitions",
                    data={"check": "clamav_outdated_definitions", "def_age": def_age},
                ))

        if self._check_daemon_running(platform):
            findings.append(Finding(
                title="ClamAV background scanner is running",
                description="ClamAV's background service (clamd) is running.",
                severity=Severity.INFO,
                category=self.category,
                code="security.clamav_scanner.clamd_running",
                data={"check": "clamd_running"},
            ))
        else:
            findings.append(Finding(
                title="ClamAV's background scanner isn't running",
                description=(
                    "ClamAV's optional background service (clamd) isn't running. That's fine if "
                    "you only run scans when you want them, which is how Reclaim City uses ClamAV."
                ),
                severity=Severity.INFO,
                category=self.category,
                code="security.clamav_scanner.clamd_not_running",
                data={"check": "clamd_not_running"},
            ))

        if not self.scan_files:
            findings.append(Finding(
                title="A ClamAV scan of your files is available",
                description=(
                    "ClamAV can check the places malware usually lands (Downloads, temporary "
                    "folders, apps, add-ons), including inside zip files and disk images. It "
                    "isn't part of the ordinary checkup because it uses a lot of memory and "
                    "reads many files. The deep virus scan runs it; the first time, it may "
                    f"download a fresh virus list ({DB_DOWNLOAD_SIZE}) from ClamAV's servers."
                ),
                severity=Severity.INFO,
                category=self.category,
                code="security.clamav_scanner.deep_scan_available",
                data={"check": "deep_scan_available", "download_size": DB_DOWNLOAD_SIZE},
            ))
            return CheckResult(module_name=self.name, findings=findings)

        try:
            findings += self._deep_scan(clamscan, freshclam, platform, db_dir, def_age)
        except _CouldNotScan as exc:
            findings.append(self._could_not_scan(exc))
        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        # Guidance only. Quarantine of a file ClamAV found is the engine's own
        # quarantine_file action, offered per finding and confirmed by the person.
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")
            if check == "clamav_not_installed":
                actions.append(Action(
                    title="Install ClamAV",
                    description=(
                        f"Download the installer for your computer from {CLAMAV_DOWNLOADS} and run "
                        "it (on Linux, install the clamav package with your package manager; with "
                        "Homebrew on a Mac, brew install clamav)."
                    ),
                    risk_level=RiskLevel.SAFE,
                    success=True,
                ))
            elif check == "freshclam_not_installed":
                actions.append(Action(
                    title="Install freshclam",
                    description=f"freshclam comes with ClamAV. Reinstall ClamAV from {CLAMAV_DOWNLOADS}.",
                    risk_level=RiskLevel.SAFE,
                    success=True,
                ))
            elif check == "clamav_outdated_definitions":
                actions.append(Action(
                    title="Update ClamAV virus definitions",
                    description="Run ClamAV's updater: freshclam",
                    risk_level=RiskLevel.SAFE,
                    success=True,
                ))
        return FixResult(module_name=self.name, actions=actions)

    # --- the deep scan ----------------------------------------------------------

    def _deep_scan(self, clamscan: str, freshclam: str | None, platform: str,
                   db_dir: str | None, def_age: int) -> list[Finding]:
        database, fetched = self._usable_database(freshclam, platform, db_dir, def_age)
        home = self.home or Path.home()
        found = file_scan.collect_targets(
            platform, home, max_file_bytes=self.max_file_bytes, max_files=self.max_files, programs_only=False,
        )
        chosen, total, left = [], 0, 0
        for target in found.targets:
            if total + target.size > self.max_total_bytes:
                left += 1
                continue
            chosen.append(target)
            total += target.size
        if not chosen:
            raise _CouldNotScan("nothing_to_scan")

        with tempfile.TemporaryDirectory(prefix="rc-clamav-") as tmp:
            listing = Path(tmp) / "files.txt"
            listing.write_text("\n".join(t.path for t in chosen) + "\n", encoding="utf-8")
            started = self._now()
            res = self._run(self._scan_args(clamscan, database, str(listing)), timeout=self.scan_timeout)
            seconds = round(self._now() - started, 1)

        hits = []
        for line in res.stdout.splitlines():
            m = _FOUND_RE.match(line.strip())
            if m:
                hits.append((m.group("path"), m.group("sig")))
        summary = {
            "files_listed": len(found.targets),
            "files_scanned": len(chosen),
            "bytes_scanned": total,
            "files_left": left,
            "skipped_too_large": found.too_large,
            "unreadable_places": found.unreadable_places,
            "seconds": seconds,
            "database_dir": database,
            "database_fetched": fetched,
            "exit_code": res.returncode,
        }
        findings = [self._hit_finding(path, sig, summary) for path, sig in hits]
        if res.timed_out:
            findings.append(Finding(
                title="The ClamAV scan didn't finish",
                description=(
                    f"ClamAV was checking {len(chosen)} files and reached this scan's time limit "
                    "before it was done. It stopped there, so files it hadn't reached weren't "
                    "checked, and this isn't a clean result."
                    + (f" It had already found {len(hits)} file(s), listed separately." if hits else "")
                ),
                severity=Severity.INFO,
                category=self.category,
                code="security.clamav_scanner.scan_incomplete",
                data={"check": "scan_incomplete", "reason": "time", **summary},
            ))
            return findings
        if res.returncode not in (0, 1) and not hits:
            raise _CouldNotScan("scan_failed", exit_code=res.returncode, detail=(res.stderr or "")[-300:])
        if not hits:
            more = f" {left} more were left out to keep the scan a manageable size." if left else ""
            findings.append(Finding(
                title=f"ClamAV found no viruses ({len(chosen)} files checked)",
                description=(
                    f"ClamAV checked {len(chosen)} files in the places malware usually lands, "
                    "including inside zip files and disk images, and found nothing it recognises."
                    f"{more} A clean scan lowers the odds of a problem without ruling one out."
                ),
                severity=Severity.INFO,
                category=self.category,
                code="security.clamav_scanner.scan_clean",
                data={"check": "scan_clean", **summary},
            ))
        return findings

    def _scan_args(self, clamscan: str, database: str, listing: str) -> list[str]:
        return [
            clamscan, "--database", database, "--file-list", listing, "--infected", "--no-summary",
            "--stdout", f"--max-filesize={self.max_file_bytes // MB}M",
            f"--max-scansize={4 * self.max_file_bytes // MB}M",
        ]

    def _hit_finding(self, path: str, signature: str, summary: dict) -> Finding:
        # A file inside an archive is reported as "archive.zip!inner" or similar;
        # the file to act on is the archive itself.
        on_disk = path.split("!")[0] if not os.path.exists(path) else path
        try:
            digest = file_scan.sha256_file(on_disk)
        except OSError:
            digest = None
        name = os.path.basename(on_disk)
        watching = file_scan.monitoring_name(on_disk, signature)
        data = {
            "check": "monitoring_found" if watching else "virus_found",
            "path": on_disk,
            "file_name": name,
            "signature": signature,
            "sha256": digest,
            "virustotal_url": file_scan.virustotal_url(digest) if digest else None,
            "scan": summary,
        }
        if watching:
            data["monitoring_name"] = watching
            return Finding(
                title=f"ClamAV found monitoring software: {name}",
                description=(
                    f"ClamAV recognises {name} as {signature}, which looks like software that "
                    f"watches a person ({watching}). If someone close to you may have set it up, "
                    "removing it can alert them.\n\nWhat to do: Read the safety note before you "
                    "change anything. When it's safe for you, Reclaim City can move it into its "
                    "quarantine folder, where it can't run, and you can put it back."
                ),
                severity=Severity.CRITICAL,
                category=self.category,
                code="security.clamav_scanner.monitoring_found",
                data=data,
                confidence=0.8,
            )
        return Finding(
            title=f"ClamAV found a virus: {name}",
            description=(
                f"ClamAV recognises {name} as {signature}, something on its list of known "
                "viruses and malware. It's worth acting on.\n\nWhat to do: Don't open it. "
                "Reclaim City can move it into its quarantine folder, where it can't run. Nothing "
                "is deleted, and you can put it back."
            ),
            severity=Severity.CRITICAL,
            category=self.category,
            code="security.clamav_scanner.virus_found",
            data=data,
            confidence=0.8,
        )

    def _could_not_scan(self, exc: _CouldNotScan) -> Finding:
        return Finding(
            title="The ClamAV scan couldn't run",
            description=_COULD_NOT_SCAN[exc.reason],
            severity=Severity.INFO,
            category=self.category,
            code="security.clamav_scanner.could_not_scan",
            data={"check": "could_not_scan", "reason": exc.reason, **exc.data},
        )

    # --- the virus list -----------------------------------------------------------

    def _cache_db(self, platform: str) -> Path:
        if self.cache_dir is not None:
            return Path(self.cache_dir)
        override = os.environ.get("RESCUE_CACHE_DIR")
        if override:
            base = Path(override)
        elif platform == "darwin":
            base = Path.home() / "Library" / "Caches"
        elif platform == "win32":
            base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
        else:
            base = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
        return base / "ReclaimCity" / "clamav-db"

    def _usable_database(self, freshclam: str | None, platform: str,
                         db_dir: str | None, def_age: int) -> tuple[str, bool]:
        """(folder with a virus list fresh enough to scan with, whether it was just downloaded)."""
        cache = self._cache_db(platform)
        cache_age = self._age_days(str(cache))
        if cache_age is not None and cache_age <= FRESH_DAYS and (db_dir is None or cache_age <= def_age):
            return str(cache), False
        if db_dir is not None and def_age <= FRESH_DAYS:
            return db_dir, False
        flag_off = os.environ.get("RESCUE_NO_DOWNLOADS") == "1"
        if flag_off or not self.downloads_allowed:
            raise _CouldNotScan("downloads_off" if flag_off else "kept_offline")
        if self._is_elevated(platform):
            raise _CouldNotScan("elevated")
        if not freshclam:
            raise _CouldNotScan("no_freshclam")
        resolves = self.mirror_resolves if self.mirror_resolves is not None else _resolves
        if not resolves():
            raise _CouldNotScan("offline")
        cache.mkdir(parents=True, exist_ok=True)
        conf = cache / "freshclam.conf"
        # Only what freshclam needs: where to download from, and where to put it.
        conf.write_text(f"DatabaseMirror {MIRROR_HOST}\nDatabaseDirectory {cache}\n", encoding="utf-8")
        res = self._run([freshclam, f"--config-file={conf}", f"--datadir={cache}", "--stdout"],
                        timeout=FRESHCLAM_TIMEOUT)
        if not res.ok or self._age_days(str(cache)) is None:
            raise _CouldNotScan("fetch_failed", detail=(res.stdout + res.stderr)[-300:])
        return str(cache), True

    def _age_days(self, folder: str) -> int | None:
        newest = None
        for name in _DB_FILES:
            try:
                mtime = os.stat(os.path.join(folder, name)).st_mtime
            except OSError:
                continue
            newest = mtime if newest is None or mtime > newest else newest
        if newest is None:
            return None
        return (datetime.now() - datetime.fromtimestamp(newest)).days

    def _newest_database(self, platform: str) -> tuple[str | None, int]:
        """(ClamAV's own folder with the newest virus list, its age in days), or (None, 999)."""
        best, best_age = None, 999
        for folder in self.db_dirs if self.db_dirs is not None else _DB_DIRS[platform]:
            folder = os.path.expanduser(folder)
            age = self._age_days(folder)
            if age is not None and (best is None or age < best_age):
                best, best_age = folder, age
        return best, best_age

    def _get_definition_version(self, db_dir: str, platform: str) -> str | None:
        sigtool = self._find("sigtool", platform)
        if not sigtool:
            return None
        for name in ("main.cvd", "main.cld"):
            path = os.path.join(db_dir, name)
            if not os.path.exists(path):
                continue
            res = self._run([sigtool, "--info", path], timeout=VERSION_TIMEOUT)
            for line in res.stdout.splitlines() if res.ok else []:
                if line.startswith("Version:"):
                    return line.split(":", 1)[1].strip() or None
        return None

    # --- helpers ------------------------------------------------------------------

    def _run(self, args: list[str], timeout: float):
        return (self.runner or run)(args, timeout=timeout)

    def _now(self) -> float:
        return (self.clock or time.monotonic)()

    def _find(self, program: str, platform: str) -> str | None:
        which = self.which or shutil.which
        found = which(program)
        if found:
            return found
        exe = program + (".exe" if platform == "win32" else "")
        for folder in _BIN_DIRS[platform]:
            candidate = os.path.join(folder, exe)
            if which(candidate):
                return candidate
        return None

    def _is_elevated(self, platform: str) -> bool:
        if self.elevated is not None:
            return bool(self.elevated)
        if platform == "win32":
            try:
                import ctypes

                return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
            except Exception:
                return False
        geteuid = getattr(os, "geteuid", None)
        return bool(geteuid is not None and geteuid() == 0)

    def _get_clamav_version(self, clamscan: str) -> str | None:
        """"ClamAV 1.4.1/27450/Mon Oct 20 ..." -> "1.4.1"."""
        res = self._run([clamscan, "--version"], timeout=VERSION_TIMEOUT)
        out = res.stdout.strip() if res.ok else ""
        if out.startswith("ClamAV "):
            return out.split()[1].split("/")[0]
        return None

    def _check_daemon_running(self, platform: str) -> bool:
        if platform == "win32":
            res = self._run(["tasklist", "/FI", "IMAGENAME eq clamd.exe", "/NH"], timeout=VERSION_TIMEOUT)
            return res.ok and "clamd.exe" in res.stdout.lower()
        res = self._run(["pgrep", "-x", "clamd"], timeout=VERSION_TIMEOUT)
        return res.ok
