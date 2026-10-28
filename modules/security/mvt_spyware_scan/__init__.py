"""mvt_spyware_scan: wraps Amnesty International's Mobile Verification Toolkit
(MVT) to check a phone for known spyware: mercenary spyware such as Pegasus and
Predator, and the stalkerware indicators MVT carries from Echap.

It reads what's already on this computer and never connects to a phone:

- an iPhone or iPad backup made with Finder or iTunes, checked with
  ``mvt-ios check-backup``;
- an Android acquisition made with Amnesty's AndroidQF tool (``<UUID>.zip``),
  checked with ``mvt-android check-androidqf``.

It does not ship indicator data: it uses the lists MVT downloads with
``mvt-ios download-iocs``. Without them MVT matches nothing, so this module
refuses to call a phone clean until they're present.

Because MVT can only detect *known, published* indicators, a clean scan is
never proof of a clean device. Every "no detections" finding this module
produces carries an explicit caveat to that effect.
"""

import json
import os
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from rescue.models import (
    Action,
    ActionKind,
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

_CLEAN_SCAN_CAVEAT = (
    "Absence of findings does NOT guarantee the device is clean. MVT can only "
    "detect indicators that have been published in known spyware IOC feeds; "
    "it cannot detect novel, unpublished, or bespoke spyware."
)

# AndroidQF names each acquisition after its UUID.
_AQF_NAME = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(\.zip|\.zip\.age)?$",
    re.IGNORECASE,
)
# Files that only an AndroidQF acquisition contains, used to tell one apart
# from any other UUID-named zip.
_AQF_MARKERS = ("acquisition.json", "packages.json", "getprop.txt")

# MVT alert levels, lowest to highest.
_LEVELS = {"INFORMATIONAL": 0, "LOW": 10, "MEDIUM": 20, "HIGH": 30, "CRITICAL": 40}

_KIND_LABEL = {"ios": "iPhone or iPad backup", "android": "Android acquisition"}


class Module(ModuleBase):
    name = "mvt_spyware_scan"
    category = "security"
    platforms = [Platform.DARWIN, Platform.LINUX, Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 60
    depends_on = []
    estimated_duration = "instant by default; minutes to an hour when scanning is on"

    # A full MVT scan is a slow forensic operation: on a full iPhone backup it
    # can take many minutes. check() is meant to be a quick, read-only probe,
    # so scanning is OPT-IN (the iphone_spyware_check and android_spyware_check
    # profiles turn it on). By default check() only reports that a scan is
    # available.
    scan_backups: bool = False
    # Which phones to look for: "ios", "android" or "both".
    look_for: str = "both"
    # Optional size guard: backups larger than this many bytes are skipped with
    # a clear finding. 0 means no limit, which is the default: a spyware check
    # that silently skips most real iPhone backups (they are usually well over
    # a few GB) is not a spyware check. Set it only for a machine short on memory.
    max_backup_bytes: int = 0
    # How long one MVT run may take before it's stopped and reported as
    # unfinished. Large backups take a while; the default module timeout (60s)
    # would abandon every real scan.
    mvt_timeout: int = 3600
    # Budget for the whole check when scanning is on: room for a few backups.
    _SCAN_CHECK_TIMEOUT = 4 * 3600 + 300

    emits_codes = [
        "security.mvt_spyware_scan.mvt_backup_encrypted",
        "security.mvt_spyware_scan.mvt_scan_incomplete",
        "security.mvt_spyware_scan.mvt_no_indicators",
        "security.mvt_spyware_scan.mvt_suspicious_signal",
        "security.mvt_spyware_scan.mvt_requires_wsl",
        "security.mvt_spyware_scan.no_backups_found",
        "security.mvt_spyware_scan.mvt_not_installed",
        "security.mvt_spyware_scan.mvt_scan_available",
        "security.mvt_spyware_scan.mvt_backup_too_large",
        "security.mvt_spyware_scan.mvt_spyware_detected",
        "security.mvt_spyware_scan.mvt_clean_scan",
    ]

    def configure(self, config: dict[str, Any]) -> None:
        """Enable/tune scanning from a profile's module_config.

        ``scan_backups: true`` opts in to actually running MVT;
        ``look_for`` picks "ios", "android" or "both";
        ``max_backup_bytes`` sets an optional size limit (0 = none).
        """
        if "scan_backups" in config:
            self.scan_backups = bool(config["scan_backups"])
        if "look_for" in config:
            value = str(config["look_for"]).lower()
            if value not in ("ios", "android", "both"):
                raise ValueError(f"look_for must be ios, android or both, not {value!r}")
            self.look_for = value
        if "max_backup_bytes" in config:
            self.max_backup_bytes = int(config["max_backup_bytes"])
        if "mvt_timeout" in config:
            self.mvt_timeout = int(config["mvt_timeout"])
        # The orchestrator reads check_timeout; without this a real scan is
        # abandoned after the 60-second default while MVT keeps running.
        if self.scan_backups:
            self.check_timeout = self._SCAN_CHECK_TIMEOUT

    # ------------------------------------------------------------------ check

    def _what(self) -> str:
        return {
            "ios": "iPhone or iPad backups",
            "android": "Android acquisitions from AndroidQF",
            "both": "iPhone backups or Android acquisitions",
        }[self.look_for]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings: list[Finding] = []

        if profile.platform == Platform.WIN32:
            findings.append(Finding(
                title="Spyware scan needs a Linux setup on Windows",
                description=(
                    "Amnesty International's Mobile Verification Toolkit (MVT) "
                    "does not run natively on Windows. Install the Windows "
                    "Subsystem for Linux (WSL), then install MVT inside the WSL "
                    "environment (`pip install mvt`) to scan iOS/Android backups "
                    "for spyware indicators."
                ),
                severity=Severity.INFO,
                category=self.category,
                code="security.mvt_spyware_scan.mvt_requires_wsl",
                data={"check": "mvt_requires_wsl", "confidence": "high", "install_command": "wsl --install"},
            ))
            return CheckResult(module_name=self.name, findings=findings)

        targets = self._discover_targets(profile)
        if not targets:
            if self.look_for == "android":
                how = (
                    "To check an Android phone, first run Amnesty International's "
                    "AndroidQF tool on this computer with the phone plugged in. It "
                    "saves a file named like 1b2c3d4e-....zip; leave it in your home "
                    "folder, Downloads or Desktop, then run this check again."
                )
            elif self.look_for == "ios":
                how = (
                    "To check an iPhone, first back it up to this computer (Finder, "
                    "or iTunes on older systems), then run this check again."
                )
            else:
                how = (
                    "Back up an iPhone to this computer, or run AndroidQF on an "
                    "Android phone, then run this check again."
                )
            findings.append(Finding(
                title="No phone data found to check",
                description=(
                    f"No {self._what()} were found on this computer, so no spyware "
                    f"scan could be done. {how} {_CLEAN_SCAN_CAVEAT}"
                ),
                severity=Severity.INFO,
                category=self.category,
                code="security.mvt_spyware_scan.no_backups_found",
                data={"check": "no_backups_found", "confidence": "high"},
            ))
            return CheckResult(module_name=self.name, findings=findings)

        kinds = sorted({t["kind"] for t in targets})
        bins = {k: shutil.which(f"mvt-{k}") for k in kinds}
        if not all(bins.values()):
            findings.append(Finding(
                title=f"Spyware scanner not installed ({len(targets)} found to check)",
                description=(
                    f"Found {len(targets)} thing(s) to check but Amnesty "
                    "International's MVT is not installed, so they could not be "
                    "scanned for spyware. Install it in Terminal with:\n"
                    "  pip install mvt\n"
                    "then download its spyware lists once:\n"
                    "  mvt-ios download-iocs"
                ),
                severity=Severity.INFO,
                category=self.category,
                code="security.mvt_spyware_scan.mvt_not_installed",
                data={"check": "mvt_not_installed", "confidence": "high", "install_command": "pip install mvt", "backups_found": len(targets)},
            ))
            return CheckResult(module_name=self.name, findings=findings)

        if not self.scan_backups:
            # Default path: do NOT launch the slow forensic scan. Report that
            # there is something to scan and a scan is available.
            findings.append(Finding(
                title=f"{len(targets)} phone backup(s) found (scan available)",
                description=(
                    f"Found {len(targets)} {self._what()} and MVT is installed, but "
                    "the spyware scan was NOT run automatically, because it can take "
                    "a long time. To run it, choose the iPhone or Android spyware "
                    "check in Reclaim City, or run `rescue scan --profile "
                    "iphone_spyware_check` (or `android_spyware_check`)."
                ),
                severity=Severity.INFO,
                category=self.category,
                code="security.mvt_spyware_scan.mvt_scan_available",
                data={"check": "mvt_scan_available", "confidence": "high", "backups_found": len(targets)},
            ))
            return CheckResult(module_name=self.name, findings=findings)

        if not self._indicators_present():
            first = bins[kinds[0]]
            findings.append(Finding(
                title="The spyware scanner has no spyware lists yet",
                description=(
                    "MVT is installed, but it hasn't downloaded the lists of known "
                    "spyware and stalkerware it compares your phone against. Without "
                    "them it can't recognise anything, so we didn't run it: a scan "
                    "now would look clean whatever was on the phone. This is not a "
                    "sign that anything is wrong.\n\n"
                    "What to do: open Terminal and run this once (it downloads the "
                    "public lists from Amnesty International and others), then run "
                    "this check again:\n"
                    f"  {first} download-iocs"
                ),
                severity=Severity.WARNING,
                category=self.category,
                code="security.mvt_spyware_scan.mvt_no_indicators",
                data={"check": "mvt_no_indicators", "confidence": "high"},
            ))
            return CheckResult(module_name=self.name, findings=findings)

        any_detected = False
        scanned = 0
        lower: list[dict] = []
        for target in targets:
            path: Path = target["path"]
            kind: str = target["kind"]
            mvt_bin = bins[kind]
            if target["encrypted"]:
                findings.append(self._encrypted_finding(kind, path, mvt_bin))
                continue
            size = (
                self._estimate_backup_size(path, self.max_backup_bytes)
                if self.max_backup_bytes > 0
                else None
            )
            if size is not None and size > self.max_backup_bytes:
                findings.append(Finding(
                    title=f"A backup is over the size limit you set: {path.name}",
                    description=(
                        f"The {_KIND_LABEL[kind]} {path.name} is larger than the "
                        f"{self.max_backup_bytes // 1024**3} GiB limit set for this "
                        "check, so it was skipped. We could not verify whether it's "
                        "safe, but this is not a sign that anything is wrong.\n\n"
                        "What to do: remove the max_backup_bytes limit from the "
                        "profile, or check it by hand:\n"
                        f"  {self._manual_command(kind, mvt_bin, path)}"
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.mvt_spyware_scan.mvt_backup_too_large",
                    data={"check": "mvt_backup_too_large", "confidence": "high", "backup_path": str(path), "max_backup_bytes": self.max_backup_bytes},
                ))
                continue

            alerts = self._run_mvt_scan(mvt_bin, path, kind)
            if alerts is None:
                findings.append(Finding(
                    title=f"The spyware scan didn't finish: {path.name}",
                    description=(
                        f"The scanner started on the {_KIND_LABEL[kind]} {path.name} "
                        "but didn't finish, so we can't say whether it's clean. This "
                        "is not a clean result, and it isn't a sign that anything is "
                        "wrong.\n\n"
                        "What to do: run the scan yourself in Terminal, where you can "
                        "see its progress and any error:\n"
                        f"  {self._manual_command(kind, mvt_bin, path)}"
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.mvt_spyware_scan.mvt_scan_incomplete",
                    data={"check": "mvt_scan_incomplete", "confidence": "high", "backup_path": str(path)},
                ))
                continue
            scanned += 1

            heuristics: dict[str, list[str]] = {}
            for alert in alerts:
                level = _LEVELS.get(alert.get("level", ""), 0)
                if alert.get("ioc_name"):
                    any_detected = True
                    findings.append(self._detection_finding(kind, path, alert))
                elif level >= _LEVELS["HIGH"]:
                    heuristics.setdefault(alert.get("module", "scan"), []).append(alert.get("message", ""))
                elif level >= _LEVELS["MEDIUM"]:
                    lower.append(alert)
            for module_name, messages in heuristics.items():
                any_detected = True
                listed = "\n".join(f"  - {m}" for m in messages[:10])
                more = f"\n  (and {len(messages) - 10} more)" if len(messages) > 10 else ""
                findings.append(Finding(
                    title=f"Something an expert should look at: {module_name}",
                    description=(
                        f"MVT flagged this in the {_KIND_LABEL[kind]} {path.name}:\n"
                        f"{listed}{more}\n\n"
                        "It isn't a match against a known spyware list, but it's "
                        "the kind of thing spyware needs or leaves behind (for "
                        "example, a phone that has been rooted or jailbroken). It "
                        "can also have an innocent explanation.\n\n"
                        "What to do: if you think someone close to you may be monitoring you, "
                        "changing things can alert them. Talk to an advocate first "
                        "(US National Domestic Violence Hotline: 1-800-799-7233, or "
                        "text START to 88788). Otherwise, Amnesty International's "
                        "Security Lab helps people who may be targeted: "
                        "https://securitylab.amnesty.org/get-help/"
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.mvt_spyware_scan.mvt_suspicious_signal",
                    data={"check": "mvt_suspicious_signal", "confidence": "high", "module": module_name, "level": "HIGH", "count": len(messages), "backup_path": str(path)},
                ))

        if lower:
            shown = "\n".join(f"  - {a.get('message', '')}" for a in lower[:12])
            more = f"\n  (and {len(lower) - 12} more)" if len(lower) > 12 else ""
            findings.append(Finding(
                title=f"{len(lower)} lower-level note(s) from the spyware scan",
                description=(
                    "MVT also noted these. Most have ordinary explanations, such as "
                    "an app installed from outside the Play Store, an old security "
                    "update, or a setting changed for the scan itself (USB "
                    "debugging). Read them for anything you didn't do yourself:\n"
                    f"{shown}{more}"
                ),
                severity=Severity.INFO,
                category=self.category,
                code="security.mvt_spyware_scan.mvt_suspicious_signal",
                data={"check": "mvt_suspicious_signal", "confidence": "high", "module": "multiple", "level": "MEDIUM", "count": len(lower)},
            ))

        if scanned and not any_detected:
            findings.append(Finding(
                title="No spyware indicators detected",
                description=(
                    f"MVT scanned {scanned} phone backup(s) and found no known "
                    f"spyware indicators. {_CLEAN_SCAN_CAVEAT}"
                ),
                severity=Severity.INFO,
                category=self.category,
                code="security.mvt_spyware_scan.mvt_clean_scan",
                data={"check": "mvt_clean_scan", "confidence": "high", "backups_scanned": scanned},
            ))

        return CheckResult(module_name=self.name, findings=findings)

    def _detection_finding(self, kind: str, path: Path, alert: dict) -> Finding:
        module_name = alert.get("module", "unknown")
        indicator = alert.get("indicator") or "unknown"
        ioc = alert.get("ioc_name") or "a known spyware list"
        phone = "phone" if kind == "android" else "phone that was backed up"
        return Finding(
            title=f"Signs of spyware found: {ioc}",
            description=(
                f"MVT matched '{indicator}' in the {_KIND_LABEL[kind]} {path.name} "
                f"against {ioc}. This suggests the {phone} may have spyware or "
                "stalkerware on it.\n\n"
                "If you think someone close to you set this up to monitor you, "
                "removing it can alert them. Talk to an advocate first (US National "
                "Domestic Violence Hotline: 1-800-799-7233, or text START to 88788).\n\n"
                "What to do: keep this file safe as evidence, don't restore it to any "
                "phone, and contact a security expert or the hotline above for next "
                "steps. Amnesty International's Security Lab helps people who may be "
                "targeted: https://securitylab.amnesty.org/get-help/"
            ),
            severity=Severity.CRITICAL,
            category=self.category,
            code="security.mvt_spyware_scan.mvt_spyware_detected",
            data={"check": "mvt_spyware_detected", "confidence": "high", "module": module_name, "indicator": indicator, "indicator_type": alert.get("indicator_type"), "ioc_name": alert.get("ioc_name"), "backup_path": str(path)},
        )

    def _encrypted_finding(self, kind: str, path: Path, mvt_bin: str) -> Finding:
        if kind == "android":
            return Finding(
                title=f"This Android acquisition is encrypted, so it couldn't be checked: {path.name}",
                description=(
                    f"AndroidQF encrypted {path.name} because it found a key.txt file "
                    "next to it. Only whoever holds the matching private key can "
                    "unlock it, so we did not check it. This is not a clean result, "
                    "and it is not a sign that anything is wrong.\n\n"
                    "What to do: if you have the private key, unlock a copy with "
                    "age (age --decrypt -i <your-key> -o acquisition.zip "
                    f"\"{path}\") and run this check again. Otherwise, run AndroidQF "
                    "again from a folder without a key.txt file."
                ),
                severity=Severity.WARNING,
                category=self.category,
                code="security.mvt_spyware_scan.mvt_backup_encrypted",
                data={"check": "mvt_backup_encrypted", "confidence": "high", "backup_path": str(path)},
            )
        return Finding(
            title=f"This backup is encrypted, so it couldn't be checked yet: {path.name}",
            description=(
                f"The backup {path.name} is encrypted (that's good: it "
                "protects your phone's data on this computer). The spyware "
                "scanner can't read it until it's unlocked with the backup "
                "password you chose in Finder or iTunes. We did not check "
                "this backup, so this is not a clean result. It is also not "
                "a sign that anything is wrong.\n\n"
                "What to do: open Terminal and run this, which makes an "
                "unlocked copy in a new folder and asks for the backup "
                "password:\n"
                f"  {mvt_bin} decrypt-backup -d ~/iphone-backup-decrypted \"{path}\"\n"
                "Then scan the copy:\n"
                f"  {mvt_bin} check-backup --output ~/mvt-results ~/iphone-backup-decrypted\n"
                "Delete the unlocked copy when you're done: it holds your "
                "messages and photos unprotected."
            ),
            severity=Severity.WARNING,
            category=self.category,
            code="security.mvt_spyware_scan.mvt_backup_encrypted",
            data={"check": "mvt_backup_encrypted", "confidence": "high", "backup_path": str(path)},
        )

    @staticmethod
    def _manual_command(kind: str, mvt_bin: str, path: Path) -> str:
        if kind == "android":
            return f"{mvt_bin} check-androidqf --output ~/mvt-results \"{path}\""
        return f"{mvt_bin} check-backup --output ~/mvt-results \"{path}\""

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        """Informational-only remediation guidance.

        MVT detections indicate a potential targeted compromise. There is no
        safe automated remediation — this module never modifies the device.
        It only surfaces guidance for the user (or their security team) to
        act on manually.
        """
        actions: list[Action] = []
        detections = [
            f for f in findings.findings if f.data.get("check") == "mvt_spyware_detected"
        ]

        if detections:
            modules_hit = sorted(
                {f.data.get("module", "unknown") for f in detections}
            )
            actions.append(
                Action(
                    title="Back up essential data, then factory reset the device",
                    description=(
                        "MVT detected spyware indicators in: "
                        f"{', '.join(modules_hit)}. Back up only essential personal "
                        "data (photos, documents) — never restore apps or a full "
                        "device backup from the compromised backup itself, as that "
                        "can reinfect the device. Then perform a full factory "
                        "reset and set the device up as new."
                    ),
                    risk_level=RiskLevel.SAFE,
                    kind=ActionKind.GUIDANCE,
                    success=True,
                )
            )
            actions.append(
                Action(
                    title="Update the device operating system immediately",
                    description=(
                        "After the factory reset, update to the latest iOS/Android "
                        "version before restoring anything. Mercenary spyware "
                        "typically relies on zero-day vulnerabilities patched in "
                        "later OS updates."
                    ),
                    risk_level=RiskLevel.SAFE,
                    kind=ActionKind.GUIDANCE,
                    success=True,
                )
            )
            actions.append(
                Action(
                    title="Enable Lockdown Mode",
                    description=(
                        "If you may be a target of state-sponsored or mercenary "
                        "spyware, enable Lockdown Mode (iOS: Settings > Privacy & "
                        "Security > Lockdown Mode) to significantly reduce the "
                        "device's attack surface."
                    ),
                    risk_level=RiskLevel.SAFE,
                    kind=ActionKind.GUIDANCE,
                    success=True,
                )
            )
            actions.append(
                Action(
                    title="Contact Amnesty International's Security Lab",
                    description=(
                        "Consider contacting Amnesty International's Security Lab "
                        "(https://www.amnesty.org/en/tech/) for forensic support, "
                        "and to help them track spyware campaigns. Preserve the "
                        "original (unmodified) backup as evidence before resetting "
                        "the device."
                    ),
                    risk_level=RiskLevel.SAFE,
                    kind=ActionKind.GUIDANCE,
                    success=True,
                )
            )
        else:
            actions.append(
                Action(
                    title="No spyware indicators detected — routine hygiene only",
                    description=(
                        "No action required. As general hygiene: keep the OS "
                        "updated, and enable Lockdown Mode if you are a high-risk "
                        f"target. {_CLEAN_SCAN_CAVEAT}"
                    ),
                    risk_level=RiskLevel.SAFE,
                    kind=ActionKind.GUIDANCE,
                    success=True,
                )
            )

        return FixResult(module_name=self.name, actions=actions)


    # ---------------------------------------------------------------- finding

    def _discover_targets(self, profile: SystemProfile) -> list[dict]:
        """Everything on this computer there is to check, as
        ``{"kind": "ios"|"android", "path": Path, "encrypted": bool}``."""
        targets: list[dict] = []
        if self.look_for in ("ios", "both"):
            for backup in self._discover_backups(profile):
                targets.append({"kind": "ios", "path": backup, "encrypted": self._is_encrypted(backup)})
        if self.look_for in ("android", "both"):
            for acq in self._discover_androidqf(profile):
                targets.append({"kind": "android", "path": acq, "encrypted": acq.name.lower().endswith(".age")})
        return targets

    def _discover_backups(self, profile: SystemProfile) -> list[Path]:
        """Return directories that look like iOS device backups."""
        roots: list[Path] = []
        if profile.platform == Platform.DARWIN:
            roots.append(
                Path.home()
                / "Library"
                / "Application Support"
                / "MobileSync"
                / "Backup"
            )
        elif profile.platform == Platform.LINUX:
            roots.append(Path.home() / ".local" / "share" / "libimobiledevice" / "Backup")
            roots.append(Path.home() / "MobileSync" / "Backup")

        backups: list[Path] = []
        for root in roots:
            try:
                if not root.exists() or not root.is_dir():
                    continue
                for entry in root.iterdir():
                    if entry.is_dir():
                        backups.append(entry)
            except OSError:
                continue
        return backups

    def _androidqf_roots(self) -> list[Path]:
        """Where an AndroidQF acquisition usually ends up. AndroidQF writes to
        the folder it was run from: the home folder when it's double-clicked
        on a Mac, or wherever it was downloaded and run from."""
        home = Path.home()
        roots = [home, home / "Downloads", home / "Desktop", home / "Documents", home / "androidqf"]
        downloads = home / "Downloads"
        try:
            for entry in downloads.iterdir():
                if entry.is_dir() and entry.name.lower().startswith("androidqf"):
                    roots.append(entry)
        except OSError:
            pass
        return roots

    def _discover_androidqf(self, profile: SystemProfile) -> list[Path]:
        """AndroidQF acquisitions: ``<UUID>.zip`` / ``<UUID>.zip.age`` files
        (AndroidQF 1.8+), or ``<UUID>/`` folders (older versions, or an
        unzipped acquisition)."""
        found: list[Path] = []
        seen: set[str] = set()
        for root in self._androidqf_roots():
            try:
                if not root.is_dir():
                    continue
                entries = list(root.iterdir())
            except OSError:
                continue
            for entry in entries:
                if not _AQF_NAME.match(entry.name):
                    continue
                key = str(entry.resolve()) if entry.exists() else str(entry)
                if key in seen:
                    continue
                if self._looks_like_androidqf(entry):
                    seen.add(key)
                    found.append(entry)
        return found

    @staticmethod
    def _looks_like_androidqf(path: Path) -> bool:
        name = path.name.lower()
        try:
            if name.endswith(".zip.age"):
                return path.is_file()
            if name.endswith(".zip"):
                if not zipfile.is_zipfile(path):
                    return False
                with zipfile.ZipFile(path) as zf:
                    return any(n.replace("\\", "/").rsplit("/", 1)[-1] in _AQF_MARKERS for n in zf.namelist())
            if path.is_dir():
                return any((path / m).exists() for m in _AQF_MARKERS)
        except (OSError, zipfile.BadZipFile):
            return False
        return False

    @staticmethod
    def _indicators_folder() -> Path:
        """Where MVT keeps the lists `download-iocs` fetches (appdirs'
        user_data_dir("mvt"), or $MVT_DATA_FOLDER)."""
        env = os.environ.get("MVT_DATA_FOLDER")
        if env:
            return Path(env) / "indicators"
        if sys.platform == "darwin":
            return Path.home() / "Library" / "Application Support" / "mvt" / "indicators"
        xdg = os.environ.get("XDG_DATA_HOME")
        base = Path(xdg) if xdg else Path.home() / ".local" / "share"
        return base / "mvt" / "indicators"

    def _indicators_present(self) -> bool:
        """Whether MVT has any indicator lists to compare against. Without
        them every scan reads clean, so we don't run one."""
        if os.environ.get("MVT_STIX2"):
            return True
        folder = self._indicators_folder()
        try:
            return any(p.is_file() and p.suffix in (".stix2", ".json") for p in folder.rglob("*"))
        except OSError:
            return False

    def _estimate_backup_size(self, backup_path: Path, cap: int) -> int | None:
        """Total size of files under ``backup_path`` in bytes, short-circuiting
        as soon as the running total exceeds ``cap`` (so this stays cheap even on
        huge backups). Returns ``None`` if the tree cannot be walked."""
        if backup_path.is_file():
            try:
                return backup_path.stat().st_size
            except OSError:
                return None
        total = 0
        try:
            for root, _dirs, files in os.walk(backup_path):
                for name in files:
                    try:
                        total += os.path.getsize(os.path.join(root, name))
                    except OSError:
                        continue
                    if total > cap:
                        return total
        except OSError:
            return None
        return total

    def _is_encrypted(self, backup_path: Path) -> bool:
        """Whether an iOS backup is encrypted (Manifest.plist's IsEncrypted).
        MVT can't scan one until it's decrypted, so scanning it would fail."""
        try:
            with open(backup_path / "Manifest.plist", "rb") as fh:
                return bool(plistlib.load(fh).get("IsEncrypted", False))
        except Exception:
            return False

    # ---------------------------------------------------------------- running

    def _run_mvt_scan(self, mvt_bin: str, target: Path, kind: str = "ios") -> list[dict] | None:
        """Run MVT on one backup or acquisition and return its alerts: [] for
        a scan that finished and raised none, None for a scan that failed,
        timed out or exited with an error. A failed scan must never read as a
        clean one.

        AndroidQF 1.8+ writes its files at the top of the zip, but MVT's
        AndroidQF modules look for them one folder down (``*/packages.json``),
        so a zip handed straight to MVT is checked against almost nothing. We
        unpack it into a private temporary folder named after the acquisition,
        scan that, and delete it.

        MVT writes its results as JSON files into ``--output``; we parse those,
        not stdout. Its (very verbose) console output is discarded rather than
        captured."""
        output_dir = Path(tempfile.mkdtemp(prefix="mvt_scan_"))
        unpack_dir: Path | None = None
        try:
            scan_path = target
            if kind == "android" and target.is_file():
                unpack_dir = Path(tempfile.mkdtemp(prefix="rescue_aqf_"))
                os.chmod(unpack_dir, 0o700)
                stem = target.name[: -len(".zip")] if target.name.lower().endswith(".zip") else target.stem
                scan_path = unpack_dir / stem
                scan_path.mkdir()
                with zipfile.ZipFile(target) as zf:
                    zf.extractall(scan_path)
            command = "check-androidqf" if kind == "android" else "check-backup"
            args = [mvt_bin, command, "--output", str(output_dir)]
            if kind == "android":
                args.append("--non-interactive")
            args.append(str(scan_path))
            proc = subprocess.run(
                args,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                timeout=self.mvt_timeout,
            )
            if proc.returncode != 0:
                return None
            return self._parse_mvt_output(output_dir)
        except (subprocess.SubprocessError, OSError, zipfile.BadZipFile):
            return None
        finally:
            shutil.rmtree(output_dir, ignore_errors=True)
            if unpack_dir is not None:
                shutil.rmtree(unpack_dir, ignore_errors=True)

    def _parse_mvt_output(self, output_dir: Path) -> list[dict]:
        """Read MVT's alerts.

        MVT writes every alert to ``alerts.json`` and each module's to
        ``<module>_detected.json``: a list of ``{level, module, message,
        event, matched_indicator}``. ``matched_indicator`` is set when the alert
        is a match against a downloaded indicator list (``{value, type, name}``,
        where name is the list, such as "Stalkerware Indicators of
        Compromise"); other alerts are MVT's own heuristics, at a level from
        INFORMATIONAL to CRITICAL. INFORMATIONAL and LOW alerts are dropped.
        """
        output_dir = Path(output_dir)
        if not output_dir.exists():
            return []
        files = [output_dir / "alerts.json"]
        if not files[0].exists():
            files = sorted(output_dir.glob("*_detected.json"))

        alerts: list[dict] = []
        for json_file in files:
            try:
                content = json.loads(json_file.read_text())
            except (json.JSONDecodeError, OSError):
                continue
            entries = content if isinstance(content, list) else [content]
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                matched = entry.get("matched_indicator")
                if not isinstance(matched, dict):
                    matched = None
                level = str(entry.get("level", "")).upper()
                if not matched and _LEVELS.get(level, 0) < _LEVELS["MEDIUM"]:
                    continue
                alerts.append(
                    {
                        "module": entry.get("module", json_file.stem.replace("_detected", "")),
                        "level": level or "UNKNOWN",
                        "message": str(entry.get("message", "")),
                        "indicator": (matched or {}).get("value"),
                        "indicator_type": (matched or {}).get("type"),
                        "ioc_name": (matched.get("name") or "a known spyware list") if matched else None,
                    }
                )
        return alerts
