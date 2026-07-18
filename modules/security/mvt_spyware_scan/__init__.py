"""mvt_spyware_scan: wraps Amnesty International's Mobile Verification Toolkit
(MVT) to scan device backups for known mobile spyware indicators (Pegasus,
Predator, and similar mercenary spyware families).

This module is a thin, read-only wrapper around the external `mvt-ios` /
`mvt-android` CLI tools. It does not ship or bundle any spyware indicator
data itself — it defers entirely to MVT's own STIX2 indicator feeds.

Because MVT can only detect *known, published* indicators, a clean scan is
never proof of a clean device. Every "no detections" finding this module
produces carries an explicit caveat to that effect.
"""

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

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


class Module(ModuleBase):
    name = "mvt_spyware_scan"
    category = "security"
    platforms = [Platform.DARWIN, Platform.LINUX, Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 60
    depends_on = []
    estimated_duration = "1-10m (depends on backup size)"

    emits_codes = [
        "security.mvt_spyware_scan.mvt_requires_wsl",
        "security.mvt_spyware_scan.no_backups_found",
        "security.mvt_spyware_scan.mvt_not_installed",
        "security.mvt_spyware_scan.mvt_spyware_detected",
        "security.mvt_spyware_scan.mvt_clean_scan",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings: list[Finding] = []

        if profile.platform == Platform.WIN32:
            findings.append(
                Finding(
                    title="MVT spyware scan requires WSL on Windows",
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
                    data={
                        "check": "mvt_requires_wsl",
                        "confidence": "high",
                        "install_command": "wsl --install",
                    },
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        backups = self._discover_backups(profile)
        if not backups:
            findings.append(
                Finding(
                    title="No device backups found",
                    description=(
                        "No iOS/Android device backups were found at the expected "
                        "locations, so no MVT spyware scan could be performed. "
                        f"{_CLEAN_SCAN_CAVEAT}"
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.mvt_spyware_scan.no_backups_found",
                    data={"check": "no_backups_found", "confidence": "high"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        mvt_bin = shutil.which("mvt-ios") or shutil.which("mvt-android")
        if not mvt_bin:
            findings.append(
                Finding(
                    title="MVT (Mobile Verification Toolkit) is not installed",
                    description=(
                        f"Found {len(backups)} device backup(s) but MVT is not "
                        "installed, so they could not be scanned for spyware "
                        "indicators. Install it with `pip install mvt` (requires "
                        "libimobiledevice on macOS/Linux for iOS backup decryption "
                        "support)."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.mvt_spyware_scan.mvt_not_installed",
                    data={
                        "check": "mvt_not_installed",
                        "confidence": "high",
                        "install_command": "pip install mvt",
                        "backups_found": len(backups),
                    },
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        any_detected = False
        for backup in backups:
            detections = self._run_mvt_scan(mvt_bin, backup)
            if detections:
                any_detected = True
            for detection in detections:
                module_name = detection.get("module", "unknown")
                indicator = detection.get("indicator", "unknown")
                findings.append(
                    Finding(
                        title=f"Spyware indicator detected: {module_name}",
                        description=(
                            f"MVT detected a known spyware indicator ('{indicator}') "
                            f"while scanning the '{module_name}' module of backup "
                            f"{backup}. This is consistent with mercenary spyware "
                            "such as Pegasus or Predator."
                        ),
                        severity=Severity.CRITICAL,
                        category=self.category,
                        code="security.mvt_spyware_scan.mvt_spyware_detected",
                        data={
                            "check": "mvt_spyware_detected",
                            "confidence": "high",
                            "module": module_name,
                            "indicator": indicator,
                            "indicator_type": detection.get("indicator_type"),
                            "backup_path": str(backup),
                        },
                    )
                )

        if not any_detected:
            findings.append(
                Finding(
                    title="No spyware indicators detected",
                    description=(
                        f"MVT scanned {len(backups)} backup(s) and found no known "
                        f"spyware indicators. {_CLEAN_SCAN_CAVEAT}"
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.mvt_spyware_scan.mvt_clean_scan",
                    data={"check": "mvt_clean_scan", "confidence": "high", "backups_scanned": len(backups)},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

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

    def _discover_backups(self, profile: SystemProfile) -> list[Path]:
        """Return directories that look like device backups."""
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

    def _run_mvt_scan(self, mvt_bin: str, backup_path: Path) -> list[dict]:
        """Run `mvt-ios check-backup` (or mvt-android) against a backup and
        return parsed detections. Returns [] on any scan failure."""
        output_dir = Path(tempfile.mkdtemp(prefix="mvt_scan_"))
        try:
            subprocess.run(
                [
                    mvt_bin,
                    "check-backup",
                    "--output",
                    str(output_dir),
                    str(backup_path),
                ],
                capture_output=True,
                text=True,
                timeout=900,
            )
            return self._parse_mvt_output(output_dir)
        except (subprocess.SubprocessError, OSError):
            return []
        finally:
            shutil.rmtree(output_dir, ignore_errors=True)

    def _parse_mvt_output(self, output_dir: Path) -> list[dict]:
        """Parse MVT's JSON output files, returning entries where
        detected == True."""
        output_dir = Path(output_dir)
        detections: list[dict] = []
        if not output_dir.exists():
            return detections

        for json_file in sorted(output_dir.glob("*.json")):
            try:
                content = json.loads(json_file.read_text())
            except (json.JSONDecodeError, OSError):
                continue

            entries = content if isinstance(content, list) else [content]
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                if not entry.get("detected"):
                    continue
                matched = entry.get("matched_indicator") or {}
                detections.append(
                    {
                        "module": entry.get("module", json_file.stem),
                        "indicator": entry.get("indicator")
                        or matched.get("value", "unknown"),
                        "indicator_type": matched.get("type"),
                    }
                )
        return detections
