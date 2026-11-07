"""win_defender_scan: what Windows Defender has found, and (when asked) a Defender quick scan.

Windows Security (Microsoft Defender Antivirus) is already on every Windows 10
and 11 computer, so nothing is downloaded. By default this check only reads
Defender's own records of what it has found (``Get-MpThreatDetection`` and
``Get-MpThreat``) and whether Defender is the antivirus in charge. When asked
(``module_config: {win_defender_scan: {quick_scan: true}}``, which the
deep_virus_scan profile sets) it first runs Defender's quick scan:

    "%ProgramFiles%\\Windows Defender\\MpCmdRun.exe" -Scan -ScanType 1

then reads the records again. A quick scan looks at the places malware usually
starts from; Defender decides what to do with anything it finds (usually, it
quarantines it itself), so this check never moves anything: Defender's own
quarantine is in Windows Security > Virus & threat protection > Protection
history.

If Defender is switched off, or another antivirus is in charge (Defender then
stands aside, "passive mode"), the check says so and names that antivirus.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from typing import Any

from rescue import file_scan
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

PS = ["powershell", "-NoProfile", "-NonInteractive", "-Command"]
STATUS_PS = (
    "Get-MpComputerStatus | Select-Object AMServiceEnabled, AntivirusEnabled, "
    "RealTimeProtectionEnabled, AMRunningMode, QuickScanEndTime | ConvertTo-Json -Compress"
)
DETECTIONS_PS = (
    "Get-MpThreatDetection | Select-Object ThreatID, InitialDetectionTime, ThreatStatusID, "
    "ActionSuccess, Resources | ConvertTo-Json -Compress -Depth 3"
)
THREATS_PS = (
    "Get-MpThreat | Select-Object ThreatID, ThreatName, SeverityID, IsActive, DidThreatExecute "
    "| ConvertTo-Json -Compress"
)
PRODUCTS_PS = (
    "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | "
    "Select-Object displayName, productState | ConvertTo-Json -Compress"
)
READ_TIMEOUT = 30
QUICK_SCAN_TIMEOUT = 1800
# Get-MpThreatDetection ThreatStatusID values that mean Defender did NOT deal
# with it: detected only, allowed by someone, or a clean-up that failed.
_STILL_THERE = {1: "detected", 5: "allowed", 102: "quarantine failed", 103: "removal failed",
                104: "allow failed", 105: "abandoned", 107: "block failed"}
_HANDLED = {2: "cleaned", 3: "quarantined", 4: "removed", 6: "blocked"}
_SEVERITY_WORDS = {1: "low", 2: "moderate", 4: "high", 5: "severe"}
_DATE_RE = re.compile(r"/Date\((-?\d+)\)/")
PROTECTION_HISTORY = "Windows Security > Virus & threat protection > Protection history"


def _json_list(text: str) -> list[dict]:
    try:
        data = json.loads(text) if text.strip() else []
    except ValueError:
        return []
    items = data if isinstance(data, list) else [data]
    return [i for i in items if isinstance(i, dict)]


def _when(value: Any) -> str | None:
    """PowerShell 5 writes dates as "/Date(ms)/"; PowerShell 7 as ISO text."""
    if not isinstance(value, str):
        return None
    m = _DATE_RE.search(value)
    if m:
        return datetime.fromtimestamp(int(m.group(1)) / 1000, tz=timezone.utc).isoformat()
    return value or None


def _paths(resources: Any) -> list[str]:
    """Defender's "file:_C:\\path\\x.exe" resources -> ["C:\\path\\x.exe"]."""
    items = resources if isinstance(resources, list) else [resources] if isinstance(resources, str) else []
    out = []
    for r in items:
        if isinstance(r, str) and ":_" in r:
            kind, _, path = r.partition(":_")
            if kind.lower() in ("file", "containerfile", "process") and path:
                out.append(path)
    return out


def _product_on(state: Any) -> bool:
    """SecurityCenter2 productState: bits 12-15 are 1 when the product is switched on."""
    return isinstance(state, int) and (state >> 12) & 0xF == 1


class Module(ModuleBase):
    name = "win_defender_scan"
    category = "security"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 65
    depends_on = []
    estimated_duration = "a few seconds; the quick scan, when asked for, takes longer"

    emits_codes = [
        "security.win_defender_scan.threat_still_there",
        "security.win_defender_scan.monitoring_threat",
        "security.win_defender_scan.threat_handled",
        "security.win_defender_scan.no_threats",
        "security.win_defender_scan.defender_off",
        "security.win_defender_scan.other_antivirus_in_charge",
        "security.win_defender_scan.quick_scan_done",
        "security.win_defender_scan.quick_scan_failed",
        "security.win_defender_scan.could_not_read",
    ]

    quick_scan: bool = False
    # Seams for tests.
    runner: Any = None
    program_files: str | None = None

    def configure(self, config: dict[str, Any]) -> None:
        if "quick_scan" in (config or {}):
            self.quick_scan = bool(config["quick_scan"])
        if self.quick_scan:
            self.check_timeout = QUICK_SCAN_TIMEOUT + 4 * READ_TIMEOUT + 60

    def check(self, profile: SystemProfile) -> CheckResult:
        findings: list[Finding] = []
        status = self._status()
        in_charge = self._other_antivirus()
        running = bool(status) and status.get("AMServiceEnabled") is not False and status.get("AntivirusEnabled") is not False
        passive = bool(status) and str(status.get("AMRunningMode") or "").lower().startswith(("passive", "edr"))

        if status is None and not in_charge:
            findings.append(self._could_not_read(
                "Windows Defender's status couldn't be read from here (it may be switched off, or "
                "this account may not be allowed to ask), so this check couldn't tell you what it "
                f"has found. You can look yourself in {PROTECTION_HISTORY}."
            ))
            return CheckResult(module_name=self.name, findings=findings)
        if not running or passive:
            if in_charge:
                findings.append(Finding(
                    title=f"{in_charge} is your antivirus, so Windows Defender stands aside",
                    description=(
                        f"Another antivirus, {in_charge}, is in charge of protecting this computer, "
                        "so Windows Defender isn't scanning and its records don't cover what "
                        f"{in_charge} found. To check for viruses, open {in_charge} and run its scan."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.win_defender_scan.other_antivirus_in_charge",
                    data={"check": "other_antivirus_in_charge", "product": in_charge,
                          "running_mode": (status or {}).get("AMRunningMode")},
                ))
            else:
                findings.append(Finding(
                    title="Windows Defender is switched off, and no other antivirus is on",
                    description=(
                        "Windows' built-in virus protection isn't running, and Windows doesn't see "
                        "another antivirus that's switched on. Nothing is checking files as they "
                        "arrive.\n\nWhat to do: Open Windows Security from the Start menu, choose "
                        "Virus & threat protection, and turn it back on."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.win_defender_scan.defender_off",
                    data={"check": "defender_off", "status": status or None},
                ))
            return CheckResult(module_name=self.name, findings=findings)

        if self.quick_scan:
            findings.append(self._run_quick_scan())

        detections = self._read(DETECTIONS_PS)
        threats = self._read(THREATS_PS)
        if detections is None or threats is None:
            findings.append(self._could_not_read(
                "Windows Defender is on, but its list of what it has found couldn't be read "
                "from here, so this check couldn't tell you about it. You can see the list "
                f"yourself in {PROTECTION_HISTORY}."
            ))
            return CheckResult(module_name=self.name, findings=findings)

        names = {t.get("ThreatID"): t for t in threats}
        found = [self._threat_finding(d, names.get(d.get("ThreatID"), {})) for d in detections]
        found.sort(key=lambda f: f.severity != Severity.CRITICAL)
        findings += found
        if not found:
            findings.append(Finding(
                title="Windows Defender's records show no threats",
                description=(
                    "Windows Defender is on and its records list nothing it has found on this "
                    "computer. A clean record lowers the odds of a problem without ruling one out."
                ),
                severity=Severity.INFO,
                category=self.category,
                code="security.win_defender_scan.no_threats",
                data={"check": "no_threats", "last_quick_scan": _when((status or {}).get("QuickScanEndTime"))},
            ))
        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        # Defender quarantines and removes what it finds itself; the person
        # acts on anything left from Windows Security. Nothing is changed here.
        return FixResult(module_name=self.name, actions=[])

    # --- Defender -----------------------------------------------------------------

    def _run(self, args: list[str], timeout: float):
        return (self.runner or run)(args, timeout=timeout)

    def _read(self, command: str) -> list[dict] | None:
        res = self._run([*PS, command], timeout=READ_TIMEOUT)
        if not res.ok:
            return None
        return _json_list(res.stdout)

    def _status(self) -> dict | None:
        items = self._read(STATUS_PS)
        return items[0] if items else None

    def _other_antivirus(self) -> str | None:
        """The name of a switched-on antivirus that isn't Defender, or None."""
        for product in self._read(PRODUCTS_PS) or []:
            name = product.get("displayName")
            if isinstance(name, str) and name and "defender" not in name.lower() and _product_on(product.get("productState")):
                return name[:80]
        return None

    def _could_not_read(self, description: str) -> Finding:
        return Finding(
            title="Couldn't read what Windows Defender has found",
            description=description,
            severity=Severity.INFO,
            category=self.category,
            code="security.win_defender_scan.could_not_read",
            data={"check": "could_not_read"},
        )

    def _mpcmdrun(self) -> str:
        base = self.program_files or os.environ.get("ProgramFiles") or "C:\\Program Files"
        return os.path.join(base, "Windows Defender", "MpCmdRun.exe")

    def _run_quick_scan(self) -> Finding:
        res = self._run([self._mpcmdrun(), "-Scan", "-ScanType", "1"], timeout=QUICK_SCAN_TIMEOUT)
        # MpCmdRun: 0 = scanned, nothing found; 2 = scanned and found something.
        if res.returncode in (0, 2) and not res.timed_out:
            return Finding(
                title="Windows Defender ran a quick scan",
                description=(
                    "Windows Defender checked the places malware usually starts from. "
                    + ("It found something; see the items below." if res.returncode == 2
                       else "It didn't find anything new.")
                ),
                severity=Severity.INFO,
                category=self.category,
                code="security.win_defender_scan.quick_scan_done",
                data={"check": "quick_scan_done", "exit_code": res.returncode,
                      "seconds": round(res.duration_s, 1)},
            )
        return Finding(
            title="Windows Defender's quick scan didn't finish",
            description=(
                ("The quick scan reached this checkup's time limit and was stopped. "
                 if res.timed_out else "The quick scan stopped with an error. ")
                + "What it didn't reach wasn't checked, so this isn't a clean result. You can run "
                "it yourself: Windows Security > Virus & threat protection > Quick scan."
            ),
            severity=Severity.INFO,
            category=self.category,
            code="security.win_defender_scan.quick_scan_failed",
            data={"check": "quick_scan_failed", "exit_code": res.returncode, "timed_out": res.timed_out,
                  "detail": (res.stdout or res.stderr or "")[-300:]},
        )

    def _threat_finding(self, detection: dict, threat: dict) -> Finding:
        name = str(threat.get("ThreatName") or "an unnamed threat")[:120]
        status_id = detection.get("ThreatStatusID")
        paths = _paths(detection.get("Resources"))
        still_there = status_id in _STILL_THERE or detection.get("ActionSuccess") is False or threat.get("IsActive") is True
        what = _STILL_THERE.get(status_id) or _HANDLED.get(status_id) or "found"
        data = {
            "threat_name": name,
            "threat_id": detection.get("ThreatID"),
            "status": what,
            "status_id": status_id,
            "severity_word": _SEVERITY_WORDS.get(threat.get("SeverityID")),
            "detected_at": _when(detection.get("InitialDetectionTime")),
            "did_run": threat.get("DidThreatExecute"),
            "files": paths[:10],
        }
        if paths:
            data["path"] = paths[0]
        file_word = f" ({os.path.basename(paths[0].replace(chr(92), '/'))})" if paths else ""
        watching = file_scan.monitoring_name(name, *paths)
        if watching:
            data.update(check="monitoring_threat", monitoring_name=watching)
            return Finding(
                title=f"Windows Defender found monitoring software: {name}",
                description=(
                    f"Windows Defender recognised {name}{file_word} as software that watches a "
                    f"person ({watching}). Its record says: {what}. If someone close to you may "
                    "have set it up, removing it can alert them.\n\nWhat to do: Read the safety "
                    f"note before you change anything. Defender's own record is in {PROTECTION_HISTORY}."
                ),
                severity=Severity.CRITICAL,
                category=self.category,
                code="security.win_defender_scan.monitoring_threat",
                data=data,
                confidence=0.9,
            )
        if still_there:
            allowed = " Someone chose to allow it on this computer." if status_id == 5 else ""
            data["check"] = "threat_still_there"
            return Finding(
                title=f"Windows Defender found a threat it hasn't removed: {name}",
                description=(
                    f"Windows Defender recognised {name}{file_word} as malware, and its record "
                    f"says: {what}.{allowed} It may still be on this computer.\n\nWhat to do: Open "
                    f"{PROTECTION_HISTORY}, choose this item, and pick Quarantine or Remove."
                ),
                severity=Severity.CRITICAL,
                category=self.category,
                code="security.win_defender_scan.threat_still_there",
                data=data,
                confidence=0.9,
            )
        data["check"] = "threat_handled"
        return Finding(
            title=f"Windows Defender found and dealt with {name}",
            description=(
                f"Windows Defender recognised {name}{file_word} as malware and its record says: "
                f"{what}. Nothing more is needed for this one, but it's a sign something unwanted "
                "reached this computer, so think about where it came from (a download, an email, "
                f"a USB stick). Details are in {PROTECTION_HISTORY}."
            ),
            severity=Severity.INFO,
            category=self.category,
            code="security.win_defender_scan.threat_handled",
            data=data,
            confidence=0.9,
        )
