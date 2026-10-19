"""Check whether installed applications are actually signed by who they claim.

docs/ROADMAP.md P2, "Trust and reputation verification", opens with the reason
this exists: *file-name and keyword checks create false positives*. Most of the
detection in this toolkit matches names and paths against lists, which is cheap
and catches known-bad, but says nothing about whether a given binary is what it
claims to be. Code signing does.

The severities here are chosen to be defensible rather than alarming:

- CRITICAL only for a signature that is present and *broken* — the binary has
  been modified since it was signed. That is tampering, not a configuration
  choice, and there is no innocent reading of it.
- WARNING for unsigned or ad-hoc-signed software in a system-wide location,
  where anyone can drop a binary and every user runs it.
- INFO for the inventory, including the coverage cap.

A locally built binary, a developer tool, or an open-source app the user
compiled is *expected* to be unsigned. Reporting those as malware would recreate
exactly the false-positive problem this module exists to reduce, so the finding
text says what was observed and leaves the judgement to the reader.

Signature verification is slow — hundreds of milliseconds per binary — so the
scan is capped by count and by wall clock, and the INFO finding states the cap
and whether it was hit. A result that silently examined 40 of 300 applications
while implying a full audit would be worse than no result at all.
"""

import time
from concurrent.futures import ThreadPoolExecutor
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
from rescue.command import run
from rescue.fsbounds import is_dir_nofollow

# Signature checks are expensive; these bound the whole scan. The engine stops
# any check at 60 seconds, and on a Mac with ~100 apps the old sequential
# 60-app scan (up to 30s of codesign + spctl per app) never finished inside
# that, so the whole check was reported as "couldn't run". The wall-clock
# budget leaves headroom, and a few apps are checked at once.
_MAX_BINARIES = 60
_PER_COMMAND_TIMEOUT = 10
_TIME_BUDGET_S = 40.0
_WORKERS = 3
# One PowerShell listing per Windows folder, all inside the same budget.
_WIN_FOLDER_TIMEOUT = 25

_DARWIN_APP_DIRS = ["/Applications", "~/Applications"]
_SYSTEM_WIDE_PREFIXES = ("/Applications",)

_WIN_PROGRAM_DIRS = [
    r"C:\Program Files",
    r"C:\Program Files (x86)",
]

def _powershell_signature_command(path: str, limit: int) -> str:
    """Build the Authenticode listing command.

    Assembled by concatenation rather than str.format: the PowerShell body is
    full of braces, and formatting it would treat them as replacement fields.
    """
    return (
        "Get-ChildItem -LiteralPath '"
        + path
        + "' -Filter *.exe -File -ErrorAction SilentlyContinue | "
        "Select-Object -First "
        + str(limit)
        + " | ForEach-Object { $s = Get-AuthenticodeSignature $_.FullName; "
        '"$($_.FullName)|$($s.Status)|$($s.SignerCertificate.Subject)" }'
    )


class Module(ModuleBase):
    name = "code_signature_audit"
    category = "security"
    platforms = [Platform.DARWIN, Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 76
    depends_on = []
    estimated_duration = "60s"

    emits_codes = [
        "security.code_signature_audit.tampered_binary",
        "security.code_signature_audit.unsigned_system_app",
        "security.code_signature_audit.gatekeeper_rejected",
        "security.code_signature_audit.inventory",
    ]

    # Scan roots and cap, overridable so tests are deterministic and bounded.
    app_dirs: list[str] | None = None
    max_binaries: int = _MAX_BINARIES
    time_budget_s: float = _TIME_BUDGET_S

    def check(self, profile: SystemProfile) -> CheckResult:
        if profile.platform not in (Platform.DARWIN, Platform.WIN32):
            return CheckResult(
                module_name=self.name,
                supported=False,
                unsupported_reason=(
                    "Code-signature verification is implemented for macOS "
                    f"(codesign/spctl) and Windows (Authenticode); this host "
                    f"reports {profile.platform.value}."
                ),
            )

        if profile.platform == Platform.DARWIN:
            results, examined, total, out_of_time = self._audit_darwin()
            unread: list[str] = []
        else:
            results, examined, total, out_of_time, unread = self._audit_windows()

        findings: list[Finding] = []

        tampered = [r for r in results if r["status"] == "tampered"]
        unsigned = [r for r in results if r["status"] == "unsigned"]
        rejected = [r for r in results if r["status"] == "gatekeeper_rejected"]
        # A check that did not finish is neither a problem nor a pass.
        incomplete = [r for r in results if r["status"] == "incomplete"]

        for entry in tampered:
            findings.append(
                Finding(
                    title=f"App {entry['name']} was changed after it was signed",
                    description=(
                        f"{entry['path']} has a digital signature, but it no longer matches "
                        "the file. This means the app was modified after the maker signed "
                        "it.\n\n"
                        "Legitimate updates are always re-signed by the maker, so there "
                        "is no normal reason for this mismatch. It is a strong sign the "
                        "app is not what it claims to be. Do not open it.\n\n"
                        "If you think someone close to you set this up to monitor you, "
                        "removing it can alert them. Talk to an advocate first (US National "
                        "Domestic Violence Hotline: 1-800-799-7233, or text START to "
                        "88788).\n\n"
                        "What to do: Download a fresh copy from the maker's official "
                        "website or the App Store and replace this one. If you do not "
                        "recognize the app, do not open it and seek help before deleting "
                        "it.\n\n"
                        f"Reported by: {entry['detail']}"
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    code="security.code_signature_audit.tampered_binary",
                    data={
                        "check": "tampered_binary",
                        "path": entry["path"],
                        "name": entry["name"],
                        "detail": entry["detail"],
                    },
                )
            )

        for entry in unsigned:
            findings.append(
                Finding(
                    title=f"Unsigned app {entry['name']} is installed for all users",
                    description=(
                        f"{entry['path']} has no digital signature, and it is in a folder "
                        "that affects everyone who uses this computer.\n\n"
                        "This is not automatically bad. Some developer tools and open-source "
                        "software are legitimately unsigned. However, if you did not "
                        "install this app yourself, it is worth checking.\n\n"
                        "If you think someone close to you set this up to monitor you, "
                        "removing it can alert them. Talk to an advocate first (US National "
                        "Domestic Violence Hotline: 1-800-799-7233, or text START to "
                        "88788).\n\n"
                        "What to do: If you do not recognize this app, do not delete "
                        "it yet. Note its name and ask a trusted technical person or "
                        "advocate to help you identify it safely.\n\n"
                        f"Reported by: {entry['detail']}"
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.code_signature_audit.unsigned_system_app",
                    data={
                        "check": "unsigned_system_app",
                        "path": entry["path"],
                        "name": entry["name"],
                        "detail": entry["detail"],
                    },
                )
            )

        for entry in rejected:
            findings.append(
                Finding(
                    title=f"macOS blocks {entry['name']} from running",
                    description=(
                        f"{entry['path']} has a signature, but macOS refuses to run it. "
                        "This usually happens when the app was not officially verified "
                        "(notarized) by Apple, or the signature is from a source Apple "
                        "does not trust.\n\n"
                        "This is common for software downloaded from websites rather "
                        "than the App Store, or for older versions of apps. It is often "
                        "harmless, but you should check where you got it.\n\n"
                        "What to do: If you trust the source, you can leave it as is. "
                        "If you are unsure, download the current version from the maker's "
                        "official website to replace it.\n\n"
                        f"Reported by: {entry['detail']}"
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.code_signature_audit.gatekeeper_rejected",
                    data={
                        "check": "gatekeeper_rejected",
                        "path": entry["path"],
                        "name": entry["name"],
                        "detail": entry["detail"],
                    },
                )
            )

        capped = total > examined
        valid = len(results) - len(tampered) - len(unsigned) - len(rejected) - len(incomplete)
        if capped and out_of_time:
            coverage = (
                f"COVERAGE LIMIT: only {examined} applications were checked because "
                "signature checks took too long. This is not a full-disk audit, and the "
                "other applications were not checked at all.\n\n"
            )
        elif capped:
            coverage = (
                f"COVERAGE LIMIT: the scan checks at most {self.max_binaries} "
                "applications, because each signature check takes a while. This is "
                "not a full-disk audit, and applications beyond that number were not "
                "checked at all.\n\n"
            )
        elif unread:
            coverage = ""
        elif incomplete:
            coverage = "Every application was looked at, but some checks did not finish.\n\n"
        else:
            coverage = "All applications in the scanned locations were checked.\n\n"
        if unread:
            coverage = (
                "COVERAGE LIMIT: these folders could not be read, so the applications "
                "in them were not checked at all: " + ", ".join(unread) + ".\n\n"
            ) + coverage
        unfinished = (
            f"Could not finish: {len(incomplete)} ("
            + ", ".join(r["name"] for r in incomplete[:10])
            + (", ..." if len(incomplete) > 10 else "")
            + "). Their signature check took too long and was stopped, so they "
            "were not checked. That does not mean they are fine.\n"
            if incomplete
            else ""
        )
        findings.append(
            Finding(
                title=f"Checked {examined} of {total} app signatures",
                description=(
                    f"Examined: {examined}\nPresent in the scanned locations: {total}\n"
                    f"Valid signatures: {valid}\n"
                    f"Broken signatures: {len(tampered)}\n"
                    f"Unsigned: {len(unsigned)}\n"
                    f"Gatekeeper-rejected: {len(rejected)}\n"
                    + unfinished
                    + "\n"
                    + coverage
                    + "Only signature status was read. No application was opened, "
                    "modified, quarantined, or sent anywhere."
                ),
                severity=Severity.INFO,
                category=self.category,
                code="security.code_signature_audit.inventory",
                data={
                    "check": "inventory",
                    "examined": examined,
                    "total_present": total,
                    "coverage_capped": capped or bool(unread),
                    "cap": self.max_binaries,
                    "stopped_by_time_limit": out_of_time,
                    "unread_folders": unread,
                    "time_budget_s": self.time_budget_s,
                    "tampered": len(tampered),
                    "unsigned": len(unsigned),
                    "gatekeeper_rejected": len(rejected),
                    "incomplete": len(incomplete),
                    "incomplete_apps": [r["path"] for r in incomplete],
                },
            )
        )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions: list[Action] = []

        for finding in findings.findings:
            check = finding.data.get("check")
            name = finding.data.get("name", "")

            if check == "tampered_binary":
                actions.append(
                    Action(
                        title=f"Replace {name} — its signature does not match its contents",
                        description=(
                            f"{finding.data.get('path')}\n\n"
                            "  1. Do not run it again until this is resolved.\n"
                            "  2. Delete it and reinstall from the vendor's own site or "
                            "the App Store — not from wherever the current copy came "
                            "from.\n"
                            "  3. If you did not modify it yourself (some tools are "
                            "patched deliberately, e.g. to remove a licence check), treat "
                            "this machine as potentially compromised and work through the "
                            "digital_security_reset profile.\n\n"
                            "Verify it yourself with:\n"
                            f"  codesign --verify --deep --strict --verbose=2 "
                            f"'{finding.data.get('path')}'"
                        ),
                        risk_level=RiskLevel.SAFE,
                        kind=ActionKind.GUIDANCE,
                        success=True,
                        data={"check": check, "path": finding.data.get("path")},
                    )
                )

            elif check == "unsigned_system_app":
                actions.append(
                    Action(
                        title=f"Account for the unsigned application {name}",
                        description=(
                            f"{finding.data.get('path')}\n\n"
                            "Ask, in order:\n"
                            "  1. Did you install this deliberately? If yes, and you got "
                            "it from a source you trust, unsigned is usually just how it "
                            "ships.\n"
                            "  2. Did you build it yourself? Then it is expected.\n"
                            "  3. If neither — you do not recognize it, or it appeared "
                            "without you installing it — that is the case worth "
                            "investigating. Look at when it was installed and what else "
                            "arrived at the same time.\n\n"
                            "Inspect it with:\n"
                            f"  codesign -dv --verbose=4 '{finding.data.get('path')}'\n"
                            f"  spctl --assess --type execute --verbose "
                            f"'{finding.data.get('path')}'"
                        ),
                        risk_level=RiskLevel.SAFE,
                        kind=ActionKind.GUIDANCE,
                        success=True,
                        data={"check": check, "path": finding.data.get("path")},
                    )
                )

            elif check == "gatekeeper_rejected":
                actions.append(
                    Action(
                        title=f"Check where {name} came from",
                        description=(
                            f"{finding.data.get('path')}\n\n"
                            "Gatekeeper rejecting an application usually means it is not "
                            "notarized. That is common for smaller developers and for "
                            "software installed years ago, and is not by itself a sign of "
                            "compromise.\n\n"
                            "Confirm it came from the developer's own distribution "
                            "channel. If it did, no action is needed. If you cannot place "
                            "it, remove it and reinstall from a known source."
                        ),
                        risk_level=RiskLevel.SAFE,
                        kind=ActionKind.GUIDANCE,
                        success=True,
                        data={"check": check, "path": finding.data.get("path")},
                    )
                )

            elif check == "inventory" and finding.data.get("coverage_capped"):
                actions.append(
                    Action(
                        title="Signature audit did not cover every application",
                        description=(
                            f"Only {finding.data.get('examined')} of "
                            f"{finding.data.get('total_present')} applications were "
                            "checked, because each signature check takes a while.\n\n"
                            "Do not read a clean result as 'everything is signed'. To "
                            "check a specific application yourself:\n"
                            "  codesign --verify --deep --strict '/Applications/Name.app'"
                        ),
                        risk_level=RiskLevel.SAFE,
                        kind=ActionKind.GUIDANCE,
                        success=True,
                        data={"check": "coverage_limit"},
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    # -- detection ---------------------------------------------------------

    def _app_dirs(self, platform: Platform) -> list[str]:
        if self.app_dirs is not None:
            return self.app_dirs
        return _DARWIN_APP_DIRS if platform == Platform.DARWIN else _WIN_PROGRAM_DIRS

    def _collect_darwin_apps(self) -> list[Path]:
        apps: list[Path] = []
        for raw_dir in self._app_dirs(Platform.DARWIN):
            directory = Path(raw_dir).expanduser()
            if not is_dir_nofollow(directory):
                continue
            try:
                entries = sorted(directory.iterdir())
            except OSError:
                continue
            apps.extend(e for e in entries if e.suffix == ".app")
        return apps

    def _audit_darwin(self) -> tuple[list[dict], int, int, bool]:
        """Check app signatures within the count cap and the time budget.

        Returns (results, examined, total, out_of_time). Apps not started
        before the budget ran out are left out of ``results`` (not examined);
        an app whose own command ran out of time is "incomplete". Every app
        that did finish is kept, even after one that was skipped.
        """
        apps = self._collect_darwin_apps()
        total = len(apps)
        deadline = time.monotonic() + self.time_budget_s

        def check_one(app: Path) -> dict | None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            return self._check_darwin_app(app, deadline)

        # These pool threads are not the engine's worker thread, so the
        # engine's abandon guard does not cover them if this check is stopped.
        # They stay bounded on their own: every command is capped at what is
        # left of this check's deadline, and nothing starts after it.
        with ThreadPoolExecutor(max_workers=_WORKERS) as pool:
            checked = list(pool.map(check_one, apps[: self.max_binaries]))
        results = [entry for entry in checked if entry is not None]
        out_of_time = len(results) < len(checked)
        return results, len(results), total, out_of_time

    def _check_darwin_app(self, app: Path, deadline: float) -> dict:
        def budget() -> float:
            return max(1.0, min(_PER_COMMAND_TIMEOUT, deadline - time.monotonic()))

        verify = run(
            ["codesign", "--verify", "--deep", "--strict", str(app)],
            timeout=budget(),
        )
        entry = {
            "path": str(app),
            "name": app.stem,
            "status": "valid",
            "detail": "codesign --verify reported a valid signature",
        }

        if not verify.ok:
            combined = (verify.stdout + verify.stderr).lower()
            if "not signed" in combined or "code object is not signed" in combined:
                # Unsigned only counts as a finding in a system-wide location:
                # an unsigned app in the user's own ~/Applications is their
                # own business and would be pure noise.
                if str(app).startswith(_SYSTEM_WIDE_PREFIXES):
                    entry["status"] = "unsigned"
                    entry["detail"] = "codesign: code object is not signed at all"
                else:
                    entry["detail"] = "unsigned, in a per-user location"
            elif verify.timed_out or verify.error:
                entry["status"] = "incomplete"
                entry["detail"] = "signature check did not complete: " + (
                    verify.error or "timed out"
                )
            else:
                entry["status"] = "tampered"
                entry["detail"] = (
                    "codesign --verify failed on a signed object: "
                    + (verify.stderr.strip() or verify.stdout.strip() or "no detail")
                )
        else:
            assess = run(
                ["spctl", "--assess", "--type", "execute", str(app)],
                timeout=budget(),
            )
            if assess.timed_out or assess.error:
                entry["status"] = "incomplete"
                entry["detail"] = "Gatekeeper check did not complete: " + (
                    assess.error or "timed out"
                )
            elif not assess.ok:
                entry["status"] = "gatekeeper_rejected"
                entry["detail"] = (
                    "spctl --assess rejected it: "
                    + (assess.stderr.strip() or assess.stdout.strip() or "no detail")
                )
        return entry

    def _audit_windows(self) -> tuple[list[dict], int, int, bool, list[str]]:
        """Returns (results, examined, total, out_of_time, unread_folders).

        A folder whose listing failed, timed out or was never started for
        lack of time is in ``unread_folders``: not checked, never "clean".
        """
        results: list[dict] = []
        total = 0
        unread: list[str] = []
        out_of_time = False
        deadline = time.monotonic() + self.time_budget_s

        for raw_dir in self._app_dirs(Platform.WIN32):
            remaining = deadline - time.monotonic()
            if remaining < 0.5:
                out_of_time = True
                unread.append(raw_dir)
                continue
            command = _powershell_signature_command(raw_dir, self.max_binaries)
            result = run(
                ["powershell", "-NoProfile", "-Command", command],
                timeout=min(_WIN_FOLDER_TIMEOUT, remaining),
            )
            if not result.ok:
                if result.timed_out:
                    out_of_time = True
                unread.append(raw_dir)
                continue

            for line in result.stdout.splitlines():
                line = line.strip()
                if not line or "|" not in line:
                    continue
                parts = line.split("|")
                if len(parts) < 2:
                    continue
                path, status = parts[0].strip(), parts[1].strip()
                subject = parts[2].strip() if len(parts) > 2 else ""
                total += 1
                if len(results) >= self.max_binaries:
                    continue

                entry = {
                    "path": path,
                    "name": Path(path).stem,
                    "status": "valid",
                    "detail": f"Authenticode status {status}"
                    + (f", signed by {subject}" if subject else ""),
                }
                normalised = status.lower()
                if normalised == "hashmismatch":
                    entry["status"] = "tampered"
                    entry["detail"] = (
                        "Get-AuthenticodeSignature reported HashMismatch: the file "
                        "was modified after signing"
                    )
                elif normalised == "notsigned":
                    entry["status"] = "unsigned"
                    entry["detail"] = (
                        "Get-AuthenticodeSignature reported NotSigned"
                    )
                elif normalised not in ("valid",):
                    entry["status"] = "gatekeeper_rejected"
                    entry["detail"] = (
                        f"Get-AuthenticodeSignature reported {status}"
                    )
                results.append(entry)

        return results, len(results), max(total, len(results)), out_of_time, unread
