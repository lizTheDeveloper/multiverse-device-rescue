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

# Signature checks are expensive; these bound the whole scan.
_MAX_BINARIES = 60
_PER_COMMAND_TIMEOUT = 15

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
            results, examined, total = self._audit_darwin()
        else:
            results, examined, total = self._audit_windows()

        findings: list[Finding] = []

        tampered = [r for r in results if r["status"] == "tampered"]
        unsigned = [r for r in results if r["status"] == "unsigned"]
        rejected = [r for r in results if r["status"] == "gatekeeper_rejected"]

        for entry in tampered:
            findings.append(
                Finding(
                    title=f"Signature does not match contents: {entry['name']}",
                    description=(
                        f"{entry['path']} carries a code signature, but the signature "
                        "does not match the file's current contents. That means the "
                        "application was modified after it was signed.\n\n"
                        "Unlike an unsigned application, there is no benign explanation "
                        "for this: legitimate updates are re-signed by the vendor. Treat "
                        "this application as untrusted until you have reinstalled it "
                        "from the vendor.\n\n"
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
                    title=f"Unsigned application in a system-wide location: {entry['name']}",
                    description=(
                        f"{entry['path']} has no valid code signature, and it lives in a "
                        "location that applies to every user of this machine.\n\n"
                        "This is evidence, not a verdict. Software you compiled yourself, "
                        "developer tooling, and some open-source applications are "
                        "legitimately unsigned. What matters is whether you can account "
                        "for this one: if you did not install it deliberately, or you do "
                        "not recognise it, that is worth following up.\n\n"
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
                    title=f"Gatekeeper will not accept: {entry['name']}",
                    description=(
                        f"{entry['path']} is signed, but macOS Gatekeeper rejects it — "
                        "typically because it is not notarised, or the signing identity "
                        "is not one macOS accepts for distribution.\n\n"
                        "Common and often benign for software distributed outside the App "
                        "Store, or installed before notarisation was required. Worth "
                        "checking against where you got it from.\n\n"
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
        findings.append(
            Finding(
                title=(
                    f"Signature audit covered {examined} of {total} application(s)"
                ),
                description=(
                    f"Examined: {examined}\nPresent in the scanned locations: {total}\n"
                    f"Valid signatures: {len(results) - len(tampered) - len(unsigned) - len(rejected)}\n"
                    f"Broken signatures: {len(tampered)}\n"
                    f"Unsigned: {len(unsigned)}\n"
                    f"Gatekeeper-rejected: {len(rejected)}\n\n"
                    + (
                        f"COVERAGE LIMIT: the scan stopped at {self.max_binaries} "
                        "applications because signature verification is slow. This is "
                        "not a full-disk audit, and applications beyond the cap were not "
                        "checked at all.\n\n"
                        if capped
                        else "All applications in the scanned locations were checked.\n\n"
                    )
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
                    "coverage_capped": capped,
                    "cap": self.max_binaries,
                    "tampered": len(tampered),
                    "unsigned": len(unsigned),
                    "gatekeeper_rejected": len(rejected),
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
                            "  3. If neither — you do not recognise it, or it appeared "
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
                            "notarised. That is common for smaller developers and for "
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
                            "checked, because signature verification takes hundreds of "
                            "milliseconds per binary.\n\n"
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

    def _audit_darwin(self) -> tuple[list[dict], int, int]:
        apps = self._collect_darwin_apps()
        total = len(apps)
        results: list[dict] = []

        for app in apps[: self.max_binaries]:
            verify = run(
                ["codesign", "--verify", "--deep", "--strict", str(app)],
                timeout=_PER_COMMAND_TIMEOUT,
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
                    entry["detail"] = "signature check did not complete"
                else:
                    entry["status"] = "tampered"
                    entry["detail"] = (
                        "codesign --verify failed on a signed object: "
                        + (verify.stderr.strip() or verify.stdout.strip() or "no detail")
                    )
            else:
                assess = run(
                    ["spctl", "--assess", "--type", "execute", str(app)],
                    timeout=_PER_COMMAND_TIMEOUT,
                )
                if not assess.ok and not assess.timed_out and not assess.error:
                    entry["status"] = "gatekeeper_rejected"
                    entry["detail"] = (
                        "spctl --assess rejected it: "
                        + (assess.stderr.strip() or assess.stdout.strip() or "no detail")
                    )

            results.append(entry)

        return results, len(results), total

    def _audit_windows(self) -> tuple[list[dict], int, int]:
        results: list[dict] = []
        total = 0

        for raw_dir in self._app_dirs(Platform.WIN32):
            command = _powershell_signature_command(raw_dir, self.max_binaries)
            result = run(
                ["powershell", "-NoProfile", "-Command", command],
                timeout=_PER_COMMAND_TIMEOUT * 4,
            )
            if not result.ok:
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

        return results, len(results), max(total, len(results))
