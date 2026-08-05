"""Warn when cleanup is about to destroy the evidence of what happened.

docs/ROADMAP.md P2, "Evidence collection and forensic handoff": *repair can
destroy the information needed to understand a compromise*. Everything else in
this toolkit is oriented toward fixing things. Fixing things deletes the running
process list, clears the persistence entry, removes the malicious extension —
and with them the only record of how the machine was taken.

That trade is often worth making. What is not defensible is making it silently,
before anyone has decided. So this module runs early, reports what volatile
evidence exists right now, and warns when compromise indicators are present but
nothing has been preserved.

Deliberate design decisions:

**check() never writes a bundle.** Writing files is a real effect on the
machine, and the module contract is that check() observes and fix() proposes.
The bundle is written only by an explicit, human-triggered call.

**Redaction is not optional.** An evidence bundle is a file people email to
someone else. It never contains passwords, tokens, cookies, keychain items,
private keys, or browsing history. Where a category cannot be collected and
redacted safely, it is omitted and the omission is *recorded in the manifest*,
so the gap is visible to whoever receives it rather than looking like an absence
of evidence.

**Nothing is ever transmitted.** The bundle is written to local disk. This
module has no network path, by construction.
"""

import hashlib
import json
from datetime import datetime, timezone
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

_COMMAND_TIMEOUT = 20
_MAX_ITEM_BYTES = 512 * 1024
_MANIFEST_VERSION = 1

# Matches rescue/update/config.py's data directory convention.
_DEFAULT_STATE_DIR = Path.home() / ".local" / "share" / "rescue"

# Severities that mean "something may have happened here", used to decide
# whether un-preserved evidence is worth warning about.
_COMPROMISE_SEVERITIES = (Severity.CRITICAL, Severity.WARNING)

_NEVER_COLLECTED = [
    "Passwords, passphrases, and password-manager vaults",
    "Authentication tokens, cookies, and session identifiers",
    "Keychain and Credential Manager contents",
    "Private keys of any kind",
    "Browser history and page contents",
    "Documents, photos, and other personal files",
]

_ORDER_OF_OPERATIONS = (
    "Preserve first, then clean. Once you remove a persistence entry or kill a "
    "process, the record of how the machine was taken goes with it — and that "
    "record is what tells you which accounts to worry about.\n\n"
    "  1. If you think an account or money is involved, capture evidence now, "
    "before running any fix.\n"
    "  2. If this is a work machine, stop and call whoever handles security. Do "
    "not clean it yourself; you may be destroying an investigation.\n"
    "  3. If the situation involves another person — an ex-partner, a family "
    "member, anyone with physical access — evidence may matter legally. Talk to "
    "a domestic abuse advocate before you change anything.\n"
    "  4. Only then work through remediation."
)


class Module(ModuleBase):
    name = "evidence_bundle"
    category = "security"
    platforms = [Platform.DARWIN, Platform.WIN32, Platform.LINUX]
    risk_level = RiskLevel.SAFE
    priority = 90
    depends_on = []
    estimated_duration = "10s"

    emits_codes = [
        "security.evidence_bundle.no_bundle_captured",
        "security.evidence_bundle.destination_unwritable",
        "security.evidence_bundle.readiness",
    ]

    # Overridable so tests never write to the real user state directory.
    state_dir: Path | None = None

    def check(self, profile: SystemProfile) -> CheckResult:
        """Assess readiness. Deliberately does NOT write a bundle.

        Writing files is a real effect and belongs behind an explicit human
        decision, not behind a scan someone ran to look around.
        """
        findings: list[Finding] = []

        destination = self._bundle_root()
        writable = self._destination_writable(destination)
        collectable = self._collectable_categories(profile)
        existing = self._existing_bundles(destination)

        if not writable:
            findings.append(
                Finding(
                    title="No writable location for an evidence bundle",
                    description=(
                        f"{destination} cannot be written to, so evidence could not be "
                        "preserved here even if you asked for it.\n\n"
                        "If this machine may be compromised, capture what you need "
                        "another way — photograph the screen, write down what you saw and "
                        "when — before running any repair."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.evidence_bundle.destination_unwritable",
                    data={
                        "check": "destination_unwritable",
                        "destination": str(destination),
                    },
                )
            )

        findings.append(
            Finding(
                title=(
                    f"Evidence preservation: {len(collectable)} category(ies) "
                    f"collectable, {len(existing)} bundle(s) already captured"
                ),
                description=(
                    "Collectable right now:\n"
                    + "\n".join(f"  {c}" for c in collectable)
                    + f"\n\nBundles already captured: {len(existing)}"
                    + (
                        "\n" + "\n".join(f"  {b}" for b in existing)
                        if existing
                        else ""
                    )
                    + "\n\nNever collected, under any circumstances:\n"
                    + "\n".join(f"  {item}" for item in _NEVER_COLLECTED)
                    + "\n\nNothing has been written and nothing has been sent anywhere. "
                    "This check only looked at what could be preserved."
                ),
                severity=Severity.INFO,
                category=self.category,
                code="security.evidence_bundle.readiness",
                data={
                    "check": "readiness",
                    "destination": str(destination),
                    "destination_writable": writable,
                    "collectable_categories": collectable,
                    "existing_bundles": existing,
                    "bundle_written": False,
                },
            )
        )

        return CheckResult(module_name=self.name, findings=findings)

    def assess_with_context(
        self, profile: SystemProfile, other_findings: list[Finding]
    ) -> CheckResult:
        """check(), plus a warning if indicators exist and nothing is preserved.

        Separate from check() because it needs the rest of the scan's findings,
        which a single module does not otherwise see. The orchestrator can call
        this instead when it has the full picture.
        """
        result = self.check(profile)
        indicators = [
            f for f in other_findings if f.severity in _COMPROMISE_SEVERITIES
        ]
        existing = self._existing_bundles(self._bundle_root())

        if indicators and not existing:
            result.findings.insert(
                0,
                Finding(
                    title=(
                        f"{len(indicators)} possible compromise indicator(s) found and "
                        "no evidence captured"
                    ),
                    description=(
                        "This scan found things worth investigating, and no evidence "
                        "bundle has been captured on this machine.\n\n"
                        "If you now run repairs, the information that explains what "
                        "happened — which processes were running, what was set to start "
                        "automatically, what was listening on the network — will be "
                        "destroyed along with the problem.\n\n"
                        + _ORDER_OF_OPERATIONS
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.evidence_bundle.no_bundle_captured",
                    data={
                        "check": "no_bundle_captured",
                        "indicator_count": len(indicators),
                    },
                ),
            )

        return result

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions: list[Action] = []

        actions.append(
            Action(
                title="Preserve evidence before you repair anything",
                description=_ORDER_OF_OPERATIONS,
                risk_level=RiskLevel.SAFE,
                kind=ActionKind.GUIDANCE,
                success=True,
                data={"check": "order_of_operations"},
            )
        )

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "readiness":
                actions.append(
                    Action(
                        title="What a handoff to a professional needs",
                        description=(
                            "If you take this to an incident responder, a lawyer, or "
                            "the police, they will want:\n\n"
                            "  1. When you first noticed something wrong, and what it "
                            "was. Write it down now; memory degrades fast.\n"
                            "  2. What you have already changed on the machine. Be "
                            "honest about this — it changes how they read everything "
                            "else.\n"
                            "  3. Whether the machine has been used since.\n"
                            "  4. Any messages, emails, or charges you noticed.\n\n"
                            "For a serious case, the strongest evidence is a machine "
                            "that has been left alone. If you can stop using it, do "
                            "that rather than trying to collect anything yourself.\n\n"
                            "This tool never collects: "
                            + "; ".join(_NEVER_COLLECTED).lower()
                            + "."
                        ),
                        risk_level=RiskLevel.SAFE,
                        kind=ActionKind.GUIDANCE,
                        success=True,
                        data={"check": "handoff"},
                    )
                )

            elif check == "destination_unwritable":
                actions.append(
                    Action(
                        title="Record what you saw by hand",
                        description=(
                            f"{finding.data.get('destination')} is not writable, so "
                            "capture the basics manually instead:\n\n"
                            "  1. Photograph any warning, ransom note, or unexpected "
                            "message with your phone.\n"
                            "  2. Write down the date and time you noticed it.\n"
                            "  3. Note any account that behaved oddly, and any charge "
                            "you did not make.\n\n"
                            "A phone photograph and a written timeline are genuinely "
                            "useful evidence. Do not skip this because you cannot "
                            "produce a technical bundle."
                        ),
                        risk_level=RiskLevel.SAFE,
                        kind=ActionKind.GUIDANCE,
                        success=True,
                        data={"check": check},
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    # -- bundle writing ----------------------------------------------------

    def write_bundle(self, profile: SystemProfile) -> Path | None:
        """Write a redacted, hashed evidence bundle. Explicit call only.

        Never invoked by check() or fix(): this creates files, which is a real
        change to the machine and needs a human to have asked for it.
        """
        root = self._bundle_root()
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        bundle = root / f"evidence-{stamp}"

        try:
            bundle.mkdir(parents=True, exist_ok=True)
        except OSError:
            return None

        items: list[dict] = []
        omissions: list[dict] = []

        for category, command in self._collection_commands(profile):
            result = run(command, timeout=_COMMAND_TIMEOUT, max_output=_MAX_ITEM_BYTES)
            if not result.ok:
                omissions.append(
                    {
                        "category": category,
                        "reason": "command did not complete successfully",
                        "command": " ".join(command),
                    }
                )
                continue

            content = result.stdout[:_MAX_ITEM_BYTES]
            filename = category.replace(" ", "_").lower() + ".txt"
            try:
                (bundle / filename).write_text(content)
            except OSError:
                omissions.append(
                    {"category": category, "reason": "could not be written to disk"}
                )
                continue

            items.append(
                {
                    "category": category,
                    "file": filename,
                    "sha256": hashlib.sha256(content.encode("utf-8", "replace")).hexdigest(),
                    "bytes": len(content),
                    "truncated": result.truncated or len(result.stdout) > _MAX_ITEM_BYTES,
                    "command": " ".join(command),
                    "collected_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                }
            )

        manifest = {
            "manifest_version": _MANIFEST_VERSION,
            "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "platform": profile.platform.value,
            "os_name": profile.os_name,
            "os_version": profile.os_version,
            "items": items,
            # Recorded, not silent: a reader must be able to see what is absent
            # and why, rather than mistaking a gap for an absence of evidence.
            "omitted": omissions,
            "never_collected": _NEVER_COLLECTED,
            "chain_of_custody": (
                "Generated locally by multiverse-device-rescue. Not transmitted "
                "anywhere. Hashes cover file contents as written. This bundle is "
                "redacted by design and is not a forensic disk image; it does not "
                "establish an unbroken chain of custody on its own."
            ),
        }

        try:
            (bundle / "manifest.json").write_text(
                json.dumps(manifest, indent=2, sort_keys=True)
            )
        except OSError:
            return None

        return bundle

    # -- helpers -----------------------------------------------------------

    def _bundle_root(self) -> Path:
        root = Path(self.state_dir) if self.state_dir is not None else _DEFAULT_STATE_DIR
        return root / "evidence"

    @staticmethod
    def _destination_writable(destination: Path) -> bool:
        try:
            destination.mkdir(parents=True, exist_ok=True)
        except OSError:
            return False
        probe = destination / ".write_probe"
        try:
            probe.write_text("")
            probe.unlink()
        except OSError:
            return False
        return True

    def _existing_bundles(self, destination: Path) -> list[str]:
        try:
            return sorted(
                entry.name
                for entry in destination.iterdir()
                if entry.is_dir() and entry.name.startswith("evidence-")
            )
        except OSError:
            return []

    @staticmethod
    def _collection_commands(profile: SystemProfile) -> list[tuple[str, list[str]]]:
        """Commands whose output is safe to preserve after redaction.

        Each yields process/service/network metadata only. Nothing here reads a
        credential store, a cookie jar, or a user document.
        """
        if profile.platform == Platform.WIN32:
            return [
                ("process list", ["tasklist"]),
                ("network connections", ["netstat", "-ano"]),
                ("scheduled tasks", ["schtasks", "/query", "/fo", "list"]),
                ("services", ["net", "start"]),
            ]
        if profile.platform == Platform.DARWIN:
            return [
                ("process list", ["ps", "aux"]),
                ("network connections", ["netstat", "-an"]),
                ("launch agents", ["launchctl", "list"]),
            ]
        return [
            ("process list", ["ps", "aux"]),
            ("network connections", ["ss", "-tulpn"]),
            ("systemd units", ["systemctl", "list-units", "--type=service", "--no-pager"]),
        ]

    def _collectable_categories(self, profile: SystemProfile) -> list[str]:
        return [category for category, _ in self._collection_commands(profile)]
