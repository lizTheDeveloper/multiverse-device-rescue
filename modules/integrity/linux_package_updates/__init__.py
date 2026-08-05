"""Are there security updates waiting, and is this release still getting them?

Unapplied updates are the most boring finding a security tool can produce and
the one that matters most: the overwhelming majority of real-world compromises
use a fixed vulnerability against a machine that had not applied the fix.

Linux makes this awkward because there is no single package manager. This
module detects which one is in use — apt, dnf, pacman, or zypper — and asks it,
using its own read-only query mode. No package manager is invoked in a way that
changes anything: `apt list --upgradable` and `dnf check-update` read, they do
not install.

The second half is end-of-life. A release that has stopped receiving updates
looks perfectly healthy — nothing is pending, because nothing is being
published any more. That is the failure mode this check exists to catch, and it
is why "0 updates available" is not reported as good news without also checking
whether updates are still being produced.
"""

import re
from pathlib import Path

from rescue.command import run
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

# Package-manager queries hit local metadata, but a stale cache can make apt
# reach out; give them room without letting them stall a scan.
_TIMEOUT = 45.0

_SECURITY_HINTS = ("security", "-security", "esm-apps", "esm-infra")


class Module(ModuleBase):
    name = "linux_package_updates"
    category = "integrity"
    platforms = [Platform.LINUX]
    risk_level = RiskLevel.SAFE
    priority = 86
    depends_on = []
    estimated_duration = "45s"

    emits_codes = [
        "integrity.linux_package_updates.security_updates_pending",
        "integrity.linux_package_updates.updates_pending",
        "integrity.linux_package_updates.reboot_required",
        "integrity.linux_package_updates.release_end_of_life",
        "integrity.linux_package_updates.no_package_manager",
    ]

    os_release_path: str = "/etc/os-release"
    reboot_required_path: str = "/var/run/reboot-required"

    def check(self, profile: SystemProfile) -> CheckResult:
        if profile.platform is not Platform.LINUX:
            return CheckResult(
                module_name=self.name,
                supported=False,
                unsupported_reason=(
                    "This check queries Linux package managers (apt, dnf, pacman, zypper); "
                    f"this host reports {profile.platform.value}."
                ),
            )

        manager, pending, security = self._pending_updates()
        findings: list[Finding] = []

        if manager is None:
            return CheckResult(
                module_name=self.name,
                supported=False,
                unsupported_reason=(
                    "No supported package manager (apt, dnf, pacman, zypper) was found, so "
                    "pending updates cannot be determined on this distribution."
                ),
            )

        if security:
            findings.append(
                Finding(
                    title=f"{len(security)} security update(s) are waiting to be installed",
                    description=(
                        "These are fixes for known vulnerabilities that have already been "
                        "published — which means they have also been published to everyone "
                        "who writes exploits.\n\n"
                        + "\n".join(f"  {name}" for name in security[:20])
                        + (f"\n  ... and {len(security) - 20} more" if len(security) > 20 else "")
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    code="integrity.linux_package_updates.security_updates_pending",
                    confidence=0.9,
                    data={"check": "security_updates_pending", "manager": manager, "packages": security[:50]},
                )
            )

        other = [p for p in pending if p not in set(security)]
        if other:
            findings.append(
                Finding(
                    title=f"{len(other)} package update(s) available",
                    description=(
                        "Ordinary updates — bug fixes and new versions. Worth applying, but "
                        "not urgent in the way security updates are.\n\n"
                        + "\n".join(f"  {name}" for name in other[:20])
                        + (f"\n  ... and {len(other) - 20} more" if len(other) > 20 else "")
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="integrity.linux_package_updates.updates_pending",
                    confidence=0.9,
                    data={"check": "updates_pending", "manager": manager, "packages": other[:50]},
                )
            )

        if Path(self.reboot_required_path).exists():
            findings.append(
                Finding(
                    title="A reboot is required to finish applying updates",
                    description=(
                        "Updates have been installed but the running kernel or libraries "
                        "are still the old ones. Until this machine restarts, the "
                        "vulnerabilities those updates fixed are still present in memory — "
                        "the fix is on disk and not in use."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="integrity.linux_package_updates.reboot_required",
                    confidence=1.0,
                    data={"check": "reboot_required"},
                )
            )

        eol = self._end_of_life_finding()
        if eol is not None:
            findings.append(eol)

        return CheckResult(module_name=self.name, findings=findings)

    def _pending_updates(self) -> tuple[str | None, list[str], list[str]]:
        for manager, method in (
            ("apt", self._apt),
            ("dnf", self._dnf),
            ("pacman", self._pacman),
            ("zypper", self._zypper),
        ):
            result = method()
            if result is not None:
                pending, security = result
                return manager, pending, security
        return None, [], []

    def _apt(self) -> tuple[list[str], list[str]] | None:
        result = run(["apt", "list", "--upgradable"], timeout=_TIMEOUT)
        if result.error is not None:
            return None
        pending, security = [], []
        for line in result.stdout.splitlines():
            if "/" not in line or line.startswith("Listing"):
                continue
            name = line.split("/", 1)[0].strip()
            if not name:
                continue
            pending.append(name)
            if any(hint in line.lower() for hint in _SECURITY_HINTS):
                security.append(name)
        return pending, security

    def _dnf(self) -> tuple[list[str], list[str]] | None:
        result = run(["dnf", "--quiet", "check-update"], timeout=_TIMEOUT)
        # dnf uses exit code 100 for "updates available" and 0 for "none".
        if result.error is not None or result.returncode not in (0, 100):
            return None
        pending = []
        for line in result.stdout.splitlines():
            fields = line.split()
            if len(fields) >= 3 and "." in fields[0] and not line.startswith(" "):
                pending.append(fields[0])

        security: list[str] = []
        sec_result = run(["dnf", "--quiet", "check-update", "--security"], timeout=_TIMEOUT)
        if sec_result.error is None and sec_result.returncode in (0, 100):
            for line in sec_result.stdout.splitlines():
                fields = line.split()
                if len(fields) >= 3 and "." in fields[0] and not line.startswith(" "):
                    security.append(fields[0])
        return pending, security

    def _pacman(self) -> tuple[list[str], list[str]] | None:
        # -Qu queries the local database only; it never touches the network.
        result = run(["pacman", "-Qu"], timeout=_TIMEOUT)
        if result.error is not None:
            return None
        pending = [line.split()[0] for line in result.stdout.splitlines() if line.strip()]
        # Arch does not separate a security channel, so every update is treated
        # as ordinary rather than inventing a distinction that does not exist.
        return pending, []

    def _zypper(self) -> tuple[list[str], list[str]] | None:
        result = run(["zypper", "--quiet", "list-updates"], timeout=_TIMEOUT)
        if result.error is not None:
            return None
        pending = []
        for line in result.stdout.splitlines():
            fields = [f.strip() for f in line.split("|")]
            if len(fields) >= 3 and fields[0] == "v":
                pending.append(fields[2])
        security: list[str] = []
        patch_result = run(["zypper", "--quiet", "list-patches", "--category", "security"], timeout=_TIMEOUT)
        if patch_result.error is None:
            for line in patch_result.stdout.splitlines():
                fields = [f.strip() for f in line.split("|")]
                if len(fields) >= 2 and fields[0] and fields[0] not in ("Repository", "--"):
                    security.append(fields[1])
        return pending, security

    def _end_of_life_finding(self) -> Finding | None:
        """Flag a release that has stopped receiving updates.

        Support end dates are not published in a machine-readable form on the
        host, so rather than shipping a table that silently goes stale, this
        reports the release and asks the reader to confirm it is still
        supported — with the exact place to check. A wrong "you are fine" would
        be worse than an honest "verify this".
        """
        try:
            text = Path(self.os_release_path).read_text(errors="replace")
        except OSError:
            return None
        values = {}
        for line in text.splitlines():
            if "=" in line:
                key, _, value = line.partition("=")
                values[key.strip()] = value.strip().strip('"')

        pretty = values.get("PRETTY_NAME") or values.get("NAME") or "this Linux release"
        version = values.get("VERSION_ID", "")
        distro_id = (values.get("ID") or "").lower()

        support_url = {
            "ubuntu": "https://ubuntu.com/about/release-cycle",
            "debian": "https://www.debian.org/releases/",
            "fedora": "https://docs.fedoraproject.org/en-US/releases/",
            "rhel": "https://access.redhat.com/support/policy/updates/errata",
            "opensuse": "https://en.opensuse.org/Lifetime",
        }.get(distro_id, "your distribution's release-cycle page")

        # Rolling releases have no end-of-life to check.
        if distro_id in ("arch", "manjaro", "endeavouros", "gentoo", "nixos"):
            return None

        return Finding(
            title=f"Confirm {pretty} is still receiving security updates",
            description=(
                f"This machine reports {pretty}"
                + (f" (version {version})" if version else "")
                + ".\n\nA release past its end-of-life keeps working and stops getting "
                "security fixes, so it reports zero pending updates while quietly "
                "accumulating unpatched vulnerabilities. That is the single most "
                "dangerous state a Linux machine can be in, precisely because nothing "
                "looks wrong.\n\n"
                f"Check the support dates here: {support_url}"
            ),
            severity=Severity.INFO,
            category=self.category,
            code="integrity.linux_package_updates.release_end_of_life",
            confidence=0.5,
            data={
                "check": "release_end_of_life",
                "distro": distro_id,
                "version": version,
                "pretty_name": pretty,
                "support_url": support_url,
            },
        )

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions: list[Action] = []
        for finding in findings.findings:
            check = finding.data.get("check")
            manager = finding.data.get("manager", "")

            if check in ("security_updates_pending", "updates_pending"):
                command = {
                    "apt": "sudo apt update && sudo apt upgrade",
                    "dnf": "sudo dnf upgrade --refresh",
                    "pacman": "sudo pacman -Syu",
                    "zypper": "sudo zypper refresh && sudo zypper update",
                }.get(manager, "your distribution's update command")
                urgency = (
                    "Do this now — these are published fixes for known holes.\n\n"
                    if check == "security_updates_pending"
                    else "Apply these when convenient.\n\n"
                )
                actions.append(self._guidance(
                    "Install the pending updates",
                    urgency + f"    {command}\n\n"
                    "The tool does not run this for you: installing packages can restart "
                    "services and, occasionally, needs a decision about a config file. "
                    "That is a change you should watch happen.",
                    check,
                ))
            elif check == "reboot_required":
                actions.append(self._guidance(
                    "Restart to finish applying the updates",
                    "Save your work and reboot when you can:\n"
                    "    sudo reboot\n\n"
                    "Until then the old kernel and libraries are still what is running.",
                    check,
                ))
            elif check == "release_end_of_life":
                actions.append(self._guidance(
                    "Verify this release is still supported",
                    f"Check {finding.data.get('support_url')}.\n\n"
                    "If it has reached end-of-life, plan an upgrade to a supported "
                    "release. Back up first — a release upgrade is the kind of change "
                    "that occasionally goes wrong, and a current backup turns that from a "
                    "disaster into an afternoon.",
                    check,
                ))
        return FixResult(module_name=self.name, actions=actions)

    def _guidance(self, title: str, description: str, check: str) -> Action:
        return Action(
            title=title,
            description=description,
            risk_level=RiskLevel.SAFE,
            kind=ActionKind.GUIDANCE,
            data={"check": check},
        )
