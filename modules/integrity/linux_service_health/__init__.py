"""What has systemd given up on, and what keeps dying and restarting?

`systemctl --failed` is the first command an experienced Linux user runs on a
misbehaving machine, and it is the last thing a non-expert ever discovers. A
failed unit is why the printer does not appear, why backups silently stopped
three weeks ago, why the machine takes ninety seconds to boot.

Beyond the failed list, this looks for the noisier pathology: units caught in a
restart loop. systemd will restart a crashing service forever, which turns a
crash into a permanent CPU and log-volume drain that shows up as "the fan is
always on" rather than as an error anyone sees.

Backup and time-synchronisation units are called out specifically. A failed
backup timer is the finding whose consequences arrive months later, and a
machine whose clock has drifted fails TLS in ways that look like a network
problem.
"""

import re
from shlex import quote

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

_TIMEOUT = 20.0

# A unit restarting more often than this is not recovering, it is looping.
_RESTART_LOOP_THRESHOLD = 5

_BACKUP_HINTS = ("backup", "borg", "restic", "duplicity", "timeshift", "snapper", "rsnapshot")
_TIME_HINTS = ("systemd-timesyncd", "chronyd", "ntpd", "ntpsec")

_NRESTARTS = re.compile(r"^NRestarts=(\d+)$", re.M)


class Module(ModuleBase):
    name = "linux_service_health"
    category = "integrity"
    platforms = [Platform.LINUX]
    risk_level = RiskLevel.SAFE
    priority = 78
    depends_on = []
    estimated_duration = "20s"

    emits_codes = [
        "integrity.linux_service_health.failed_unit",
        "integrity.linux_service_health.failed_backup_unit",
        "integrity.linux_service_health.restart_loop",
        "integrity.linux_service_health.time_sync_inactive",
    ]
    # A system without systemd is reported through CheckResult.supported rather
    # than as a finding, so it has no code: "this check does not apply here" is
    # not something a remediation walkthrough can act on.

    # Cap how many failed units get an individual `systemctl show` call: on a
    # badly broken machine there can be dozens, and each one costs a subprocess.
    max_detailed_units: int = 15

    def check(self, profile: SystemProfile) -> CheckResult:
        if profile.platform is not Platform.LINUX:
            return CheckResult(
                module_name=self.name,
                supported=False,
                unsupported_reason=(
                    "This check reads systemd unit state; this host reports "
                    f"{profile.platform.value}."
                ),
            )

        listing = run(
            ["systemctl", "list-units", "--failed", "--no-legend", "--plain", "--no-pager"],
            timeout=_TIMEOUT,
        )
        if listing.error is not None:
            return CheckResult(
                module_name=self.name,
                supported=False,
                unsupported_reason=(
                    "systemctl is not available, so this system is not running systemd. "
                    "Service health would need to be checked through its own init system "
                    "(OpenRC, runit, s6)."
                ),
            )

        failed = [
            line.split()[0]
            for line in listing.stdout.splitlines()
            if line.strip() and not line.startswith("●")
        ]
        failed = [name for name in failed if name.endswith((".service", ".timer", ".mount", ".socket"))]

        findings: list[Finding] = []
        for unit in failed:
            how_to_look = (
                f"See why:\n    systemctl status {quote(unit)}\n"
                f"    journalctl -u {quote(unit)} -n 50 --no-pager"
            )
            # Two constructions rather than one with conditional arguments: the
            # code literal has to be visible at the call site, which is what
            # lets the remediation catalog know statically which codes this
            # module can emit.
            if any(hint in unit.lower() for hint in _BACKUP_HINTS):
                findings.append(
                    Finding(
                        title=f"Backup service '{unit}' has stopped working",
                        description=(
                            f"The service '{unit}' is responsible for backups, but it "
                            "has failed and stopped running. This means your backups "
                            "may not be happening. You might not notice until you need "
                            "to restore a file.\n\n"
                            "What to do: Find out why it failed, fix the problem, then "
                            "start it again and confirm a new backup appears.\n\n"
                            + how_to_look
                        ),
                        severity=Severity.CRITICAL,
                        category=self.category,
                        code="integrity.linux_service_health.failed_backup_unit",
                        confidence=1.0,
                        data={"check": "failed_backup_unit", "unit": unit},
                    )
                )
            else:
                findings.append(
                    Finding(
                        title=f"Service '{unit}' has stopped working",
                        description=(
                            f"The service '{unit}' failed to start or crashed, and the "
                            "system has stopped trying to run it. Whatever feature this "
                            "service provides is currently not working.\n\n"
                            "What to do: Read the error logs to see why it failed, fix "
                            "the issue, then restart it.\n\n"
                            + how_to_look
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        code="integrity.linux_service_health.failed_unit",
                        confidence=1.0,
                        data={"check": "failed_unit", "unit": unit},
                    )
                )

        findings.extend(self._restart_loop_findings(failed))
        time_finding = self._time_sync_finding()
        if time_finding is not None:
            findings.append(time_finding)

        return CheckResult(module_name=self.name, findings=findings)

    def _restart_loop_findings(self, already_failed: list[str]) -> list[Finding]:
        listing = run(
            ["systemctl", "list-units", "--type=service", "--state=running",
             "--no-legend", "--plain", "--no-pager"],
            timeout=_TIMEOUT,
        )
        if listing.error is not None:
            return []

        units = [
            line.split()[0]
            for line in listing.stdout.splitlines()
            if line.strip() and line.split()[0].endswith(".service")
        ]
        findings = []
        for unit in units[: self.max_detailed_units]:
            if unit in already_failed:
                continue
            shown = run(["systemctl", "show", unit, "--property=NRestarts"], timeout=_TIMEOUT)
            if shown.error is not None:
                continue
            match = _NRESTARTS.search(shown.stdout.strip())
            if match is None:
                continue
            restarts = int(match.group(1))
            if restarts < _RESTART_LOOP_THRESHOLD:
                continue
            findings.append(
                Finding(
                    title=f"Service '{unit}' keeps crashing and restarting",
                    description=(
                        f"The service '{unit}' has crashed and restarted {restarts} times. "
                        "It appears to be running, but it is actually stuck in a loop "
                        "of failing and restarting. This wastes computer power and hides "
                        "the real error.\n\n"
                        "What to do: Check the logs to see why it is failing, fix the "
                        "issue, then restart the service.\n\n"
                        f"    journalctl -u {quote(unit)} --since '1 hour ago' --no-pager"
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="integrity.linux_service_health.restart_loop",
                    confidence=0.8,
                    data={"check": "restart_loop", "unit": unit, "restarts": restarts},
                )
            )
        return findings

    def _time_sync_finding(self) -> Finding | None:
        for unit in _TIME_HINTS:
            result = run(["systemctl", "is-active", f"{unit}.service"], timeout=_TIMEOUT)
            if result.error is None and result.stdout.strip() == "active":
                return None
        # Nothing answered "active". That is only meaningful if systemctl worked
        # at all, which the caller has already established.
        return Finding(
            title="Your computer's clock is not syncing automatically",
            description=(
                "Your computer is not automatically keeping its clock accurate. If the "
                "time is wrong, secure websites (HTTPS) and two-factor login codes may "
                "stop working. This often looks like a network error, but it is just a "
                "time issue.\n\n"
                "What to do: Turn on automatic time in your desktop's Date & Time "
                "settings, or run: sudo timedatectl set-ntp true\n\n"
                "Checked for: " + ", ".join(_TIME_HINTS)
            ),
            severity=Severity.WARNING,
            category=self.category,
            code="integrity.linux_service_health.time_sync_inactive",
            confidence=0.7,
            data={"check": "time_sync_inactive"},
        )

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions: list[Action] = []
        for finding in findings.findings:
            check = finding.data.get("check")
            unit = finding.data.get("unit", "")

            if check in ("failed_unit", "failed_backup_unit"):
                actions.append(self._guidance(
                    f"Find out why {unit} failed",
                    f"  1. Read the failure:\n"
                    f"         systemctl status {quote(str(unit))}\n"
                    f"         journalctl -u {quote(str(unit))} -n 100 --no-pager\n"
                    "  2. Try it once by hand and watch what happens:\n"
                    f"         sudo systemctl restart {quote(str(unit))}\n"
                    "  3. If it fails again, the journal from step 1 now has the current "
                    "error rather than a stale one.\n\n"
                    + (
                        "Because this is a backup unit, also verify that a restore "
                        "actually works once it is running again — a backup you have "
                        "never restored from is a hypothesis, not a backup."
                        if check == "failed_backup_unit"
                        else "If you do not recognise the unit and nothing depends on it, "
                        f"disabling it is reasonable: sudo systemctl disable --now {quote(str(unit))}"
                    ),
                    check, unit,
                ))
            elif check == "restart_loop":
                actions.append(self._guidance(
                    f"Break the restart loop for {unit}",
                    f"  1. Find the first failure rather than the latest:\n"
                    f"         journalctl -u {quote(str(unit))} --no-pager | head -50\n"
                    "  2. Stop the loop while you work:\n"
                    f"         sudo systemctl stop {quote(str(unit))}\n"
                    "  3. Fix the cause, then start it again and re-check the count:\n"
                    f"         systemctl show {quote(str(unit))} --property=NRestarts",
                    check, unit,
                ))
            elif check == "time_sync_inactive":
                actions.append(self._guidance(
                    "Turn on time synchronisation",
                    "On most systemd distributions:\n"
                    "    sudo systemctl enable --now systemd-timesyncd\n"
                    "    timedatectl status\n\n"
                    "On Fedora/RHEL, chrony is the default instead:\n"
                    "    sudo systemctl enable --now chronyd\n"
                    "    chronyc tracking",
                    check, unit,
                ))
        return FixResult(module_name=self.name, actions=actions)

    def _guidance(self, title: str, description: str, check: str, unit: str) -> Action:
        return Action(
            title=title,
            description=description,
            risk_level=RiskLevel.SAFE,
            kind=ActionKind.GUIDANCE,
            data={"check": check, "unit": unit},
        )
