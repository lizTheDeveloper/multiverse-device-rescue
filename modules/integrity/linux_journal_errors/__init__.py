"""Read the system journal for the errors that predict hardware failure.

The journal is where a Linux machine writes down what went wrong, and almost
nobody reads it. That matters most for the small number of messages that are
early warnings rather than noise:

- **Storage I/O errors and SMART warnings.** A drive that has started throwing
  read errors is often weeks from failing outright, and those weeks are the
  entire window in which a backup can still be taken.
- **Memory errors (EDAC/MCE).** Bad RAM corrupts data silently — files written
  during the corruption are wrong on disk, and no filesystem check will find
  it, because the data was already wrong when it arrived.
- **Filesystem errors and read-only remounts.** ext4 remounts read-only when it
  detects corruption. The machine keeps running and silently stops saving.
- **Out-of-memory kills.** The kernel picking processes to kill explains
  "things randomly close" better than any other single signal.
- **Repeated segfaults** in one program, which distinguishes "that app is
  broken" from "this machine is broken".

Everything else in the journal is left alone. A tool that reported every
priority-3 message would produce hundreds of findings on a healthy desktop and
teach the reader to ignore all of them.
"""

import re
from collections import Counter
from dataclasses import dataclass

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

_TIMEOUT = 30.0

@dataclass(frozen=True)
class _Signal:
    """One class of journal message worth reporting.

    The finding code is spelled out here as a literal rather than derived from
    ``key``. Building it with an f-string would make it invisible to the
    emits_codes consistency gate, which exists so every code a module can emit
    is statically discoverable — that is what powers the remediation catalog.
    """

    key: str
    pattern: re.Pattern[str]
    severity: Severity
    label: str
    code: str


# Ordered: the first pattern that matches a line classifies it, so the more
# specific hardware signals come before the generic ones.
_SIGNALS: list[_Signal] = [
    _Signal(
        key="storage_io_error",
        pattern=re.compile(
            r"(?i)\b(i/o error|blk_update_request|medium error|unrecovered read error|"
            r"failed command: (read|write) fpdma|ata\d+\.\d+: exception emask)\b"
        ),
        severity=Severity.CRITICAL,
        label="storage read/write errors",
        code="integrity.linux_journal_errors.storage_io_error",
    ),
    _Signal(
        key="smart_failure",
        pattern=re.compile(
            r"(?i)\b(smart error|failure prediction|reallocated_sector|pending sector)\b"
        ),
        severity=Severity.CRITICAL,
        label="drive self-monitoring warnings",
        code="integrity.linux_journal_errors.smart_failure",
    ),
    _Signal(
        key="memory_error",
        pattern=re.compile(r"(?i)\b(edac|machine check|mce:|hardware error|corrected error)\b"),
        severity=Severity.CRITICAL,
        label="memory or CPU hardware errors",
        code="integrity.linux_journal_errors.memory_error",
    ),
    _Signal(
        key="filesystem_error",
        pattern=re.compile(
            r"(?i)(ext4-fs error|xfs .*(corruption|internal error)|btrfs.*(checksum|csum) "
            r"(error|failed)|remounting filesystem read-only|journal has aborted)"
        ),
        severity=Severity.CRITICAL,
        label="filesystem corruption",
        code="integrity.linux_journal_errors.filesystem_error",
    ),
    _Signal(
        key="oom_kill",
        pattern=re.compile(r"(?i)(out of memory: kill|oom-kill|killed process \d+)"),
        severity=Severity.WARNING,
        label="out-of-memory kills",
        code="integrity.linux_journal_errors.oom_kill",
    ),
    _Signal(
        key="segfault",
        pattern=re.compile(r"(?i)\b(segfault at|general protection fault|traps:)\b"),
        severity=Severity.WARNING,
        label="program crashes",
        code="integrity.linux_journal_errors.segfault",
    ),
]

# A single segfault is an application bug; a pile of them in one week is a
# pattern worth reporting.
_SEGFAULT_MIN = 3


class Module(ModuleBase):
    name = "linux_journal_errors"
    category = "integrity"
    platforms = [Platform.LINUX]
    risk_level = RiskLevel.SAFE
    priority = 83
    depends_on = []
    estimated_duration = "30s"

    emits_codes = [
        "integrity.linux_journal_errors.storage_io_error",
        "integrity.linux_journal_errors.smart_failure",
        "integrity.linux_journal_errors.memory_error",
        "integrity.linux_journal_errors.filesystem_error",
        "integrity.linux_journal_errors.oom_kill",
        "integrity.linux_journal_errors.segfault",
    ]

    # How far back to read, and how many lines to accept. The journal on a
    # long-running machine is large; both bounds keep this from becoming the
    # slowest check in a scan.
    since: str = "7 days ago"
    max_lines: int = 5000

    def check(self, profile: SystemProfile) -> CheckResult:
        if profile.platform is not Platform.LINUX:
            return CheckResult(
                module_name=self.name,
                supported=False,
                unsupported_reason=(
                    "This check reads the systemd journal; this host reports "
                    f"{profile.platform.value}."
                ),
            )

        result = run(
            [
                "journalctl",
                "--priority=0..4",
                f"--since={self.since}",
                f"--lines={self.max_lines}",
                "--no-pager",
                "--quiet",
            ],
            timeout=_TIMEOUT,
        )
        if result.error is not None:
            return CheckResult(
                module_name=self.name,
                supported=False,
                unsupported_reason=(
                    "journalctl is not available, so this system does not use the systemd "
                    "journal. Errors would be in /var/log instead."
                ),
            )
        if result.returncode != 0 and not result.stdout.strip():
            # Non-root callers on some distributions cannot read the system
            # journal at all. That is "not checked", not "nothing found".
            return CheckResult(
                module_name=self.name,
                supported=False,
                unsupported_reason=(
                    "The system journal could not be read by this account. Re-run with "
                    "sudo, or add your user to the 'systemd-journal' group, to include "
                    "system-wide errors."
                ),
            )

        matches: dict[str, list[str]] = {}
        for line in result.stdout.splitlines():
            for signal in _SIGNALS:
                if signal.pattern.search(line):
                    matches.setdefault(signal.key, []).append(line.strip()[:300])
                    break

        findings: list[Finding] = []
        for signal in _SIGNALS:
            lines = matches.get(signal.key, [])
            if not lines:
                continue
            if signal.key == "segfault" and len(lines) < _SEGFAULT_MIN:
                continue
            findings.append(self._finding(signal, lines))
        return CheckResult(module_name=self.name, findings=findings)

    def _finding(self, signal: _Signal, lines: list[str]) -> Finding:
        explanation = {
            "storage_io_error": (
                "The kernel could not read from or write to a drive. Drives that have "
                "started doing this usually keep working for a while and then do not. "
                "The useful response is to back up now, while it still reads."
            ),
            "smart_failure": (
                "The drive's own self-monitoring is reporting degradation. This is the "
                "earliest warning available and it is worth acting on immediately."
            ),
            "memory_error": (
                "The hardware reported a memory or CPU error. Even 'corrected' errors "
                "indicate failing RAM, and uncorrected ones silently corrupt whatever "
                "was in memory at the time — including files being written."
            ),
            "filesystem_error": (
                "The filesystem detected corruption. If it remounted read-only, the "
                "machine is still running but is no longer saving anything, which is "
                "usually discovered hours later when work disappears."
            ),
            "oom_kill": (
                "The kernel ran out of memory and killed running programs to recover. "
                "This is what 'applications close by themselves' looks like from the "
                "system's side."
            ),
            "segfault": (
                "Programs crashed repeatedly. If they are all the same program, that "
                "program is broken; if they are different programs, suspect memory."
            ),
        }[signal.key]

        counts = Counter(self._normalise(line) for line in lines)
        top = counts.most_common(5)
        sample = "\n".join(f"  [{count}x] {text}" for text, count in top)

        return Finding(
            title=f"{len(lines)} journal entries indicating {signal.label}",
            description=(
                f"{explanation}\n\nIn the last {self.since}:\n{sample}"
            ),
            severity=signal.severity,
            category=self.category,
            code=signal.code,
            confidence=0.8,
            data={
                "check": signal.key,
                "count": len(lines),
                "since": self.since,
                "samples": [text for text, _ in top],
            },
        )

    @staticmethod
    def _normalise(line: str) -> str:
        """Strip the timestamp and hostname so repeats of one error group together."""
        parts = line.split(":", 3)
        text = parts[-1].strip() if len(parts) > 1 else line
        # Numbers vary between otherwise identical messages (sector, pid, addr).
        return re.sub(r"\b(0x)?[0-9a-f]{4,}\b|\b\d+\b", "N", text)[:200]

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions: list[Action] = []
        for finding in findings.findings:
            check = finding.data.get("check")

            if check in ("storage_io_error", "smart_failure"):
                actions.append(self._guidance(
                    "Back up now, then check the drive",
                    "Order matters here. Copy your data off first — running diagnostics "
                    "on a failing drive can be the thing that finishes it off.\n\n"
                    "  1. Back up anything irreplaceable to another device.\n"
                    "  2. Then look at the drive's own health record:\n"
                    "         sudo smartctl -a /dev/sda      # install smartmontools if needed\n"
                    "     Look at Reallocated_Sector_Ct, Current_Pending_Sector, and\n"
                    "     Offline_Uncorrectable. Any of them climbing means replace it.\n"
                    "  3. Check which filesystem is affected:\n"
                    "         dmesg -T | grep -i 'i/o error'\n\n"
                    "A drive reporting errors is not repairable in software. Plan a "
                    "replacement rather than a fix.",
                    check,
                ))
            elif check == "memory_error":
                actions.append(self._guidance(
                    "Test the memory before trusting this machine with data",
                    "  1. Reboot and run memtest86+ (most distributions offer it in the "
                    "boot menu; otherwise install it). Let it complete at least one full "
                    "pass — errors often appear only after the first few minutes.\n"
                    "  2. If it reports errors and you have more than one module, test "
                    "them one at a time to find the bad one.\n"
                    "  3. Until it is clean, avoid work you cannot afford to have silently "
                    "corrupted — bad RAM writes wrong data to disk without any error.",
                    check,
                ))
            elif check == "filesystem_error":
                actions.append(self._guidance(
                    "Check the filesystem from outside itself",
                    "A filesystem cannot be repaired safely while it is mounted.\n\n"
                    "  1. Confirm whether it went read-only:\n"
                    "         mount | grep ' / '\n"
                    "  2. Back up anything not yet backed up. Do this first.\n"
                    "  3. Boot from a live USB and check the unmounted filesystem:\n"
                    "         sudo fsck -f /dev/sdaX        # ext4\n"
                    "         sudo xfs_repair /dev/sdaX     # xfs\n"
                    "         sudo btrfs check /dev/sdaX    # btrfs (read-only by default)\n"
                    "  4. Repeated corruption on a healthy drive usually means failing "
                    "hardware, not a filesystem bug — check the drive too.",
                    check,
                ))
            elif check == "oom_kill":
                actions.append(self._guidance(
                    "Find what is exhausting memory",
                    "    journalctl -k --since '7 days ago' | grep -i 'killed process'\n"
                    "    systemd-cgtop -m\n\n"
                    "That names both the process the kernel killed and, usually, the one "
                    "that consumed the memory. Options: use less at once, add swap "
                    "(`sudo systemctl status systemd-zram-setup@zram0` on many distros), "
                    "or add RAM. `rescue run linux_memory_pressure --yes` gives the "
                    "current picture.",
                    check,
                ))
            elif check == "segfault":
                actions.append(self._guidance(
                    "Work out whether one program is broken or the machine is",
                    "    journalctl --since '7 days ago' | grep -i segfault\n\n"
                    "All the same program: reinstall or update it, and report the crash "
                    "upstream.\n"
                    "Many different programs: that pattern points at memory or an "
                    "overheating CPU rather than at software. Test memory, and check "
                    "temperatures under load.",
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
