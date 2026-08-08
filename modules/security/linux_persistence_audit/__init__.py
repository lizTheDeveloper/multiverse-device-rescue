"""Inventory the places on Linux where something can arrange to run again.

Malware's first job after landing is to survive a reboot. On Linux there is no
single autostart list — there are at least seven, spread across systemd, cron,
desktop autostart, and shell startup files — and an attacker only needs one of
them. This module enumerates all of them and reports what it finds.

The reporting stance is the important part. Almost everything found here is
legitimate: a user systemd unit is how Syncthing starts, `~/.profile` sets
`PATH` on every machine ever. Flagging those as malware would be the
false-positive machine the roadmap warns against. So:

- The inventory itself is INFO. It exists so a person can look at a list and
  notice the entry they do not recognise, which is the actual detection
  mechanism for anything novel.
- Only structural properties escalate: a unit or cron entry that pipes the
  network into a shell, an autostart entry pointing at a file in /tmp, a
  world-writable unit file that any local process can rewrite. Those are
  suspicious regardless of what the software claims to be.

Everything is read-only and bounded: a fixed set of roots, a depth limit, and a
file cap, so a pathological home directory cannot stall a rescue.
"""

import os
import re
import stat
from pathlib import Path

from rescue.command import run
from rescue.fsbounds import WalkLimits, bounded_walk, is_dir_nofollow
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

_TIMEOUT = 15.0

# Content patterns that are suspicious wherever they appear, because they
# describe a *shape* — fetch and execute — rather than a name that can be
# changed.
_SUSPICIOUS_CONTENT = [
    (re.compile(r"(curl|wget)[^\n|]*\|\s*(ba|z|k|d)?sh"), "downloads and pipes a script straight into a shell"),
    (re.compile(r"\bbase64\s+(-d|--decode)\b.*\|\s*(ba|z|k|d)?sh"), "decodes base64 and executes the result"),
    (re.compile(r"\b(python3?|perl|ruby|node)\b[^\n]*-e\s+['\"]"), "runs an inline script from the command line"),
    (re.compile(r"/dev/tcp/\d"), "opens a raw network socket from the shell (reverse-shell pattern)"),
    (re.compile(r"\bnc\b[^\n]*\s-e\b"), "runs netcat with -e (reverse shell)"),
]

# Directories nothing legitimate should be persistently executing out of.
_VOLATILE_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/")


class Module(ModuleBase):
    name = "linux_persistence_audit"
    category = "security"
    platforms = [Platform.LINUX]
    risk_level = RiskLevel.SAFE
    priority = 88
    depends_on = []
    estimated_duration = "20s"

    emits_codes = [
        "security.linux_persistence_audit.suspicious_content",
        "security.linux_persistence_audit.volatile_path_execution",
        "security.linux_persistence_audit.world_writable_unit",
        "security.linux_persistence_audit.ld_preload_set",
        "security.linux_persistence_audit.inventory",
    ]

    # Traversal roots as class attributes so tests point them at a fixture tree
    # rather than at the machine running the suite. Absolute paths are used as
    # given; paths starting with "~" are expanded per user.
    system_unit_dirs: list[str] = [
        "/etc/systemd/system",
        "/usr/local/lib/systemd/system",
    ]
    user_unit_dirs: list[str] = ["~/.config/systemd/user"]
    autostart_dirs: list[str] = ["~/.config/autostart", "/etc/xdg/autostart"]
    cron_dirs: list[str] = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly"]
    shell_rc_files: list[str] = [
        "~/.bashrc",
        "~/.bash_profile",
        "~/.profile",
        "~/.zshrc",
        "~/.config/fish/config.fish",
    ]
    ld_preload_path: str = "/etc/ld.so.preload"

    max_files: int = 2000

    def check(self, profile: SystemProfile) -> CheckResult:
        if profile.platform is not Platform.LINUX:
            return CheckResult(
                module_name=self.name,
                supported=False,
                unsupported_reason=(
                    "This check reads Linux persistence locations (systemd units, cron, "
                    f"XDG autostart, shell rc files); this host reports {profile.platform.value}."
                ),
            )

        entries: list[dict] = []
        entries += self._scan_dirs(self.system_unit_dirs, "systemd system unit", ("*.service", "*.timer"))
        entries += self._scan_dirs(self.user_unit_dirs, "systemd user unit", ("*.service", "*.timer"))
        entries += self._scan_dirs(self.autostart_dirs, "desktop autostart", ("*.desktop",))
        entries += self._scan_dirs(self.cron_dirs, "cron job", ("*",))
        entries += self._scan_files(self.shell_rc_files, "shell startup file")
        entries += self._user_crontab()

        findings: list[Finding] = []
        for entry in entries:
            findings.extend(self._findings_for(entry))

        findings.extend(self._ld_preload_findings())

        findings.append(
            Finding(
                title=f"{len(entries)} startup entries inventoried",
                description=(
                    "Every place something can arrange to run again on this machine, "
                    "listed so you can look for the one you do not recognise. Most "
                    "entries here are ordinary software.\n\n"
                    + self._inventory_text(entries)
                ),
                severity=Severity.INFO,
                category=self.category,
                code="security.linux_persistence_audit.inventory",
                confidence=1.0,
                data={
                    "check": "inventory",
                    "count": len(entries),
                    "entries": [
                        {"path": e["path"], "kind": e["kind"]} for e in entries
                    ],
                },
            )
        )

        return CheckResult(module_name=self.name, findings=findings)

    def _scan_dirs(self, roots: list[str], kind: str, patterns: tuple[str, ...]) -> list[dict]:
        entries: list[dict] = []
        expanded = [Path(os.path.expanduser(root)) for root in roots]
        existing = [p for p in expanded if is_dir_nofollow(p)]
        if not existing:
            return entries
        limits = WalkLimits(max_depth=2, max_files=self.max_files, deadline_s=10.0)
        for path in bounded_walk(existing, limits=limits):
            if patterns != ("*",) and not any(path.match(p) for p in patterns):
                continue
            entries.append(self._describe(path, kind))
        return entries

    def _scan_files(self, paths: list[str], kind: str) -> list[dict]:
        entries = []
        for raw in paths:
            path = Path(os.path.expanduser(raw))
            try:
                if path.is_file():
                    entries.append(self._describe(path, kind))
            except OSError:
                continue
        return entries

    def _user_crontab(self) -> list[dict]:
        """The invoking user's crontab, which lives in a spool file no user can read."""
        result = run(["crontab", "-l"], timeout=_TIMEOUT)
        if result.error is not None or result.returncode != 0 or not result.stdout.strip():
            return []
        lines = [
            line for line in result.stdout.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        if not lines:
            return []
        return [{
            "path": "crontab -l (current user)",
            "kind": "user crontab",
            "content": "\n".join(lines),
            "mode": None,
        }]

    def _describe(self, path: Path, kind: str) -> dict:
        content = ""
        mode = None
        try:
            # Persistence files are small; a huge one is itself odd, and reading
            # a bounded prefix is enough to spot an execution pattern.
            content = path.read_text(errors="replace")[:64_000]
        except OSError:
            pass
        try:
            mode = stat.S_IMODE(path.lstat().st_mode)
        except OSError:
            pass
        return {"path": str(path), "kind": kind, "content": content, "mode": mode}

    def _findings_for(self, entry: dict) -> list[Finding]:
        findings: list[Finding] = []
        content = entry.get("content") or ""
        path = entry["path"]

        for pattern, explanation in _SUSPICIOUS_CONTENT:
            match = pattern.search(content)
            if match is None:
                continue
            findings.append(
                Finding(
                    title=f"A startup entry {explanation}",
                    description=(
                        f"{entry['kind']}: {path}\n\n"
                        f"Matched: {match.group(0)[:200]}\n\n"
                        "Running code fetched from the network at every login or boot is "
                        "how a compromise stays alive across reboots. Some developer "
                        "tooling does install itself this way, so check whether you "
                        "recognise it before acting — but do check."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    code="security.linux_persistence_audit.suspicious_content",
                    confidence=0.6,
                    data={
                        "check": "suspicious_content",
                        "path": path,
                        "kind": entry["kind"],
                        "pattern": explanation,
                        "excerpt": match.group(0)[:200],
                    },
                )
            )
            break  # one finding per file is enough to get it looked at

        for line in content.splitlines():
            if any(prefix in line for prefix in _VOLATILE_PREFIXES) and (
                "Exec" in line or line.strip().startswith("/") or "sh " in line
            ):
                findings.append(
                    Finding(
                        title="A startup entry runs a program from a temporary directory",
                        description=(
                            f"{entry['kind']}: {path}\n\n"
                            f"Line: {line.strip()[:200]}\n\n"
                            "/tmp, /var/tmp, and /dev/shm are cleared on reboot and are "
                            "writable by every local account. Software that expects to "
                            "persist does not install itself there; malware does, because "
                            "it can write there without privileges."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        code="security.linux_persistence_audit.volatile_path_execution",
                        confidence=0.65,
                        data={
                            "check": "volatile_path_execution",
                            "path": path,
                            "kind": entry["kind"],
                            "line": line.strip()[:200],
                        },
                    )
                )
                break

        mode = entry.get("mode")
        if mode is not None and mode & stat.S_IWOTH:
            findings.append(
                Finding(
                    title="A startup file is writable by any local account",
                    description=(
                        f"{entry['kind']}: {path} (mode {oct(mode)})\n\n"
                        "Anything running on this machine — including software you ran "
                        "once and forgot — can rewrite this file and have its own code run "
                        "at the next boot or login. This is a privilege-escalation path "
                        "whether or not anything has used it yet."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.linux_persistence_audit.world_writable_unit",
                    confidence=0.9,
                    data={
                        "check": "world_writable_unit",
                        "path": path,
                        "kind": entry["kind"],
                        "mode": oct(mode),
                    },
                )
            )

        return findings

    def _ld_preload_findings(self) -> list[Finding]:
        """/etc/ld.so.preload injects a library into every dynamically linked process.

        It is empty or absent on a normal system. When it is not, whatever it
        names is running inside every program on the machine, which is why
        userland rootkits reach for it first.
        """
        path = Path(self.ld_preload_path)
        try:
            if not path.is_file():
                return []
            content = path.read_text(errors="replace").strip()
        except OSError:
            return []
        if not content:
            return []
        return [
            Finding(
                title="A library is being preloaded into every process on this system",
                description=(
                    f"{self.ld_preload_path} lists:\n{content[:500]}\n\n"
                    "This file forces a library into every dynamically linked program that "
                    "starts. Legitimate uses exist (some sandboxes and compatibility "
                    "shims), but it is also the classic userland rootkit mechanism, used "
                    "to hide files and processes from the tools you would check with. If "
                    "you did not put this here, treat this machine as compromised and stop "
                    "using it for anything sensitive until it is investigated."
                ),
                severity=Severity.CRITICAL,
                category=self.category,
                code="security.linux_persistence_audit.ld_preload_set",
                confidence=0.7,
                data={"check": "ld_preload_set", "path": self.ld_preload_path, "content": content[:500]},
            )
        ]

    @staticmethod
    def _inventory_text(entries: list[dict]) -> str:
        by_kind: dict[str, list[str]] = {}
        for entry in entries:
            by_kind.setdefault(entry["kind"], []).append(entry["path"])
        lines = []
        for kind in sorted(by_kind):
            paths = sorted(by_kind[kind])
            lines.append(f"{kind} ({len(paths)}):")
            for path in paths[:25]:
                lines.append(f"  {path}")
            if len(paths) > 25:
                lines.append(f"  ... and {len(paths) - 25} more")
        return "\n".join(lines)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions: list[Action] = []
        for finding in findings.findings:
            check = finding.data.get("check")
            path = finding.data.get("path", "")

            if check == "suspicious_content":
                actions.append(self._guidance(
                    f"Work out what {path} is before removing it",
                    "  1. Read the whole file:\n"
                    f"         cat '{path}'\n"
                    "  2. Find out when it appeared:\n"
                    f"         stat '{path}'\n"
                    "  3. If it is a systemd unit, see what it is doing:\n"
                    "         systemctl status <unit>\n"
                    "         journalctl -u <unit> --since '7 days ago'\n"
                    "  4. If you recognise the software, leave it. If you do not, disable "
                    "it rather than deleting it — a deleted file cannot be examined:\n"
                    "         sudo systemctl disable --now <unit>\n\n"
                    "If this machine holds anything that matters, capture evidence before "
                    "cleanup: `rescue run evidence_bundle --yes`.",
                    check, path,
                ))
            elif check == "volatile_path_execution":
                actions.append(self._guidance(
                    f"Check what {path} runs out of a temporary directory",
                    f"    cat '{path}'\n\n"
                    "Then look at the target it points into /tmp or /dev/shm. If the "
                    "target does not exist, this entry is broken leftovers and can be "
                    "removed. If it does exist, find out what wrote it before deleting "
                    "either one.",
                    check, path,
                ))
            elif check == "world_writable_unit":
                actions.append(self._guidance(
                    f"Remove world-write permission from {path}",
                    f"    sudo chmod o-w '{path}'\n"
                    f"    ls -l '{path}'\n\n"
                    "Startup files should be writable only by root (or by you, for files "
                    "under your own home directory).",
                    check, path,
                ))
            elif check == "ld_preload_set":
                actions.append(self._guidance(
                    "Investigate the preloaded library before changing anything",
                    "Do not simply delete the file. First record what it names:\n"
                    f"    cat {self.ld_preload_path}\n"
                    "    ls -l <each library listed>\n"
                    "    dpkg -S <library>   # or: rpm -qf <library>\n\n"
                    "If no package owns the library and you did not install it, this "
                    "machine should be treated as compromised: the tools you would "
                    "normally investigate with may themselves be lying to you. Work from "
                    "a live USB or a known-clean machine, and run the digital_security_reset "
                    "profile for the account-recovery order.",
                    check, self.ld_preload_path,
                ))
        return FixResult(module_name=self.name, actions=actions)

    def _guidance(self, title: str, description: str, check: str, path: str) -> Action:
        return Action(
            title=title,
            description=description,
            risk_level=RiskLevel.SAFE,
            kind=ActionKind.GUIDANCE,
            data={"check": check, "path": path},
        )
