"""Detect cryptojacking that has been made to survive a reboot.

``crypto_miner_detect`` looks at what is running right now. That is only half
the problem: killing a miner process achieves nothing if a LaunchAgent, cron
entry, systemd unit, Run key, or scheduled task starts it again a minute
later. This module looks for the persistence mechanism and the miner's own
configuration (pool address, wallet address), which together are what a
victim actually has to remove.

All checks are read-only and bounded — a fixed list of persistence locations,
one level of globbing, and a cap on the number of files read — so this is safe
to run on a machine that is already struggling under a miner's CPU load.
"""

import re
import subprocess
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
from rescue.runtime import content_directory, load_content_module

_IOC_DIR = content_directory("modules/security/cryptojacking_iocs")
_IOC_LOADER_KEY = "rescue_cryptojacking_iocs_loader"

# Command timeout for every external command this module runs. A compromised
# machine is often heavily loaded, so this is generous but always bounded.
_COMMAND_TIMEOUT = 15

# Caps on read-only filesystem work, so a check can never turn into an
# unbounded traversal of the user's home directory.
_MAX_FILES_PER_LOCATION = 200
_MAX_READ_BYTES = 64 * 1024

# Monero addresses are 95 base58 characters starting with 4 or 8; a wallet
# address sitting in a startup command or config file is about as close to
# proof of mining as a local check can get.
_MONERO_ADDRESS = re.compile(r"\b[48][1-9A-HJ-NP-Za-km-z]{94}\b")

# Miner command-line flags. XMRig and its forks share this vocabulary, so
# these catch renamed binaries that a name-only check would miss.
_MINER_ARGUMENTS = [
    re.compile(r"stratum\+(tcp|ssl)://", re.IGNORECASE),
    re.compile(r"--donate-level", re.IGNORECASE),
    re.compile(r"--cpu-max-threads-hint", re.IGNORECASE),
    re.compile(r"--randomx", re.IGNORECASE),
    re.compile(r"\s-o\s+\S+:(3333|4444|5555|7777|8888|9999|14433|14444|45700)\b"),
]

_DARWIN_PERSISTENCE_DIRS = [
    "~/Library/LaunchAgents",
    "/Library/LaunchAgents",
    "/Library/LaunchDaemons",
]

_LINUX_PERSISTENCE_DIRS = [
    "~/.config/systemd/user",
    "/etc/systemd/system",
    "/etc/systemd/user",
    "/etc/cron.d",
    "/etc/cron.hourly",
    "/etc/cron.daily",
]

_LINUX_PERSISTENCE_FILES = [
    "/etc/crontab",
    "/etc/rc.local",
]

_SHELL_PROFILES = [
    "~/.bashrc",
    "~/.bash_profile",
    "~/.profile",
    "~/.zshrc",
    "~/.zprofile",
]

# Directories a dropped miner and its config realistically live in. Deliberately
# short: each is globbed one level deep only.
_DARWIN_DROP_DIRS = [
    "~/Library/Application Support",
    "~/.config",
    "/tmp",
    "/var/tmp",
    "/usr/local/bin",
]

_LINUX_DROP_DIRS = [
    "~/.config",
    "/tmp",
    "/var/tmp",
    "/dev/shm",
    "/usr/local/bin",
    "/opt",
]

_WIN_RUN_KEYS = [
    (r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
    (r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce"),
    (r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"),
    (r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce"),
]


def _load_iocs():
    """Load the shared cryptojacking IOC database, or None if unavailable."""
    loader = load_content_module(
        "modules/security/cryptojacking_iocs/loader.py", _IOC_LOADER_KEY
    )
    if loader is None:
        return None
    try:
        return loader.load_cryptojacking_iocs(_IOC_DIR)
    except Exception:
        return None


_IOCS = _load_iocs()


class Module(ModuleBase):
    name = "crypto_miner_persistence"
    category = "security"
    platforms = [Platform.DARWIN, Platform.WIN32, Platform.LINUX]
    risk_level = RiskLevel.SAFE
    priority = 78
    depends_on = []
    estimated_duration = "15s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings: list[Finding] = []

        if profile.platform == Platform.DARWIN:
            findings.extend(self._check_plists())
            findings.extend(self._check_cron())
            findings.extend(self._check_shell_profiles())
            findings.extend(self._check_dropped_configs(_DARWIN_DROP_DIRS))
        elif profile.platform == Platform.LINUX:
            findings.extend(self._check_unit_and_cron_files())
            findings.extend(self._check_cron())
            findings.extend(self._check_shell_profiles())
            findings.extend(self._check_dropped_configs(_LINUX_DROP_DIRS))
        elif profile.platform == Platform.WIN32:
            findings.extend(self._check_windows_run_keys())
            findings.extend(self._check_windows_scheduled_tasks())

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        """Guidance only — this module never removes persistence itself.

        Deleting the startup entry without also removing the payload (or vice
        versa) leaves a half-cleaned machine, and on a device the owner may
        want examined later, deletion destroys the evidence. Every action is
        therefore a manual step.
        """
        actions: list[Action] = []
        if not findings.findings:
            return FixResult(module_name=self.name, actions=actions)

        for finding in findings.findings:
            location = finding.data.get("location", "unknown location")
            actions.append(
                Action(
                    title=f"Remove the mining startup entry at {location}",
                    description=(
                        f"{finding.title}\n\n"
                        "Remove it in this order, or the miner comes straight back:\n"
                        "1. Write down (or screenshot) the full entry first — the pool "
                        "and wallet address are the evidence of who was mining.\n"
                        "2. Disable the startup entry, then reboot.\n"
                        "3. Delete the miner binary and its config file.\n"
                        "4. Re-run this check to confirm nothing recreated it.\n\n"
                        "If the entry reappears after a reboot, something else on the "
                        "machine is still running with enough privilege to recreate it. "
                        "Stop cleaning up and treat the machine as fully compromised."
                    ),
                    risk_level=RiskLevel.MODERATE,
                    kind=ActionKind.GUIDANCE,
                    success=True,
                    data={"location": location},
                )
            )

        actions.append(
            Action(
                title="Find out how the miner got installed",
                description=(
                    "Cryptojacking is almost never the first thing that happens to a "
                    "machine — it is what an attacker does with access they already "
                    "have. Before declaring this fixed, check how they got in: a "
                    "pirated or cracked installer, a malicious browser extension, an "
                    "exposed remote-access service, or a shared/compromised password. "
                    "Run the stalkerware, remote-access, and router checks in this "
                    "toolkit as well."
                ),
                risk_level=RiskLevel.SAFE,
                kind=ActionKind.GUIDANCE,
                success=True,
            )
        )
        return FixResult(module_name=self.name, actions=actions)

    # ---------------- macOS / Linux ----------------

    def _check_plists(self) -> list[Finding]:
        findings: list[Finding] = []
        for directory in _DARWIN_PERSISTENCE_DIRS:
            for path in _bounded_files(directory, "*.plist"):
                content = _read_text(path)
                if not content:
                    continue
                hit = self._classify(content)
                if hit is None:
                    continue
                findings.append(
                    self._make_finding(
                        check="miner_launch_item",
                        location=str(path),
                        mechanism="launchd job",
                        hit=hit,
                    )
                )
        return findings

    def _check_unit_and_cron_files(self) -> list[Finding]:
        findings: list[Finding] = []
        for directory in _LINUX_PERSISTENCE_DIRS:
            for path in _bounded_files(directory, "*"):
                content = _read_text(path)
                if not content:
                    continue
                hit = self._classify(content)
                if hit is None:
                    continue
                mechanism = "systemd unit" if path.suffix in {".service", ".timer"} else "cron entry"
                findings.append(
                    self._make_finding(
                        check="miner_launch_item",
                        location=str(path),
                        mechanism=mechanism,
                        hit=hit,
                    )
                )
        for file_path in _LINUX_PERSISTENCE_FILES:
            path = Path(file_path)
            content = _read_text(path)
            if not content:
                continue
            hit = self._classify(content)
            if hit is not None:
                findings.append(
                    self._make_finding(
                        check="miner_launch_item",
                        location=str(path),
                        mechanism="system startup file",
                        hit=hit,
                    )
                )
        return findings

    def _check_cron(self) -> list[Finding]:
        output = _run(["crontab", "-l"])
        if not output:
            return []
        findings: list[Finding] = []
        for line in output.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            hit = self._classify(stripped)
            if hit is not None:
                findings.append(
                    self._make_finding(
                        check="miner_cron_job",
                        location="user crontab",
                        mechanism="cron job",
                        hit=hit,
                        extra={"entry": stripped[:400]},
                    )
                )
        return findings

    def _check_shell_profiles(self) -> list[Finding]:
        findings: list[Finding] = []
        for profile_path in _SHELL_PROFILES:
            path = Path(profile_path).expanduser()
            content = _read_text(path)
            if not content:
                continue
            hit = self._classify(content)
            if hit is not None:
                findings.append(
                    self._make_finding(
                        check="miner_shell_profile",
                        location=str(path),
                        mechanism="shell startup file",
                        hit=hit,
                    )
                )
        return findings

    def _check_dropped_configs(self, directories: list[str]) -> list[Finding]:
        """Look for a miner config sitting in a directory malware drops into."""
        findings: list[Finding] = []
        for directory in directories:
            for path in _bounded_files(directory, "*.json"):
                content = _read_text(path)
                if not content:
                    continue
                hit = self._classify(content, require_strong=True)
                if hit is None:
                    continue
                findings.append(
                    self._make_finding(
                        check="miner_config_file",
                        location=str(path),
                        mechanism="miner configuration file",
                        hit=hit,
                    )
                )
        return findings

    # ---------------- Windows ----------------

    def _check_windows_run_keys(self) -> list[Finding]:
        findings: list[Finding] = []
        for key, label in _WIN_RUN_KEYS:
            output = _run(["reg", "query", key])
            if not output:
                continue
            for line in output.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("HKEY_"):
                    continue
                hit = self._classify(stripped)
                if hit is not None:
                    findings.append(
                        self._make_finding(
                            check="miner_run_key",
                            location=f"{label}: {stripped.split()[0]}",
                            mechanism="registry Run key",
                            hit=hit,
                            extra={"registry_key": key, "entry": stripped[:400]},
                        )
                    )
        return findings

    def _check_windows_scheduled_tasks(self) -> list[Finding]:
        output = _run(["schtasks", "/query", "/fo", "csv", "/v"])
        if not output:
            return []
        findings: list[Finding] = []
        seen: set[str] = set()
        for line in output.splitlines()[1:]:
            hit = self._classify(line)
            if hit is None:
                continue
            task_name = line.split(",")[1].strip('"') if "," in line else "unknown task"
            if task_name in seen:
                continue
            seen.add(task_name)
            findings.append(
                self._make_finding(
                    check="miner_scheduled_task",
                    location=task_name,
                    mechanism="scheduled task",
                    hit=hit,
                )
            )
        return findings

    # ---------------- classification ----------------

    def _classify(self, text: str, require_strong: bool = False) -> dict | None:
        """Return the strongest cryptojacking indicator in ``text``, if any.

        ``require_strong`` drops name-only matches, which is what the dropped
        config scan needs: an arbitrary JSON file mentioning "nicehash" is not
        interesting, but one containing a wallet address or stratum URL is.
        """
        lowered = text.lower()

        wallet = _MONERO_ADDRESS.search(text)
        if wallet is not None:
            return {
                "indicator": "monero_wallet_address",
                "severity": Severity.CRITICAL,
                "confidence": "high",
                "detail": (
                    "contains a Monero wallet address "
                    f"({wallet.group(0)[:12]}…{wallet.group(0)[-6:]}), which is where "
                    "the mined currency is being paid"
                ),
                "evidence": wallet.group(0),
            }

        for pattern in _MINER_ARGUMENTS:
            match = pattern.search(text)
            if match is not None:
                return {
                    "indicator": "miner_arguments",
                    "severity": Severity.CRITICAL,
                    "confidence": "high",
                    "detail": (
                        f"invokes a program with mining arguments ({match.group(0).strip()}), "
                        "which is how a miner is pointed at a pool"
                    ),
                    "evidence": match.group(0).strip(),
                }

        if _IOCS is not None:
            for pool in _IOCS.pools:
                if pool.domain.lower() in lowered:
                    return {
                        "indicator": "mining_pool",
                        "severity": Severity.CRITICAL,
                        "confidence": "high",
                        "detail": f"references the mining pool {pool.domain} — {pool.description}",
                        "evidence": pool.domain,
                    }

        if require_strong:
            return None

        if _IOCS is not None:
            for miner in _IOCS.miners:
                if miner.pattern.lower() in lowered:
                    return {
                        "indicator": "known_miner",
                        "severity": (
                            Severity.CRITICAL
                            if miner.severity == "critical"
                            else Severity.WARNING
                        ),
                        "confidence": "medium",
                        "detail": f"starts {miner.name} — {miner.description}",
                        "evidence": miner.pattern,
                    }
        return None

    def _make_finding(
        self,
        check: str,
        location: str,
        mechanism: str,
        hit: dict,
        extra: dict | None = None,
    ) -> Finding:
        data = {
            "check": check,
            "location": location,
            "mechanism": mechanism,
            "indicator": hit["indicator"],
            "confidence": hit["confidence"],
            "evidence": hit["evidence"],
        }
        if extra:
            data.update(extra)
        return Finding(
            title=f"Mining startup entry found in {location}",
            description=(
                f"This {mechanism} {hit['detail']}. It runs automatically, so the "
                "miner restarts after every reboot even if you kill the process. "
                "Symptoms are a machine that runs hot, loud, and slow while doing "
                "nothing, and a higher electricity bill."
            ),
            severity=hit["severity"],
            category=self.category,
            data=data,
        )


# ---------------- bounded helpers ----------------


def _run(command: list[str]) -> str:
    """Run a read-only command with a timeout; return "" on any failure."""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=_COMMAND_TIMEOUT,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return result.stdout or ""


def _bounded_files(directory: str, pattern: str) -> list[Path]:
    """Glob one level of ``directory``, capped, skipping anything unreadable."""
    try:
        base = Path(directory).expanduser()
        if not base.is_dir():
            return []
        files: list[Path] = []
        for path in sorted(base.glob(pattern)):
            if len(files) >= _MAX_FILES_PER_LOCATION:
                break
            try:
                if path.is_file():
                    files.append(path)
            except OSError:
                continue
        return files
    except OSError:
        return []


def _read_text(path: Path) -> str:
    """Read at most ``_MAX_READ_BYTES`` of a file; return "" if unreadable."""
    try:
        if not path.is_file():
            return ""
        if path.stat().st_size > _MAX_READ_BYTES * 16:
            return ""
        with open(path, "r", errors="replace") as f:
            return f.read(_MAX_READ_BYTES)
    except (OSError, ValueError):
        return ""
