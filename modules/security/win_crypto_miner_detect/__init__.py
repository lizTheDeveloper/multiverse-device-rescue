"""Windows counterpart to the macOS ``crypto_miner_detect`` module.

Cryptojacking is overwhelmingly a Windows problem — bundled with cracked
software, game "boosters", and browser installers — but the toolkit only had a
macOS miner detector. This module looks at the three things a live miner
cannot hide: its process name, its command line (which has to name a pool and
a wallet), and its network connection to a mining pool.
"""

import csv
import io
import re
import subprocess

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

_COMMAND_TIMEOUT = 30

# Percent processor time (summed across cores by the performance counter) at
# which a non-allowlisted process becomes worth mentioning. Deliberately high:
# a CPU-only signal is a lead, never a conclusion.
_HIGH_CPU_THRESHOLD = 70.0

_MONERO_ADDRESS = re.compile(r"\b[48][1-9A-HJ-NP-Za-km-z]{94}\b")

_MINER_ARGUMENTS = [
    re.compile(r"stratum\+(tcp|ssl)://", re.IGNORECASE),
    re.compile(r"--donate-level", re.IGNORECASE),
    re.compile(r"--cpu-max-threads-hint", re.IGNORECASE),
    re.compile(r"--randomx", re.IGNORECASE),
]

# Windows processes that legitimately spike to high CPU. Matched on the
# performance-counter instance name, which has no .exe suffix.
_KNOWN_HIGH_CPU_PROCESSES = {
    "system",
    "svchost",
    "msmpeng",
    "searchindexer",
    "searchprotocolhost",
    "tiworker",
    "trustedinstaller",
    "wuauclt",
    "compattelrunner",
    "dwm",
    "explorer",
    "runtimebroker",
    "chrome",
    "msedge",
    "firefox",
    "code",
    "devenv",
    "msbuild",
    "node",
    "python",
    "java",
    "ffmpeg",
    "handbrake",
    "blender",
    "obs64",
    "photoshop",
    "premiere pro",
    "unrealeditor",
    "unity",
}


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
    name = "win_crypto_miner_detect"
    category = "security"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 60
    depends_on = []
    estimated_duration = "20s"

    def check(self, profile: SystemProfile) -> CheckResult:
        processes = self._get_processes()
        findings = self._check_processes(processes)
        findings.extend(self._check_pool_connections(processes))
        findings.extend(self._check_high_cpu())
        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        """Guidance only — never terminates processes or deletes files."""
        actions: list[Action] = []

        confirmed = [
            f for f in findings.findings if f.data.get("confidence") == "high"
        ]
        leads = [f for f in findings.findings if f.data.get("confidence") != "high"]

        for finding in confirmed:
            process = finding.data.get("process", "unknown")
            pid = finding.data.get("pid")
            actions.append(
                Action(
                    title=f"Stop and remove the miner {process} (PID {pid})",
                    description=(
                        f"{finding.description}\n\n"
                        "1. Note the pool and wallet address shown above before you "
                        "delete anything — that is the evidence.\n"
                        "2. Open Task Manager > Details, right-click the process, and "
                        "choose 'Open file location' so you know what to delete.\n"
                        "3. End the process, then delete the file.\n"
                        "4. Run the crypto_miner_persistence check: miners are almost "
                        "always restarted by a scheduled task or Run key, so the "
                        "process coming back is expected until you remove that too.\n"
                        "5. Run a full Microsoft Defender offline scan."
                    ),
                    risk_level=RiskLevel.MODERATE,
                    kind=ActionKind.GUIDANCE,
                    success=True,
                    data={"pid": pid, "process": process},
                )
            )

        for finding in leads:
            process = finding.data.get("process", "unknown")
            actions.append(
                Action(
                    title=f"Identify what {process} is before assuming the worst",
                    description=(
                        f"{finding.description}\n\n"
                        "High CPU on its own is not proof of mining — video encoding, "
                        "game shader compilation, backups, and Windows Update all look "
                        "like this. Check the publisher and file location in Task "
                        "Manager > Details. Treat it as a miner only if the file lives "
                        "in a temp/AppData folder, has no publisher, or you cannot "
                        "explain why it is running."
                    ),
                    risk_level=RiskLevel.SAFE,
                    kind=ActionKind.GUIDANCE,
                    success=True,
                    data={"process": process},
                )
            )

        return FixResult(module_name=self.name, actions=actions)

    # ---------------- collection ----------------

    def _get_processes(self) -> list[dict]:
        """Return running processes with their command lines."""
        output = _run_powershell(
            "Get-CimInstance Win32_Process | "
            "Select-Object ProcessId,Name,CommandLine | "
            "ConvertTo-Csv -NoTypeInformation"
        )
        processes = []
        for row in _parse_csv(output):
            pid = row.get("ProcessId", "").strip()
            processes.append(
                {
                    "pid": int(pid) if pid.isdigit() else 0,
                    "name": row.get("Name", "").strip(),
                    "command": (row.get("CommandLine") or "").strip(),
                }
            )
        return processes

    # ---------------- checks ----------------

    def _check_processes(self, processes: list[dict]) -> list[Finding]:
        findings: list[Finding] = []
        for proc in processes:
            haystack = f"{proc['name']} {proc['command']}"
            hit = self._classify(haystack)
            if hit is None:
                continue
            findings.append(
                Finding(
                    title=f"Cryptocurrency miner running: {proc['name']}",
                    description=(
                        f"Process {proc['name']} (PID {proc['pid']}) {hit['detail']}. "
                        "A miner uses your CPU or GPU to earn cryptocurrency for "
                        "whoever installed it, which is why the machine is hot, loud, "
                        "and slow."
                    ),
                    severity=hit["severity"],
                    category=self.category,
                    data={
                        "check": "known_miner",
                        "pid": proc["pid"],
                        "process": proc["name"],
                        "command": proc["command"][:400],
                        "indicator": hit["indicator"],
                        "confidence": hit["confidence"],
                        "evidence": hit["evidence"],
                    },
                )
            )
        return findings

    def _check_pool_connections(self, processes: list[dict]) -> list[Finding]:
        """Flag established connections to mining-pool ports."""
        if _IOCS is None or not _IOCS.pool_ports:
            return []

        output = _run(["netstat", "-ano"])
        if not output:
            return []

        by_pid = {proc["pid"]: proc for proc in processes}
        findings: list[Finding] = []
        seen: set[tuple[int, int]] = set()

        for line in output.splitlines():
            parts = line.split()
            if len(parts) < 5 or parts[0].upper() not in {"TCP", "UDP"}:
                continue
            remote = parts[2]
            state = parts[3].upper()
            pid_str = parts[4]
            if not pid_str.isdigit() or state != "ESTABLISHED":
                continue
            port = _port_of(remote)
            if port is None or port not in _IOCS.pool_ports:
                continue

            pid = int(pid_str)
            if (pid, port) in seen:
                continue
            seen.add((pid, port))

            proc = by_pid.get(pid, {})
            process_name = proc.get("name", f"PID {pid}")
            findings.append(
                Finding(
                    title=f"Connection to a mining pool port from {process_name}",
                    description=(
                        f"{process_name} (PID {pid}) holds an established connection to "
                        f"{remote}. Port {port} is a standard Stratum mining-pool port. "
                        "Unless someone deliberately set up mining on this machine, "
                        "this is a miner reporting work to someone else's wallet."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={
                        "check": "mining_pool_connection",
                        "pid": pid,
                        "process": process_name,
                        "remote": remote,
                        "port": port,
                        "confidence": "high",
                    },
                )
            )
        return findings

    def _check_high_cpu(self) -> list[Finding]:
        output = _run_powershell(
            "Get-CimInstance Win32_PerfFormattedData_PerfProc_Process | "
            "Where-Object { $_.Name -ne '_Total' -and $_.Name -ne 'Idle' } | "
            "Select-Object Name,IDProcess,PercentProcessorTime | "
            "ConvertTo-Csv -NoTypeInformation"
        )
        findings: list[Finding] = []
        for row in _parse_csv(output):
            name = row.get("Name", "").strip()
            pid_str = row.get("IDProcess", "").strip()
            percent_str = row.get("PercentProcessorTime", "").strip()
            if not name or not percent_str:
                continue
            try:
                percent = float(percent_str)
            except ValueError:
                continue
            if percent < _HIGH_CPU_THRESHOLD:
                continue
            if _is_known_high_cpu(name):
                continue
            findings.append(
                Finding(
                    title=f"Sustained high CPU usage by {name}",
                    description=(
                        f"{name} (PID {pid_str or 'unknown'}) is using {percent:.0f}% of "
                        "processor time and is not a process Windows normally pegs the "
                        "CPU with. Silent mining looks exactly like this. It may equally "
                        "be legitimate heavy work, so confirm what the program is before "
                        "removing it."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "high_cpu_process",
                        "pid": int(pid_str) if pid_str.isdigit() else 0,
                        "process": name,
                        "cpu_percent": percent,
                        "confidence": "low",
                    },
                )
            )
        return findings

    # ---------------- classification ----------------

    def _classify(self, text: str) -> dict | None:
        lowered = text.lower()

        wallet = _MONERO_ADDRESS.search(text)
        if wallet is not None:
            return {
                "indicator": "monero_wallet_address",
                "severity": Severity.CRITICAL,
                "confidence": "high",
                "detail": (
                    "was started with a Monero wallet address on its command line "
                    f"({wallet.group(0)[:12]}…{wallet.group(0)[-6:]}) — the account being paid"
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
                        f"was started with mining arguments ({match.group(0).strip()})"
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
                        "detail": f"references the mining pool {pool.domain}",
                        "evidence": pool.domain,
                    }
            for miner in _IOCS.miners_for("win32"):
                if miner.pattern.lower() in lowered:
                    return {
                        "indicator": "known_miner",
                        "severity": (
                            Severity.CRITICAL
                            if miner.severity == "critical"
                            else Severity.WARNING
                        ),
                        "confidence": "high" if miner.severity == "critical" else "medium",
                        "detail": f"is {miner.name} — {miner.description}",
                        "evidence": miner.pattern,
                    }
        return None


# ---------------- helpers ----------------


def _run(command: list[str]) -> str:
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=_COMMAND_TIMEOUT
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return result.stdout or ""


def _run_powershell(script: str) -> str:
    return _run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script]
    )


def _parse_csv(output: str) -> list[dict]:
    if not output.strip():
        return []
    try:
        return list(csv.DictReader(io.StringIO(output)))
    except csv.Error:
        return []


def _port_of(address: str) -> int | None:
    if ":" not in address:
        return None
    port_str = address.rsplit(":", 1)[-1]
    return int(port_str) if port_str.isdigit() else None


def _is_known_high_cpu(name: str) -> bool:
    # Performance-counter instance names are suffixed for duplicates
    # ("chrome#3"), so compare on the base name.
    base = name.split("#")[0].lower().removesuffix(".exe")
    return base in _KNOWN_HIGH_CPU_PROCESSES
