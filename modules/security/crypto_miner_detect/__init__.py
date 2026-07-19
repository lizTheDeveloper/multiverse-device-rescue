import subprocess
import re
from collections import defaultdict

from rescue.models import (
    Action,
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


# Known cryptocurrency miner process names
KNOWN_MINER_PROCESSES = {
    "xmrig",
    "minerd",
    "minergate",
    "coinhive",
    "cryptonight",
    "stratum",
    "cgminer",
    "bfgminer",
    "ethminer",
    "phoenixminer",
    "t-rex",
    "nbminer",
    "gminer",
    "lolminer",
}

# Known mining pool ports
MINING_POOL_PORTS = {3333, 4444, 5555, 7777, 8888, 9999, 14444}

# Known safe macOS processes that may have high CPU occasionally
KNOWN_SAFE_HIGH_CPU_PROCESSES = {
    "kernel_task",
    "WindowServer",
    "Finder",
    "Spotlight",
    "Safari",
    "Chrome",
    "Firefox",
    "Mail",
    "Photos",
    "Music",
    "Xcode",
    "gcc",
    "clang",
    "make",
    "node",
    "python",
    "java",
    "ruby",
    "Compressor",
    "Final Cut Pro",
    "Logic Pro",
}

# Mining pool domain patterns
MINING_POOL_PATTERNS = [
    r".*pool\..*",
    r".*mining\..*",
    r".*stratum\+tcp.*",
]


class Module(ModuleBase):
    name = "crypto_miner_detect"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 60
    depends_on = []
    estimated_duration = "5s"

    emits_codes = [
        "security.crypto_miner_detect.known_miner",
        "security.crypto_miner_detect.high_cpu_process",
        "security.crypto_miner_detect.mining_pool_connection",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check for known miner processes
        miner_findings = self._check_known_miners()
        findings.extend(miner_findings)

        # Check for high CPU processes
        high_cpu_findings = self._check_high_cpu_processes()
        findings.extend(high_cpu_findings)

        # Check for mining pool connections
        pool_findings = self._check_mining_pool_connections()
        findings.extend(pool_findings)

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        """Report cryptocurrency mining activity without taking action (informational only)."""
        actions = []

        for finding in findings.findings:
            check_type = finding.data.get("check")
            process = finding.data.get("process")
            pid = finding.data.get("pid")
            cpu_percent = finding.data.get("cpu_percent")
            port = finding.data.get("port")

            if check_type == "known_miner":
                title = f"Remove known cryptocurrency miner: {process}"
                description = (
                    f"Process {process} (PID {pid}) is a known cryptocurrency miner. "
                    f"This process should be removed from the system. "
                    f"Consider reviewing system logs to understand how it was installed."
                )
            elif check_type == "high_cpu_process":
                title = f"Investigate high CPU process: {process}"
                description = (
                    f"Process {process} (PID {pid}) is using {cpu_percent}% CPU, "
                    f"which is unusually high for a non-system process. "
                    f"This could indicate a cryptocurrency miner or other resource-intensive malware. "
                    f"Check what this process is doing with Activity Monitor."
                )
            elif check_type == "mining_pool_connection":
                title = f"Investigate mining pool connection from {process}"
                description = (
                    f"Process {process} (PID {pid}) has an active connection on port {port}, "
                    f"which is commonly used by mining pools. This could indicate cryptocurrency mining activity. "
                    f"Investigate the destination and consider terminating this process."
                )
            else:
                continue

            actions.append(
                Action(
                    title=title,
                    description=description,
                    risk_level=RiskLevel.SAFE,
                    success=True,
                    error=None,
                )
            )

        return FixResult(module_name=self.name, actions=actions)

    def _check_known_miners(self) -> list[Finding]:
        """Check for known cryptocurrency miner processes."""
        findings = []

        try:
            ps_output = subprocess.run(
                ["ps", "aux"],
                capture_output=True,
                text=True,
            ).stdout
        except OSError:
            return findings

        for line in ps_output.split("\n")[1:]:  # Skip header
            if not line.strip():
                continue

            parts = line.split()
            if len(parts) < 11:
                continue

            try:
                pid = int(parts[1])
                # Get the command (everything after the 10th column)
                command = " ".join(parts[10:])
                process_name = parts[10].split("/")[-1]

                # Check if process name is a known miner
                for miner_name in KNOWN_MINER_PROCESSES:
                    if miner_name.lower() in process_name.lower():
                        findings.append(
                            Finding(
                                title=f"Known cryptocurrency miner detected: {process_name}",
                                description=(
                                    f"Process {process_name} (PID {pid}) is a known cryptocurrency miner. "
                                    f"This malware mines digital currency using your system resources. "
                                    f"Command: {command}"
                                ),
                                severity=Severity.CRITICAL,
                                category=self.category,
                                code="security.crypto_miner_detect.known_miner",
                                data={
                                    "check": "known_miner",
                                    "pid": pid,
                                    "process": process_name,
                                    "command": command,
                                },
                            )
                        )
                        break
            except (ValueError, IndexError):
                continue

        return findings

    def _check_high_cpu_processes(self) -> list[Finding]:
        """Check for processes with unusually high CPU usage that aren't known safe processes."""
        findings = []

        try:
            ps_output = subprocess.run(
                ["ps", "-eo", "pid,pcpu,comm"],
                capture_output=True,
                text=True,
            ).stdout
        except OSError:
            return findings

        # Parse output and get top CPU processes
        high_cpu_processes = []
        for line in ps_output.split("\n")[1:]:  # Skip header
            if not line.strip():
                continue

            parts = line.split()
            if len(parts) < 3:
                continue

            try:
                pid = int(parts[0])
                cpu_percent = float(parts[1])
                process_name = parts[2]

                if cpu_percent > 80:
                    high_cpu_processes.append(
                        {
                            "pid": pid,
                            "cpu_percent": cpu_percent,
                            "process": process_name,
                        }
                    )
            except (ValueError, IndexError):
                continue

        # Flag high CPU processes that aren't known safe
        for proc in high_cpu_processes:
            process_name = proc["process"].split("/")[-1]
            if not self._is_known_safe_process(process_name):
                findings.append(
                    Finding(
                        title=f"Suspicious high CPU usage by {process_name}",
                        description=(
                            f"Process {process_name} (PID {proc['pid']}) is using {proc['cpu_percent']}% CPU, "
                            f"which is unusually high. This could indicate a cryptocurrency miner or other "
                            f"resource-intensive malware consuming system resources. Your computer may feel slow or hot."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        code="security.crypto_miner_detect.high_cpu_process",
                        data={
                            "check": "high_cpu_process",
                            "pid": proc["pid"],
                            "process": process_name,
                            "cpu_percent": proc["cpu_percent"],
                        },
                    )
                )

        return findings

    def _check_mining_pool_connections(self) -> list[Finding]:
        """Check for connections to known mining pool ports and domains."""
        findings = []

        try:
            lsof_output = subprocess.run(
                ["lsof", "-i", "-n", "-P"],
                capture_output=True,
                text=True,
            ).stdout
        except OSError:
            return findings

        for line in lsof_output.split("\n")[1:]:  # Skip header
            if not line.strip():
                continue

            parts = line.split()
            if len(parts) < 10:
                continue

            try:
                process = parts[0]
                pid_str = parts[1]

                if not pid_str.isdigit():
                    continue

                pid = int(pid_str)

                # Skip known safe processes
                process_name = process.split("/")[-1]
                if self._is_known_safe_process(process_name):
                    continue

                # Extract port and address info
                local_addr = parts[8] if len(parts) > 8 else ""
                remote_addr = parts[9] if len(parts) > 9 else ""

                # Check local address for mining pool ports
                local_port = self._extract_port(local_addr)
                if local_port and local_port in MINING_POOL_PORTS:
                    findings.append(
                        Finding(
                            title=f"Connection on mining pool port {local_port} from {process}",
                            description=(
                                f"Process {process} (PID {pid}) has a connection on port {local_port}, "
                                f"which is commonly used by cryptocurrency mining pools. "
                                f"This could indicate cryptocurrency mining activity."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            code="security.crypto_miner_detect.mining_pool_connection",
                            data={
                                "check": "mining_pool_connection",
                                "pid": pid,
                                "process": process,
                                "port": local_port,
                                "address": remote_addr,
                            },
                        )
                    )

                # Check remote address for mining pool patterns
                if remote_addr and self._is_mining_pool_domain(remote_addr):
                    findings.append(
                        Finding(
                            title=f"Connection to mining pool domain from {process}",
                            description=(
                                f"Process {process} (PID {pid}) is connected to {remote_addr}, "
                                f"which matches a mining pool domain pattern. "
                                f"This indicates cryptocurrency mining activity."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            code="security.crypto_miner_detect.mining_pool_connection",
                            data={
                                "check": "mining_pool_connection",
                                "pid": pid,
                                "process": process,
                                "port": None,
                                "address": remote_addr,
                            },
                        )
                    )
            except (ValueError, IndexError):
                continue

        return findings

    def _extract_port(self, addr: str) -> int | None:
        """Extract port number from address like IP:PORT."""
        if ":" in addr:
            try:
                parts = addr.rsplit(":", 1)
                port_str = parts[-1]
                port = int(port_str)
                return port
            except (ValueError, IndexError):
                return None
        return None

    def _is_known_safe_process(self, process: str) -> bool:
        """Check if process is in known safe list."""
        process_name = process.split("/")[-1] if "/" in process else process
        return process_name in KNOWN_SAFE_HIGH_CPU_PROCESSES

    def _is_mining_pool_domain(self, domain: str) -> bool:
        """Check if domain matches mining pool patterns."""
        for pattern in MINING_POOL_PATTERNS:
            if re.match(pattern, domain, re.IGNORECASE):
                return True
        return False
