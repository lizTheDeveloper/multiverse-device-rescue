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


# Standard ports commonly used by legitimate services
STANDARD_PORTS = {
    20, 21,    # FTP
    22,        # SSH
    25,        # SMTP
    53,        # DNS
    80,        # HTTP
    110,       # POP3
    143,       # IMAP
    443,       # HTTPS
    465,       # SMTPS
    587,       # SMTP submission
    993,       # IMAPS
    995,       # POP3S
    3306,      # MySQL
    5432,      # PostgreSQL
    5984,      # CouchDB
    6379,      # Redis
    27017,     # MongoDB
}

# Known safe macOS processes that commonly have network connections
KNOWN_SAFE_PROCESSES = {
    "mDNSResponder",
    "UserEventAgent",
    "Spotlight",
    "Finder",
    "Safari",
    "Chrome",
    "Firefox",
    "Mail",
    "Messages",
    "FaceTime",
    "Maps",
    "News",
    "Stocks",
    "Weather",
    "iTunes",
    "Music",
    "Podcasts",
    "TV",
    "Books",
    "AppStore",
    "System Events",
    "System Preferences",
    "Dock",
    "Notification Center",
    "Time Machine",
    "Cloud Sync",
    "iCloud",
    "Siri",
    "Spotlight",
    "Directory Service",
    "LoginWindow",
    "SecurityAgent",
    "spindump",
    "Simulator",
    "node",
    "java",
    "python",
}


class Module(ModuleBase):
    name = "suspicious_connections"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 55
    depends_on = []
    estimated_duration = "3s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        try:
            lsof_output = self._run_lsof()
        except OSError as e:
            # lsof might not be available or require sudo
            return CheckResult(module_name=self.name, findings=[])

        # Parse lsof output
        connections = self._parse_lsof_output(lsof_output)

        # Check for unusual listening ports
        for conn in connections:
            if conn["type"] == "LISTEN":
                port = conn["port"]
                if port and not self._is_standard_port(port):
                    findings.append(
                        Finding(
                            title=f"Unusual listening port {port} by {conn['process']}",
                            description=(
                                f"Process {conn['process']} (PID {conn['pid']}) is listening on "
                                f"port {port}, which is not a standard service port. This could "
                                f"indicate malware or an unauthorized service."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            data={
                                "check": "unusual_listening_port",
                                "pid": conn["pid"],
                                "process": conn["process"],
                                "port": port,
                            },
                        )
                    )

        # Check for unusual established connections
        for conn in connections:
            if conn["type"] == "ESTABLISHED":
                port = conn["port"]
                if port and not self._is_standard_port(port):
                    # Only flag if process is not in known safe list
                    if not self._is_known_safe_process(conn["process"]):
                        findings.append(
                            Finding(
                                title=f"Unusual outbound connection on port {port} from {conn['process']}",
                                description=(
                                    f"Process {conn['process']} (PID {conn['pid']}) has an "
                                    f"established connection to port {port}, which is not a standard "
                                    f"service port. This could indicate data exfiltration or C2 communication."
                                ),
                                severity=Severity.WARNING,
                                category=self.category,
                                data={
                                    "check": "unusual_outbound_connection",
                                    "pid": conn["pid"],
                                    "process": conn["process"],
                                    "port": port,
                                },
                            )
                        )

        # Check for high connection counts per process (potential C2 beaconing)
        connection_counts = self._count_connections_by_process(connections)
        for process, count in connection_counts.items():
            if count > 10 and not self._is_known_safe_process(process):
                findings.append(
                    Finding(
                        title=f"High connection count from {process}",
                        description=(
                            f"Process {process} has {count} open network connections, "
                            f"which is unusual and could indicate C2 beaconing or network scanning."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={
                            "check": "high_connection_count",
                            "process": process,
                            "count": count,
                        },
                    )
                )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        """Report suspicious connections without taking action (informational only)."""
        actions = []

        for finding in findings.findings:
            check_type = finding.data.get("check")
            process = finding.data.get("process")
            port = finding.data.get("port")

            if check_type == "unusual_listening_port":
                title = f"Review listening port {port} on {process}"
                description = (
                    f"Investigate why {process} is listening on port {port}. "
                    f"Verify this is an expected service before taking action."
                )
            elif check_type == "unusual_outbound_connection":
                title = f"Review outbound connection from {process} on port {port}"
                description = (
                    f"Investigate the destination of the connection from {process} on port {port}. "
                    f"This may indicate data exfiltration or C2 communication."
                )
            elif check_type == "high_connection_count":
                count = finding.data.get("count")
                title = f"Review high connection count from {process}"
                description = (
                    f"Process {process} has {count} open connections. "
                    f"This is unusual and may indicate C2 beaconing or scanning."
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

    def _run_lsof(self) -> str:
        """Run lsof -i -n -P to get network connections."""
        result = subprocess.run(
            ["lsof", "-i", "-n", "-P"],
            capture_output=True,
            text=True,
        )
        return result.stdout

    def _parse_lsof_output(self, output: str) -> list[dict]:
        """Parse lsof output into structured connection data."""
        connections = []
        lines = output.strip().split("\n")

        # Skip header line
        for line in lines[1:]:
            if not line.strip():
                continue

            parts = line.split()
            if len(parts) < 10:
                continue

            process = parts[0]
            pid = parts[1]
            conn_type = parts[7]  # TCP/UDP
            state = parts[9] if len(parts) > 9 else ""

            # Determine connection state (LISTEN or ESTABLISHED)
            if "LISTEN" in state:
                connection_state = "LISTEN"
            elif "ESTABLISHED" in state:
                connection_state = "ESTABLISHED"
            else:
                continue

            # Extract port from the local address (format: IP:PORT)
            local_addr = parts[8] if len(parts) > 8 else ""
            port = self._extract_port(local_addr)

            if port:
                connections.append(
                    {
                        "process": process,
                        "pid": int(pid) if pid.isdigit() else pid,
                        "type": connection_state,
                        "port": port,
                        "local_addr": local_addr,
                    }
                )

        return connections

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

    def _is_standard_port(self, port: int) -> bool:
        """Check if port is a standard service port."""
        return port in STANDARD_PORTS

    def _is_known_safe_process(self, process: str) -> bool:
        """Check if process is in known safe list."""
        # Extract the process name from full path if needed
        process_name = process.split("/")[-1] if "/" in process else process
        return process_name in KNOWN_SAFE_PROCESSES

    def _count_connections_by_process(self, connections: list[dict]) -> dict[str, int]:
        """Count total network connections per process."""
        counts = defaultdict(int)
        for conn in connections:
            counts[conn["process"]] += 1
        return dict(counts)
