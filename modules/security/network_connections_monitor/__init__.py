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


# Known backdoor ports - should be flagged as CRITICAL
BACKDOOR_PORTS = {4444, 5555, 8080, 8888, 1337, 31337}

# Well-known legitimate ports that are expected
LEGITIMATE_PORTS = {80, 443, 53, 22, 993, 587}

# Private IP ranges
PRIVATE_IP_RANGES = [
    "10.",
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.20.",
    "172.21.",
    "172.22.",
    "172.23.",
    "172.24.",
    "172.25.",
    "172.26.",
    "172.27.",
    "172.28.",
    "172.29.",
    "172.30.",
    "172.31.",
    "192.168.",
    "127.",
    "169.254.",
]


class Module(ModuleBase):
    name = "network_connections_monitor"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    emits_codes = [
        "security.network_connections_monitor.backdoor_ports",
        "security.network_connections_monitor.high_connection_count",
        "security.network_connections_monitor.unusual_ports",
        "security.network_connections_monitor.private_ip_connections",
        "security.network_connections_monitor.connection_summary",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get active connections from netstat and lsof
        connections = self._get_active_connections()

        if not connections:
            # No connections found or error getting them
            return CheckResult(module_name=self.name, findings=findings)

        # Check for connections on backdoor ports
        backdoor_connections = []
        for conn in connections:
            if conn["port"] in BACKDOOR_PORTS:
                backdoor_connections.append(
                    f"{conn['process']} (PID {conn['pid']}) -> {conn['remote_addr']}:{conn['port']}"
                )

        if backdoor_connections:
            findings.append(
                Finding(
                    title=f"CRITICAL: Connections on backdoor ports: {len(backdoor_connections)}",
                    description=(
                        f"Found {len(backdoor_connections)} connection(s) on known backdoor ports:\n"
                        f"{chr(10).join(backdoor_connections)}\n\n"
                        "These ports are commonly used by malware/C2 servers. "
                        "Investigate immediately."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    code="security.network_connections_monitor.backdoor_ports",
                    data={"check": "backdoor_ports", "connections": backdoor_connections},
                )
            )

        # Check for processes with many outbound connections (possible botnet)
        process_conn_count = defaultdict(list)
        for conn in connections:
            if conn["state"] == "ESTABLISHED":
                process_key = f"{conn['process']} (PID {conn['pid']})"
                process_conn_count[process_key].append(conn)

        high_conn_processes = []
        for process_key, conns in process_conn_count.items():
            if len(conns) > 20:
                high_conn_processes.append(f"{process_key}: {len(conns)} connections")

        if high_conn_processes:
            findings.append(
                Finding(
                    title=f"WARNING: Processes with high connection count: {len(high_conn_processes)}",
                    description=(
                        f"Found {len(high_conn_processes)} process(es) with >20 active connections:\n"
                        f"{chr(10).join(high_conn_processes)}\n\n"
                        "This may indicate a botnet, scanner, or malicious activity. "
                        "Review these processes."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.network_connections_monitor.high_connection_count",
                    data={"check": "high_connection_count", "processes": high_conn_processes},
                )
            )

        # Check for connections on unusual ports from unknown processes
        unusual_port_connections = []
        for conn in connections:
            port = conn["port"]
            # Flag if on unusual port (not in legitimate list) and not a system port (< 1024)
            if port not in LEGITIMATE_PORTS and port not in BACKDOOR_PORTS:
                if port > 1024:  # Skip system ports
                    unusual_port_connections.append(
                        f"{conn['process']} -> {conn['remote_addr']}:{port}"
                    )

        if unusual_port_connections:
            findings.append(
                Finding(
                    title=f"WARNING: Connections on unusual ports: {len(unusual_port_connections)}",
                    description=(
                        f"Found {len(unusual_port_connections)} connection(s) on unusual ports:\n"
                        f"{chr(10).join(unusual_port_connections[:20])}"
                        f"{chr(10) + '... and more' if len(unusual_port_connections) > 20 else ''}\n\n"
                        "Review these connections to ensure they are legitimate."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.network_connections_monitor.unusual_ports",
                    data={
                        "check": "unusual_ports",
                        "connections": unusual_port_connections,
                    },
                )
            )

        # Check for connections to private IPs from unexpected processes
        private_ip_connections = []
        for conn in connections:
            remote_addr = conn["remote_addr"]
            # Check if connection is to private IP
            is_private = any(remote_addr.startswith(prefix) for prefix in PRIVATE_IP_RANGES)
            if is_private and remote_addr not in ["127.0.0.1", "::1"]:
                # Localhost is expected, so skip it
                private_ip_connections.append(
                    f"{conn['process']} -> {remote_addr}:{conn['port']}"
                )

        if private_ip_connections:
            findings.append(
                Finding(
                    title=f"INFO: Connections to private IP ranges: {len(private_ip_connections)}",
                    description=(
                        f"Found {len(private_ip_connections)} connection(s) to private IP ranges:\n"
                        f"{chr(10).join(private_ip_connections[:15])}"
                        f"{chr(10) + '... and more' if len(private_ip_connections) > 15 else ''}\n\n"
                        "These may be legitimate internal network connections."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.network_connections_monitor.private_ip_connections",
                    data={"check": "private_ip_connections", "count": len(private_ip_connections)},
                )
            )

        # Summary report
        if connections:
            findings.append(
                Finding(
                    title=f"Connection summary: {len(connections)} active connection(s)",
                    description=(
                        f"System has {len(connections)} active network connection(s). "
                        f"Review above findings for any suspicious activity."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.network_connections_monitor.connection_summary",
                    data={"check": "connection_summary", "total_count": len(connections)},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "backdoor_ports":
                connections = finding.data.get("connections", [])
                conn_str = "\n".join(connections[:5])
                if len(connections) > 5:
                    conn_str += f"\n... and {len(connections) - 5} more"

                actions.append(
                    Action(
                        title="URGENT: Investigate backdoor port connections",
                        description=(
                            f"Connections found on backdoor ports:\n{conn_str}\n\n"
                            "Steps to investigate:\n"
                            "1. Use `lsof -p <PID>` to see all connections for this process\n"
                            "2. Check the process binary: `ps -p <PID> -o comm=`\n"
                            "3. Verify if the binary is signed: `codesign -v /path/to/binary`\n"
                            "4. Check process in Activity Monitor\n"
                            "5. If suspicious, terminate the process and quarantine it\n"
                            "6. Run a full malware scan\n\n"
                            "DO NOT kill the process without investigation as it may be "
                            "legitimate development/testing."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )

            elif check == "high_connection_count":
                processes = finding.data.get("processes", [])
                proc_str = "\n".join(processes[:3])
                if len(processes) > 3:
                    proc_str += f"\n... and {len(processes) - 3} more"

                actions.append(
                    Action(
                        title="Investigate processes with high connection count",
                        description=(
                            f"Processes with >20 connections:\n{proc_str}\n\n"
                            "This may indicate:\n"
                            "- Botnet/malware activity\n"
                            "- Network scanner/port scanner\n"
                            "- Legitimate high-traffic service\n\n"
                            "To investigate:\n"
                            "1. Check process details: `ps aux | grep <PID>`\n"
                            "2. View connections: `lsof -p <PID>`\n"
                            "3. Check remote IPs: `lsof -i -nP | grep <PID>`\n"
                            "4. If suspicious, research the process name/binary"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )

            elif check == "unusual_ports":
                connections = finding.data.get("connections", [])
                conn_str = "\n".join(connections[:5])
                if len(connections) > 5:
                    conn_str += f"\n... and {len(connections) - 5} more"

                actions.append(
                    Action(
                        title="Review connections on unusual ports",
                        description=(
                            f"Connections on non-standard ports:\n{conn_str}\n\n"
                            "To investigate:\n"
                            "1. Research the port number online\n"
                            "2. Check if the process is expected to use this port\n"
                            "3. Use `lsof -i :<port>` to see what's using the port\n"
                            "4. Verify the remote IP/domain\n\n"
                            "Common suspicious ports: 4444, 5555, 8080, 8888, 1337, 31337"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )

            elif check == "private_ip_connections":
                count = finding.data.get("count", 0)
                actions.append(
                    Action(
                        title=f"Review {count} connection(s) to private IPs",
                        description=(
                            f"Found {count} connection(s) to private IP ranges.\n\n"
                            "These are typically expected in corporate/home networks, but verify:\n"
                            "1. They match your expected network topology\n"
                            "2. They are to trusted internal IPs\n"
                            "3. The processes making these connections are expected\n\n"
                            "Command to view all private IP connections:\n"
                            "  lsof -i -nP | grep -E '(10\\.|172\\.|192\\.168)'"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )

            elif check == "connection_summary":
                count = finding.data.get("total_count", 0)
                actions.append(
                    Action(
                        title=f"Monitor {count} active network connection(s)",
                        description=(
                            f"Your system has {count} active network connection(s).\n\n"
                            "Regular monitoring commands:\n"
                            "1. View all connections: `netstat -anp tcp`\n"
                            "2. View connections by process: `lsof -i -nP`\n"
                            "3. Monitor in real-time: `netstat -anp tcp | watch`\n"
                            "4. Filter established: `netstat -anp tcp | grep ESTABLISHED`\n\n"
                            "Review regularly for unauthorized outbound connections."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_active_connections(self) -> list[dict]:
        """
        Get active network connections using lsof.

        Returns list of dicts with keys:
        - process (str): process name
        - pid (int): process ID
        - remote_addr (str): remote IP address
        - port (int): remote port
        - state (str): connection state (ESTABLISHED, etc.)

        Returns empty list on any failure.
        """
        try:
            result = subprocess.run(
                ["lsof", "-i", "-nP"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode != 0:
                return []

            connections = []
            lines = result.stdout.strip().split("\n")

            # Skip header line
            for line in lines[1:]:
                if not line.strip():
                    continue

                # Parse lsof output format
                # COMMAND  PID  USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
                # Example: Chrome 1234 user 42u IPv4 0x123456 0t0 TCP 192.168.1.100:54321->8.8.8.8:443 (ESTABLISHED)
                parts = line.split()
                if len(parts) < 9:
                    continue

                command = parts[0]
                pid = parts[1]
                # NAME field is second to last
                name_field = parts[-2] if len(parts) > 8 else ""

                # Parse connection info from name field
                # Format: local_ip:local_port->remote_ip:remote_port (STATE)
                # or IPv6 format with []
                try:
                    pid_int = int(pid)

                    if "->" not in name_field:
                        continue

                    # Split on ->
                    addr_parts = name_field.split("->")
                    if len(addr_parts) != 2:
                        continue

                    remote_part = addr_parts[1]

                    # Extract remote IP and port
                    # Handle IPv6 addresses with []
                    if "[" in remote_part:
                        # IPv6 format: [ipv6]:port
                        if "]:" in remote_part:
                            ip_part, port_part = remote_part.rsplit("]:", 1)
                            remote_ip = ip_part.lstrip("[")
                            remote_port = int(port_part)
                        else:
                            continue
                    else:
                        # IPv4 format: ip:port
                        if ":" in remote_part:
                            ip_parts = remote_part.rsplit(":", 1)
                            remote_ip = ip_parts[0]
                            remote_port = int(ip_parts[1])
                        else:
                            continue

                    # Determine state - usually in last part
                    state = "ESTABLISHED"
                    if len(parts) > 0:
                        last_part = parts[-1]
                        if last_part.startswith("(") and last_part.endswith(")"):
                            state = last_part.strip("()")

                    connections.append({
                        "process": command,
                        "pid": pid_int,
                        "remote_addr": remote_ip,
                        "port": remote_port,
                        "state": state,
                    })

                except (ValueError, IndexError):
                    continue

            return connections

        except subprocess.TimeoutExpired:
            return []
        except FileNotFoundError:
            return []
        except Exception:
            return []
