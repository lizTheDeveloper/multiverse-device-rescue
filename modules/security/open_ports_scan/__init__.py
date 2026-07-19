import subprocess

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


# Map well-known ports to service names
WELL_KNOWN_PORTS = {
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
    5901: "VNC",
    8080: "HTTP (alternate)",
    9200: "Elasticsearch",
    27017: "MongoDB",
}

# Risky database/service ports that should NOT be exposed to 0.0.0.0
RISKY_PORTS = {
    3306,      # MySQL
    5432,      # PostgreSQL
    27017,     # MongoDB
    9200,      # Elasticsearch
    6379,      # Redis
    5984,      # CouchDB
    8086,      # InfluxDB
}


class Module(ModuleBase):
    name = "open_ports_scan"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "3s"

    emits_codes = [
        "security.open_ports_scan.exposed_risky_ports",
        "security.open_ports_scan.listening_ports",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        listening_ports = self._get_listening_ports()

        if not listening_ports:
            return CheckResult(module_name=self.name, findings=findings)

        # Flag WARNING for risky ports exposed to 0.0.0.0
        exposed_risky = []
        for port_info in listening_ports:
            port = port_info["port"]
            address = port_info["address"]
            process = port_info["process"]

            # Check if risky database port is exposed to all interfaces
            if port in RISKY_PORTS and address == "0.0.0.0":
                exposed_risky.append(
                    f"{port} ({process}) listening on 0.0.0.0"
                )

        if exposed_risky:
            findings.append(
                Finding(
                    title=f"Risky ports exposed to network: {len(exposed_risky)}",
                    description=(
                        f"Found {len(exposed_risky)} database/service port(s) "
                        f"exposed to all network interfaces (0.0.0.0):\n"
                        f"{chr(10).join(exposed_risky)}\n\n"
                        "This allows network access to sensitive services. "
                        "Database ports should bind to localhost (127.0.0.1) unless "
                        "remote access is explicitly required."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.open_ports_scan.exposed_risky_ports",
                    data={"check": "exposed_risky_ports", "ports": exposed_risky},
                )
            )

        # Flag INFO for all listening ports with process information
        all_ports_info = []
        for port_info in listening_ports:
            port = port_info["port"]
            address = port_info["address"]
            process = port_info["process"]

            service_name = WELL_KNOWN_PORTS.get(port, "custom")
            all_ports_info.append(
                f"Port {port} ({service_name}) - {process} on {address}"
            )

        if all_ports_info:
            findings.append(
                Finding(
                    title=f"Listening ports: {len(all_ports_info)}",
                    description=(
                        f"Found {len(all_ports_info)} listening port(s):\n"
                        f"{chr(10).join(all_ports_info)}"
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.open_ports_scan.listening_ports",
                    data={
                        "check": "listening_ports",
                        "count": len(all_ports_info),
                        "ports": all_ports_info,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "exposed_risky_ports":
                ports_list = finding.data.get("ports", [])
                port_str = ", ".join(ports_list) if ports_list else "unknown"

                actions.append(
                    Action(
                        title="Review and restrict exposed database ports",
                        description=(
                            f"Exposed ports: {port_str}\n\n"
                            "To restrict these ports to localhost only:\n"
                            "1. Stop the affected service\n"
                            "2. Edit the service configuration to bind to 127.0.0.1 "
                            "instead of 0.0.0.0\n"
                            "3. Restart the service\n"
                            "4. If network access is needed, use SSH tunneling or "
                            "a VPN instead\n\n"
                            "Example with MySQL:\n"
                            "  Edit /etc/mysql/my.cnf and set: bind-address=127.0.0.1"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )

            elif check == "listening_ports":
                count = finding.data.get("count", 0)
                actions.append(
                    Action(
                        title=f"Review {count} listening port(s)",
                        description=(
                            f"You have {count} service(s) listening on the network. "
                            "Review each one to ensure it is expected and necessary:\n"
                            "- Close ports for services you don't need\n"
                            "- For database services, restrict to localhost if possible\n"
                            "- Enable firewall rules to limit access by IP\n\n"
                            "Check which process is listening:\n"
                            "  lsof -i :{port}\n\n"
                            "Check all listening ports:\n"
                            "  lsof -iTCP -sTCP:LISTEN -nP"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_listening_ports(self) -> list[dict]:
        """
        Execute lsof to get listening ports.

        Returns list of dicts with keys: port (int), address (str), process (str), pid (int)
        Returns empty list on any failure.
        """
        try:
            result = subprocess.run(
                ["lsof", "-iTCP", "-sTCP:LISTEN", "-nP"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode != 0:
                return []

            ports = []
            lines = result.stdout.strip().split("\n")

            # Skip header line
            for line in lines[1:]:
                if not line.strip():
                    continue

                # Parse lsof output format
                # COMMAND  PID  USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
                # Example: sshd      123 root   4  IPv4  0x123456 0t0 TCP 0.0.0.0:22 (LISTEN)
                parts = line.split()
                if len(parts) < 9:
                    continue

                command = parts[0]
                # The NAME field is second to last (before (LISTEN))
                # parts[-2] is the address:port, parts[-1] is (LISTEN)
                name_field = parts[-2] if len(parts) > 8 else ""

                # Parse address:port from name field
                # Format is like: 0.0.0.0:8000 or 127.0.0.1:5432
                try:
                    if ":" in name_field:
                        addr_port = name_field.split(":")
                        address = addr_port[0]
                        port = int(addr_port[1])

                        ports.append({
                            "port": port,
                            "address": address,
                            "process": command,
                            "pid": int(parts[1]),
                        })
                except (ValueError, IndexError):
                    continue

            return ports

        except subprocess.TimeoutExpired:
            return []
        except FileNotFoundError:
            return []
        except Exception:
            return []
