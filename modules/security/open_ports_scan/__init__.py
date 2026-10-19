from rescue import command
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
from rescue.runtime import load_content_module


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

# Addresses that mean "every network this computer is on"
ALL_INTERFACES = {"0.0.0.0", "*", "::"}

_COLLECT_KEY = "rescue_conn_common_collect"

# How to see which program holds a port, per platform
_LOOKUP_HELP = {
    "darwin": (
        "Check which process is listening:\n"
        "  lsof -i :<port>\n\n"
        "Check all listening ports:\n"
        "  lsof -iTCP -sTCP:LISTEN -nP"
    ),
    "linux": (
        "Check all listening ports and their programs:\n"
        "  ss -tlnp\n"
        "(Programs that belong to other accounts show only when an administrator runs it.)"
    ),
    "win32": (
        "Check which program holds each port: open Resource Monitor (type "
        "\"Resource Monitor\" in the Start menu), go to the Network tab and look "
        "under Listening Ports. Task Manager's Details tab shows the same program "
        "by its PID."
    ),
}


def _collect_module():
    return load_content_module("modules/network/conn_common/collect.py", _COLLECT_KEY)


class Module(ModuleBase):
    name = "open_ports_scan"
    category = "security"
    platforms = [Platform.DARWIN, Platform.LINUX, Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "3s"

    emits_codes = [
        "security.open_ports_scan.exposed_risky_ports",
        "security.open_ports_scan.listening_ports",
        "security.open_ports_scan.couldnt_check",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []
        platform = profile.platform.value

        collect = _collect_module()
        if collect is None:
            return self._couldnt_check("The connection helper could not be loaded.")
        snap = collect.snapshot(platform, run=command.run)
        if snap["error"]:
            return self._couldnt_check(snap["error"])

        listening_ports = self._listening_ports(snap["records"])

        if not listening_ports:
            return CheckResult(module_name=self.name, findings=findings)

        # Flag WARNING for risky ports exposed to 0.0.0.0. A listener whose
        # program couldn't be seen is listed below instead (info), since this
        # check can't say what it is.
        exposed_risky = []
        for port_info in listening_ports:
            port = port_info["port"]
            address = port_info["address"]
            process = port_info["process"]

            # Check if risky database port is exposed to all interfaces
            if port in RISKY_PORTS and address in ALL_INTERFACES and process is not None:
                exposed_risky.append(
                    f"{port} ({process}) listening on {address}"
                )

        if exposed_risky:
            findings.append(
                Finding(
                    title=(
                        f"A database service is open to your network ({len(exposed_risky)} found)"
                    ),
                    description=(
                        f"We found {len(exposed_risky)} service(s) that are open to your "
                        f"entire network, not just your own computer:\n{chr(10).join(exposed_risky)}\n\n"
                        "This means other devices on your Wi-Fi or home network could "
                        "potentially connect to these services. Usually, these should "
                        "only be reachable by your own computer.\n\n"
                        "What to do: Check if you actually need remote access to these "
                        "services. If you do not, open the app that uses the port and "
                        "look for a setting to 'Listen on localhost only' or 'Local network "
                        "only' and turn it on."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.open_ports_scan.exposed_risky_ports",
                    data={
                        "check": "exposed_risky_ports",
                        "ports": exposed_risky,
                        "platform": platform,
                    },
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
                f"Port {port} ({service_name}) - "
                f"{process or 'program not visible'} on {address}"
            )

        unseen = sum(1 for p in listening_ports if p["process"] is None)
        if all_ports_info:
            note = ""
            if unseen:
                note = (
                    f"\n\nThis check couldn't see which program owns {unseen} of these "
                    "without admin rights, so it can't say whether they are expected."
                )
            findings.append(
                Finding(
                    title=f"Open ports: {len(all_ports_info)}",
                    description=(
                        f"Found {len(all_ports_info)} listening port(s):\n"
                        f"{chr(10).join(all_ports_info)}{note}"
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.open_ports_scan.listening_ports",
                    data={
                        "check": "listening_ports",
                        "count": len(all_ports_info),
                        "ports": all_ports_info,
                        "unseen": unseen,
                        "platform": platform,
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
                lookup = _LOOKUP_HELP.get(
                    finding.data.get("platform", "darwin"), _LOOKUP_HELP["darwin"]
                )
                actions.append(
                    Action(
                        title=f"Review {count} listening port(s)",
                        description=(
                            f"You have {count} service(s) listening on the network. "
                            "Review each one to ensure it is expected and necessary:\n"
                            "- Close ports for services you don't need\n"
                            "- For database services, restrict to localhost if possible\n"
                            "- Enable firewall rules to limit access by IP\n\n"
                            + lookup
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _listening_ports(self, records: list[dict]) -> list[dict]:
        """TCP listeners as dicts with keys: port, address, process (None if unseen), pid."""
        ports = []
        for record in records:
            if record.get("proto") != "tcp" or record.get("state") != "LISTEN":
                continue
            if record.get("local_port") is None:
                continue
            ports.append({
                "port": record["local_port"],
                "address": record.get("local_addr") or "*",
                "process": record.get("process"),
                "pid": record.get("pid"),
            })
        return ports

    def _couldnt_check(self, reason: str) -> CheckResult:
        return CheckResult(
            module_name=self.name,
            findings=[
                Finding(
                    title="Couldn't check which ports are open",
                    description=(
                        "This check couldn't read the list of listening ports, so it "
                        "hasn't checked anything. That is not the same as a clean "
                        f"result. {reason}"
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.open_ports_scan.couldnt_check",
                    data={"check": "couldnt_check", "reason": reason},
                )
            ],
        )
