import ctypes
import ctypes.util
import os
import posixpath
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


# Remote ports that are normal for everyday software
# (5228: Google/FCM push, 5223: Apple push)
WELL_KNOWN_REMOTE_PORTS = {5228, 5223}

# Executables under these prefixes are shipped with macOS
APPLE_SYSTEM_PREFIXES = ("/System/", "/usr/libexec/")


class Module(ModuleBase):
    name = "suspicious_connections"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 55
    depends_on = []
    estimated_duration = "3s"

    emits_codes = [
        "security.suspicious_connections.unusual_listening_port",
        "security.suspicious_connections.unusual_outbound_connection",
        "security.suspicious_connections.high_connection_count",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        try:
            lsof_output = self._run_lsof()
        except OSError as e:
            # lsof might not be available or require sudo
            return CheckResult(module_name=self.name, findings=[])

        # Parse lsof output
        connections = self._parse_lsof_output(lsof_output)


        # Unusual listening ports: only listeners reachable from the network
        # matter. Loopback-only listeners are summarised in one info line.
        listen_by_proc: dict[tuple, dict] = {}
        loopback_listeners: dict[str, set] = defaultdict(set)
        for conn in connections:
            if conn["type"] != "LISTEN":
                continue
            port = conn["port"]
            if not port or self._is_standard_port(port):
                continue
            if self._is_loopback_host(conn["local_host"]):
                loopback_listeners[conn["process"]].add(port)
                continue
            if self._is_apple_system_process(conn["pid"]):
                continue
            entry = listen_by_proc.setdefault(
                (conn["process"], conn["pid"]), {"ports": set()}
            )
            entry["ports"].add(port)

        for (process, pid), entry in listen_by_proc.items():
            ports = sorted(entry["ports"])
            port_text = ", ".join(str(p) for p in ports)
            plural = "ports" if len(ports) > 1 else "port"
            findings.append(
                Finding(
                    title=f"Unusual listening {plural} {port_text} by {process}",
                    description=(
                        f"Process {process} (PID {pid}) is accepting connections from "
                        f"other devices on your network on {plural} {port_text}. Many "
                        f"developer tools and sync apps do this on purpose. If you do "
                        f"not recognize {process}, check where it came from."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.suspicious_connections.unusual_listening_port",
                    data={
                        "check": "unusual_listening_port",
                        "pid": pid,
                        "process": process,
                        "port": ports[0],
                        "ports": ports,
                    },
                )
            )

        if loopback_listeners:
            names = sorted(loopback_listeners)
            total = sum(len(v) for v in loopback_listeners.values())
            findings.append(
                Finding(
                    title=f"{total} local-only service port(s) in use",
                    description=(
                        "These programs listen only on this computer (localhost), so "
                        "nothing on your network or the internet can reach them: "
                        + ", ".join(names) + "."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.suspicious_connections.unusual_listening_port",
                    data={
                        "check": "loopback_listeners",
                        "processes": names,
                        "count": total,
                    },
                )
            )

        # Unusual established connections, one finding per process
        out_by_proc: dict[tuple, dict] = {}
        for conn in connections:
            if conn["type"] != "ESTABLISHED":
                continue
            port = conn["port"]
            if not port or self._is_standard_port(port) or port in WELL_KNOWN_REMOTE_PORTS:
                continue
            if self._is_loopback_host(conn["local_host"]) and self._is_loopback_host(
                conn.get("remote_host") or conn["local_host"]
            ):
                continue
            if self._is_known_safe_process(conn["process"]):
                continue
            if self._is_apple_system_process(conn["pid"]):
                continue
            entry = out_by_proc.setdefault(
                (conn["process"], conn["pid"]), {"ports": set()}
            )
            entry["ports"].add(port)

        for (process, pid), entry in out_by_proc.items():
            ports = sorted(entry["ports"])
            port_text = ", ".join(str(p) for p in ports)
            findings.append(
                Finding(
                    title=f"Unusual outbound connection on port {port_text} from {process}",
                    description=(
                        f"Process {process} (PID {pid}) has connections to port "
                        f"{port_text} on another machine, which is not a common service "
                        f"port. Plenty of normal software does this; if you do not "
                        f"recognize {process}, it is worth a closer look."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.suspicious_connections.unusual_outbound_connection",
                    data={
                        "check": "unusual_outbound_connection",
                        "pid": pid,
                        "process": process,
                        "port": ports[0],
                        "ports": ports,
                    },
                )
            )

        # Check for high connection counts per process (potential C2 beaconing)
        connection_counts = self._count_connections_by_process(
            [
                c for c in connections
                if not (
                    self._is_loopback_host(c["local_host"])
                    and self._is_loopback_host(c.get("remote_host") or c["local_host"])
                )
            ]
        )
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
                        code="security.suspicious_connections.high_connection_count",
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

            # NAME is "local" or "local->remote". For established connections
            # the port of interest is the remote one.
            name = parts[8] if len(parts) > 8 else ""
            local_addr, _, remote_addr = name.partition("->")
            target = remote_addr or local_addr
            port = self._extract_port(target)

            if port:
                connections.append(
                    {
                        "process": process,
                        "pid": int(pid) if pid.isdigit() else pid,
                        "type": connection_state,
                        "port": port,
                        "local_addr": local_addr,
                        "local_host": self._extract_host(local_addr),
                        "remote_host": self._extract_host(remote_addr) if remote_addr else None,
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

    @staticmethod
    def _extract_host(addr: str) -> str:
        host = addr.rsplit(":", 1)[0] if ":" in addr else addr
        return host.strip("[]")

    @staticmethod
    def _is_loopback_host(host: str | None) -> bool:
        if not host:
            return False
        return host in ("::1", "localhost") or host.startswith("127.")

    @staticmethod
    def _kernel_path(pid) -> str | None:
        """Executable path reported by the kernel (libproc proc_pidpath).

        Unlike the ps/lsof command name this cannot be set by the process.
        None means unknown, which is never trusted.
        """
        try:
            lib = ctypes.CDLL(
                ctypes.util.find_library("proc") or "/usr/lib/libproc.dylib", use_errno=True
            )
            buf = ctypes.create_string_buffer(4096)
            n = lib.proc_pidpath(int(pid), buf, ctypes.c_uint32(len(buf)))
            return buf.value.decode("utf-8", "surrogateescape") if n > 0 else None
        except Exception:
            return None

    def _apple_signed(self, path: str) -> bool:
        """True if ``path`` verifies against Apple's anchor. Cached per path."""
        cache = self.__dict__.setdefault("_apple_sig_cache", {})
        if path not in cache:
            from rescue import command

            res = command.run(
                ["/usr/bin/codesign", "--verify", "--strict", "-R=anchor apple", path],
                timeout=5,
            )
            cache[path] = res.ok
        return cache[path]

    def _is_apple_system_process(self, pid) -> bool:
        """Apple daemon = kernel path in a SIP directory AND a valid Apple signature.

        Names and ps paths are attacker-controlled and are not consulted.
        """
        key = ("_apple_proc", str(pid))
        cache = self.__dict__.setdefault("_apple_proc_cache", {})
        if key in cache:
            return cache[key]
        verdict = False
        kpath = self._kernel_path(pid)
        if kpath:
            real = posixpath.normpath(os.path.realpath(kpath))
            if real.startswith(APPLE_SYSTEM_PREFIXES):
                verdict = self._apple_signed(real)
        cache[key] = verdict
        return verdict

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
