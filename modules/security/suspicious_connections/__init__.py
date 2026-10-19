import ctypes
import ctypes.util
import os
import posixpath
from collections import defaultdict

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

_COLLECT_KEY = "rescue_conn_common_collect"

# Shown in place of a program's name when the collector couldn't see it.
_UNNAMED = "a program this check couldn't see"


def _collect_module():
    return load_content_module("modules/network/conn_common/collect.py", _COLLECT_KEY)


def _listen_what_to_do(platform: str, process: str) -> str:
    if platform == "win32":
        return (
            f"What to do: If you recognize {process}, you can likely ignore this. If you "
            "do not recognize it, open Resource Monitor (type \"Resource Monitor\" in "
            "the Start menu), go to the Network tab and look under Listening Ports to "
            "see where the program lives. Then check Windows Security > Firewall & "
            "network protection > Allow an app through firewall to make sure it is not "
            "allowed through, or look up the app name to see if it is a known remote "
            "access tool."
        )
    if platform == "linux":
        return (
            f"What to do: If you recognize {process}, you can likely ignore this. If you "
            "do not recognize it, run `ss -tlnp` in a terminal to see which program has "
            "the port open, check that your firewall does not allow it in, or look up "
            "the app name to see if it is a known remote access tool."
        )
    return (
        f"What to do: If you recognize {process}, you can likely ignore "
        "this. If you do not recognize it, check your System Settings "
        "> Network > Firewall to ensure it is not allowed through, or "
        "look up the app name to see if it is a known remote access tool."
    )


def _outbound_what_to_do(platform: str, process: str) -> str:
    if platform == "win32":
        return (
            f"What to do: If you do not recognize {process}, search for its name online "
            "to see if it is a known app. To see where it lives, open Task Manager, go "
            f"to the Details tab, right-click {process} and choose Open file location."
        )
    if platform == "linux":
        return (
            f"What to do: If you do not recognize {process}, search for its name online "
            "to see if it is a known app. Running `ss -tnp` in a terminal shows each "
            "connection with the program that opened it."
        )
    return (
        f"What to do: If you do not recognize {process}, search for its "
        "name online to see if it is a known app. If you are unsure, "
        "you can quit the app to stop the connection and see if it restarts "
        "on its own."
    )




class Module(ModuleBase):
    name = "suspicious_connections"
    category = "security"
    platforms = [Platform.DARWIN, Platform.LINUX, Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 55
    depends_on = []
    estimated_duration = "3s"

    emits_codes = [
        "security.suspicious_connections.unusual_listening_port",
        "security.suspicious_connections.unusual_outbound_connection",
        "security.suspicious_connections.high_connection_count",
        "security.suspicious_connections.couldnt_check",
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

        connections = self._connections(snap["records"])

        # Unusual listening ports: only listeners reachable from the network
        # matter. Loopback-only listeners are summarised in one info line.
        listen_by_proc: dict[tuple, dict] = {}
        loopback_listeners: dict[str, set] = defaultdict(set)
        unnamed_listeners: list[dict] = []
        for conn in connections:
            if conn["type"] != "LISTEN":
                continue
            port = conn["port"]
            if not port or self._is_standard_port(port):
                continue
            if self._is_loopback_host(conn["local_host"]):
                loopback_listeners[conn["process"] or _UNNAMED].add(port)
                continue
            verdict = self.listening_verdict(platform, conn["record"])
            if verdict == "expected":
                continue
            if verdict == "unnamed":
                unnamed_listeners.append(
                    {"process": conn["process"], "pid": conn["pid"], "port": port}
                )
                continue
            entry = listen_by_proc.setdefault(
                (conn["process"], conn["pid"]), {"ports": set()}
            )
            entry["ports"].add(port)

        for (process, pid), entry in listen_by_proc.items():
            ports = sorted(entry["ports"])
            port_text = ", ".join(str(p) for p in ports)
            findings.append(
                Finding(
                    title=(
                        f"{process} is waiting for connections from other devices on port "
                        f"{port_text}"
                    ),
                    description=(
                        "Your computer is currently listening for connections from other "
                        f"devices on port {port_text} via the program {process}.\n\n"
                        "This is often normal for developer tools, file-sharing apps, "
                        f"or remote access software. However, if you did not install {process} "
                        "or do not remember turning on a feature that allows others to "
                        "connect to your computer, it could be a sign that someone else "
                        "has access.\n\n"
                        + _listen_what_to_do(platform, process)
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
                        "platform": platform,
                    },
                )
            )

        if unnamed_listeners:
            findings.append(
                Finding(
                    title=(
                        f"{len(unnamed_listeners)} listening port(s) whose program "
                        "couldn't be confirmed"
                    ),
                    description=self._unnamed_description(platform, unnamed_listeners),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.suspicious_connections.unusual_listening_port",
                    data={
                        "check": "unnamed_listeners",
                        "items": unnamed_listeners,
                        "limits": list(snap["limits"]),
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
        familiar: dict[tuple, dict] = {}
        unnamed_out = 0
        for conn in connections:
            if conn["type"] != "ESTABLISHED":
                continue
            port = conn["port"]
            if not port or self._is_standard_port(port):
                continue
            if self._is_loopback_host(conn["local_host"]) and self._is_loopback_host(
                conn.get("remote_host") or conn["local_host"]
            ):
                continue
            # Only an Apple-signed program in a SIP folder is skipped outright.
            if platform == "darwin" and self._is_apple_system_process(conn["pid"]):
                continue
            # Without a program name there is nothing to look up; counted below.
            if conn["process"] is None:
                unnamed_out += 1
                continue
            # A familiar process name or a push-notification port is shown to
            # the person, but is not a reason to treat the connection as odd.
            # Both are chosen by the program, so they never hide it.
            bucket = (
                familiar
                if port in WELL_KNOWN_REMOTE_PORTS or self._is_known_safe_process(conn["process"])
                else out_by_proc
            )
            entry = bucket.setdefault((conn["process"], conn["pid"]), {"ports": set()})
            entry["ports"].add(port)

        if familiar:
            items = [
                {"process": proc, "pid": pid, "ports": sorted(e["ports"])}
                for (proc, pid), e in familiar.items()
            ]
            names = sorted({i["process"] for i in items})
            findings.append(
                Finding(
                    title=(
                        f"{len(items)} connection(s) from familiar-looking programs on "
                        "uncommon ports"
                    ),
                    description=(
                        "These programs use a familiar name or a port used for push "
                        f"notifications: {', '.join(names)}. That is normal for browsers, "
                        "chat apps and developer tools. This tool has not verified who "
                        "made them, because a program can pick any name."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.suspicious_connections.unusual_outbound_connection",
                    data={"check": "familiar_connections", "items": items},
                )
            )

        for (process, pid), entry in out_by_proc.items():
            ports = sorted(entry["ports"])
            port_text = ", ".join(str(p) for p in ports)
            findings.append(
                Finding(
                    title=(
                        f"{process} is sending data to another computer on port {port_text}"
                    ),
                    description=(
                        f"The program {process} is currently sending data to another computer "
                        f"using port {port_text}.\n\n"
                        "This is not a standard port for common services like web browsing. "
                        "Many legitimate apps (like cloud backups or chat apps) use unusual "
                        "ports, so this is not automatically a sign of a problem. However, "
                        f"if you do not recognize {process}, it is worth checking what "
                        "it is.\n\n"
                        + _outbound_what_to_do(platform, process)
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
                        "platform": platform,
                    },
                )
            )

        if unnamed_out:
            findings.append(
                Finding(
                    title=(
                        f"{unnamed_out} connection(s) on uncommon ports from programs this "
                        "check couldn't see"
                    ),
                    description=(
                        "This check couldn't see which program owns these connections "
                        "without admin rights, so it can't say whether they are expected. "
                        + " ".join(snap["limits"])
                    ).strip(),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.suspicious_connections.unusual_outbound_connection",
                    data={"check": "unnamed_connections", "count": unnamed_out},
                )
            )

        # Check for high connection counts per process (potential C2 beaconing)
        connection_counts = self._count_connections_by_process(
            [
                c for c in connections
                if c["process"] is not None
                and not (
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

    def listening_verdict(self, platform: str, record: dict) -> str:
        """Decide whether a listener deserves a warning.

        ``"expected"``: not worth raising (a standard port, localhost only, or
        a service the operating system itself runs). ``"unnamed"``: the owner
        couldn't be confirmed, which is noted as info and never warned about.
        ``"flag"``: a warning. ``check()`` and the connection watch both use
        this, so they agree.
        """
        port = record.get("local_port")
        if not port or self._is_standard_port(port):
            return "expected"
        if self._is_loopback_host(record.get("local_addr")):
            return "expected"
        if platform == "darwin":
            if record.get("pid") is not None and self._is_apple_system_process(record["pid"]):
                return "expected"
        else:
            collect = _collect_module()
            if collect is not None:
                if collect.is_expected_listener(platform, record):
                    return "expected"
                if collect.claims_expected_service(platform, record):
                    return "unnamed"
        if record.get("process") is None:
            return "unnamed"
        return "flag"

    def _unnamed_description(self, platform: str, items: list[dict]) -> str:
        unseen = sorted({i["port"] for i in items if i["process"] is None})
        claimed = [i for i in items if i["process"] is not None]
        parts = []
        if unseen:
            parts.append(
                "This check couldn't see which program owns the listening port(s) "
                f"{', '.join(str(p) for p in unseen)} without admin rights, so it can't "
                "say whether they are expected."
            )
        if claimed:
            names = sorted({i["process"] for i in claimed})
            ports = sorted({i["port"] for i in claimed})
            parts.append(
                "This check couldn't confirm which program owns the listening port(s) "
                f"{', '.join(str(p) for p in ports)}. They carry the name of a Windows "
                f"service ({', '.join(names)}) and Windows hides where the program lives "
                "unless the check runs as admin. That is normal for Windows' own "
                "services, but a name alone doesn't prove it."
            )
        if platform == "linux":
            parts.append("An administrator can see every owner with `ss -tlnp`.")
        elif platform == "win32":
            parts.append(
                "Resource Monitor's Network tab, under Listening Ports, shows each "
                "program and where it lives."
            )
        return "\n\n".join(parts)

    def _couldnt_check(self, reason: str) -> CheckResult:
        return CheckResult(
            module_name=self.name,
            findings=[
                Finding(
                    title="Couldn't check this computer's network connections",
                    description=(
                        "This check couldn't read the list of network connections, so "
                        "it hasn't checked anything. That is not the same as a clean "
                        f"result. {reason}"
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.suspicious_connections.couldnt_check",
                    data={"check": "couldnt_check", "reason": reason},
                )
            ],
        )

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

    def _connections(self, records: list[dict]) -> list[dict]:
        """The listening and established TCP connections, in the shape check() uses.

        For an established connection the port of interest is the remote one.
        """
        connections = []
        for record in records:
            state = record.get("state")
            if record.get("proto") != "tcp" or state not in ("LISTEN", "ESTABLISHED"):
                continue
            remote = record.get("remote_addr")
            port = record.get("remote_port") if remote else record.get("local_port")
            if not port:
                continue
            connections.append(
                {
                    "process": record.get("process"),
                    "pid": record.get("pid"),
                    "type": state,
                    "port": port,
                    "local_host": record.get("local_addr") or "",
                    "remote_host": remote,
                    "record": record,
                }
            )
        return connections

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
