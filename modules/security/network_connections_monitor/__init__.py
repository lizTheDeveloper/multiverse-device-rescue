import re
import shlex
from collections import defaultdict
from pathlib import Path

from rescue import command
from rescue import netaddr
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


# Known backdoor ports - should be flagged as CRITICAL
BACKDOOR_PORTS = {4444, 5555, 8080, 8888, 1337, 31337}

# Well-known legitimate ports that are expected
LEGITIMATE_PORTS = {80, 443, 53, 22, 993, 587}

# Remote ports normal for everyday software (5228 Google/FCM push, 5223 Apple push)
WELL_KNOWN_REMOTE_PORTS = {5228, 5223}

# Browsers legitimately hold hundreds of connections (tabs, extensions, helpers)
BROWSER_PREFIXES = (
    "google", "chrome", "safari", "firefox", "brave", "arc", "opera",
    "vivaldi", "msedge", "microsoft edge", "com.apple.webkit",
    "chromium",
)
BROWSER_CONNECTION_THRESHOLD = 300

# Developer tools and AI coding agents poll APIs and hold many sockets
DEV_TOOL_PREFIXES = ("node", "opencode", "claude", "python", "code", "cursor", "electron")
DEV_TOOL_CONNECTION_THRESHOLD = 60

DEFAULT_CONNECTION_THRESHOLD = 20


def _is_loopback(addr: str) -> bool:
    addr = addr.lower()
    if addr.startswith("::ffff:"):
        addr = addr[len("::ffff:"):]
    return addr in ("::1", "localhost") or addr.startswith("127.")


def _is_link_local_v6(addr: str) -> bool:
    return addr.lower().startswith("fe80")


_COLLECT_KEY = "rescue_conn_common_collect"


def _collect_module():
    return load_content_module("modules/network/conn_common/collect.py", _COLLECT_KEY)


def _match_name(process: str) -> str:
    """The lower-case program name without a Windows ".exe", for prefix matching."""
    name = process.lower()
    return name[:-4] if name.endswith(".exe") else name


def _threshold_for(process: str) -> int:
    name = _match_name(process)
    if name.startswith(BROWSER_PREFIXES):
        return BROWSER_CONNECTION_THRESHOLD
    if name.startswith(DEV_TOOL_PREFIXES):
        return DEV_TOOL_CONNECTION_THRESHOLD
    return DEFAULT_CONNECTION_THRESHOLD


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


def _numbered(steps: list[str]) -> str:
    return "\n".join(f"{n}. {step}" for n, step in enumerate(steps, 1))


def _backdoor_steps(platform: str) -> list[str]:
    if platform == "win32":
        return [
            "Open Resource Monitor (type \"Resource Monitor\" in the Start menu) and "
            "look on the Network tab for the program named above",
            "In Task Manager's Details tab, right-click the program and choose "
            "Open file location to see where it lives",
            "Right-click the file, choose Properties, and look at the Digital "
            "Signatures tab to see who made it",
            "Run a full scan with Windows Security",
            "If it looks suspicious, write down the name and location and ask a "
            "trusted professional before removing anything",
        ]
    if platform == "linux":
        return [
            "Run `ss -tnap` to see each connection with the program that opened it",
            "Run `ls -l /proc/<PID>/exe` to see where that program lives",
            "Run `dpkg -S <path>` or `rpm -qf <path>` to see whether a package "
            "installed it",
            "Run a full malware scan, for example with ClamAV",
            "If it looks suspicious, write down the name and location and ask a "
            "trusted professional before removing anything",
        ]
    return [
        "Use `lsof -p <PID>` to see all connections for this process",
        "Check the process binary: `ps -p <PID> -o comm=`",
        "Verify if the binary is signed: `codesign -v /path/to/binary`",
        "Check the process in Activity Monitor",
        "If it looks suspicious, write down the name and location and ask a "
        "trusted professional before removing anything",
        "Run a full malware scan",
    ]


def _high_count_steps(platform: str) -> list[str]:
    if platform == "win32":
        return [
            "Open Resource Monitor and look at the Network tab for the program",
            "In Task Manager's Details tab, right-click it and choose Open file "
            "location to see where it lives",
            "Look at the remote addresses it talks to in Resource Monitor",
            "If suspicious, research the program name and file online",
        ]
    if platform == "linux":
        return [
            "See the program's connections: `ss -tnap | grep pid=<PID>`",
            "Check what it is: `ps -p <PID> -o args=`",
            "Look at the remote addresses in the `ss` output",
            "If suspicious, research the program name and file online",
        ]
    return [
        "Check process details: `ps aux | grep <PID>`",
        "View connections: `lsof -p <PID>`",
        "Check remote IPs: `lsof -i -nP | grep <PID>`",
        "If suspicious, research the process name/binary",
    ]


def _unusual_port_steps(platform: str) -> list[str]:
    if platform == "win32":
        return [
            "Research the port number online",
            "Check if the program is expected to use this port",
            "In Resource Monitor's Network tab, look under TCP Connections for "
            "the program using the port",
            "Verify the remote IP/domain",
        ]
    if platform == "linux":
        return [
            "Research the port number online",
            "Check if the program is expected to use this port",
            "Run `ss -tnap` to see what is using the port",
            "Verify the remote IP/domain",
        ]
    return [
        "Research the port number online",
        "Check if the process is expected to use this port",
        "Use `lsof -i :<port>` to see what's using the port",
        "Verify the remote IP/domain",
    ]


def _unnamed_steps(platform: str) -> list[str]:
    if platform == "win32":
        return [
            "Open Resource Monitor (type \"Resource Monitor\" in the Start menu), "
            "go to the Network tab and look under TCP Connections",
            "To see every program's connections, run this check again as admin",
            "If a program there is unfamiliar, search for its name online",
        ]
    if platform == "linux":
        return [
            "Run `sudo ss -tnap` to see each connection with the program that opened it",
            "Or run this check again as an administrator",
            "If a program there is unfamiliar, search for its name online",
        ]
    return [
        "Run `sudo lsof -i -nP` to see every program's connections",
        "Or run this check again as an administrator",
        "If a program there is unfamiliar, search for its name online",
    ]


def _private_ip_how_to(platform: str) -> str:
    if platform == "win32":
        return (
            "To view them: open Resource Monitor, go to the Network tab and look "
            "under TCP Connections for remote addresses starting 10., 172.16 to "
            "172.31, or 192.168."
        )
    if platform == "linux":
        return (
            "Command to view all private IP connections:\n"
            "  ss -tnp | grep -E '(10\\.|172\\.|192\\.168)'"
        )
    return (
        "Command to view all private IP connections:\n"
        "  lsof -i -nP | grep -E '(10\\.|172\\.|192\\.168)'"
    )


def _monitor_steps(platform: str) -> list[str]:
    if platform == "win32":
        return [
            "Open Resource Monitor (type \"Resource Monitor\" in the Start menu) "
            "and go to the Network tab",
            "Task Manager's Performance tab shows live network use",
        ]
    if platform == "linux":
        return [
            "View all connections with their programs: `ss -tnap`",
            "Only established ones: `ss -tnap state established`",
        ]
    return [
        "View all connections: `netstat -anp tcp`",
        "View connections by process: `lsof -i -nP`",
        "Filter established: `netstat -anp tcp | grep ESTABLISHED`",
    ]


# --- connection items: what the game's clue shows for each connection --------
# Read-only and local: the connection list already gathered, one `ps` for the
# few flagged programs (macOS and Linux), and the Host/HostName/Port lines of
# ~/.ssh/config. Nothing else from the SSH settings is kept.

ITEMS_MAX = 20
# The flagged programs' parent and command line; the pids go on the end.
PS_ARGS = ["ps", "-o", "pid=,ppid=,command=", "-p"]
_COMMAND_MAX = 300
_SSH_CONFIG_MAX = 64 * 1024


def _listening(records: list[dict]) -> set:
    """(proto, local port) of every listening socket."""
    return {
        (r.get("proto"), r.get("local_port"))
        for r in records
        if r.get("state") == "LISTEN" and r.get("local_port")
    }


def _scope(addr: str | None) -> str:
    if netaddr.is_loopback(addr):
        return "this computer"
    return "public" if netaddr.is_public(addr) else "local network"


def _process_details(pids, platform: str) -> dict:
    """{pid: {"ppid", "command"}} from one `ps`; empty when it can't say."""
    pids = sorted({p for p in pids if isinstance(p, int) and p > 0})
    if not pids or platform not in ("darwin", "linux"):
        return {}
    result = command.run(
        [*PS_ARGS, ",".join(str(p) for p in pids)], timeout=5
    )
    if result.returncode != 0 or not result.stdout:
        return {}
    out = {}
    for line in result.stdout.splitlines():
        parts = line.split(None, 2)
        if len(parts) < 2 or not parts[0].isdigit() or not parts[1].isdigit():
            continue
        entry = {"ppid": int(parts[1])}
        summary = _command_summary(parts[2]) if len(parts) == 3 else None
        if summary:
            entry["command"] = summary
        out[int(parts[0])] = entry
    return out


# Keep less rather than redact more: command lines carry secrets in too many
# shapes (--password x, -pSECRET, sshpass -p x, user:pass@host…). Only the
# program's name is kept, plus, for ssh and its kin, the destination host and
# port (what ~/.ssh/config is matched on), or a script path a program runs.
_SSH_LIKE = {"ssh", "scp", "sftp", "mosh", "autossh"}
# Options that take a value, per program (man ssh, scp, sftp, autossh); mosh's
# short options are ssh's. The port option is -p for ssh, -P for scp and sftp.
_VALUE_OPTS = {
    "ssh": set("BbcDEeFIiJLlmOoPpQRSWw"),
    "mosh": set("BbcDEeFIiJLlmOoPpQRSWw"),
    "autossh": set("BbcDEeFIiJLlMmOoPpQRSWw"),
    "scp": set("cDFiJlLoPSX"),
    "sftp": set("BbcDFiJlLoPRSs"),
}
_PORT_OPT = {"scp": "P", "sftp": "P"}
_SCRIPT_EXTS = (".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".rb", ".pl", ".ps1")
_HOST_RE = re.compile(r"^(?:[A-Za-z0-9][A-Za-z0-9._-]*|\[[0-9A-Fa-f:.]+\])$")
_SSH_URL_RE = re.compile(r"^ssh://(?:[^@/]*@)?([^:/@]+|\[[0-9A-Fa-f:.]+\])(?::(\d{1,5}))?/?$")
_NONE = (None, None)


def _words(text: str) -> list[str]:
    try:
        return shlex.split(text)
    except ValueError:
        return text.split()


def _host_of(word: str, exe: str) -> tuple[str | None, str | None]:
    """(host, port in the word) for one destination word, or _NONE when it's unclear."""
    if word.startswith("ssh://"):
        m = _SSH_URL_RE.match(word)
        return (m.group(1), m.group(2)) if m and _HOST_RE.match(m.group(1)) else _NONE
    if "://" in word:
        return _NONE
    if exe in ("scp", "sftp"):
        word = word.split(":", 1)[0] if not word.startswith("[") else word
    host = word.rsplit("@", 1)[-1]  # never the user
    return (host, None) if _HOST_RE.match(host) else _NONE


def _ssh_destination(exe: str, args: list[str]) -> tuple[str | None, str | None]:
    """(host, port) from an ssh-like command line, parsed the way getopt does.

    Only the host and port are ever returned, never a user or an option's value.
    Anything unclear (a long option, two candidates for scp, odd characters)
    gives _NONE, and the summary is then the bare program name.
    """
    value_opts = _VALUE_OPTS.get(exe, _VALUE_OPTS["ssh"])
    port_opt = _PORT_OPT.get(exe, "p")
    port = None
    operands: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        i += 1
        if a == "--":
            operands.extend(args[i:])
            break
        if a.startswith("--"):
            return _NONE  # long options (mosh's) aren't parsed: keep nothing
        if a.startswith("-") and len(a) > 1:
            for j in range(1, len(a)):
                c = a[j]
                if c in value_opts:
                    value = a[j + 1:]
                    if not value:
                        if i >= len(args):
                            return _NONE
                        value = args[i]
                        i += 1
                    if c == port_opt:
                        if not value.isdigit():
                            return _NONE
                        port = value
                    break
                if not c.isalnum():
                    return _NONE
            continue
        operands.append(a)
        if exe not in ("scp", "sftp"):
            # ssh and its kin: the first operand is the destination; the rest is the remote command.
            operands.extend(args[i:])
            break
    if not operands:
        return _NONE
    if exe == "scp":
        remote = [w for w in operands if ":" in w and not w.startswith(("/", "./", "~"))]
        if len(remote) != 1:
            return _NONE
        dest = remote[0]
    else:
        dest = operands[0]
    host, url_port = _host_of(dest, exe)
    if host is None:
        return _NONE
    return host, url_port or port


def _command_summary(text: str) -> str | None:
    words = _words(text.strip())
    if not words:
        return None
    exe = words[0].rsplit("/", 1)[-1][:64]
    if not exe or not re.match(r"^[\w.+-]+$", exe):
        return None
    if exe in _SSH_LIKE:
        host, port = _ssh_destination(exe, words[1:])
        if host:
            return f"{exe} {host}" + (f" -p {port}" if port else "")
        return exe
    for w in words[1:]:
        if w.startswith("-"):
            continue
        if w.endswith(_SCRIPT_EXTS) and re.match(r"^[\w./~-]+$", w):
            return f"{exe} {w}"[:_COMMAND_MAX]
        break
    return exe


def _ssh_hosts() -> list[tuple[str, str, int]]:
    """(alias, HostName, Port) for each plain Host entry in ~/.ssh/config."""
    try:
        path = Path.home() / ".ssh" / "config"
        if not path.is_file() or path.stat().st_size > _SSH_CONFIG_MAX:
            return []
        text = path.read_text(errors="replace")
    except OSError:
        return []
    hosts: list[tuple[str, str, int]] = []
    aliases: list[str] = []
    fields: dict = {}

    def flush():
        for alias in aliases:
            if not any(ch in alias for ch in "*?!"):
                port = fields.get("port", "22")
                if port.isdigit():
                    hosts.append((alias, fields.get("hostname", alias), int(port)))

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.replace("=", " ", 1).partition(" ")
        key, value = key.lower(), value.strip().strip('"')
        if key in ("host", "match"):
            flush()
            aliases = value.split() if key == "host" else []
            fields = {}
        elif key in ("hostname", "port") and key not in fields:
            fields[key] = value
    flush()
    return hosts


def _ssh_host_for(item: dict, hosts) -> str | None:
    for alias, hostname, port in hosts:
        if port != item["remote_port"]:
            continue
        if hostname == item["remote_addr"]:
            return alias
        # A HostName that is a name, not an address: an `ssh <alias>` command line says which.
        words = item.get("command", "").split()
        if words and words[0].rsplit("/", 1)[-1] == "ssh" and alias in words[1:]:
            return alias
    return None


def connection_items(conns: list[dict], records: list[dict], platform: str) -> list[dict]:
    """One plain record per connection: direction, program, its parent and command, both ends."""
    conns = conns[:ITEMS_MAX]
    if not conns:
        return []
    listening = _listening(records)
    details = _process_details([c["pid"] for c in conns], platform)
    hosts = _ssh_hosts()
    items = []
    for c in conns:
        r = c["record"]
        item = {
            # A connection to a port this computer listens on came in; any other went out.
            "direction": "in" if (r.get("proto"), r.get("local_port")) in listening else "out",
            "process": c["process"],
            "pid": c["pid"],
            "proto": r.get("proto"),
            "local_addr": r.get("local_addr"),
            "local_port": r.get("local_port"),
            "remote_addr": c["remote_addr"],
            "remote_port": c["port"],
            "remote_scope": _scope(c["remote_addr"]),
            "state": c["state"],
        }
        item.update(details.get(c["pid"], {}))
        if item["direction"] == "out":
            alias = _ssh_host_for(item, hosts)
            if alias:
                item["ssh_host"] = alias
        items.append(item)
    return items


class Module(ModuleBase):
    name = "network_connections_monitor"
    category = "security"
    platforms = [Platform.DARWIN, Platform.LINUX, Platform.WIN32]
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
        "security.network_connections_monitor.couldnt_check",
        "security.network_connections_monitor.unnamed_connections",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []
        platform = profile.platform.value

        collect = _collect_module()
        if collect is None:
            return self._couldnt_check("The connection helper could not be loaded.")
        snap = collect.snapshot(platform, run=command.run, with_bytes=False)
        if snap["error"]:
            return self._couldnt_check(snap["error"])

        all_connections = self._connections(snap["records"])
        if not all_connections:
            return CheckResult(module_name=self.name, findings=findings)

        # A connection whose program this check couldn't see is noted below as
        # info; it never counts towards a warning about a named program.
        connections = [c for c in all_connections if c["process"] is not None]
        # Except a backdoor-port connection to another computer: that is
        # critical whoever owns it. One that stays on this computer (a local
        # notebook or dev server on 8888 or 8080) is not reaching anyone.
        def remote_backdoor(conn: dict) -> bool:
            return conn["port"] in BACKDOOR_PORTS and not _is_loopback(conn["remote_addr"])

        unseen = [
            c for c in all_connections
            if c["process"] is None and not remote_backdoor(c)
        ]

        # Check for connections on backdoor ports
        backdoor_connections = []
        backdoor_conns = []
        for conn in all_connections:
            if remote_backdoor(conn):
                backdoor_conns.append(conn)
                who = (
                    f"{conn['process']} (PID {conn['pid']})"
                    if conn["process"] is not None
                    else "program not visible"
                )
                backdoor_connections.append(f"{who} -> {conn['remote_addr']}:{conn['port']}")

        if backdoor_connections:
            findings.append(
                Finding(
                    title=(
                        f"Connections found on ports often used by malware ({len(backdoor_connections)})"
                    ),
                    description=(
                        f"We found {len(backdoor_connections)} active connection(s) using "
                        "port numbers that are frequently used by malicious software "
                        f"to control a computer from a distance:\n{chr(10).join(backdoor_connections)}\n\n"
                        "This is a serious sign that something on your computer may be "
                        "communicating with a bad actor. It is not normal for everyday "
                        "apps to use these specific ports.\n\n"
                        "What to do: Do not delete files yet. First, restart your computer "
                        "and run this check again to see if the connections return. If "
                        "they do, or if you suspect someone is spying on you, please "
                        "contact a professional for help before making changes."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    code="security.network_connections_monitor.backdoor_ports",
                    data={
                        "check": "backdoor_ports",
                        "connections": backdoor_connections,
                        "items": connection_items(backdoor_conns, snap["records"], platform),
                        "platform": platform,
                    },
                )
            )

        # Check for processes with many outbound connections (possible botnet)
        process_conn_count = defaultdict(list)
        for conn in connections:
            if _is_loopback(conn["remote_addr"]):
                continue  # talking to itself, not the network
            if conn["state"] == "ESTABLISHED":
                process_key = f"{conn['process']} (PID {conn['pid']})"
                process_conn_count[process_key].append(conn)

        high_conn_processes = []
        familiar_many = []
        for process_key, conns in process_conn_count.items():
            if len(conns) > _threshold_for(conns[0]["process"]):
                high_conn_processes.append(f"{process_key}: {len(conns)} connections")
            elif len(conns) > DEFAULT_CONNECTION_THRESHOLD:
                # The higher browser/developer limit applies only because of the
                # process NAME, which any program can choose. Keep it listed.
                familiar_many.append(f"{process_key}: {len(conns)} connections")

        if familiar_many:
            findings.append(
                Finding(
                    title=f"Programs with many network connections: {len(familiar_many)}",
                    description=(
                        "These programs have many open connections, which is normal for "
                        "web browsers and developer tools:\n"
                        f"{chr(10).join(familiar_many)}\n\n"
                        "This tool went by the program's name and has not verified who made it. "
                        "If you do not recognize one, look it up."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.network_connections_monitor.high_connection_count",
                    data={"check": "many_connections_familiar_name", "processes": familiar_many},
                )
            )

        if high_conn_processes:
            findings.append(
                Finding(
                    title=(
                        f"Programs with many open network connections ({len(high_conn_processes)})"
                    ),
                    description=(
                        "These programs are currently holding a large number of open "
                        f"network connections:\n{chr(10).join(high_conn_processes)}\n\n"
                        "This is often normal for web browsers, cloud sync tools, or "
                        "developer software that talk to many servers at once. However, "
                        "if you do not recognize a program name, it is worth checking "
                        "what it is.\n\n"
                        "What to do: Look up the program names listed above. If you recognize "
                        "them (like Safari, Chrome, or Dropbox), no action is needed. "
                        "If you do not recognize a name, search for it online to see "
                        "if it is a known app or something suspicious."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.network_connections_monitor.high_connection_count",
                    data={
                        "check": "high_connection_count",
                        "processes": high_conn_processes,
                        "platform": platform,
                    },
                )
            )

        # Check for connections on unusual ports from unknown processes
        unusual_port_connections = []
        unusual_conns = []
        push_port_connections = []
        claimed_connections = []
        for conn in connections:
            port = conn["port"]
            # Flag if on unusual port (not in legitimate list) and not a system port (< 1024)
            if _is_loopback(conn["remote_addr"]) or _is_link_local_v6(conn["remote_addr"]):
                continue  # stays on this computer or the local link
            # The operating system's own, verified traffic (Windows file sharing
            # and update sharing on the local network) is not worth a line.
            if collect.is_expected_outbound(platform, conn["record"]):
                continue
            if collect.claims_expected_outbound(platform, conn["record"]):
                claimed_connections.append(
                    f"{conn['process']} -> {conn['remote_addr']}:{port}"
                )
                continue
            if port in WELL_KNOWN_REMOTE_PORTS:
                # Push-notification ports are common, but a port number is chosen
                # by the program, so list these as info instead of skipping them.
                push_port_connections.append(
                    f"{conn['process']} -> {conn['remote_addr']}:{port}"
                )
                continue
            if port not in LEGITIMATE_PORTS and port not in BACKDOOR_PORTS:
                if port > 1024:  # Skip system ports
                    unusual_conns.append(conn)
                    unusual_port_connections.append(
                        f"{conn['process']} -> {conn['remote_addr']}:{port}"
                    )

        if claimed_connections:
            findings.append(
                Finding(
                    title=(
                        f"{len(claimed_connections)} connection(s) from a Windows service "
                        "whose location couldn't be confirmed"
                    ),
                    description=(
                        "These connections carry the name of a Windows service, and "
                        "Windows hides where the program lives unless the check runs "
                        "as admin. That is normal for Windows' own services on your "
                        "local network, but a name alone doesn't prove it:\n"
                        + "\n".join(claimed_connections[:20])
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.network_connections_monitor.unnamed_connections",
                    data={
                        "check": "unverified_service_connections",
                        "connections": claimed_connections,
                        "platform": platform,
                    },
                )
            )

        if push_port_connections:
            findings.append(
                Finding(
                    title=f"Connections for push notifications: {len(push_port_connections)}",
                    description=(
                        "Ports 5223 and 5228 are used for Apple and Google push notifications, "
                        "so this is normal for chat and mail apps:\n"
                        f"{chr(10).join(push_port_connections[:20])}\n\n"
                        "A port number does not prove who is using it; check that you "
                        "recognize the programs listed."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.network_connections_monitor.unusual_ports",
                    data={
                        "check": "push_port_connections",
                        "connections": push_port_connections,
                    },
                )
            )

        if unusual_port_connections:
            findings.append(
                Finding(
                    title=f"Connections on uncommon ports ({len(unusual_port_connections)})",
                    description=(
                        f"We found {len(unusual_port_connections)} connection(s) using "
                        f"port numbers that are not typically used by standard apps:\n{chr(10).join(unusual_port_connections[:20])}{chr(10) + '... and more' if len(unusual_port_connections) > 20 else ''}\n\n"
                        "Many legitimate apps use unusual ports for specific features, "
                        "so this is not automatically a sign of a problem. However, it "
                        "is good to verify that you recognize the programs listed.\n\n"
                        "What to do: Check the program names in the list. If you recognize "
                        "them, you can ignore this. If you see a program you do not know, "
                        "look it up to confirm it is safe."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.network_connections_monitor.unusual_ports",
                    data={
                        "check": "unusual_ports",
                        "connections": unusual_port_connections,
                        "items": connection_items(unusual_conns, snap["records"], platform),
                        "platform": platform,
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
                    title=(
                        f"Connections to local network addresses: {len(private_ip_connections)}"
                    ),
                    description=(
                        f"Found {len(private_ip_connections)} connection(s) to private IP ranges:\n"
                        f"{chr(10).join(private_ip_connections[:15])}"
                        f"{chr(10) + '... and more' if len(private_ip_connections) > 15 else ''}\n\n"
                        "These may be legitimate internal network connections."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.network_connections_monitor.private_ip_connections",
                    data={
                        "check": "private_ip_connections",
                        "count": len(private_ip_connections),
                        "platform": platform,
                    },
                )
            )

        if unseen:
            lines = [
                f"{c['record'].get('proto')} local port {c['record'].get('local_port')} "
                f"-> {c['remote_addr']}:{c['port']}"
                for c in unseen
            ]
            findings.append(
                Finding(
                    title=f"{len(unseen)} connection(s) whose program couldn't be seen",
                    description=(
                        "This check couldn't see which program owns these connections "
                        "without admin rights, so it can't say whether they are "
                        f"expected: {'; '.join(lines[:20])}"
                        f"{' and more' if len(lines) > 20 else ''}."
                        + (
                            "\n\n" + " ".join(snap["limits"])
                            if snap["limits"] else ""
                        )
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.network_connections_monitor.unnamed_connections",
                    data={
                        "check": "unnamed_connections",
                        "count": len(unseen),
                        "connections": lines,
                        "limits": list(snap["limits"]),
                        "platform": platform,
                    },
                )
            )

        # Summary report
        if all_connections:
            findings.append(
                Finding(
                    title=f"Current network connections: {len(all_connections)}",
                    description=(
                        f"System has {len(all_connections)} active network connection(s). "
                        f"Review above findings for any suspicious activity."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.network_connections_monitor.connection_summary",
                    data={
                        "check": "connection_summary",
                        "total_count": len(all_connections),
                        "platform": platform,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

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
                    code="security.network_connections_monitor.couldnt_check",
                    data={"check": "couldnt_check", "reason": reason},
                )
            ],
        )

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")
            platform = finding.data.get("platform", "darwin")

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
                            + _numbered(_backdoor_steps(platform))
                            + "\n\nDo not remove anything without investigating first, "
                            "as it may be legitimate development/testing."
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
                            f"Programs with many open connections:\n{proc_str}\n\n"
                            "This may indicate:\n"
                            "- Botnet/malware activity\n"
                            "- Network scanner/port scanner\n"
                            "- Legitimate high-traffic service\n\n"
                            "To investigate:\n"
                            + _numbered(_high_count_steps(platform))
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
                            + _numbered(_unusual_port_steps(platform))
                            + "\n\nCommon suspicious ports: 4444, 5555, 8080, 8888, 1337, 31337"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )

            elif check in ("unnamed_connections", "unverified_service_connections"):
                connections = finding.data.get("connections", [])
                conn_str = "\n".join(connections[:5])
                if len(connections) > 5:
                    conn_str += f"\n... and {len(connections) - 5} more"
                actions.append(
                    Action(
                        title="Find out which program owns connections this check couldn't see",
                        description=(
                            f"Connections with no program name:\n{conn_str}\n\n"
                            "To find out who owns them:\n"
                            + _numbered(_unnamed_steps(platform))
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
                            "3. The programs making these connections are expected\n\n"
                            + _private_ip_how_to(platform)
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
                            "Ways to look at them:\n"
                            + _numbered(_monitor_steps(platform))
                            + "\n\nReview regularly for unauthorized outbound connections."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _connections(self, records: list[dict]) -> list[dict]:
        """The open (not just listening) connections, in the shape check() uses."""
        connections = []
        for record in records:
            remote = record.get("remote_addr")
            port = record.get("remote_port")
            if not remote or not port or record.get("state") == "LISTEN":
                continue
            connections.append(
                {
                    "process": record.get("process"),
                    "pid": record.get("pid"),
                    "remote_addr": remote,
                    "port": port,
                    "state": record.get("state") or "ESTABLISHED",
                    "record": record,
                }
            )
        return connections
