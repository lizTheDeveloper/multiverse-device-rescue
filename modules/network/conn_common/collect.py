"""One read-only view of this computer's network connections, on every platform.

macOS reads ``lsof``, Linux reads ``ss`` and Windows reads PowerShell's
``Get-NetTCPConnection``. Each is turned into the same record shape so the
checks above this file never care which system they are on.

Parsers are pure functions over text. ``snapshot`` and ``dns_cache`` take the
command runner as an argument so tests can hand them canned output. Every
command has a timeout, every parse failure degrades to "nothing found", and a
command that could not run is reported as ``error`` (never as an empty, clean
result).
"""

from __future__ import annotations

import ipaddress
import json
import os
import re

from rescue import command

_TIMEOUT = 30

LSOF_ARGS = ["lsof", "-i", "-n", "-P"]
NETTOP_ARGS = ["nettop", "-P", "-L", "1", "-n", "-x", "-J", "bytes_in,bytes_out"]
SS_ARGS = ["ss", "-tunapH"]
SS_BYTES_ARGS = ["ss", "-tniH"]

# One PowerShell run prints three JSON documents, one per line: TCP, UDP, processes.
_WIN_SCRIPT = (
    "$t = Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,"
    "RemotePort,State,OwningProcess | ConvertTo-Json -Compress; "
    "$u = Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,OwningProcess "
    "| ConvertTo-Json -Compress; "
    "$p = Get-Process | Select-Object Id,ProcessName,Path | ConvertTo-Json -Compress; "
    "Write-Output \"$t\"; Write-Output \"$u\"; Write-Output \"$p\""
)
_WIN_DNS_SCRIPT = (
    "Get-DnsClientCache | Select-Object Entry,Type | ConvertTo-Json -Compress"
)


WIN_ARGS = ["powershell", "-NoProfile", "-NonInteractive", "-Command", _WIN_SCRIPT]
WIN_DNS_ARGS = ["powershell", "-NoProfile", "-NonInteractive", "-Command", _WIN_DNS_SCRIPT]


# --- records ---------------------------------------------------------------


def _record(
    proto: str,
    state: str | None,
    local_addr: str | None,
    local_port: int | None,
    remote_addr: str | None,
    remote_port: int | None,
    pid: int | None,
    process: str | None,
    exe: str | None = None,
) -> dict:
    return {
        "proto": proto,
        "state": state,
        "local_addr": local_addr,
        "local_port": local_port,
        "remote_addr": remote_addr,
        "remote_port": remote_port,
        "pid": pid,
        "process": process,
        "exe": exe,
    }


def _to_int(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _split_endpoint(text: str) -> tuple[str | None, int | None]:
    """Split ``1.2.3.4:443``, ``[2001:db8::1]:443`` or ``*:*`` into (addr, port)."""
    text = text.strip()
    if text.startswith("["):
        addr, _, rest = text[1:].partition("]")
        port_text = rest.lstrip(":")
    else:
        addr, _, port_text = text.rpartition(":")
    addr = addr.split("%", 1)[0]
    return (addr or None), _to_int(port_text)


def _is_unset(addr: str | None, port: int | None) -> bool:
    return addr in (None, "", "*", "0.0.0.0", "::") and not port


# --- macOS: lsof / nettop --------------------------------------------------


def _lsof_name(raw: str) -> str:
    # lsof escapes spaces and other bytes in command names as \xNN.
    return re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), raw)


def parse_lsof(text: str) -> list[dict]:
    records: list[dict] = []
    for line in (text or "").splitlines():
        parts = line.split()
        # COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME [(STATE)]
        if len(parts) < 9 or parts[7] not in ("TCP", "UDP"):
            continue
        pid = _to_int(parts[1])
        if pid is None:
            continue
        proto = parts[7].lower()
        name = parts[8]
        state = None
        if len(parts) > 9 and parts[9].startswith("(") and parts[9].endswith(")"):
            state = parts[9][1:-1].upper()
        local_text, arrow, remote_text = name.partition("->")
        local_addr, local_port = _split_endpoint(local_text)
        remote_addr, remote_port = (None, None)
        if arrow:
            remote_addr, remote_port = _split_endpoint(remote_text)
        records.append(
            _record(
                proto, state, local_addr, local_port, remote_addr, remote_port,
                pid, _lsof_name(parts[0]),
            )
        )
    return records


def parse_nettop(text: str) -> dict[int, tuple[int, int]]:
    """Parse ``nettop -P -x -J bytes_in,bytes_out``: rows are ``name.pid,in,out,``."""
    totals: dict[int, tuple[int, int]] = {}
    for line in (text or "").splitlines():
        cols = line.split(",")
        if len(cols) < 3:
            continue
        pid = _to_int(cols[0].rsplit(".", 1)[-1]) if "." in cols[0] else None
        bytes_in, bytes_out = _to_int(cols[1]), _to_int(cols[2])
        if pid is None or bytes_in is None or bytes_out is None:
            continue
        totals[pid] = (bytes_in, bytes_out)
    return totals


# --- Linux: ss -------------------------------------------------------------

_SS_STATES = {"ESTAB": "ESTABLISHED"}
_SS_USERS = re.compile(r'\("([^"]*)",pid=(\d+)')


def parse_ss(text: str) -> list[dict]:
    records: list[dict] = []
    for line in (text or "").splitlines():
        parts = line.split()
        # Netid State Recv-Q Send-Q Local:Port Peer:Port [users:(...)]
        if len(parts) < 6 or parts[0] not in ("tcp", "udp"):
            continue
        local_addr, local_port = _split_endpoint(parts[4])
        remote_addr, remote_port = _split_endpoint(parts[5])
        if _is_unset(remote_addr, remote_port):
            remote_addr, remote_port = None, None
        state = parts[1].upper().replace("-", "_")
        state = _SS_STATES.get(state, state)
        pid = process = None
        owner = _SS_USERS.search(line)
        if owner:
            process, pid = owner.group(1), int(owner.group(2))
        records.append(
            _record(
                parts[0], state, local_addr, local_port, remote_addr, remote_port,
                pid, process,
            )
        )
    return records


def parse_ss_bytes(text: str) -> dict[tuple, tuple[int, int]]:
    """Parse ``ss -tni``: a connection line, then an indented line of counters."""
    totals: dict[tuple, tuple[int, int]] = {}
    key = None
    for line in (text or "").splitlines():
        if not line.strip():
            continue
        if not line[0].isspace():
            parts = line.split()
            key = None
            if len(parts) >= 5:
                local_addr, local_port = _split_endpoint(parts[3])
                remote_addr, remote_port = _split_endpoint(parts[4])
                key = (local_addr, local_port, remote_addr, remote_port)
            continue
        if key is None:
            continue
        received = re.search(r"\bbytes_received:(\d+)", line)
        sent = re.search(r"\bbytes_sent:(\d+)", line)
        if received or sent:
            totals[key] = (
                int(received.group(1)) if received else 0,
                int(sent.group(1)) if sent else 0,
            )
        key = None
    return totals


# --- Windows: PowerShell JSON ----------------------------------------------

# MSFT_NetTCPConnection.State values, and the names PowerShell prints for them.
_WIN_STATES = {
    1: "CLOSED", 2: "LISTEN", 3: "SYN_SENT", 4: "SYN_RECEIVED", 5: "ESTABLISHED",
    6: "FIN_WAIT_1", 7: "FIN_WAIT_2", 8: "CLOSE_WAIT", 9: "CLOSING",
    10: "LAST_ACK", 11: "TIME_WAIT", 12: "DELETE_TCB", 100: "BOUND",
}
_WIN_STATE_NAMES = {
    "SYNSENT": "SYN_SENT", "SYNRECEIVED": "SYN_RECEIVED", "FINWAIT1": "FIN_WAIT_1",
    "FINWAIT2": "FIN_WAIT_2", "CLOSEWAIT": "CLOSE_WAIT", "LASTACK": "LAST_ACK",
    "TIMEWAIT": "TIME_WAIT", "DELETETCB": "DELETE_TCB",
}
_WIN_DNS_TYPES = {1: "A", 5: "CNAME", 28: "AAAA"}


def _win_rows(json_text: str) -> list[dict]:
    """PowerShell prints one object as an object and many as a list; accept both."""
    try:
        data = json.loads(json_text) if (json_text or "").strip() else []
    except (ValueError, TypeError):
        return []
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        return []
    return [row for row in data if isinstance(row, dict)]


def _win_state(value) -> str | None:
    number = _to_int(value)
    if number is not None:
        return _WIN_STATES.get(number, str(number))
    if isinstance(value, str) and value.strip():
        name = value.strip().upper()
        return _WIN_STATE_NAMES.get(name, name)
    return None


def parse_win_connections(tcp_json: str, udp_json: str, proc_json: str) -> list[dict]:
    procs: dict[int, tuple[str | None, str | None]] = {}
    for row in _win_rows(proc_json):
        pid = _to_int(row.get("Id"))
        if pid is not None:
            procs[pid] = (row.get("ProcessName"), row.get("Path") or None)

    def owner(row: dict):
        pid = _to_int(row.get("OwningProcess"))
        name, path = procs.get(pid, (None, None)) if pid is not None else (None, None)
        return pid, name, path

    records: list[dict] = []
    for row in _win_rows(tcp_json):
        pid, name, path = owner(row)
        remote_addr = row.get("RemoteAddress") or None
        remote_port = _to_int(row.get("RemotePort"))
        if _is_unset(remote_addr, remote_port):
            remote_addr, remote_port = None, None
        records.append(
            _record(
                "tcp", _win_state(row.get("State")), row.get("LocalAddress") or None,
                _to_int(row.get("LocalPort")), remote_addr, remote_port,
                pid, name, path,
            )
        )
    for row in _win_rows(udp_json):
        pid, name, path = owner(row)
        records.append(
            _record(
                "udp", None, row.get("LocalAddress") or None,
                _to_int(row.get("LocalPort")), None, None, pid, name, path,
            )
        )
    return records


def parse_win_dns(json_text: str) -> list[dict]:
    names: list[dict] = []
    for row in _win_rows(json_text):
        entry = row.get("Entry")
        if not isinstance(entry, str) or not entry:
            continue
        number = _to_int(row.get("Type"))
        kind = _WIN_DNS_TYPES.get(number, str(row.get("Type")) if number is None else str(number))
        names.append({"name": entry, "type": kind})
    return names


# --- running the commands --------------------------------------------------


def _failure(result) -> str | None:
    """A plain reason the command gave us nothing, or None if it produced output."""
    if result.timed_out:
        return "The check took too long and was stopped."
    if result.error:
        return f"The command could not be run ({result.error})."
    if result.returncode != 0 and not (result.stdout or "").strip():
        detail = (result.stderr or "").strip().splitlines()
        return "The command failed" + (f" ({detail[0]})." if detail else ".")
    return None


def _unreadable(result, records: list[dict]) -> str | None:
    """Output arrived but none of it parsed: a changed format, not a clean machine."""
    if (result.stdout or "").strip() and not records:
        return "The command's output wasn't in a form this check understands."
    return None


def snapshot(platform: str, run=command.run, with_bytes: bool = True) -> dict:
    """Collect connections now.

    Returns ``{"records", "bytes", "limits", "error"}``. ``error`` is set (and
    ``records`` empty) when the connection command could not run; ``bytes`` is
    None whenever per-connection data counts are not available, which is
    reported in ``limits`` rather than failing the snapshot. ``with_bytes=False``
    skips the data-count command for callers that don't use it.
    """
    out: dict = {"records": [], "bytes": None, "limits": [], "error": None}

    if platform == "darwin":
        result = run(LSOF_ARGS, timeout=_TIMEOUT)
        # lsof exits 1 with no output when nothing has a network file open.
        if result.returncode == 1 and not result.timed_out and not result.error \
                and not (result.stdout or "").strip():
            out["records"] = []
        else:
            out["error"] = _failure(result)
            if out["error"]:
                return out
            out["records"] = parse_lsof(result.stdout)
            out["error"] = _unreadable(result, out["records"])
            if out["error"]:
                return out
        # geteuid is POSIX-only; tests replay macOS output on any system.
        if getattr(os, "geteuid", lambda: 0)() != 0:
            out["limits"].append(
                "macOS shows connections only for programs running as you unless "
                "the check runs as admin."
            )
        if not with_bytes:
            return out
        sent = run(NETTOP_ARGS, timeout=_TIMEOUT)
        if _failure(sent) is None:
            out["bytes"] = parse_nettop(sent.stdout)
        else:
            out["limits"].append("Couldn't read how much data each program sent or received.")
    elif platform == "linux":
        result = run(SS_ARGS, timeout=_TIMEOUT)
        out["error"] = _failure(result)
        if out["error"]:
            return out
        out["records"] = parse_ss(result.stdout)
        out["error"] = _unreadable(result, out["records"])
        if out["error"]:
            return out
        if any(r["pid"] is None for r in out["records"]):
            out["limits"].append(
                "Linux shows which program owns a connection only for your own "
                "programs unless the check runs as admin."
            )
        if not with_bytes:
            return out
        sent = run(SS_BYTES_ARGS, timeout=_TIMEOUT)
        if _failure(sent) is None:
            out["bytes"] = parse_ss_bytes(sent.stdout)
        else:
            out["limits"].append("Couldn't read how much data each connection carried.")
    elif platform == "win32":
        result = run(WIN_ARGS, timeout=_TIMEOUT)
        out["error"] = _failure(result)
        if out["error"]:
            return out
        lines = (result.stdout or "").splitlines()
        lines += [""] * (3 - len(lines))
        if not _win_rows(lines[0]):
            # A working Windows machine always has TCP listeners; a blank or
            # unparseable first document means the query failed.
            out["error"] = "Windows didn't return the list of connections."
            return out
        out["records"] = parse_win_connections(lines[0], lines[1], lines[2])
        if not with_bytes:
            return out
        out["limits"].append(
            "Windows doesn't show how much data each connection carried without admin."
        )
    else:
        out["error"] = "This kind of computer isn't supported for connection checks."
    return out


def dns_cache(platform: str, run=command.run) -> dict:
    """Names this computer recently looked up. Only Windows lets us read them."""
    if platform == "win32":
        result = run(WIN_DNS_ARGS, timeout=_TIMEOUT)
        reason = _failure(result)
        if reason:
            return {"names": None, "reason": f"Couldn't read the list of looked-up names. {reason}"}
        return {"names": parse_win_dns(result.stdout), "reason": None}
    if platform == "darwin":
        return {
            "names": None,
            "reason": "macOS doesn't show which names were looked up unless you're an admin.",
        }
    if platform == "linux":
        return {
            "names": None,
            "reason": "Linux shows looked-up names only to admins (resolvectl monitor needs root).",
        }
    return {"names": None, "reason": "This kind of computer isn't supported."}


# --- ordinary listeners ----------------------------------------------------

_SYSTEM_PID = 4
_WIN_SERVICE_HOSTS = ("lsass.exe", "wininit.exe", "services.exe", "svchost.exe", "spoolsv.exe")
_WIN_FIXED_PORTS = {
    135: ("svchost.exe",),
    5040: ("svchost.exe",),
}
_WIN_SYSTEM_PORTS = {139, 445, 5357}
# Outbound: file sharing (SMB) is opened by the System process itself, and
# Delivery Optimization's peer-to-peer updates by a System32 svchost.
_WIN_OUTBOUND_SYSTEM_PORTS = {139, 445}
_WIN_OUTBOUND_PORTS = {7680: ("svchost.exe",)}
_LINUX_PRIVILEGED = {
    ("sshd", 22), ("systemd-resolve", 53), ("cupsd", 631),
    ("chronyd", 123), ("ntpd", 123),
}
_LINUX_STUB_ADDRS = {"127.0.0.53", "127.0.0.54"}
_AVAHI_EXE = "/usr/sbin/avahi-daemon"


def _windows_dir() -> str:
    """The real Windows folder, asked of the OS (never an environment variable)."""
    try:
        import ctypes

        buf = ctypes.create_unicode_buffer(260)
        if ctypes.windll.kernel32.GetSystemWindowsDirectoryW(buf, 260):
            return buf.value
    except (AttributeError, OSError, ImportError):
        pass
    return "C:\\Windows"


def _win_allowed(port: int) -> tuple[str, ...]:
    """The service programs a clean Windows install listens with on ``port``."""
    if port in _WIN_FIXED_PORTS:
        return _WIN_FIXED_PORTS[port]
    if 49664 <= port <= 49699:
        return _WIN_SERVICE_HOSTS
    return ()


def _win_exe_name(record: dict) -> str:
    name = (record.get("process") or "").lower()
    return name if name.endswith(".exe") else name + ".exe"


def _win_expected(record: dict, port: int, windows_dir: str | None) -> bool:
    if port in _WIN_SYSTEM_PORTS:
        return record.get("pid") == _SYSTEM_PID
    # Without a path there is nothing to verify, so it is never expected;
    # ``claims_expected_service`` tells the caller it merely looks like one.
    return _win_system32(record, _win_allowed(port), windows_dir)


def claims_expected_service(platform: str, record: dict) -> bool:
    """True when a Windows listener has no path but carries a service's name.

    Without admin, Windows hides the path of service programs, so an ordinary
    svchost listener looks like this. The name alone proves nothing, so the
    caller notes it (info) rather than calling it expected or raising a warning.
    """
    port = record.get("local_port")
    if platform != "win32" or port is None or record.get("exe"):
        return False
    if port in _WIN_SYSTEM_PORTS:
        return False
    return _win_exe_name(record) in _win_allowed(port)


def _win_system32(record: dict, allowed: tuple[str, ...], windows_dir: str | None) -> bool:
    """True only when ``exe`` is exactly <WindowsDir>\\System32\\<one of allowed>."""
    exe = (record.get("exe") or "").replace("/", "\\").lower()
    if not allowed or not exe:
        return False
    base = (windows_dir or _windows_dir()).replace("/", "\\").rstrip("\\").lower()
    return any(exe == f"{base}\\system32\\{name}" for name in allowed)


_LOCAL_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
        "fe80::/10", "fc00::/7",
    )
)


def _is_local_remote(addr: str | None) -> bool:
    """True for a private or link-local remote address (the home or office network)."""
    try:
        ip = ipaddress.ip_address((addr or "").split("%")[0])
    except ValueError:
        return False
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return any(ip in net for net in _LOCAL_NETWORKS if net.version == ip.version)


def is_expected_outbound(platform: str, record: dict, windows_dir: str | None = None) -> bool:
    """True for an outgoing connection a normal, healthy install of the OS makes.

    Windows only, and fail-closed like listeners: SMB from PID 4, and
    Delivery Optimization from svchost with its exact System32 path. A
    pathless svchost only claims it (``claims_expected_outbound``). Both are
    local-network traffic only: the same port to a public address is not expected.
    """
    port = record.get("remote_port")
    if platform != "win32" or port is None or not _is_local_remote(record.get("remote_addr")):
        return False
    if port in _WIN_OUTBOUND_SYSTEM_PORTS:
        return record.get("pid") == _SYSTEM_PID
    return _win_system32(record, _WIN_OUTBOUND_PORTS.get(port, ()), windows_dir)


def claims_expected_outbound(platform: str, record: dict) -> bool:
    """A pathless Windows connection carrying the name of the service that makes it."""
    port = record.get("remote_port")
    if platform != "win32" or port is None or record.get("exe"):
        return False
    if not _is_local_remote(record.get("remote_addr")):
        return False
    return _win_exe_name(record) in _WIN_OUTBOUND_PORTS.get(port, ())


def is_expected_listener(
    platform: str, record: dict, readlink=os.readlink, windows_dir: str | None = None
) -> bool:
    """True for a listener that a normal, healthy install of the OS opens.

    ``readlink`` and ``windows_dir`` are injectable so tests don't need a real
    Linux or Windows machine.
    """
    port = record.get("local_port")
    if port is None:
        return False
    if platform == "win32":
        return _win_expected(record, port, windows_dir)
    if platform == "linux":
        process = record.get("process")
        if process == "avahi-daemon" and port == 5353:
            pid = record.get("pid")
            if pid is None:
                return False
            try:
                return readlink(f"/proc/{pid}/exe") == _AVAHI_EXE
            except OSError:
                return False
        if (process, port) not in _LINUX_PRIVILEGED:
            return False
        if port == 53:
            return record.get("local_addr") in _LINUX_STUB_ADDRS
        return True
    return False
