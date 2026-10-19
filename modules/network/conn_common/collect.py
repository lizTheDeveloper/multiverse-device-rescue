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


def _powershell(script: str) -> list[str]:
    return ["powershell", "-NoProfile", "-NonInteractive", "-Command", script]


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
        state = parts[1].upper()
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


def snapshot(platform: str, run=command.run) -> dict:
    """Collect connections now.

    Returns ``{"records", "bytes", "limits", "error"}``. ``error`` is set (and
    ``records`` empty) when the connection command could not run; ``bytes`` is
    None whenever per-connection data counts are not available, which is
    reported in ``limits`` rather than failing the snapshot.
    """
    out: dict = {"records": [], "bytes": None, "limits": [], "error": None}

    if platform == "darwin":
        result = run(LSOF_ARGS, timeout=_TIMEOUT)
        out["error"] = _failure(result)
        if out["error"]:
            return out
        out["records"] = parse_lsof(result.stdout)
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
        if any(r["pid"] is None for r in out["records"]):
            out["limits"].append(
                "Linux shows which program owns a connection only for your own "
                "programs unless the check runs as admin."
            )
        sent = run(SS_BYTES_ARGS, timeout=_TIMEOUT)
        if _failure(sent) is None:
            out["bytes"] = parse_ss_bytes(sent.stdout)
        else:
            out["limits"].append("Couldn't read how much data each connection carried.")
    elif platform == "win32":
        result = run(_powershell(_WIN_SCRIPT), timeout=_TIMEOUT)
        out["error"] = _failure(result)
        if out["error"]:
            return out
        lines = (result.stdout or "").splitlines()
        lines += [""] * (3 - len(lines))
        out["records"] = parse_win_connections(lines[0], lines[1], lines[2])
        out["limits"].append(
            "Windows doesn't show how much data each connection carried without admin."
        )
    else:
        out["error"] = "This kind of computer isn't supported for connection checks."
    return out


def dns_cache(platform: str, run=command.run) -> dict:
    """Names this computer recently looked up. Only Windows lets us read them."""
    if platform == "win32":
        result = run(_powershell(_WIN_DNS_SCRIPT), timeout=_TIMEOUT)
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

_WIN_LISTEN_PORTS = {135, 139, 445, 5040, 5357}
_LINUX_LISTENERS = {
    ("sshd", 22), ("systemd-resolve", 53), ("cupsd", 631),
    ("avahi-daemon", 5353), ("chronyd", 123), ("ntpd", 123),
}
_LINUX_STUB_ADDRS = {"127.0.0.53", "127.0.0.54"}


def is_expected_listener(platform: str, record: dict) -> bool:
    """True for a listener that a normal, healthy install of the OS opens."""
    port = record.get("local_port")
    if port is None:
        return False
    if platform == "win32":
        if not (port in _WIN_LISTEN_PORTS or 49664 <= port <= 49699):
            return False
        if record.get("pid") == 4:
            return True
        root = os.environ.get("SystemRoot") or r"C:\Windows"
        system32 = root.replace("/", "\\").rstrip("\\").lower() + "\\system32\\"
        exe = (record.get("exe") or "").replace("/", "\\").lower()
        return exe.startswith(system32)
    if platform == "linux":
        if (record.get("process"), port) not in _LINUX_LISTENERS:
            return False
        if port == 53:
            return record.get("local_addr") in _LINUX_STUB_ADDRS
        return True
    return False
