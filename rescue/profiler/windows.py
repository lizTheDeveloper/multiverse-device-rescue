import logging
import platform
import subprocess

from rescue.models import DiskInfo, Platform, ProcessInfo, SystemProfile

logger = logging.getLogger(__name__)


def gather_windows_profile() -> SystemProfile:
    architecture = platform.machine()
    hostname = _run("hostname").strip()

    os_rows = _parse_wmic_list(
        _run("wmic", "os", "get", "Caption,Version", "/format:list")
    )
    os_name = os_rows[0].get("Caption", "Windows").strip() if os_rows else "Windows"
    os_version = os_rows[0].get("Version", "").strip() if os_rows else ""

    cpu_rows = _parse_wmic_list(
        _run("wmic", "cpu", "get", "Name,NumberOfCores", "/format:list")
    )
    cpu_model = cpu_rows[0].get("Name", "").strip() if cpu_rows else ""
    cpu_cores_str = cpu_rows[0].get("NumberOfCores", "").strip() if cpu_rows else ""
    cpu_cores = int(cpu_cores_str) if cpu_cores_str.isdigit() else 0

    mem_rows = _parse_wmic_list(
        _run("wmic", "computersystem", "get", "TotalPhysicalMemory", "/format:list")
    )
    ram_str = mem_rows[0].get("TotalPhysicalMemory", "").strip() if mem_rows else ""
    ram_bytes = int(ram_str) if ram_str.isdigit() else 0

    disk_output = _run(
        "wmic", "logicaldisk", "get", "Caption,FreeSpace,Size", "/format:list"
    )
    disks = _parse_disk_rows(_parse_wmic_list(disk_output))

    process_output = _run(
        "wmic", "process", "get", "ProcessId,Name,WorkingSetSize", "/format:list"
    )
    processes = _parse_process_rows(_parse_wmic_list(process_output))

    return SystemProfile(
        platform=Platform.WIN32,
        os_name=os_name,
        os_version=os_version,
        architecture=architecture,
        cpu_model=cpu_model,
        cpu_cores=cpu_cores,
        ram_bytes=ram_bytes,
        disks=disks,
        processes=processes,
        hostname=hostname,
    )


def _run(*cmd: str) -> str:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            logger.debug(
                f"Command {cmd} failed with return code {result.returncode}: {result.stderr}"
            )
        return result.stdout
    except (OSError, subprocess.SubprocessError) as e:
        logger.debug(f"Failed to run command {cmd}: {e}")
        return ""


def _parse_wmic_list(output: str) -> list[dict[str, str]]:
    """Parse `wmic ... /format:list` output.

    That format emits repeated `Key=Value` blocks, one block per row,
    separated by blank lines, e.g.::

        Caption=C:
        FreeSpace=107374182400
        Size=256060514304

        Caption=D:
        FreeSpace=53687091200
        Size=107374182400
    """
    rows: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for raw_line in output.splitlines():
        line = raw_line.strip("\r\n").strip()
        if not line:
            if current:
                rows.append(current)
                current = {}
            continue
        if "=" in line:
            key, _, value = line.partition("=")
            current[key.strip()] = value.strip()
    if current:
        rows.append(current)
    return rows


def _parse_disk_rows(rows: list[dict[str, str]]) -> list[DiskInfo]:
    disks = []
    for row in rows:
        caption = row.get("Caption", "").strip()
        size_str = row.get("Size", "").strip()
        free_str = row.get("FreeSpace", "").strip()
        if not caption or not size_str:
            continue
        try:
            total = int(size_str)
        except ValueError:
            continue
        try:
            free = int(free_str) if free_str else 0
        except ValueError:
            free = 0
        used = total - free
        disks.append(
            DiskInfo(
                device=caption,
                mount_point=caption,
                total_bytes=total,
                used_bytes=used,
                free_bytes=free,
                filesystem="NTFS",
            )
        )
    return disks


def _parse_process_rows(rows: list[dict[str, str]]) -> list[ProcessInfo]:
    processes = []
    for row in rows:
        name = row.get("Name", "").strip()
        pid_str = row.get("ProcessId", "").strip()
        ws_str = row.get("WorkingSetSize", "").strip()
        if not name or not pid_str:
            continue
        try:
            pid = int(pid_str)
        except ValueError:
            continue
        try:
            memory_bytes = int(ws_str) if ws_str else 0
        except ValueError:
            memory_bytes = 0
        processes.append(
            ProcessInfo(
                pid=pid,
                name=name,
                cpu_percent=0.0,
                memory_bytes=memory_bytes,
                command=name,
            )
        )
    return processes
