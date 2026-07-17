import os
import platform
import shutil
import socket
import subprocess
from pathlib import Path

from rescue.models import DiskInfo, Platform, ProcessInfo, SystemProfile


def gather_linux_profile() -> SystemProfile:
    return SystemProfile(
        platform=Platform.LINUX,
        os_name=_os_name(),
        os_version=platform.release(),
        architecture=platform.machine(),
        cpu_model=_cpu_model(),
        cpu_cores=os.cpu_count() or 0,
        ram_bytes=_ram_bytes(),
        disks=_disks(),
        processes=_processes(),
        hostname=socket.gethostname(),
    )


def _os_name() -> str:
    path = Path("/etc/os-release")
    try:
        values = dict(
            line.split("=", 1)
            for line in path.read_text().splitlines()
            if "=" in line
        )
        return values.get("PRETTY_NAME", "Linux").strip('"')
    except OSError:
        return "Linux"


def _cpu_model() -> str:
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.lower().startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor()


def _ram_bytes() -> int:
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        pass
    return 0


def _disks() -> list[DiskInfo]:
    disks = []
    try:
        mounts = Path("/proc/mounts").read_text().splitlines()
    except OSError:
        return disks

    seen_mounts: set[str] = set()
    for entry in mounts:
        fields = entry.split()
        if len(fields) < 3:
            continue
        device, mount_point, filesystem = fields[:3]
        if not device.startswith("/dev/") or mount_point in seen_mounts:
            continue
        try:
            usage = shutil.disk_usage(mount_point)
        except OSError:
            continue
        seen_mounts.add(mount_point)
        disks.append(
            DiskInfo(
                device=device,
                mount_point=mount_point,
                total_bytes=usage.total,
                used_bytes=usage.used,
                free_bytes=usage.free,
                filesystem=filesystem,
            )
        )
    return disks


def _processes() -> list[ProcessInfo]:
    try:
        result = subprocess.run(
            ["ps", "-eo", "pid=,comm=,%cpu=,rss=,args="],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return []

    processes = []
    for line in result.stdout.splitlines():
        fields = line.split(None, 4)
        if len(fields) != 5:
            continue
        try:
            processes.append(
                ProcessInfo(
                    pid=int(fields[0]),
                    name=fields[1],
                    cpu_percent=float(fields[2]),
                    memory_bytes=int(fields[3]) * 1024,
                    command=fields[4],
                )
            )
        except ValueError:
            continue
    return processes
