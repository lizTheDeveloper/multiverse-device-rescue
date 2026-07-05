import logging
import platform
import subprocess

from rescue.models import DiskInfo, Platform, ProcessInfo, SystemProfile

logger = logging.getLogger(__name__)


def gather_darwin_profile() -> SystemProfile:
    os_version = platform.mac_ver()[0]
    architecture = platform.machine()
    cpu_model = _run("sysctl", "-n", "machdep.cpu.brand_string").strip()
    cpu_cores_str = _run("sysctl", "-n", "hw.ncpu").strip()
    cpu_cores = int(cpu_cores_str) if cpu_cores_str else 0
    ram_str = _run("sysctl", "-n", "hw.memsize").strip()
    ram_bytes = int(ram_str) if ram_str else 0
    hostname = _run("hostname").strip()

    df_output = _run("df", "-k")
    disks = _parse_df_output(df_output)

    ps_output = _run("ps", "aux")
    processes = _parse_ps_output(ps_output)

    return SystemProfile(
        platform=Platform.DARWIN,
        os_name="macOS",
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
            logger.debug(f"Command {cmd} failed with return code {result.returncode}: {result.stderr}")
        return result.stdout
    except (OSError, subprocess.SubprocessError) as e:
        logger.debug(f"Failed to run command {cmd}: {e}")
        return ""


def _parse_df_output(output: str) -> list[DiskInfo]:
    disks = []
    for line in output.strip().split("\n")[1:]:
        parts = line.split()
        if len(parts) >= 6 and parts[0].startswith("/dev/"):
            total = int(parts[1]) * 1024
            used = int(parts[2]) * 1024
            free = int(parts[3]) * 1024
            mount = parts[-1]
            disks.append(
                DiskInfo(
                    device=parts[0],
                    mount_point=mount,
                    total_bytes=total,
                    used_bytes=used,
                    free_bytes=free,
                    filesystem="apfs",
                )
            )
    return disks


def _parse_ps_output(output: str) -> list[ProcessInfo]:
    processes = []
    for line in output.strip().split("\n")[1:]:
        parts = line.split(None, 10)
        if len(parts) >= 11:
            try:
                name = parts[10].split("/")[-1].split()[0]
                processes.append(
                    ProcessInfo(
                        pid=int(parts[1]),
                        name=name,
                        cpu_percent=float(parts[2]),
                        memory_bytes=int(parts[5]) * 1024,
                        command=parts[10],
                    )
                )
            except (ValueError, IndexError):
                continue
    return processes
