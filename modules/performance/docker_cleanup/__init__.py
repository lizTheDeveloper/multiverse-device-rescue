import re
import subprocess
from pathlib import Path

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

# Thresholds
DOCKER_DISK_WARNING_GB = 20
DANGLING_IMAGES_WARNING = 0  # Any dangling images is a warning
STOPPED_CONTAINERS_WARNING = 10


class Module(ModuleBase):
    name = "docker_cleanup"
    category = "performance"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 65
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check if Docker is installed
        if not self._is_docker_installed():
            return CheckResult(module_name=self.name, findings=findings)

        # Get Docker disk usage
        docker_usage = self._get_docker_disk_usage()
        if docker_usage is None:
            return CheckResult(module_name=self.name, findings=findings)

        total_usage_gb = docker_usage["total_bytes"] / (1024 ** 3)

        # Check dangling images
        dangling_images = self._get_dangling_images()

        # Check stopped containers
        stopped_containers = self._get_stopped_containers()

        # Check Docker VM disk size
        vm_disk_size = self._get_docker_vm_disk_size()

        # Flag WARNING if Docker disk usage exceeds 20GB
        if total_usage_gb > DOCKER_DISK_WARNING_GB:
            findings.append(
                Finding(
                    title=f"High Docker disk usage: {_fmt_bytes(docker_usage['total_bytes'])}",
                    description=(
                        f"Docker is using {_fmt_bytes(docker_usage['total_bytes'])} of disk space, "
                        f"exceeding the {DOCKER_DISK_WARNING_GB}GB warning threshold. "
                        f"Consider cleaning up unused images and containers."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "type": "high_docker_usage",
                        "total_bytes": docker_usage["total_bytes"],
                        "total_formatted": _fmt_bytes(docker_usage["total_bytes"]),
                        "images_bytes": docker_usage["images_bytes"],
                        "containers_bytes": docker_usage["containers_bytes"],
                        "volumes_bytes": docker_usage["volumes_bytes"],
                    },
                )
            )
        else:
            # Report INFO with breakdown
            findings.append(
                Finding(
                    title=f"Docker disk usage: {_fmt_bytes(docker_usage['total_bytes'])}",
                    description=(
                        f"Docker disk breakdown: Images: {_fmt_bytes(docker_usage['images_bytes'])}, "
                        f"Containers: {_fmt_bytes(docker_usage['containers_bytes'])}, "
                        f"Volumes: {_fmt_bytes(docker_usage['volumes_bytes'])}"
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "type": "docker_disk_usage",
                        "total_bytes": docker_usage["total_bytes"],
                        "total_formatted": _fmt_bytes(docker_usage["total_bytes"]),
                        "images_bytes": docker_usage["images_bytes"],
                        "containers_bytes": docker_usage["containers_bytes"],
                        "volumes_bytes": docker_usage["volumes_bytes"],
                    },
                )
            )

        # Flag WARNING if there are dangling images
        if dangling_images > 0:
            findings.append(
                Finding(
                    title=f"Dangling Docker images: {dangling_images}",
                    description=(
                        f"Found {dangling_images} dangling Docker image(s) that are not tagged or used. "
                        f"These waste disk space and can be safely removed."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "type": "dangling_images",
                        "count": dangling_images,
                    },
                )
            )

        # Flag WARNING if there are many stopped containers (>10)
        if stopped_containers > STOPPED_CONTAINERS_WARNING:
            findings.append(
                Finding(
                    title=f"Many stopped containers: {stopped_containers}",
                    description=(
                        f"Found {stopped_containers} stopped Docker container(s). "
                        f"These are no longer running but still use disk space. Consider removing them."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "type": "stopped_containers",
                        "count": stopped_containers,
                    },
                )
            )

        # Check Docker VM disk size (if available)
        if vm_disk_size is not None:
            findings.append(
                Finding(
                    title=f"Docker VM disk image size: {_fmt_bytes(vm_disk_size)}",
                    description=(
                        f"Docker's VM disk image (Docker.raw or Docker.qcow2) is {_fmt_bytes(vm_disk_size)}. "
                        f"This file can grow over time as Docker containers and images consume space."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "type": "docker_vm_disk_size",
                        "size_bytes": vm_disk_size,
                        "size_formatted": _fmt_bytes(vm_disk_size),
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            finding_type = finding.data.get("type", "unknown")

            if finding_type == "high_docker_usage":
                size_str = finding.data.get("total_formatted", "unknown")
                actions.append(
                    Action(
                        title=f"High Docker disk usage: {size_str}",
                        description=(
                            f"Docker is using {size_str}. Run 'docker system prune' to remove unused "
                            f"images, containers, and networks. For aggressive cleanup, use "
                            f"'docker system prune -a --volumes'. This is safe and will not affect "
                            f"running containers."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "docker_disk_usage":
                size_str = finding.data.get("total_formatted", "unknown")
                actions.append(
                    Action(
                        title=f"Docker disk usage report: {size_str}",
                        description=(
                            f"Current Docker usage is within acceptable limits. "
                            f"Monitor this metric regularly to catch space issues early."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "dangling_images":
                count = finding.data.get("count", 0)
                actions.append(
                    Action(
                        title=f"Dangling Docker images: {count}",
                        description=(
                            f"Found {count} dangling image(s). Run 'docker image prune' to remove them. "
                            f"Dangling images are untagged and not used by any container, "
                            f"so they are safe to delete."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "stopped_containers":
                count = finding.data.get("count", 0)
                actions.append(
                    Action(
                        title=f"Stopped Docker containers: {count}",
                        description=(
                            f"Found {count} stopped container(s). Run 'docker container prune' to remove them. "
                            f"Stopped containers are not running and can be safely removed."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "docker_vm_disk_size":
                size_str = finding.data.get("size_formatted", "unknown")
                actions.append(
                    Action(
                        title=f"Docker VM disk image size: {size_str}",
                        description=(
                            f"Docker's VM disk image is {size_str}. This is informational. "
                            f"The disk image can shrink after cleanup via 'docker system prune'."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _is_docker_installed(self) -> bool:
        """Check if Docker is installed via 'which docker'."""
        try:
            result = subprocess.run(
                ["which", "docker"],
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, TimeoutError, OSError):
            return False

    def _get_docker_disk_usage(self) -> dict | None:
        """Get Docker disk usage via 'docker system df'."""
        try:
            result = subprocess.run(
                ["docker", "system", "df", "--format", "{{json .}}"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return None

            import json

            output = result.stdout.strip()
            if not output:
                return None

            # 'docker system df --format "{{json .}}"' emits NDJSON: one
            # JSON object per line, one line per row (Images, Containers,
            # Local Volumes, Build Cache). Parse each line individually
            # rather than json.loads()-ing the whole blob, which would
            # raise on the very first newline.
            images_bytes = 0
            containers_bytes = 0
            volumes_bytes = 0
            parsed_any = False

            for line in output.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if not isinstance(entry, dict):
                    continue

                entry_type = entry.get("Type", "")
                size_value = entry.get("Size", 0)
                if isinstance(size_value, str):
                    size_value = self._parse_docker_size(size_value)
                elif not isinstance(size_value, (int, float)):
                    size_value = 0

                if entry_type == "Images":
                    images_bytes = size_value
                elif entry_type == "Containers":
                    containers_bytes = size_value
                elif entry_type in ("Local Volumes", "Volumes"):
                    volumes_bytes = size_value
                else:
                    continue
                parsed_any = True

            if not parsed_any:
                return None

            return {
                "total_bytes": images_bytes + containers_bytes + volumes_bytes,
                "images_bytes": images_bytes,
                "containers_bytes": containers_bytes,
                "volumes_bytes": volumes_bytes,
            }
        except (subprocess.SubprocessError, TimeoutError, OSError):
            return None

    def _get_dangling_images(self) -> int:
        """Check dangling images via 'docker images -f dangling=true -q'."""
        try:
            result = subprocess.run(
                ["docker", "images", "-f", "dangling=true", "-q"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return 0

            # Count lines in output (each line is an image ID)
            lines = result.stdout.strip().split("\n")
            return len([line for line in lines if line])
        except (subprocess.SubprocessError, TimeoutError, OSError):
            return 0

    def _get_stopped_containers(self) -> int:
        """Check stopped containers via 'docker ps -a -f status=exited -q'."""
        try:
            result = subprocess.run(
                ["docker", "ps", "-a", "-f", "status=exited", "-q"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return 0

            # Count lines in output (each line is a container ID)
            lines = result.stdout.strip().split("\n")
            return len([line for line in lines if line])
        except (subprocess.SubprocessError, TimeoutError, OSError):
            return 0

    def _get_docker_vm_disk_size(self) -> int | None:
        """Check Docker VM disk size at ~/Library/Containers/com.docker.docker."""
        try:
            docker_dir = Path.home() / "Library" / "Containers" / "com.docker.docker"
            if not docker_dir.exists():
                return None

            # Look for Docker.raw or Docker.qcow2
            for filename in ["Docker.raw", "Docker.qcow2"]:
                vm_file = docker_dir / filename
                if vm_file.exists():
                    return vm_file.stat().st_size

            return None
        except (OSError, PermissionError):
            return None

    def _parse_docker_size(self, size_str: str) -> int:
        """Parse Docker size string to bytes.

        Docker's real output (via go-units HumanSize) has no space between
        the number and unit, e.g. '5.2GB', '500MB', '1.235GB' -- not
        '2.5 GB'. Accept both forms.
        """
        if not isinstance(size_str, str):
            return int(size_str) if size_str else 0

        size_str = size_str.strip()
        match = re.match(r"^([\d.]+)\s*([A-Za-z]+)$", size_str)

        if not match:
            return 0

        try:
            value = float(match.group(1))
            unit = match.group(2).upper()

            multipliers = {
                "B": 1,
                "KB": 1024,
                "MB": 1024 ** 2,
                "GB": 1024 ** 3,
                "TB": 1024 ** 4,
            }

            return int(value * multipliers.get(unit, 1))
        except (ValueError, IndexError):
            return 0


def _fmt_bytes(n: int) -> str:
    """Format bytes as human-readable string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"
