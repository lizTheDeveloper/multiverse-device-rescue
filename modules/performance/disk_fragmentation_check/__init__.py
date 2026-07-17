import subprocess
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


class Module(ModuleBase):
    name = "disk_fragmentation_check"
    category = "performance"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 60
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        try:
            disk_info = self._get_disk_info()
            if disk_info is None:
                return CheckResult(module_name=self.name, findings=findings)

            is_ssd = disk_info.get("is_ssd", None)
            filesystem = disk_info.get("filesystem", "unknown")
            usage_percent = disk_info.get("usage_percent", 0)
            total_bytes = disk_info.get("total_bytes", 0)
            used_bytes = disk_info.get("used_bytes", 0)
            free_bytes = disk_info.get("free_bytes", 0)

            # Flag if SSD detected (informational - no defrag needed)
            if is_ssd is True:
                findings.append(
                    Finding(
                        title="SSD detected - fragmentation not a concern",
                        description=(
                            "This Mac has a Solid State Drive (SSD). SSDs do not suffer from fragmentation "
                            "like traditional hard drives, and macOS automatically optimizes SSD performance. "
                            "No defragmentation is needed."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={
                            "disk_type": "SSD",
                            "filesystem": filesystem,
                            "usage_percent": usage_percent,
                        },
                    )
                )

            # Check HDD status if it's not an SSD
            elif is_ssd is False:
                findings.append(
                    Finding(
                        title=f"HDD detected - monitoring fragmentation ({filesystem})",
                        description=(
                            f"This Mac has a traditional hard drive (HDD). Currently using {usage_percent}% of "
                            f"disk space with {_fmt_bytes(free_bytes)} free. Filesystem: {filesystem}. "
                            f"HDD fragmentation becomes problematic when disk usage is very high."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={
                            "disk_type": "HDD",
                            "filesystem": filesystem,
                            "usage_percent": usage_percent,
                            "total_bytes": total_bytes,
                            "used_bytes": used_bytes,
                            "free_bytes": free_bytes,
                        },
                    )
                )

                # Warning: HDD >90% full
                if usage_percent > 90:
                    findings.append(
                        Finding(
                            title=f"HDD critically full - fragmentation risk ({usage_percent}%)",
                            description=(
                                f"Your HDD is {usage_percent}% full with only {_fmt_bytes(free_bytes)} free space. "
                                f"At this capacity, disk fragmentation will significantly impact performance. "
                                f"Free up space as soon as possible to restore normal operation."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            data={
                                "disk_type": "HDD",
                                "filesystem": filesystem,
                                "usage_percent": usage_percent,
                                "free_bytes": free_bytes,
                                "risk_type": "critically_full",
                            },
                        )
                    )

                # Warning: HFS+ on HDD with high usage
                elif filesystem == "HFS+" and usage_percent > 70:
                    findings.append(
                        Finding(
                            title=f"HFS+ HDD with high usage - fragmentation likely ({usage_percent}%)",
                            description=(
                                f"You have an HFS+ filesystem on an HDD with {usage_percent}% capacity used. "
                                f"HFS+ is more prone to fragmentation than APFS. At this usage level, "
                                f"you may notice performance degradation. Consider freeing space or upgrading to APFS."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            data={
                                "disk_type": "HDD",
                                "filesystem": filesystem,
                                "usage_percent": usage_percent,
                                "risk_type": "hfs_plus_high_usage",
                            },
                        )
                    )

            else:
                # Unknown disk type
                findings.append(
                    Finding(
                        title="Unable to determine disk type",
                        description=(
                            "Could not determine whether this disk is an SSD or HDD. "
                            "Fragmentation risk cannot be assessed."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={
                            "disk_type": "unknown",
                            "filesystem": filesystem,
                            "usage_percent": usage_percent,
                        },
                    )
                )

        except Exception as e:
            findings.append(
                Finding(
                    title="Error checking disk fragmentation status",
                    description=f"Failed to check disk type and fragmentation: {str(e)}",
                    severity=Severity.INFO,
                    category=self.category,
                    data={"error": str(e)},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            risk_type = finding.data.get("risk_type")
            disk_type = finding.data.get("disk_type")
            filesystem = finding.data.get("filesystem")
            usage_percent = finding.data.get("usage_percent", 0)

            if disk_type == "SSD":
                actions.append(
                    Action(
                        title="SSD detected - no action needed",
                        description=(
                            "Your Mac uses an SSD, which does not suffer from fragmentation. "
                            "macOS automatically optimizes SSD performance through TRIM and other mechanisms. "
                            "No defragmentation is necessary."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif disk_type == "HDD":
                if risk_type == "critically_full":
                    actions.append(
                        Action(
                            title="Free disk space to reduce fragmentation",
                            description=(
                                f"Your HDD is {usage_percent}% full. To improve performance:\n"
                                f"1. Delete unnecessary files, especially old downloads and caches\n"
                                f"2. Move files to external storage\n"
                                f"3. Aim to keep at least 10-15% of disk free for optimal performance\n"
                                f"macOS handles HDD optimization automatically - you don't need to manually defragment. "
                                f"Simply freeing space will improve performance as new files will be less fragmented."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )

                elif risk_type == "hfs_plus_high_usage":
                    actions.append(
                        Action(
                            title="Reduce usage and consider upgrading filesystem",
                            description=(
                                f"Your HFS+ HDD is at {usage_percent}% capacity.\n"
                                f"Recommendations:\n"
                                f"1. Free up disk space (target: <70% usage)\n"
                                f"2. macOS automatically optimizes HFS+ - no manual defragmentation needed\n"
                                f"3. Consider upgrading to APFS if possible, which handles fragmentation better\n"
                                f"4. Freeing space will allow less-fragmented file placement going forward"
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )

                else:
                    # General HDD monitoring
                    actions.append(
                        Action(
                            title="HDD fragmentation monitoring",
                            description=(
                                f"Your HDD ({filesystem}) is at {usage_percent}% capacity. "
                                f"macOS automatically optimizes disk layout on HFS+ and APFS. "
                                f"Keep disk usage below 90% for optimal performance. "
                                f"If performance degrades, freeing space will help with future file placement."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )

            elif disk_type == "unknown":
                actions.append(
                    Action(
                        title="Unable to determine disk type",
                        description=(
                            "Could not determine whether this disk is an SSD or HDD. "
                            "General recommendations: keep at least 10-15% of disk free, "
                            "and macOS will handle any necessary optimization automatically."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_disk_info(self) -> dict | None:
        """Get disk information including type and filesystem."""
        try:
            # Get disk info using diskutil
            result = subprocess.run(
                ["diskutil", "info", "/"],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode != 0:
                return None

            output = result.stdout

            # Parse disk info
            disk_info = {
                "is_ssd": None,
                "filesystem": "unknown",
                "usage_percent": 0,
                "total_bytes": 0,
                "used_bytes": 0,
                "free_bytes": 0,
            }

            # Check for SSD
            is_ssd = "Solid State" in output and "Yes" in output.split("Solid State")[-1].split("\n")[0]
            disk_info["is_ssd"] = is_ssd

            # Parse filesystem
            for line in output.split("\n"):
                if "Type (Bundle):" in line or "Type:" in line:
                    parts = line.split(":")
                    if len(parts) > 1:
                        fs_type = parts[-1].strip()
                        if fs_type in ("apfs", "hfs+", "APFS", "HFS+", "JHFS+"):
                            disk_info["filesystem"] = fs_type.upper() if fs_type.upper() in ("APFS", "HFS+") else "APFS"
                        break

            # Get space info
            try:
                space_result = subprocess.run(
                    ["df", "-b", "/"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )

                if space_result.returncode == 0:
                    lines = space_result.stdout.strip().split("\n")
                    if len(lines) > 1:
                        parts = lines[1].split()
                        if len(parts) >= 3:
                            total = int(parts[1])
                            used = int(parts[2])
                            free = int(parts[3])
                            disk_info["total_bytes"] = total
                            disk_info["used_bytes"] = used
                            disk_info["free_bytes"] = free
                            if total > 0:
                                disk_info["usage_percent"] = int((used / total) * 100)
            except (ValueError, IndexError, subprocess.TimeoutExpired):
                pass

            return disk_info

        except subprocess.TimeoutExpired:
            return None
        except Exception:
            return None


def _fmt_bytes(n: int) -> str:
    """Format bytes as human-readable string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"
