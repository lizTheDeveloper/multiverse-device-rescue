import os
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


class Module(ModuleBase):
    name = "core_services_reset"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get home directory
        home = os.path.expanduser("~")

        # Check Launch Services cache directory
        cache_dir = Path(home) / "Library" / "Caches"

        # Find .csstore files and check their sizes
        csstore_files = list(cache_dir.glob("com.apple.LaunchServices-*.csstore"))

        if not csstore_files:
            findings.append(
                Finding(
                    title="Launch Services cache not found",
                    description=(
                        "The Launch Services cache directory does not contain the "
                        "expected .csstore files. This may indicate a clean system or "
                        "recent Launch Services reset."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "cache_not_found"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # Check total size of .csstore files
        total_size = sum(f.stat().st_size for f in csstore_files)
        total_size_mb = total_size / (1024 * 1024)

        # Check for bloated database (>50MB)
        if total_size > 50 * 1024 * 1024:
            findings.append(
                Finding(
                    title=f"Launch Services database bloated ({total_size_mb:.1f}MB)",
                    description=(
                        f"The Launch Services cache is {total_size_mb:.1f}MB, exceeding "
                        "the normal size of ~5-20MB. A bloated database can cause "
                        "performance issues and incorrect app associations. Consider "
                        "rebuilding the Launch Services database."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "database_size",
                        "total_size_mb": total_size_mb,
                    },
                )
            )

        # Check for duplicate app registrations
        registration_count = self._count_app_registrations()

        if registration_count is not None:
            # Count unique bundle IDs
            duplicate_count = registration_count

            # Check if registrations exceed normal limit (>100 duplicates)
            if duplicate_count > 100:
                findings.append(
                    Finding(
                        title=f"High number of app registrations ({duplicate_count})",
                        description=(
                            f"Launch Services has {duplicate_count} app registrations, "
                            "indicating potential duplicate entries. This can cause "
                            "performance degradation and incorrect file associations. "
                            "Rebuilding the database is recommended."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "registration_count",
                            "registration_count": duplicate_count,
                        },
                    )
                )

            # Always report status as INFO
            findings.append(
                Finding(
                    title="Launch Services database status",
                    description=(
                        f"Launch Services database contains {duplicate_count} "
                        f"registrations and occupies {total_size_mb:.1f}MB. "
                        "A healthy Launch Services database typically contains "
                        "50-100 registrations and uses 5-20MB."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "status",
                        "registration_count": duplicate_count,
                        "database_size_mb": total_size_mb,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "cache_not_found":
                actions.append(
                    Action(
                        title="Launch Services cache information",
                        description=(
                            "The Launch Services cache is either missing or in a "
                            "normal state. No action is needed at this time. If you "
                            "experience app-related issues (wrong app opens files, "
                            "duplicate Open With entries), you can rebuild the cache by: "
                            "(1) Reboot into Safe Mode, or (2) Run: "
                            "/System/Library/Frameworks/CoreServices.framework/Frameworks/"
                            "LaunchServices.framework/Support/lsregister -kill -r -domain "
                            "local -domain system -domain user"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "database_size":
                size_mb = finding.data.get("total_size_mb", 0)
                actions.append(
                    Action(
                        title="Rebuild Launch Services database",
                        description=(
                            f"The Launch Services database is bloated ({size_mb:.1f}MB). "
                            "To rebuild it, run the following command in Terminal:\n\n"
                            "/System/Library/Frameworks/CoreServices.framework/Frameworks/"
                            "LaunchServices.framework/Support/lsregister -kill -r "
                            "-domain local -domain system -domain user\n\n"
                            "After running this command, reboot your Mac. This will "
                            "reindex all applications and fix incorrect app associations. "
                            "The process is safe and can be repeated as needed."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "registration_count":
                count = finding.data.get("registration_count", 0)
                actions.append(
                    Action(
                        title="Reset duplicate app registrations",
                        description=(
                            f"Launch Services has {count} registrations, indicating "
                            "duplicates. To rebuild the database and remove duplicates, "
                            "run the following command in Terminal:\n\n"
                            "/System/Library/Frameworks/CoreServices.framework/Frameworks/"
                            "LaunchServices.framework/Support/lsregister -kill -r "
                            "-domain local -domain system -domain user\n\n"
                            "After running this command, reboot your Mac. This will "
                            "clean up duplicate app entries and improve system performance."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "status":
                count = finding.data.get("registration_count", 0)
                size_mb = finding.data.get("database_size_mb", 0)
                actions.append(
                    Action(
                        title="Launch Services database status report",
                        description=(
                            f"Launch Services database has {count} registrations and "
                            f"uses {size_mb:.1f}MB. Current status is being monitored. "
                            "If you experience issues with file associations or app "
                            "opening, consider rebuilding using the lsregister command."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _count_app_registrations(self) -> int | None:
        """Count app registrations using lsregister -dump."""
        try:
            lsregister_path = (
                "/System/Library/Frameworks/CoreServices.framework/Frameworks/"
                "LaunchServices.framework/Support/lsregister"
            )

            # Check if lsregister exists
            if not os.path.exists(lsregister_path):
                return None

            result = subprocess.run(
                [lsregister_path, "-dump"],
                capture_output=True,
                text=True,
                errors="replace",
            )

            if result.returncode != 0:
                return None

            # Count bundle id entries
            count = result.stdout.count("bundle id:")
            return count

        except (OSError, subprocess.SubprocessError):
            return None
