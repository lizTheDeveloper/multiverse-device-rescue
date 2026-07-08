import re
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
    name = "filesystem_health_check"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get filesystem type and info
        fs_info = self._get_filesystem_info()
        if not fs_info:
            findings.append(
                Finding(
                    title="Could not retrieve filesystem information",
                    description="Failed to run diskutil commands to check filesystem health.",
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "fs_info_retrieval"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # Check filesystem type
        fs_type = fs_info.get("type", "Unknown")
        is_apfs = fs_type == "APFS"
        is_hfs_plus = fs_type == "HFS+"

        # Report filesystem type
        findings.append(
            Finding(
                title=f"Filesystem type: {fs_type}",
                description=f"Root volume is formatted as {fs_type}.",
                severity=Severity.INFO,
                category=self.category,
                data={"check": "filesystem_type", "type": fs_type},
            )
        )

        # Check if HFS+ (warning - should upgrade)
        if is_hfs_plus:
            findings.append(
                Finding(
                    title="HFS+ filesystem detected (should upgrade to APFS)",
                    description=(
                        "Your Mac is using HFS+ (Mac OS Extended) filesystem. "
                        "Apple recommends upgrading to APFS for modern macOS versions. "
                        "APFS provides better performance, security, and space efficiency."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "hfs_plus_detection"},
                )
            )

        # Check FileVault encryption
        encryption_status = fs_info.get("encryption", "Unknown")
        is_encrypted = "Yes" in encryption_status or "encrypted" in encryption_status.lower()

        findings.append(
            Finding(
                title=f"FileVault encryption: {encryption_status}",
                description=f"FileVault encryption status: {encryption_status}",
                severity=Severity.INFO,
                category=self.category,
                data={"check": "encryption_status", "encrypted": is_encrypted},
            )
        )

        # Check if laptop without FileVault (warning)
        if not is_encrypted and self._is_laptop(profile):
            findings.append(
                Finding(
                    title="FileVault disabled on laptop",
                    description=(
                        "Your Mac appears to be a laptop with FileVault encryption disabled. "
                        "Enable FileVault to protect your data if the device is lost or stolen."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "unencrypted_laptop"},
                )
            )

        # Check APFS-specific health if APFS filesystem
        if is_apfs:
            apfs_health = self._check_apfs_health()
            findings.extend(apfs_health)

        # Check filesystem consistency
        verify_result = self._run_verify_volume()
        if verify_result:
            verify_findings = self._parse_verify_output(verify_result)
            findings.extend(verify_findings)

        # Check inode usage
        inode_info = self._check_inode_usage()
        if inode_info:
            findings.append(inode_info)

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "fs_info_retrieval":
                actions.append(
                    Action(
                        title="Filesystem information retrieval failed",
                        description=(
                            "Unable to retrieve filesystem information. "
                            "Ensure diskutil is available and you have sufficient permissions."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "filesystem_type":
                actions.append(
                    Action(
                        title="Filesystem information",
                        description=(
                            f"Your Mac is using {finding.data.get('type')} filesystem. "
                            "No action required for basic filesystem type information."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "hfs_plus_detection":
                actions.append(
                    Action(
                        title="HFS+ upgrade guidance",
                        description=(
                            "To upgrade your filesystem from HFS+ to APFS: "
                            "(1) Backup all data to external drive; "
                            "(2) Open Disk Utility; "
                            "(3) Select your drive and click Erase; "
                            "(4) Choose APFS as the format; "
                            "(5) Restore data from backup. "
                            "This is a significant operation - consult Apple Support if unsure."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "encryption_status":
                actions.append(
                    Action(
                        title="FileVault encryption information",
                        description=(
                            f"FileVault status: {finding.data.get('encrypted')}. "
                            "You can enable or disable FileVault in System Settings > Privacy & Security > FileVault."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "unencrypted_laptop":
                actions.append(
                    Action(
                        title="Enable FileVault encryption",
                        description=(
                            "To enable FileVault on your laptop: "
                            "(1) Go to System Settings > Privacy & Security; "
                            "(2) Click the lock icon to authenticate; "
                            "(3) Click 'Turn On' next to FileVault; "
                            "(4) Save your recovery key in a safe place; "
                            "(5) Click 'Continue' and wait for encryption to complete (may take hours). "
                            "Your Mac will be protected if lost or stolen."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "apfs_snapshot_count":
                snapshot_count = finding.data.get("snapshot_count", 0)
                actions.append(
                    Action(
                        title="Too many APFS snapshots",
                        description=(
                            f"You have {snapshot_count} APFS snapshots consuming disk space. "
                            "Snapshots are created automatically during updates and Time Machine backups. "
                            "To manage snapshots: "
                            "(1) Open Terminal; "
                            "(2) Run 'diskutil apfs listSnapshots / | grep diskutil' to list snapshots; "
                            "(3) Consider removing old snapshots if disk space is critical. "
                            "Note: Snapshots may be needed for system recovery - only delete if you understand the risk."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "fs_verification_error":
                actions.append(
                    Action(
                        title="Filesystem verification error detected",
                        description=(
                            "Filesystem verification detected errors indicating potential data corruption. "
                            "To repair: "
                            "(1) Shut down your Mac; "
                            "(2) Hold Command + R while powering on (Recovery Mode); "
                            "(3) Wait for macOS Utilities to load; "
                            "(4) Click 'Disk Utility' and select your drive; "
                            "(5) Click 'First Aid' and follow prompts; "
                            "(6) If First Aid finds errors, back up data immediately and consider professional recovery. "
                            "Data corruption is serious - prioritize data backup."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "inode_low":
                inode_percent = finding.data.get("inode_percent", 0)
                actions.append(
                    Action(
                        title="Low inode availability",
                        description=(
                            f"Your filesystem has only {inode_percent:.1f}% inode availability remaining. "
                            "When inodes run out, you cannot create new files even if space is available. "
                            "To free inodes: "
                            "(1) Identify large directories with many files (especially .cache, .npm, node_modules); "
                            "(2) Use disk analysis tools to find and remove unnecessary files; "
                            "(3) Consider cleaning up development caches or temporary files; "
                            "(4) If critical, backup and reformat the drive to reset inode counts."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "apfs_fusion_drive":
                actions.append(
                    Action(
                        title="APFS Fusion Drive detected",
                        description=(
                            "Your Mac uses an APFS Fusion Drive (typical for iMacs). "
                            "Fusion Drives combine SSD and HDD storage for performance. "
                            "Maintenance tips: "
                            "(1) Keep at least 10% free space for tier management; "
                            "(2) Avoid removing the SSD or HDD separately - they're paired; "
                            "(3) Run First Aid regularly to check both tiers; "
                            "(4) Monitor thermal status as HDD may run warm during syncing."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_filesystem_info(self) -> dict:
        """Get filesystem type and encryption status from diskutil info."""
        try:
            result = subprocess.run(
                ["diskutil", "info", "/"],
                capture_output=True,
                text=True,
                errors="replace",
                timeout=10,
            )
            if result.returncode == 0:
                return self._parse_diskutil_info(result.stdout)
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            pass
        return {}

    def _parse_diskutil_info(self, output: str) -> dict:
        """Parse diskutil info output."""
        info = {}

        # Get filesystem type
        type_match = re.search(r"Type \(Bundle Code\):\s+(\S+)", output)
        if type_match:
            fs_type = type_match.group(1).lower()
            if "apfs" in fs_type:
                info["type"] = "APFS"
            elif "hfs" in fs_type:
                info["type"] = "HFS+"
            else:
                info["type"] = fs_type

        # Get encryption status
        encryption_match = re.search(r"Encrypted:\s+(Yes|No)", output)
        if encryption_match:
            info["encryption"] = encryption_match.group(1)

        return info

    def _check_apfs_health(self) -> list[Finding]:
        """Check APFS-specific health metrics."""
        findings = []

        # Check APFS container
        container_info = self._run_apfs_list()
        if container_info:
            snapshot_findings = self._check_snapshots(container_info)
            findings.extend(snapshot_findings)

            if "Fusion Drive" in container_info:
                findings.append(
                    Finding(
                        title="APFS Fusion Drive detected",
                        description="Your Mac is using an APFS Fusion Drive with combined SSD/HDD storage.",
                        severity=Severity.INFO,
                        category=self.category,
                        data={"check": "apfs_fusion_drive"},
                    )
                )

        return findings

    def _run_apfs_list(self) -> str:
        """Run diskutil apfs list and return output."""
        try:
            result = subprocess.run(
                ["diskutil", "apfs", "list"],
                capture_output=True,
                text=True,
                errors="replace",
                timeout=10,
            )
            if result.returncode == 0:
                return result.stdout
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            pass
        return ""

    def _check_snapshots(self, apfs_output: str) -> list[Finding]:
        """Check for excessive APFS snapshots."""
        findings = []

        # Count snapshot lines
        snapshot_lines = [line for line in apfs_output.split("\n") if "Snapshot" in line]
        snapshot_count = len(snapshot_lines)

        if snapshot_count > 50:
            findings.append(
                Finding(
                    title=f"High APFS snapshot count ({snapshot_count})",
                    description=(
                        f"You have {snapshot_count} APFS snapshots consuming disk space. "
                        "This is higher than recommended. Consider removing old snapshots."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "apfs_snapshot_count", "snapshot_count": snapshot_count},
                )
            )

        return findings

    def _run_verify_volume(self) -> str:
        """Run diskutil verifyVolume / and return output."""
        try:
            result = subprocess.run(
                ["diskutil", "verifyVolume", "/"],
                capture_output=True,
                text=True,
                errors="replace",
                timeout=30,
            )
            return result.stdout + result.stderr
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            pass
        return ""

    def _parse_verify_output(self, output: str) -> list[Finding]:
        """Parse diskutil verifyVolume output for errors."""
        findings = []

        # Check for verification errors
        if "error" in output.lower() or "appears to be corrupt" in output.lower():
            findings.append(
                Finding(
                    title="Filesystem verification error",
                    description=(
                        "Filesystem verification detected errors indicating potential data corruption. "
                        "Immediate action is recommended to prevent data loss."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={"check": "fs_verification_error"},
                )
            )
        elif "appears to be OK" in output or "is OK" in output:
            findings.append(
                Finding(
                    title="Filesystem verification passed",
                    description="Filesystem verification completed successfully with no errors detected.",
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "fs_verification_ok"},
                )
            )

        return findings

    def _check_inode_usage(self) -> Finding | None:
        """Check inode usage on the filesystem."""
        try:
            result = subprocess.run(
                ["df", "-i", "/"],
                capture_output=True,
                text=True,
                errors="replace",
                timeout=10,
            )
            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")
                if len(lines) > 1:
                    parts = lines[1].split()
                    # df -i columns: Filesystem, inodes, iused, ifree, %iused, Mounted on
                    # parts: [0]=filesystem, [1]=total, [2]=used, [3]=avail, [4]=%used, [5]=iused, [6]=ifree, [7]=%iused, [8]=mount
                    if len(parts) >= 8:
                        try:
                            # Extract inode usage percentage from the %iused column
                            inode_percent_str = parts[7].rstrip("%")
                            inode_percent = float(inode_percent_str)
                            if inode_percent > 85:
                                return Finding(
                                    title=f"High inode usage ({inode_percent:.1f}%)",
                                    description=(
                                        f"Your filesystem is using {inode_percent:.1f}% of available inodes. "
                                        "When inodes are exhausted, you cannot create new files even with free space."
                                    ),
                                    severity=Severity.WARNING if inode_percent < 95 else Severity.CRITICAL,
                                    category=self.category,
                                    data={"check": "inode_low", "inode_percent": inode_percent},
                                )
                        except (ValueError, IndexError):
                            pass
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            pass
        return None

    def _is_laptop(self, profile: SystemProfile) -> bool:
        """Determine if this is a laptop based on system profile."""
        # Check if we have battery info in the profile (laptops have batteries)
        # For now, check if it's not an iMac, Mac mini, or Mac Studio
        model = getattr(profile, "cpu_model", "").lower()
        return "imac" not in model and "mac mini" not in model and "studio" not in model
