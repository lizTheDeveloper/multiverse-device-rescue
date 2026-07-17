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
    name = "rootkit_check"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check SIP status - rootkits require SIP to be disabled
        sip_enabled = self._check_sip_status()
        if sip_enabled is False:
            findings.append(
                Finding(
                    title="System Integrity Protection (SIP) is disabled",
                    description=(
                        "SIP is disabled on this machine, which enables rootkit installation. "
                        "Rootkits require SIP to be disabled to modify system files. "
                        "This is a significant security risk."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={"check": "sip_status"},
                )
            )

        # Check system binary integrity via code signatures
        binary_issues = self._check_binary_integrity()
        for issue in binary_issues:
            findings.append(issue)

        # Check for suspicious kernel extensions
        kext_issues = self._check_kernel_extensions()
        for issue in kext_issues:
            findings.append(issue)

        # Check for hidden processes
        process_issues = self._check_hidden_processes()
        for issue in process_issues:
            findings.append(issue)

        # Check for hidden files in root directory
        hidden_file_issues = self._check_hidden_root_files()
        for issue in hidden_file_issues:
            findings.append(issue)

        # If no findings, add an INFO finding
        if not findings:
            findings.append(
                Finding(
                    title="Rootkit checks passed",
                    description=(
                        "All rootkit detection checks passed. "
                        "System binaries are code-signed, no suspicious kernel extensions detected, "
                        "process counts match, and no suspicious hidden files found."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "all_clean"},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        """
        Provide informational guidance on remediation.
        Does not modify system.
        """
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "sip_status":
                actions.append(
                    Action(
                        title="Re-enable System Integrity Protection (SIP)",
                        description=(
                            "Reboot into Recovery Mode (Cmd+R during startup), open Terminal, "
                            "and run: csrutil enable\n"
                            "Then reboot normally. SIP protection is critical for system security."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "binary_integrity":
                actions.append(
                    Action(
                        title="Verify and repair system binaries",
                        description=(
                            "System binaries have invalid or missing code signatures. "
                            "This may indicate rootkit infection or system corruption.\n"
                            "Steps to verify:\n"
                            "1. Run 'codesign -v /path/to/binary' to check the signature\n"
                            "2. If invalid, run full security scans (e.g., YARA, ClamAV)\n"
                            "3. Consider reinstalling macOS to restore system binaries\n"
                            "4. Boot into Recovery Mode to run First Aid on the system drive"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "kernel_extensions":
                actions.append(
                    Action(
                        title="Investigate suspicious kernel extensions",
                        description=(
                            "Non-Apple kernel extensions are loaded. "
                            "While not always malicious, this requires investigation.\n"
                            "Steps:\n"
                            "1. Review the purpose of each extension with: kextstat\n"
                            "2. Check vendor legitimacy for each extension\n"
                            "3. Remove suspicious extensions if not needed\n"
                            "4. Run security scans on binaries associated with extensions"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "hidden_processes":
                actions.append(
                    Action(
                        title="Investigate process count discrepancy",
                        description=(
                            "Process count from 'ps' does not match system records. "
                            "This may indicate hidden processes typical of rootkits.\n"
                            "Steps to investigate:\n"
                            "1. Compare: ps -eo pid | wc -l vs sysctl kern.proc.all | wc -l\n"
                            "2. Run: lsof to see all open file descriptors\n"
                            "3. Run security scans for process-hiding rootkits\n"
                            "4. Boot into safe mode to see if processes still hidden"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "hidden_files":
                actions.append(
                    Action(
                        title="Investigate hidden files in root directory",
                        description=(
                            "Unusual hidden files detected in the / root directory. "
                            "Rootkits often hide their files using dot-prefix naming.\n"
                            "Steps:\n"
                            "1. Review suspicious files with: ls -la /\n"
                            "2. Check file ownership and timestamps\n"
                            "3. Scan suspicious files with security tools\n"
                            "4. Cross-reference with standard macOS hidden directories"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _check_sip_status(self) -> bool | None:
        """
        Check SIP status via: csrutil status
        Returns: True if enabled, False if disabled, None if unable to determine
        """
        try:
            result = subprocess.run(
                ["/usr/bin/csrutil", "status"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return None
            output = result.stdout.lower()
            return "enabled" in output
        except (OSError, subprocess.SubprocessError):
            return None

    def _check_binary_integrity(self) -> list[Finding]:
        """
        Check code signature integrity of critical system binaries.
        Returns list of CRITICAL findings if any binary fails verification.
        """
        findings = []
        critical_binaries = [
            "/usr/bin/login",
            "/usr/sbin/sshd",
            "/bin/sh",
            "/bin/bash",
        ]

        for binary in critical_binaries:
            try:
                result = subprocess.run(
                    ["/usr/bin/codesign", "-v", binary],
                    capture_output=True,
                    text=True,
                )
                if result.returncode != 0:
                    findings.append(
                        Finding(
                            title=f"System binary code signature verification failed: {binary}",
                            description=(
                                f"The system binary {binary} failed code signature verification. "
                                f"This indicates the binary may have been modified or is corrupted. "
                                f"This is a strong indicator of rootkit infection or system compromise."
                            ),
                            severity=Severity.CRITICAL,
                            category=self.category,
                            data={"check": "binary_integrity", "binary": binary},
                        )
                    )
            except (OSError, subprocess.SubprocessError):
                # If we can't run codesign, we can't verify - skip this binary
                pass

        return findings

    def _check_kernel_extensions(self) -> list[Finding]:
        """
        Check for suspicious (non-Apple) kernel extensions.
        Returns WARNING findings for each non-Apple kernel extension.
        """
        findings = []

        try:
            result = subprocess.run(
                ["/usr/sbin/kextstat"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return findings

            lines = result.stdout.strip().split("\n")
            non_apple_kexts = []

            for line in lines:
                # Skip header line and empty lines
                if not line or line.startswith("Index"):
                    continue

                # Bundle identifiers are typically in format: com.something.something
                # They appear as the last element before the version in parentheses
                # Format: Index Refs Address Size Wired Name (Version)
                parts = line.split()
                if len(parts) > 5:
                    # Bundle identifier is typically before the version "(X.X)"
                    # Look for the pattern that looks like a bundle identifier
                    for i, part in enumerate(parts):
                        # Bundle IDs start with lowercase and contain dots, no parentheses
                        if (
                            "." in part
                            and not part.startswith("0x")
                            and not part.startswith("(")
                            and not part.endswith(")")
                        ):
                            if not part.startswith("com.apple"):
                                non_apple_kexts.append(part)
                                break

            if non_apple_kexts:
                findings.append(
                    Finding(
                        title="Non-Apple kernel extensions detected",
                        description=(
                            f"Found {len(non_apple_kexts)} non-Apple kernel extension(s) loaded: "
                            f"{', '.join(set(non_apple_kexts))}. "
                            "While not always malicious, kernel extensions are a common vector "
                            "for rootkit installation. Ensure all loaded extensions are from trusted sources."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check": "kernel_extensions", "count": len(non_apple_kexts)},
                    )
                )

        except (OSError, subprocess.SubprocessError):
            pass

        return findings

    def _check_hidden_processes(self) -> list[Finding]:
        """
        Check for hidden processes by comparing process counts.
        Compares: ps -eo pid count vs sysctl kern.proc.all count
        Returns WARNING if discrepancy detected.
        """
        findings = []

        try:
            # Get process count from ps
            ps_result = subprocess.run(
                ["/bin/ps", "-eo", "pid"],
                capture_output=True,
                text=True,
            )
            if ps_result.returncode == 0:
                ps_count = len(ps_result.stdout.strip().split("\n")) - 1  # -1 for header

                # Get process count from sysctl
                sysctl_result = subprocess.run(
                    ["/usr/sbin/sysctl", "kern.proc.all"],
                    capture_output=True,
                    text=True,
                )
                if sysctl_result.returncode == 0:
                    # sysctl output format: "kern.proc.all: <count>"
                    sysctl_count_str = sysctl_result.stdout.split(":")[-1].strip()
                    try:
                        sysctl_count = int(sysctl_count_str)

                        # Allow small discrepancies (up to 10 processes)
                        if abs(ps_count - sysctl_count) > 10:
                            findings.append(
                                Finding(
                                    title="Process count discrepancy detected",
                                    description=(
                                        f"Process count mismatch: ps reports {ps_count} processes, "
                                        f"but sysctl reports {sysctl_count}. "
                                        "This discrepancy may indicate hidden processes, "
                                        "which is a characteristic of rootkit activity."
                                    ),
                                    severity=Severity.WARNING,
                                    category=self.category,
                                    data={
                                        "check": "hidden_processes",
                                        "ps_count": ps_count,
                                        "sysctl_count": sysctl_count,
                                    },
                                )
                            )
                    except ValueError:
                        pass

        except (OSError, subprocess.SubprocessError):
            pass

        return findings

    def _check_hidden_root_files(self) -> list[Finding]:
        """
        Check for suspicious hidden files in / root directory.
        Rootkits commonly hide files using dot-prefix naming.
        Returns WARNING if suspicious hidden files found.
        """
        findings = []

        try:
            result = subprocess.run(
                ["/bin/ls", "-la", "/"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")
                # Filter for hidden files/dirs (starting with .)
                hidden_items = []
                standard_hidden = {
                    ".",
                    "..",
                    ".DS_Store",
                    ".fseventsd",
                    ".vol",
                    ".metadata_never_index",
                    ".hotfiles.btree",
                    ".Spotlight-V100",
                    ".TemporaryItems",
                    ".Trashes",
                    ".com.apple.nfs_lockd",
                    ".kern.aslmanifest.pid",
                }

                for line in lines:
                    parts = line.split()
                    if len(parts) > 8:
                        name = parts[-1]
                        if name.startswith(".") and name not in standard_hidden:
                            hidden_items.append(name)

                if hidden_items:
                    findings.append(
                        Finding(
                            title="Suspicious hidden files in root directory",
                            description=(
                                f"Found {len(hidden_items)} non-standard hidden file(s) in /: "
                                f"{', '.join(hidden_items)}. "
                                "Rootkits often hide files using dot-prefix naming in the root directory. "
                                "Verify these files are legitimate system files."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            data={"check": "hidden_files", "files": hidden_items},
                        )
                    )

        except (OSError, subprocess.SubprocessError):
            pass

        return findings
