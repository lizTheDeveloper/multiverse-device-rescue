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

    emits_codes = [
        "security.rootkit_check.sip_disabled",
        "security.rootkit_check.binary_integrity",
        "security.rootkit_check.kernel_extensions",
        "security.rootkit_check.hidden_processes",
        "security.rootkit_check.hidden_files",
        "security.rootkit_check.all_clean",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check SIP status - rootkits require SIP to be disabled
        sip_enabled = self._check_sip_status()
        if sip_enabled is False:
            findings.append(
                Finding(
                    title="System Integrity Protection (SIP) is turned off",
                    description=(
                        "System Integrity Protection (SIP) stops any app, even one with "
                        "your password, from changing the core parts of macOS. It's switched "
                        "off. People sometimes turn it off for specialist software, but "
                        "if you didn't, something or someone else did, and hidden software "
                        "can dig in deeper while it's off.\n\n"
                        "What to do: Shut down your Mac. On a Mac with Apple silicon, "
                        "hold the power button until you see startup options, then choose "
                        "Options. On an Intel Mac, hold Command-R while it starts. Choose "
                        "Utilities > Terminal, type csrutil enable, press Return, and "
                        "restart."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    code="security.rootkit_check.sip_disabled",
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
                    code="security.rootkit_check.all_clean",
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
                            title=(
                                "A core system file on your Mac looks changed or broken "
                                f"({binary})"
                            ),
                            description=(
                                f"The system file {binary} failed Apple's signature check, "
                                "so it may have been changed or damaged. Malware that "
                                "hides itself sometimes replaces system files like this, "
                                "but disk damage can also cause it.\n\n"
                                "What to do: Back up your personal files, then reinstall "
                                "macOS from Recovery; this replaces system files and "
                                "keeps your own. Run the checkup again afterwards. The "
                                "steps below go through it."
                            ),
                            severity=Severity.CRITICAL,
                            category=self.category,
                            code="security.rootkit_check.binary_integrity",
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
                        title=(
                            f"Kernel extensions from outside Apple are loaded ({len(non_apple_kexts)})"
                        ),
                        description=(
                            f"Your Mac has {len(non_apple_kexts)} kernel extension(s) "
                            f"from companies other than Apple: {', '.join(set(non_apple_kexts))}. "
                            "Kernel extensions run at the deepest level of the system. "
                            "Drivers for printers, audio gear, VPNs and security tools "
                            "use them; so does some malware.\n\n"
                            "What to do: Check whether each name belongs to hardware "
                            "or software you use. If one doesn't, uninstall the app it "
                            "came with, or look in System Settings > General > Login "
                            "Items & Extensions."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        code="security.rootkit_check.kernel_extensions",
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
                                    title=(
                                        f"Your Mac is hiding processes from view ({ps_count} "
                                        f"vs {sysctl_count})"
                                    ),
                                    description=(
                                        "Two ways of counting running programs disagree: "
                                        f"{ps_count} versus {sysctl_count}. Programs start "
                                        "and stop all the time, so a small gap can be "
                                        "a coincidence of timing. A gap that stays can "
                                        "mean something is hiding itself, which is what "
                                        "some monitoring tools do.\n\n"
                                        "If you think someone close to you may have put "
                                        "monitoring software on this Mac, removing it "
                                        "can alert them. Talk to an advocate first (US "
                                        "National Domestic Violence Hotline: 1-800-799-7233, "
                                        "or text START to 88788).\n\n"
                                        "What to do: Run the checkup again. If the gap "
                                        "is still there, follow the steps below."
                                    ),
                                    severity=Severity.WARNING,
                                    category=self.category,
                                    code="security.rootkit_check.hidden_processes",
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

    # Exact names (no wildcards) and the file type each one has on a real Mac.
    # "d" directory, "f" regular file, "l" symlink. An entry with an expected
    # name but the wrong type is still reported, so a rootkit cannot hide behind
    # a look-alike name.
    STANDARD_ROOT_DOT_ENTRIES = {
        ".DS_Store": "f",
        ".fseventsd": "d",
        ".vol": "d",
        ".metadata_never_index": "f",
        ".hotfiles.btree": "f",
        ".Spotlight-V100": "d",
        ".TemporaryItems": "d",
        ".Trashes": "d",
        ".file": "f",
        ".nofollow": "d",
        ".resolve": "d",
        ".VolumeIcon.icns": "l",
        ".DocumentRevisions-V100": "d",
        ".PKInstallSandboxManager": "d",
        ".PKInstallSandboxManager-SystemSoftware": "d",
        ".MobileBackups": "d",
        ".com.apple.nfs_lockd": "d",
    }

    @staticmethod
    def _list_root_dot_entries() -> list[tuple[str, str]]:
        """Return (name, type) for dot-entries in /, using lstat (never follows links)."""
        import os
        import stat

        entries = []
        with os.scandir("/") as it:
            for entry in it:
                if not entry.name.startswith("."):
                    continue
                mode = os.lstat(entry.path).st_mode
                if stat.S_ISLNK(mode):
                    kind = "l"
                elif stat.S_ISDIR(mode):
                    kind = "d"
                elif stat.S_ISREG(mode):
                    kind = "f"
                else:
                    kind = "o"
                entries.append((entry.name, kind))
        return entries

    def _check_hidden_root_files(self) -> list[Finding]:
        """Flag dot-entries in / that are not exact, correctly-typed standard ones."""
        findings = []
        try:
            entries = self._list_root_dot_entries()
        except OSError:
            return findings

        hidden_items = [
            name
            for name, kind in entries
            if self.STANDARD_ROOT_DOT_ENTRIES.get(name) != kind
        ]
        if hidden_items:
            hidden_items.sort()
            findings.append(
                Finding(
                    title=(
                        f"Unusual hidden files found in your Mac's main folder ({len(hidden_items)})"
                    ),
                    description=(
                        f"We found {len(hidden_items)} hidden item(s) at the top level "
                        f"of your disk that aren't standard macOS files: {', '.join(hidden_items)}. "
                        "Apps sometimes leave things there, but it's also a hiding place "
                        "for unwanted software.\n\n"
                        "What to do: Look each name up. In Finder, press Command-Shift-G, "
                        "type /, then press Command-Shift-. (period) to show hidden files. "
                        "Don't delete anything you can't identify; ask someone you trust "
                        "to help."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.rootkit_check.hidden_files",
                    data={"check": "hidden_files", "files": hidden_items},
                )
            )
        return findings
