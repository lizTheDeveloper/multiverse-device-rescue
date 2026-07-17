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
    name = "kernel_extensions_audit"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    # Known problematic kexts that cause issues
    KNOWN_PROBLEMATIC_KEXTS = {
        "com.kaspersky": "Kaspersky antivirus (legacy)",
        "com.mcafee": "McAfee antivirus (legacy)",
        "com.norton": "Norton antivirus (legacy)",
        "com.symantec": "Symantec antivirus (legacy)",
        "com.avast": "Avast antivirus (may be legacy)",
        "com.avg": "AVG antivirus (may be legacy)",
        "com.bitdefender": "Bitdefender antivirus (may be legacy)",
        "com.oracle.virtualbox": "VirtualBox (legacy kext)",
        "com.parallels": "Parallels Desktop (may have legacy kext)",
        "org.openvpn": "OpenVPN (legacy kext)",
        "com.openvpn": "OpenVPN (legacy kext)",
        "at.obdev.nke": "Little Snitch (kext-based, legacy approach)",
    }

    # Apple's own kernel extensions (safe)
    APPLE_BUNDLE_PREFIXES = [
        "com.apple",
        "apple",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get list of loaded kernel extensions
        loaded_kexts = self._get_loaded_kexts()

        if not loaded_kexts:
            # If we can't get kexts, flag it as informational
            findings.append(
                Finding(
                    title="Unable to audit kernel extensions",
                    description=(
                        "Could not retrieve kernel extensions. This may occur on "
                        "newer macOS versions (Monterey+) with restricted permissions "
                        "or on systems without legacy kexts support."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "kext_retrieval_failed"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # Separate Apple and third-party kexts
        apple_kexts = []
        third_party_kexts = []

        for bundle_id, kext_info in loaded_kexts.items():
            is_apple = any(
                bundle_id.startswith(prefix)
                for prefix in self.APPLE_BUNDLE_PREFIXES
            )
            if is_apple:
                apple_kexts.append((bundle_id, kext_info))
            else:
                third_party_kexts.append((bundle_id, kext_info))

        # Check for known problematic kexts
        problematic_kexts = []
        for bundle_id, kext_info in third_party_kexts:
            for known_id, description in self.KNOWN_PROBLEMATIC_KEXTS.items():
                if bundle_id.lower().startswith(known_id.lower()):
                    problematic_kexts.append((bundle_id, description, kext_info))
                    break

        # Flag problematic kexts
        if problematic_kexts:
            kext_list = "\n".join(
                f"  - {bid} ({desc}): {info}"
                for bid, desc, info in problematic_kexts
            )
            findings.append(
                Finding(
                    title=f"Known problematic kernel extensions: {len(problematic_kexts)}",
                    description=(
                        f"Found {len(problematic_kexts)} kernel extension(s) known to cause "
                        f"stability or security issues:\n{kext_list}\n\n"
                        "These are typically legacy kexts that should be updated to use "
                        "System Extensions or removed entirely."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "problematic_kexts",
                        "kexts": [bid for bid, _, _ in problematic_kexts],
                    },
                )
            )

        # Flag all non-Apple kexts (informational)
        if third_party_kexts:
            # Only flag non-problematic third-party kexts as INFO
            non_problematic = [
                bid for bid, _ in third_party_kexts
                if not any(
                    bid.lower().startswith(known_id.lower())
                    for known_id in self.KNOWN_PROBLEMATIC_KEXTS.keys()
                )
            ]

            if non_problematic:
                kext_list = "\n".join(f"  - {bid}" for bid in sorted(non_problematic))
                findings.append(
                    Finding(
                        title=f"Third-party kernel extensions: {len(non_problematic)}",
                        description=(
                            f"Found {len(non_problematic)} non-Apple kernel extension(s):\n{kext_list}\n\n"
                            "Third-party kexts can impact system stability and security. "
                            "Consider updating to System Extensions (modern replacement) "
                            "or removing unnecessary kexts."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={
                            "check": "third_party_kexts",
                            "kexts": non_problematic,
                        },
                    )
                )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")
            kexts = finding.data.get("kexts", [])

            if check == "problematic_kexts":
                kext_list = ", ".join(sorted(kexts))
                actions.append(
                    Action(
                        title="Update or remove problematic kernel extensions",
                        description=(
                            f"Problematic kexts found: {kext_list}\n\n"
                            "Actions to take:\n"
                            "1. For antivirus software (Kaspersky, McAfee, Norton, etc.): "
                            "Update to the latest version or uninstall and switch to "
                            "built-in macOS Gatekeeper/XProtect or modern alternatives.\n"
                            "2. For VPN (OpenVPN): Install official OpenVPN client which uses "
                            "System Extensions instead of legacy kexts.\n"
                            "3. For VirtualBox/Parallels: Update to latest version with "
                            "System Extensions support or use Apple Silicon native virtualization.\n\n"
                            "To remove a kext:\n"
                            "- sudo rm -rf /Library/Extensions/[kext_name].kext\n"
                            "- sudo kextunload /Library/Extensions/[kext_name].kext (before removal)\n"
                            "- Restart required after changes"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "third_party_kexts":
                kext_list = ", ".join(sorted(kexts[:5]))
                if len(kexts) > 5:
                    kext_list += f", and {len(kexts) - 5} more"
                actions.append(
                    Action(
                        title="Review third-party kernel extensions",
                        description=(
                            f"Third-party kexts loaded: {kext_list}\n\n"
                            "To improve system stability and security:\n"
                            "1. Verify each kext is necessary for your workflow\n"
                            "2. Check if vendor provides System Extensions alternative\n"
                            "3. Uninstall unneeded kexts via the vendor's uninstaller\n"
                            "4. Monitor System Preferences > Security & Privacy > Extensions "
                            "(on Big Sur+) for System Extensions alternatives\n\n"
                            "Note: On macOS Monterey and later, kernel extensions are "
                            "increasingly deprecated in favor of System Extensions."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "kext_retrieval_failed":
                actions.append(
                    Action(
                        title="Check kernel extensions manually",
                        description=(
                            "If you suspect problematic kernel extensions are loaded, "
                            "check using:\n"
                            "- kextstat (older macOS)\n"
                            "- kmutil showloaded (macOS Monterey+)\n\n"
                            "Or use System Preferences > Security & Privacy > Extensions "
                            "to view System Extensions (modern replacement for kexts)."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_loaded_kexts(self) -> dict[str, str]:
        """Get dictionary of loaded kernel extensions.

        Returns {bundle_id: description} on success, {} on failure.
        Tries both kextstat (older) and kmutil (macOS Monterey+).
        """
        kexts = {}

        # Try kmutil first (macOS Monterey+)
        try:
            result = subprocess.run(
                ["kmutil", "showloaded"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                return self._parse_kmutil_output(result.stdout)
        except (OSError, subprocess.TimeoutExpired, Exception):
            pass

        # Fall back to kextstat (older macOS)
        try:
            result = subprocess.run(
                ["kextstat"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                return self._parse_kextstat_output(result.stdout)
        except (OSError, subprocess.TimeoutExpired, Exception):
            pass

        return {}

    def _parse_kmutil_output(self, output: str) -> dict[str, str]:
        """Parse kmutil showloaded output.

        Format:
        Index Bundle identifier                   Version
            0 com.apple.kext.foo                 1.0.0
        """
        kexts = {}
        lines = output.strip().split("\n")

        for line in lines[1:]:  # Skip header
            if not line.strip():
                continue
            # Split on whitespace
            parts = line.split()
            if len(parts) >= 2:
                # Skip first column (index), look for bundle ID (contains dots)
                for i in range(1, len(parts)):
                    part = parts[i]
                    if "." in part and not part[0].isdigit():
                        kexts[part] = line.strip()
                        break

        return kexts

    def _parse_kextstat_output(self, output: str) -> dict[str, str]:
        """Parse kextstat output.

        Format:
        Index Refs Address                Size     Wired Name (Version) <Address>
            0   36 0xffffff7f80200000    0x70c000 0x70c000 com.apple.kext.foo (1.0.0)
        """
        kexts = {}
        lines = output.strip().split("\n")

        for line in lines[1:]:  # Skip header
            if not line.strip():
                continue
            # Find where the bundle ID starts (after the numeric columns)
            # Look for a pattern with dots (bundle IDs have dots)
            parts = line.split()
            # Skip Index, Refs, Address, Size, Wired (first 5 columns)
            if len(parts) >= 6:
                # Bundle ID is at position 5 (0-indexed)
                bundle_id = parts[5]
                if bundle_id and "." in bundle_id:
                    kexts[bundle_id] = line.strip()

        return kexts
