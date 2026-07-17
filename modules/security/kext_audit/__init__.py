import subprocess
import os
import re
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

# Common problematic kexts to flag specifically
PROBLEMATIC_KEXTS = {
    "org.virtualbox": {
        "name": "VirtualBox",
        "description": "VirtualBox kernel extension. This is deprecated and unsupported on modern macOS.",
    },
    "com.vmware": {
        "name": "VMware",
        "description": "VMware kernel extension. This is deprecated and unsupported on modern macOS.",
    },
    "com.cisco.anyconnect": {
        "name": "Cisco AnyConnect VPN",
        "description": "Old Cisco VPN kext. May be incompatible with modern macOS.",
    },
    "com.paragon": {
        "name": "Paragon NTFS",
        "description": "Paragon NTFS kernel extension. No longer supported on modern macOS.",
    },
}


class Module(ModuleBase):
    name = "kext_audit"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 65
    depends_on = []
    estimated_duration = "3s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get loaded kexts from kextstat
        loaded_kexts = self._get_loaded_kexts()

        # Check for third-party loaded kexts
        for kext in loaded_kexts:
            bundle_id = kext["bundle_id"]
            name = kext["name"]
            version = kext.get("version", "unknown")

            # Skip Apple kexts
            if bundle_id.startswith("com.apple."):
                continue

            # Check if kext is unsigned (no version or other signature issues)
            is_unsigned = self._is_unsigned_kext(kext)

            # Check if it's a problematic kext
            is_problematic = False
            problem_info = None
            for prefix, info in PROBLEMATIC_KEXTS.items():
                if bundle_id.startswith(prefix):
                    is_problematic = True
                    problem_info = info
                    break

            # Create finding for third-party kext
            if is_problematic:
                severity = Severity.CRITICAL if is_unsigned else Severity.WARNING
                findings.append(
                    Finding(
                        title=f"{problem_info['name']} kext loaded",
                        description=f"{problem_info['description']} Bundle ID: {bundle_id}, Version: {version}",
                        severity=severity,
                        category=self.category,
                        data={
                            "check": "loaded_third_party_kext",
                            "bundle_id": bundle_id,
                            "name": name,
                            "version": version,
                            "is_unsigned": is_unsigned,
                            "source": "kextstat",
                        },
                    )
                )
            else:
                # Generic third-party kext warning
                severity = Severity.CRITICAL if is_unsigned else Severity.WARNING
                findings.append(
                    Finding(
                        title=f"Third-party kext loaded: {name}",
                        description=f"Third-party kernel extension '{name}' is loaded. Bundle ID: {bundle_id}, Version: {version}. Third-party kexts are deprecated and may cause stability issues.",
                        severity=severity,
                        category=self.category,
                        data={
                            "check": "loaded_third_party_kext",
                            "bundle_id": bundle_id,
                            "name": name,
                            "version": version,
                            "is_unsigned": is_unsigned,
                            "source": "kextstat",
                        },
                    )
                )

        # Check /Library/Extensions/ for kext files
        kext_files = self._get_kext_files()
        for kext_path in kext_files:
            kext_name = Path(kext_path).stem
            findings.append(
                Finding(
                    title=f"Kext file found in /Library/Extensions/: {kext_name}",
                    description=f"Kernel extension file '{kext_name}.kext' is present in /Library/Extensions/. This is deprecated on modern macOS. Consider removing it.",
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "kext_file",
                        "path": kext_path,
                        "name": kext_name,
                        "source": "filesystem",
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")
            bundle_id = finding.data.get("bundle_id")
            kext_name = finding.data.get("name")
            kext_path = finding.data.get("path")

            if check == "loaded_third_party_kext":
                description = (
                    f"Unload the kext '{kext_name}' (ID: {bundle_id}). "
                    f"This requires sudo: `sudo kextunload -b {bundle_id}`. "
                    f"Then reboot or disable the kext in System Preferences to prevent reload."
                )
            elif check == "kext_file":
                description = (
                    f"Remove the kext file '{kext_path}'. "
                    f"This requires sudo: `sudo rm -rf '{kext_path}'`. "
                    f"Consider backing it up first if you need it."
                )
            else:
                continue

            actions.append(
                Action(
                    title=f"Remove/unload kext: {kext_name}",
                    description=description,
                    risk_level=RiskLevel.SAFE,
                    success=True,
                    error=None,
                )
            )
        return FixResult(module_name=self.name, actions=actions)

    def _get_loaded_kexts(self) -> list[dict]:
        """Parse kextstat output to get list of loaded kexts"""
        kexts = []
        try:
            result = subprocess.run(
                ["kextstat"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return kexts

            lines = result.stdout.strip().split("\n")
            # Skip header line
            for line in lines[1:]:
                if not line.strip():
                    continue
                kext = self._parse_kextstat_line(line)
                if kext:
                    kexts.append(kext)
        except OSError:
            pass

        return kexts

    def _parse_kextstat_line(self, line: str) -> dict | None:
        """Parse a single line from kextstat output"""
        # Format: Index Refs Address Size Wired Name (Version) <Linked>
        # Example: 1    0 0xffffff7f80000000 0x1000 0x1000 com.apple.driver.AppleACPIPlatform (1.0) <7 6 5 4 3 1>
        parts = line.split()
        if len(parts) < 6:
            return None

        # Extract bundle ID, version, and linked references
        # Find the bundle ID (format: com.xxx.yyy.zzz)
        bundle_id = None
        version = "unknown"
        has_linked_refs = False

        for i, part in enumerate(parts):
            # Bundle IDs start with a letter and contain dots
            if "." in part and not part.startswith("0x"):
                bundle_id = part
                # Check if next part is version (in parentheses)
                if i + 1 < len(parts):
                    next_part = parts[i + 1]
                    if next_part.startswith("(") and next_part.endswith(")"):
                        version = next_part.strip("()")
                        # Check if there are linked references after version
                        if i + 2 < len(parts) and parts[i + 2].startswith("<"):
                            has_linked_refs = True
                    elif next_part.startswith("<"):
                        has_linked_refs = True
                break

        if not bundle_id:
            return None

        return {
            "bundle_id": bundle_id,
            "name": bundle_id.split(".")[-1],
            "version": version,
            "has_linked_refs": has_linked_refs,
        }

    def _is_unsigned_kext(self, kext: dict) -> bool:
        """Check if a kext is unsigned"""
        # A kext without linked references is likely unsigned or improperly signed
        return not kext.get("has_linked_refs", False)

    def _get_kext_files(self) -> list[str]:
        """Find kext files in /Library/Extensions/"""
        kext_files = []
        extensions_dir = "/Library/Extensions"

        if not os.path.exists(extensions_dir):
            return kext_files

        try:
            result = subprocess.run(
                ["find", extensions_dir, "-name", "*.kext", "-type", "d"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    if line.strip():
                        kext_files.append(line.strip())
        except OSError:
            pass

        return kext_files
