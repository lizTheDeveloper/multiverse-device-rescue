import subprocess
from datetime import datetime, timedelta

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

# Common third-party AV applications to check for
THIRD_PARTY_AV_APPS = {
    "Malwarebytes": {"bundle_id": "com.malwarebytes.Malwarebytes", "process": "malwarebytes"},
    "Norton": {"bundle_id": "com.symantec.norton", "process": "Norton"},
    "Avast": {"bundle_id": "com.avast.macos", "process": "Avast"},
    "Sophos": {"bundle_id": "com.sophos.endpoint", "process": "Sophos"},
    "CrowdStrike": {"bundle_id": "com.crowdstrike.falconsensor", "process": "falcon"},
    "SentinelOne": {"bundle_id": "com.sentinelone.agent", "process": "SentinelOne"},
}

# XProtect and MRT plist paths
XPROTECT_INFO_PLIST = "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"
XPROTECT_REMEDIATOR_INFO_PLIST = "/Library/Apple/System/Library/CoreServices/XProtect Remediator.bundle/Contents/Info.plist"
MRT_INFO_PLIST = "/System/Library/CoreServices/MRT.app/Contents/Info.plist"


class Module(ModuleBase):
    name = "antivirus_status"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 56
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check XProtect Remediator version
        xprotect_remediator_version = self._get_xprotect_remediator_version()
        findings.append(
            Finding(
                title=f"XProtect Remediator: {'Present' if xprotect_remediator_version else 'Not found'}",
                description=(
                    f"XProtect Remediator (malware remediation tool) is "
                    f"{'installed' if xprotect_remediator_version else 'not detected'}. "
                    f"Version: {xprotect_remediator_version or 'Unknown'}"
                ),
                severity=Severity.INFO,
                category=self.category,
                data={"check": "xprotect_remediator", "version": xprotect_remediator_version},
            )
        )

        # Check MRT version
        mrt_version = self._get_mrt_version()
        findings.append(
            Finding(
                title=f"MRT (Malware Removal Tool): {'Present' if mrt_version else 'Not found'}",
                description=(
                    f"MRT is Apple's Malware Removal Tool, a background process that "
                    f"{'is installed' if mrt_version else 'was not detected'}. "
                    f"Version: {mrt_version or 'Unknown'}"
                ),
                severity=Severity.INFO,
                category=self.category,
                data={"check": "mrt", "version": mrt_version},
            )
        )

        # Check for third-party AV installations
        detected_av = self._detect_third_party_av()
        if detected_av:
            av_list = ", ".join(detected_av.keys())
            findings.append(
                Finding(
                    title=f"Third-party antivirus detected: {av_list}",
                    description=(
                        f"The following third-party antivirus/anti-malware applications are installed: "
                        f"{av_list}. These provide additional protection beyond macOS built-in tools."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "third_party_av", "applications": list(detected_av.keys())},
                )
            )

            # Check if detected AV is running
            for av_name, av_info in detected_av.items():
                is_running = self._is_process_running(av_info["process"])
                if not is_running:
                    findings.append(
                        Finding(
                            title=f"Third-party AV not running: {av_name}",
                            description=(
                                f"{av_name} is installed but does not appear to be running. "
                                f"Check System Settings > General > Login Items to ensure it launches at startup, "
                                f"or open {av_name} to start its protection services."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            data={"check": "av_not_running", "av_name": av_name},
                        )
                    )
        else:
            findings.append(
                Finding(
                    title="No third-party antivirus detected",
                    description=(
                        "No common third-party antivirus applications were detected. "
                        "macOS built-in protections (XProtect, MRT) are active."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "no_third_party_av"},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")
            if check == "av_not_running":
                av_name = finding.data.get("av_name")
                actions.append(
                    Action(
                        title=f"Start {av_name} protection",
                        description=(
                            f"Open {av_name} from Applications or check System Settings > General > Login Items "
                            f"to ensure {av_name} starts automatically at boot. Verify its real-time protection is enabled."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
        return FixResult(module_name=self.name, actions=actions)

    def _get_xprotect_remediator_version(self) -> str | None:
        """
        Retrieve XProtect Remediator version from its Info.plist.
        Returns the version string, or None if not found.
        """
        try:
            result = subprocess.run(
                [
                    "defaults",
                    "read",
                    XPROTECT_REMEDIATOR_INFO_PLIST,
                    "CFBundleShortVersionString",
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return None
            return result.stdout.strip()
        except OSError:
            return None

    def _get_mrt_version(self) -> str | None:
        """
        Retrieve MRT (Malware Removal Tool) version from its Info.plist.
        Returns the version string, or None if not found.
        """
        try:
            result = subprocess.run(
                [
                    "defaults",
                    "read",
                    MRT_INFO_PLIST,
                    "CFBundleShortVersionString",
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return None
            return result.stdout.strip()
        except OSError:
            return None

    def _detect_third_party_av(self) -> dict[str, dict]:
        """
        Detect installed third-party antivirus applications.
        Returns a dict mapping AV name to its info (bundle_id, process name).
        """
        detected = {}
        for av_name, av_info in THIRD_PARTY_AV_APPS.items():
            if self._is_app_installed(av_name):
                detected[av_name] = av_info
        return detected

    def _is_app_installed(self, app_name: str) -> bool:
        """
        Check if an application is installed in /Applications or ~/Applications.
        """
        try:
            # Use mdfind to search for the application
            result = subprocess.run(
                [
                    "mdfind",
                    f"kMDItemKind == 'Application' && kMDItemDisplayName == '{app_name}*'",
                ],
                capture_output=True,
                text=True,
                timeout=3,
            )
            return result.returncode == 0 and len(result.stdout.strip()) > 0
        except (OSError, subprocess.TimeoutExpired):
            # Fall back to checking /Applications directory
            try:
                result = subprocess.run(
                    ["ls", "/Applications"],
                    capture_output=True,
                    text=True,
                )
                if result.returncode == 0:
                    return app_name.lower() in result.stdout.lower()
            except OSError:
                pass
            return False

    def _is_process_running(self, process_name: str) -> bool:
        """
        Check if a process is currently running via pgrep.
        """
        try:
            result = subprocess.run(
                ["pgrep", "-i", process_name],
                capture_output=True,
                text=True,
            )
            return result.returncode == 0
        except OSError:
            return False
