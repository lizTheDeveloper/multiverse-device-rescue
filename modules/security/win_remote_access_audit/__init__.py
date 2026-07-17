import subprocess
import re

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
    name = "win_remote_access_audit"
    category = "security"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 55
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []
        found_tools = {}

        # Check TeamViewer
        if self._check_teamviewer():
            found_tools["TeamViewer"] = True
            findings.append(
                Finding(
                    title="TeamViewer is installed",
                    description=(
                        "TeamViewer remote access software is installed on this system. "
                        "Verify you authorized this installation — unauthorized remote access "
                        "is a common vector for scammers and attackers."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "teamviewer_installed", "tool": "TeamViewer"},
                )
            )

        # Check AnyDesk
        if self._check_anydesk():
            found_tools["AnyDesk"] = True
            findings.append(
                Finding(
                    title="AnyDesk is installed",
                    description=(
                        "AnyDesk remote access software is installed on this system. "
                        "Verify you authorized this installation — unauthorized remote access "
                        "is a common vector for scammers and attackers."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "anydesk_installed", "tool": "AnyDesk"},
                )
            )

        # Check VNC servers
        vnc_found = self._check_vnc()
        if vnc_found:
            found_tools["VNC"] = True
            findings.append(
                Finding(
                    title="VNC server is installed",
                    description=(
                        "A VNC (Virtual Network Computing) remote access server is installed. "
                        "Verify you authorized this installation — unauthorized remote access "
                        "is a common vector for attackers."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "vnc_installed", "tool": "VNC", "processes": vnc_found},
                )
            )

        # Check LogMeIn
        if self._check_logmein():
            found_tools["LogMeIn"] = True
            findings.append(
                Finding(
                    title="LogMeIn is installed",
                    description=(
                        "LogMeIn remote access software is installed on this system. "
                        "Verify you authorized this installation — unauthorized remote access "
                        "is a common vector for scammers and attackers."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "logmein_installed", "tool": "LogMeIn"},
                )
            )

        # Check Chrome Remote Desktop
        if self._check_chrome_remote_desktop():
            found_tools["Chrome Remote Desktop"] = True
            findings.append(
                Finding(
                    title="Chrome Remote Desktop is running",
                    description=(
                        "Chrome Remote Desktop process is running on this system. "
                        "Verify you authorized this — unauthorized remote access "
                        "is a common vector for attackers."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "chrome_remote_desktop", "tool": "Chrome Remote Desktop"},
                )
            )

        # Check RDP status
        rdp_enabled = self._check_rdp_enabled()
        if rdp_enabled:
            findings.append(
                Finding(
                    title="RDP is enabled",
                    description=(
                        "Remote Desktop Protocol (RDP) is enabled on this system. "
                        "RDP is often left enabled after support sessions and should be disabled "
                        "if not actively needed. Disabled RDP is less exposed to brute-force attacks."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "rdp_enabled"},
                )
            )

        # Add CRITICAL if multiple tools found
        if len(found_tools) >= 2:
            findings.append(
                Finding(
                    title="Multiple remote access tools installed (potential tech support scam)",
                    description=(
                        f"This system has {len(found_tools)} remote access tools installed: "
                        f"{', '.join(found_tools.keys())}. "
                        "Having multiple remote access tools is a hallmark of tech support scams, "
                        "where attackers install multiple tools to maintain persistent control. "
                        "Review each tool and uninstall any you did not authorize."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={"check": "multiple_tools", "tools": list(found_tools.keys()), "count": len(found_tools)},
                )
            )

        # Add INFO summary of all found tools
        if found_tools:
            findings.append(
                Finding(
                    title=f"Remote access audit complete: {len(found_tools)} tool(s) found",
                    description=(
                        f"Found the following remote access tools: {', '.join(found_tools.keys())}. "
                        "Review each installation and uninstall any you did not explicitly authorize."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "tools_summary", "tools": list(found_tools.keys()), "count": len(found_tools)},
                )
            )
        else:
            findings.append(
                Finding(
                    title="No unauthorized remote access tools detected",
                    description=(
                        "No common remote access tools (TeamViewer, AnyDesk, VNC, LogMeIn, "
                        "Chrome Remote Desktop) were found on this system."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "no_tools_found"},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check_type = finding.data.get("check")

            if check_type == "teamviewer_installed":
                actions.append(
                    Action(
                        title="Uninstall TeamViewer",
                        description=(
                            "To remove TeamViewer, go to Settings > Apps > Apps and features, "
                            "search for 'TeamViewer', click it, and select 'Uninstall'. "
                            "After uninstalling, restart your computer."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=False,
                        error="This is an informational action — manual removal required.",
                    )
                )
            elif check_type == "anydesk_installed":
                actions.append(
                    Action(
                        title="Uninstall AnyDesk",
                        description=(
                            "To remove AnyDesk, go to Settings > Apps > Apps and features, "
                            "search for 'AnyDesk', click it, and select 'Uninstall'. "
                            "After uninstalling, restart your computer."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=False,
                        error="This is an informational action — manual removal required.",
                    )
                )
            elif check_type == "vnc_installed":
                processes = finding.data.get("processes", [])
                process_str = ", ".join(processes) if processes else "VNC server"
                actions.append(
                    Action(
                        title=f"Uninstall VNC server ({process_str})",
                        description=(
                            f"To remove {process_str}, go to Settings > Apps > Apps and features, "
                            "search for the VNC software, click it, and select 'Uninstall'. "
                            "After uninstalling, restart your computer."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=False,
                        error="This is an informational action — manual removal required.",
                    )
                )
            elif check_type == "logmein_installed":
                actions.append(
                    Action(
                        title="Uninstall LogMeIn",
                        description=(
                            "To remove LogMeIn, go to Settings > Apps > Apps and features, "
                            "search for 'LogMeIn', click it, and select 'Uninstall'. "
                            "After uninstalling, restart your computer."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=False,
                        error="This is an informational action — manual removal required.",
                    )
                )
            elif check_type == "chrome_remote_desktop":
                actions.append(
                    Action(
                        title="Disable Chrome Remote Desktop",
                        description=(
                            "To disable Chrome Remote Desktop, open Chrome and navigate to "
                            "chrome://apps, find 'Chrome Remote Desktop', and remove it. "
                            "Alternatively, uninstall the Chrome extension from the Extensions page."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=False,
                        error="This is an informational action — manual removal required.",
                    )
                )
            elif check_type == "rdp_enabled":
                actions.append(
                    Action(
                        title="Disable RDP if not needed",
                        description=(
                            "If you do not actively need RDP, disable it: Right-click 'This PC', "
                            "select 'Properties', click 'Remote settings', and uncheck "
                            "'Allow remote assistance connections to this computer'. "
                            "If you need RDP, ensure it is secured with a strong password "
                            "and only accessible from trusted networks."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=False,
                        error="This is an informational action — manual configuration required.",
                    )
                )
            elif check_type == "multiple_tools":
                tools = finding.data.get("tools", [])
                tools_str = ", ".join(tools)
                actions.append(
                    Action(
                        title=f"Review and remove multiple remote access tools: {tools_str}",
                        description=(
                            f"Multiple remote access tools ({tools_str}) are installed. "
                            "This is a common sign of unauthorized access. Review each tool's installation: "
                            "if you did not explicitly authorize it, uninstall it immediately. "
                            "Consider running a full antivirus scan afterward."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=False,
                        error="This is an informational action — manual review and removal required.",
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _check_teamviewer(self) -> bool:
        """Check for TeamViewer via registry and process list."""
        # Check registry
        try:
            result = subprocess.run(
                ["reg", "query", "HKLM\\SOFTWARE\\WOW6432Node\\TeamViewer"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                return True
        except (OSError, subprocess.SubprocessError):
            pass

        # Check process list
        try:
            result = subprocess.run(
                ["tasklist"],
                capture_output=True,
                text=True,
            )
            if "teamviewer" in result.stdout.lower():
                return True
        except (OSError, subprocess.SubprocessError):
            pass

        return False

    def _check_anydesk(self) -> bool:
        """Check for AnyDesk via registry and process list."""
        # Check registry
        try:
            result = subprocess.run(
                ["reg", "query", "HKLM\\SOFTWARE\\AnyDesk"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                return True
        except (OSError, subprocess.SubprocessError):
            pass

        # Check process list
        try:
            result = subprocess.run(
                ["tasklist"],
                capture_output=True,
                text=True,
            )
            if "anydesk" in result.stdout.lower():
                return True
        except (OSError, subprocess.SubprocessError):
            pass

        return False

    def _check_vnc(self) -> list[str]:
        """Check for VNC servers in process list. Returns list of found VNC processes."""
        vnc_processes = []
        vnc_names = ["winvnc", "uvnc", "tightvnc", "vncviewer", "vncserver"]

        try:
            result = subprocess.run(
                ["tasklist"],
                capture_output=True,
                text=True,
            )
            output_lower = result.stdout.lower()
            for vnc_name in vnc_names:
                if vnc_name in output_lower:
                    vnc_processes.append(vnc_name)
        except (OSError, subprocess.SubprocessError):
            pass

        return vnc_processes

    def _check_logmein(self) -> bool:
        """Check for LogMeIn via registry and process list."""
        # Check registry
        try:
            result = subprocess.run(
                ["reg", "query", "HKLM\\SOFTWARE\\LogMeIn"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                return True
        except (OSError, subprocess.SubprocessError):
            pass

        # Also check common LogMeIn locations
        try:
            result = subprocess.run(
                ["reg", "query", "HKLM\\SOFTWARE\\WOW6432Node\\LogMeIn"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                return True
        except (OSError, subprocess.SubprocessError):
            pass

        # Check process list
        try:
            result = subprocess.run(
                ["tasklist"],
                capture_output=True,
                text=True,
            )
            if "logmein" in result.stdout.lower():
                return True
        except (OSError, subprocess.SubprocessError):
            pass

        return False

    def _check_chrome_remote_desktop(self) -> bool:
        """Check for Chrome Remote Desktop via process list."""
        try:
            result = subprocess.run(
                ["tasklist"],
                capture_output=True,
                text=True,
            )
            if "remoting_locating_chromoting" in result.stdout.lower() or \
               "chrome_remote_desktop" in result.stdout.lower():
                return True
        except (OSError, subprocess.SubprocessError):
            pass

        return False

    def _check_rdp_enabled(self) -> bool:
        """Check if RDP is enabled via registry. Returns True if RDP is ENABLED."""
        try:
            result = subprocess.run(
                ["reg", "query", "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server", "/v", "fDenyTSConnections"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                # Parse the output to get the value
                # Expected format: "fDenyTSConnections    REG_DWORD    0x0" or "0x1"
                # 0x0 = RDP enabled (connections NOT denied)
                # 0x1 = RDP disabled (connections denied)
                output_lines = result.stdout.strip().split("\n")
                for line in output_lines:
                    if "fDenyTSConnections" in line:
                        # Extract the hex value
                        parts = line.split()
                        if len(parts) > 0:
                            last_part = parts[-1].lower()
                            # If value is 0x0, RDP is enabled
                            if last_part == "0x0" or last_part == "0":
                                return True
                            # If value is 0x1, RDP is disabled
                            elif last_part == "0x1" or last_part == "1":
                                return False
        except (OSError, subprocess.SubprocessError):
            pass

        return False
