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

    emits_codes = [
        "security.win_remote_access_audit.teamviewer_installed",
        "security.win_remote_access_audit.anydesk_installed",
        "security.win_remote_access_audit.vnc_installed",
        "security.win_remote_access_audit.logmein_installed",
        "security.win_remote_access_audit.chrome_remote_desktop",
        "security.win_remote_access_audit.rdp_enabled",
        "security.win_remote_access_audit.multiple_tools",
        "security.win_remote_access_audit.tools_summary",
        "security.win_remote_access_audit.no_tools_found",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []
        found_tools = {}

        # Check TeamViewer
        if self._check_teamviewer():
            found_tools["TeamViewer"] = True
            findings.append(
                Finding(
                    title="TeamViewer is installed on your computer",
                    description=(
                        "We found TeamViewer, a program that lets someone else control "
                        "your screen from another computer. If you installed this for "
                        "work or to help a friend, that is fine. However, if you do not "
                        "remember installing it, it may have been added by someone else "
                        "to watch your activity.\n\n"
                        "If you think a partner, ex, or family member installed this to "
                        "monitor you, removing it can alert them. Talk to an advocate "
                        "first (US National Domestic Violence Hotline: 1-800-799-7233, "
                        "or text START to 88788).\n\n"
                        "What to do: If you did not install TeamViewer, open Windows Settings "
                        "> Apps > Installed apps, find TeamViewer, and select Uninstall."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.win_remote_access_audit.teamviewer_installed",
                    data={"check": "teamviewer_installed", "tool": "TeamViewer"},
                )
            )

        # Check AnyDesk
        if self._check_anydesk():
            found_tools["AnyDesk"] = True
            findings.append(
                Finding(
                    title="AnyDesk is installed on your computer",
                    description=(
                        "We found AnyDesk, a program that allows someone to remotely control "
                        "your computer. This is often used for tech support, but if you "
                        "did not install it, it could be a way for someone to spy on you.\n\n"
                        "If you think a partner, ex, or family member installed this to "
                        "monitor you, removing it can alert them. Talk to an advocate "
                        "first (US National Domestic Violence Hotline: 1-800-799-7233, "
                        "or text START to 88788).\n\n"
                        "What to do: If you did not install AnyDesk, open Windows Settings "
                        "> Apps > Installed apps, find AnyDesk, and select Uninstall."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.win_remote_access_audit.anydesk_installed",
                    data={"check": "anydesk_installed", "tool": "AnyDesk"},
                )
            )

        # Check VNC servers
        vnc_found = self._check_vnc()
        if vnc_found:
            found_tools["VNC"] = True
            findings.append(
                Finding(
                    title="A VNC remote control program is installed",
                    description=(
                        "We found a VNC server, which is a tool that lets someone connect "
                        "to and control your computer from a distance. If you use this "
                        "for work, it is expected. If not, it is a common way for attackers "
                        "or stalkers to access your device.\n\n"
                        "If you think a partner, ex, or family member installed this to "
                        "monitor you, removing it can alert them. Talk to an advocate "
                        "first (US National Domestic Violence Hotline: 1-800-799-7233, "
                        "or text START to 88788).\n\n"
                        "What to do: If you did not install this, open Windows Settings "
                        "> Apps > Installed apps, find the VNC program, and select Uninstall."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.win_remote_access_audit.vnc_installed",
                    data={"check": "vnc_installed", "tool": "VNC", "processes": vnc_found},
                )
            )

        # Check LogMeIn
        if self._check_logmein():
            found_tools["LogMeIn"] = True
            findings.append(
                Finding(
                    title="LogMeIn is installed on your computer",
                    description=(
                        "We found LogMeIn, a service that allows remote access to your "
                        "computer. If you use this for work, it is likely fine. If you "
                        "do not recognize it, it may have been installed to monitor your "
                        "activity.\n\n"
                        "If you think a partner, ex, or family member installed this to "
                        "monitor you, removing it can alert them. Talk to an advocate "
                        "first (US National Domestic Violence Hotline: 1-800-799-7233, "
                        "or text START to 88788).\n\n"
                        "What to do: If you did not install LogMeIn, open Windows Settings "
                        "> Apps > Installed apps, find LogMeIn, and select Uninstall."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.win_remote_access_audit.logmein_installed",
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
                        "We found that Chrome Remote Desktop is currently running. This "
                        "allows someone to view and control your screen via a web link. "
                        "If you are using it for support, that is okay. If not, it is "
                        "a potential risk for unauthorized access.\n\n"
                        "If you think a partner, ex, or family member set this up to monitor "
                        "you, removing it can alert them. Talk to an advocate first (US "
                        "National Domestic Violence Hotline: 1-800-799-7233, or text START "
                        "to 88788).\n\n"
                        "What to do: If you didn't set this up, open "
                        "remotedesktop.google.com/access in Chrome and delete this computer "
                        "from the list, then uninstall 'Chrome Remote Desktop Host' in "
                        "Settings > Apps > Installed apps."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.win_remote_access_audit.chrome_remote_desktop",
                    data={"check": "chrome_remote_desktop", "tool": "Chrome Remote Desktop"},
                )
            )

        # Check RDP status
        rdp_enabled = self._check_rdp_enabled()
        if rdp_enabled:
            findings.append(
                Finding(
                    title="Remote Desktop (RDP) is turned on",
                    description=(
                        "Your computer's Remote Desktop feature is enabled. This allows "
                        "others to connect to your computer over a network. It is often "
                        "left on after a tech support session. If you do not use it, it "
                        "is safer to turn it off to reduce exposure.\n\n"
                        "If you think a partner, ex, or family member enabled this to "
                        "monitor you, removing it can alert them. Talk to an advocate "
                        "first (US National Domestic Violence Hotline: 1-800-799-7233, "
                        "or text START to 88788).\n\n"
                        "What to do: Open Windows Settings > System > Remote Desktop and "
                        "toggle it to Off."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.win_remote_access_audit.rdp_enabled",
                    data={"check": "rdp_enabled"},
                )
            )

        # Add CRITICAL if multiple tools found
        if len(found_tools) >= 2:
            findings.append(
                Finding(
                    title=(
                        f"Multiple remote access tools found: {', '.join(found_tools.keys())}"
                    ),
                    description=(
                        f"We found {len(found_tools)} different remote access tools installed: "
                        f"{', '.join(found_tools.keys())}. Having multiple tools is a "
                        "strong sign of a tech support scam or unauthorized monitoring. "
                        "If you did not install all of these, they should be removed.\n\n"
                        "If you think a partner, ex, or family member installed these "
                        "to monitor you, removing them can alert them. Talk to an advocate "
                        "first (US National Domestic Violence Hotline: 1-800-799-7233, "
                        "or text START to 88788).\n\n"
                        "What to do: Open Windows Settings > Apps > Installed apps and "
                        "uninstall any tool you do not recognize or did not install."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    code="security.win_remote_access_audit.multiple_tools",
                    data={"check": "multiple_tools", "tools": list(found_tools.keys()), "count": len(found_tools)},
                )
            )

        # Add INFO summary of all found tools
        if found_tools:
            findings.append(
                Finding(
                    title=f"Remote access tools found: {len(found_tools)}",
                    description=(
                        f"Found the following remote access tools: {', '.join(found_tools.keys())}. "
                        "Review each installation and uninstall any you did not explicitly authorize."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.win_remote_access_audit.tools_summary",
                    data={"check": "tools_summary", "tools": list(found_tools.keys()), "count": len(found_tools)},
                )
            )
        else:
            findings.append(
                Finding(
                    title="No remote access tools found",
                    description=(
                        "No common remote access tools (TeamViewer, AnyDesk, VNC, LogMeIn, "
                        "Chrome Remote Desktop) were found on this system."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.win_remote_access_audit.no_tools_found",
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
