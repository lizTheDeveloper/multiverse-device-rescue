import subprocess
import os
from datetime import datetime, timedelta
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
    name = "clamav_scanner"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 56
    depends_on = []
    estimated_duration = "2s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check if clamscan is installed
        clamscan_installed = self._check_executable("clamscan")
        freshclam_installed = self._check_executable("freshclam")

        if not clamscan_installed:
            # ClamAV is not installed - this is a warning/info
            findings.append(
                Finding(
                    title="ClamAV antivirus is not installed",
                    description=(
                        "ClamAV is a free, open-source antivirus engine. "
                        "Consider installing it as a complementary security tool. "
                        "Install via: brew install clamav"
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "clamav_not_installed"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # ClamAV is installed - get version and check definitions
        version = self._get_clamav_version()
        if version:
            findings.append(
                Finding(
                    title=f"ClamAV antivirus is installed (version {version})",
                    description=(
                        f"ClamAV version {version} is installed. "
                        "This provides free, open-source antivirus scanning capability."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "clamav_version", "version": version},
                )
            )

        # Check if freshclam is installed
        if not freshclam_installed:
            findings.append(
                Finding(
                    title="freshclam (ClamAV definition updater) is not installed",
                    description=(
                        "freshclam is used to automatically update ClamAV virus definitions. "
                        "Install via: brew install clamav"
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "freshclam_not_installed"},
                )
            )

        # Check virus definition database age
        def_age, def_version = self._get_definition_age()
        if def_version:
            findings.append(
                Finding(
                    title=f"ClamAV virus definitions (version {def_version})",
                    description=(
                        f"Virus definition version {def_version} is installed. "
                        f"Definition database age: {def_age} days."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "clamav_definitions",
                        "def_version": def_version,
                        "def_age": def_age,
                    },
                )
            )

            # Check if definitions are outdated (>30 days old)
            if def_age > 30:
                findings.append(
                    Finding(
                        title="ClamAV virus definitions are outdated",
                        description=(
                            f"Virus definitions are {def_age} days old (>30 days). "
                            "This creates a false sense of security. "
                            "Update definitions manually via: freshclam"
                        ),
                        severity=Severity.CRITICAL,
                        category=self.category,
                        data={"check": "clamav_outdated_definitions", "def_age": def_age},
                    )
                )

        # Check if clamd daemon is running
        clamd_running = self._check_daemon_running()
        if not clamd_running:
            findings.append(
                Finding(
                    title="clamd daemon is not running",
                    description=(
                        "The ClamAV daemon (clamd) is not running. "
                        "This disables on-access scanning. "
                        "Start clamd via: brew services start clamav"
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "clamd_not_running"},
                )
            )
        else:
            findings.append(
                Finding(
                    title="clamd daemon is running",
                    description="The ClamAV daemon (clamd) is running and provides on-access scanning.",
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "clamd_running"},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "clamav_not_installed":
                actions.append(
                    Action(
                        title="Install ClamAV",
                        description=(
                            "Install ClamAV (antivirus engine and freshclam definition updater) via Homebrew:\n"
                            "  brew install clamav\n"
                            "Then start the daemon:\n"
                            "  brew services start clamav"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "freshclam_not_installed":
                actions.append(
                    Action(
                        title="Install freshclam",
                        description=(
                            "freshclam is included with ClamAV. "
                            "Install via Homebrew if not already installed:\n"
                            "  brew install clamav"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "clamav_outdated_definitions":
                actions.append(
                    Action(
                        title="Update ClamAV virus definitions",
                        description=(
                            "Run freshclam to update virus definitions:\n"
                            "  freshclam\n"
                            "Or set up automatic updates via cron or launchd."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "clamd_not_running":
                actions.append(
                    Action(
                        title="Start clamd daemon",
                        description=(
                            "Start the ClamAV daemon for on-access scanning:\n"
                            "  brew services start clamav"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _check_executable(self, executable: str) -> bool:
        """Check if an executable is available in PATH."""
        try:
            result = subprocess.run(
                ["which", executable],
                capture_output=True,
                text=True,
            )
            return result.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    def _get_clamav_version(self) -> str | None:
        """Get ClamAV version via clamscan --version."""
        try:
            result = subprocess.run(
                ["clamscan", "--version"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return None
            # Output is like "ClamAV 0.103.7/26551/Wed Dec 19 12:31:08 2024"
            # Extract version number
            output = result.stdout.strip()
            if output.startswith("ClamAV "):
                version_part = output.split()[1].split("/")[0]
                return version_part
            return None
        except (OSError, subprocess.SubprocessError, IndexError):
            return None

    def _get_definition_age(self) -> tuple[int, str | None]:
        """
        Get virus definition database age in days and version.
        Checks modification time of signature files in common ClamAV database locations.
        Returns (age_in_days, version_string) or (999, None) if unable to determine.
        """
        # Common ClamAV database locations on macOS
        db_paths = [
            Path("/opt/homebrew/var/lib/clamav/main.cvd"),
            Path("/opt/homebrew/var/lib/clamav/main.cld"),
            Path("/usr/local/var/lib/clamav/main.cvd"),
            Path("/usr/local/var/lib/clamav/main.cld"),
            Path(os.path.expanduser("~/.clamav/main.cvd")),
        ]

        # Find the newest definition file
        newest_mtime = None
        for db_path in db_paths:
            if db_path.exists():
                try:
                    mtime = db_path.stat().st_mtime
                    if newest_mtime is None or mtime > newest_mtime:
                        newest_mtime = mtime
                except (OSError, FileNotFoundError):
                    continue

        if newest_mtime is None:
            return 999, None

        # Calculate age in days
        mod_time = datetime.fromtimestamp(newest_mtime)
        age = (datetime.now() - mod_time).days

        # Try to get definition version via sigtool
        version = self._get_definition_version()

        return age, version

    def _get_definition_version(self) -> str | None:
        """Get virus definition version via sigtool --info."""
        try:
            # Find the main.cvd file
            db_paths = [
                "/opt/homebrew/var/lib/clamav/main.cvd",
                "/opt/homebrew/var/lib/clamav/main.cld",
                "/usr/local/var/lib/clamav/main.cvd",
                "/usr/local/var/lib/clamav/main.cld",
            ]

            db_path = None
            for path in db_paths:
                if os.path.exists(path):
                    db_path = path
                    break

            if not db_path:
                return None

            result = subprocess.run(
                ["sigtool", "--info", db_path],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return None

            # Parse output for version (looks like "Version: 26551")
            for line in result.stdout.split("\n"):
                if "Version:" in line:
                    parts = line.split(":")
                    if len(parts) >= 2:
                        return parts[1].strip()
            return None
        except (OSError, subprocess.SubprocessError, FileNotFoundError):
            return None

    def _check_daemon_running(self) -> bool:
        """Check if clamd daemon is running via pgrep."""
        try:
            result = subprocess.run(
                ["pgrep", "clamd"],
                capture_output=True,
                text=True,
            )
            return result.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False
