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
    name = "keychain_health"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check login keychain existence
        login_keychain_path = Path.home() / "Library" / "Keychains" / "login.keychain-db"
        if not login_keychain_path.exists():
            findings.append(
                Finding(
                    title="Login keychain not found",
                    description=(
                        f"Expected login keychain at {login_keychain_path} does not exist. "
                        "This may cause password prompts and app crashes. "
                        "The keychain may be corrupted or in an unexpected location."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "missing_login_keychain"},
                )
            )
        else:
            # Check keychain file size
            try:
                file_size = login_keychain_path.stat().st_size
                size_mb = file_size / (1024 * 1024)
                if size_mb > 100:
                    findings.append(
                        Finding(
                            title=f"Login keychain is very large ({size_mb:.1f} MB)",
                            description=(
                                f"The login keychain is {size_mb:.1f} MB, which is larger than 100 MB. "
                                "Large keychains can be slow and may indicate corruption. "
                                "Consider rebuilding the keychain."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            data={
                                "check": "large_keychain",
                                "size_mb": size_mb,
                            },
                        )
                    )
            except (OSError, AttributeError):
                pass

        # Check keychain lock status
        lock_status = self._check_keychain_lock(str(login_keychain_path))
        if lock_status == "locked":
            findings.append(
                Finding(
                    title="Login keychain is locked",
                    description=(
                        "The login keychain is locked. "
                        "A locked keychain may cause repeated password prompts and app crashes. "
                        "Unlock the keychain in Keychain Access or via the security command."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "keychain_locked"},
                )
            )

        # Check if login keychain is listed in available keychains
        keychains = self._list_keychains()
        if login_keychain_path.name not in keychains:
            findings.append(
                Finding(
                    title="Login keychain not listed in system keychains",
                    description=(
                        f"The login keychain is not listed in 'security list-keychains'. "
                        "This may indicate a configuration issue or corruption."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "keychain_not_listed"},
                )
            )

        # Check default keychain
        default_keychain = self._get_default_keychain()
        if default_keychain and "login" not in default_keychain.lower():
            findings.append(
                Finding(
                    title=f"Default keychain is not login keychain",
                    description=(
                        f"Default keychain is set to: {default_keychain}. "
                        "It is recommended to set the default keychain to login.keychain-db "
                        "to avoid authentication issues."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "default_keychain_mismatch"},
                )
            )

        # Add informational finding about keychain configuration
        if not findings:
            findings.append(
                Finding(
                    title="Login keychain is healthy",
                    description=(
                        f"Login keychain at {login_keychain_path} exists and is accessible. "
                        "Configuration appears normal."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "keychain_healthy"},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "missing_login_keychain":
                actions.append(
                    Action(
                        title="Rebuild or restore login keychain",
                        description=(
                            "The login keychain is missing or corrupted. "
                            "Try these steps: (1) Open Keychain Access (/Applications/Utilities/Keychain Access.app). "
                            "(2) From the menu, select Keychain Access > Preferences and check the default keychain setting. "
                            "(3) If the keychain is missing, create a new login keychain by going to File > New Keychain. "
                            "(4) If you have a backup, restore it. "
                            "(5) As a last resort, restart your Mac and let it rebuild the keychain automatically."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "large_keychain":
                size_mb = finding.data.get("size_mb", "unknown")
                actions.append(
                    Action(
                        title="Consider rebuilding the large keychain",
                        description=(
                            f"Your login keychain is {size_mb} MB, which may be corrupted or bloated. "
                            "Try these steps: (1) Export important certificates and keys from Keychain Access. "
                            "(2) Rename the current login.keychain-db to login.keychain-db.backup. "
                            "(3) Restart your Mac to auto-create a fresh keychain. "
                            "(4) Import the exported items back if needed. "
                            "Alternatively, use third-party tools like Keychain Cleaner to repair it."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "keychain_locked":
                actions.append(
                    Action(
                        title="Unlock the login keychain",
                        description=(
                            "The login keychain is locked. "
                            "To unlock it: (1) Open Keychain Access (/Applications/Utilities/Keychain Access.app). "
                            "(2) In the left sidebar, right-click on 'login' and select 'Lock Keychain login'. "
                            "(3) Then right-click again and select 'Unlock Keychain login'. "
                            "(4) Enter your login password when prompted. "
                            "Alternatively, use: security unlock-keychain ~/Library/Keychains/login.keychain-db"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "keychain_not_listed":
                actions.append(
                    Action(
                        title="Re-add login keychain to list",
                        description=(
                            "The login keychain is not listed in the system. "
                            "Try these steps: (1) Open Keychain Access. "
                            "(2) Go to File > Add Keychain. "
                            "(3) Navigate to ~/Library/Keychains/ and select login.keychain-db. "
                            "(4) Click 'Add'. "
                            "If this doesn't work, the keychain may be corrupted and need rebuilding."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "default_keychain_mismatch":
                actions.append(
                    Action(
                        title="Set login keychain as default",
                        description=(
                            "The default keychain should be set to login.keychain-db. "
                            "To fix this: (1) Open Keychain Access. "
                            "(2) Right-click on 'login' in the left sidebar. "
                            "(3) Select 'Set as Default Keychain'. "
                            "Alternatively, use: security default-keychain -s ~/Library/Keychains/login.keychain-db"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "keychain_healthy":
                actions.append(
                    Action(
                        title="Keychain is healthy",
                        description=(
                            "Your login keychain appears to be in good health. "
                            "Continue to monitor for any authentication issues or app crashes. "
                            "Regularly back up your keychain by exporting important certificates and keys."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _check_keychain_lock(self, keychain_path: str) -> str:
        """Check if keychain is locked. Returns 'locked', 'unlocked', or 'unknown'."""
        try:
            result = subprocess.run(
                ["security", "show-keychain-info", keychain_path],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                output = result.stdout.lower()
                # Check for unlocked first since "locked" is substring of "unlocked"
                if "unlocked" in output:
                    return "unlocked"
                elif "locked" in output:
                    return "locked"
        except (OSError, subprocess.SubprocessError):
            pass
        return "unknown"

    def _list_keychains(self) -> list[str]:
        """Get list of available keychains."""
        try:
            result = subprocess.run(
                ["security", "list-keychains"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                # Parse output: keychains are listed as quoted paths
                keychains = []
                for line in result.stdout.strip().split("\n"):
                    line = line.strip()
                    if line:
                        # Remove quotes and get just the filename
                        keychain_path = line.strip('"')
                        keychain_name = Path(keychain_path).name
                        keychains.append(keychain_name)
                return keychains
        except (OSError, subprocess.SubprocessError):
            pass
        return []

    def _get_default_keychain(self) -> str:
        """Get the default keychain."""
        try:
            result = subprocess.run(
                ["security", "default-keychain"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                # Output is typically: "/Users/username/Library/Keychains/login.keychain-db"
                return result.stdout.strip().strip('"')
        except (OSError, subprocess.SubprocessError):
            pass
        return ""
