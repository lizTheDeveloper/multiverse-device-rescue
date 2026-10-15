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
    name = "login_keychain_repair"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check login keychain existence
        login_keychain_path = Path.home() / "Library" / "Keychains" / "login.keychain-db"
        if not login_keychain_path.exists():
            findings.append(
                Finding(
                    title="Your Mac's password storage file is missing",
                    description=(
                        "We couldn't find the file that stores your saved passwords at "
                        f"{login_keychain_path}. "
                        "It usually means the file was moved, renamed, or corrupted. "
                        "The main effect is that your Mac will ask you to re-enter passwords "
                        "more often than usual.\n\n"
                        "What to do: Restart your Mac. If it's still missing, ask Apple "
                        "Support for help before making a new one, so saved passwords "
                        "aren't lost."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "missing_login_keychain"},
                )
            )
        else:
            # Check if login keychain is unlocked
            lock_status = self._check_keychain_lock()
            if lock_status == "locked":
                findings.append(
                    Finding(
                        title="Your Mac's password storage is currently locked",
                        description=(
                            "Your Mac's password storage (called the login keychain) is "
                            "currently locked. This is a normal security feature, but "
                            "if it stays locked, apps will keep asking for your password.\n\n"
                            "What to do: Restart your Mac and log in; that unlocks it. If "
                            "apps keep asking, open Keychain Access and unlock 'login' in "
                            "the sidebar."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check": "keychain_locked"},
                    )
                )

            # Check if login keychain is the default
            default_keychain = self._get_default_keychain()
            is_default = (
                default_keychain
                and "login.keychain-db" in default_keychain.lower()
            )
            if not is_default:
                findings.append(
                    Finding(
                        title="Your Mac is using the wrong password storage file",
                        description=(
                            f"Your Mac is set to use {default_keychain or 'unknown'} as "
                            "its main password storage, instead of your standard login "
                            "keychain. This causes your Mac to ask for passwords repeatedly "
                            "because it's looking in the wrong place.\n\n"
                            "What to do: Open Keychain Access, right-click 'login' in the "
                            "sidebar, and choose Make Keychain \"login\" Default."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "not_default_keychain",
                            "current_default": default_keychain,
                        },
                    )
                )

            # Check keychain lock timeout
            lock_timeout = self._get_lock_timeout()
            if lock_timeout is not None and lock_timeout < 300:  # 5 minutes = 300 seconds
                findings.append(
                    Finding(
                        title=(
                            f"Your Mac locks its password storage too quickly ({lock_timeout}s)"
                        ),
                        description=(
                            "Your Mac automatically locks its password storage after "
                            f"{lock_timeout} seconds ({lock_timeout/60:.1f} minutes). "
                            "This is a very short time. It means you will be asked to "
                            "re-enter your password constantly, which is annoying.\n\n"
                            "What to do: Open Keychain Access, select 'login' in the sidebar, "
                            "choose Edit > Change Settings for Keychain \"login\", and "
                            "set a longer time, or turn off 'Lock after'."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check": "short_lock_timeout", "timeout_seconds": lock_timeout},
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
                        title="Rebuild or restore the login keychain",
                        description=(
                            "The login keychain is missing. "
                            "Steps to resolve: (1) Open Keychain Access (/Applications/Utilities/Keychain Access.app). "
                            "(2) Check Keychain Access > Preferences for default keychain setting. "
                            "(3) If missing, create a new login keychain via File > New Keychain. "
                            "(4) If you have a backup, restore it from ~/Library/Keychains/. "
                            "(5) Restart your Mac and let it rebuild the keychain automatically. "
                            "(6) If problems persist, contact Apple support or use Time Machine to restore from backup."
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
                            "The login keychain is locked, causing password prompts. "
                            "Steps to unlock: (1) Open Keychain Access (/Applications/Utilities/Keychain Access.app). "
                            "(2) In the left sidebar, right-click 'login'. "
                            "(3) Select 'Unlock Keychain login'. "
                            "(4) Enter your login password when prompted. "
                            "Alternatively, run: security unlock-keychain ~/Library/Keychains/login.keychain-db"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "not_default_keychain":
                current_default = finding.data.get("current_default", "unknown")
                actions.append(
                    Action(
                        title="Set login keychain as the default",
                        description=(
                            f"Currently, {current_default} is the default keychain, but it should be login.keychain-db. "
                            "This is a primary cause of repeated password prompts. "
                            "Steps to fix: (1) Open Keychain Access (/Applications/Utilities/Keychain Access.app). "
                            "(2) Right-click 'login' in the left sidebar. "
                            "(3) Select 'Set as Default Keychain'. "
                            "Alternatively, run: security default-keychain -s ~/Library/Keychains/login.keychain-db"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "short_lock_timeout":
                timeout = finding.data.get("timeout_seconds", "unknown")
                actions.append(
                    Action(
                        title="Increase the keychain lock timeout",
                        description=(
                            f"Current lock timeout is {timeout} seconds. "
                            "This is too short and causes the keychain to lock frequently, triggering password prompts. "
                            "Steps to fix: (1) Open Keychain Access (/Applications/Utilities/Keychain Access.app). "
                            "(2) Go to Keychain Access > Preferences. "
                            "(3) In the General tab, set 'Lock keychain after X minutes of inactivity'. "
                            "(4) Set it to at least 5 minutes (300 seconds), or disable auto-lock entirely. "
                            "(5) Click OK to save. "
                            "Note: Disabling auto-lock is convenient but less secure."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _check_keychain_lock(self) -> str:
        """Check if login keychain is locked. Returns 'locked', 'unlocked', or 'unknown'."""
        try:
            keychain_path = str(
                Path.home() / "Library" / "Keychains" / "login.keychain-db"
            )
            result = subprocess.run(
                ["security", "show-keychain-info", keychain_path],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                output = result.stdout.lower()
                # Check for unlocked first since "locked" is substring of "unlocked"
                if "unlocked" in output:
                    return "unlocked"
                elif "locked" in output:
                    return "locked"
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            pass
        return "unknown"

    def _get_default_keychain(self) -> str:
        """Get the default keychain path."""
        try:
            result = subprocess.run(
                ["security", "default-keychain"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                # Output is typically: "/Users/username/Library/Keychains/login.keychain-db"
                return result.stdout.strip().strip('"')
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            pass
        return ""

    def _get_lock_timeout(self) -> int | None:
        """Get the keychain lock timeout in seconds. Returns None if unable to determine."""
        try:
            # Use security show-keychain-info to get lock timeout
            keychain_path = str(
                Path.home() / "Library" / "Keychains" / "login.keychain-db"
            )
            result = subprocess.run(
                ["security", "show-keychain-info", keychain_path],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                output = result.stdout
                # Look for timeout information in output
                # Example: "Keychain "/Users/username/Library/Keychains/login.keychain-db" lock timeout is 300 seconds"
                if "timeout" in output.lower():
                    parts = output.split()
                    for i, part in enumerate(parts):
                        if part.isdigit():
                            if i + 1 < len(parts) and "second" in parts[i + 1].lower():
                                return int(part)
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            pass
        return None
