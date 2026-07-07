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
                    title="Login keychain file is missing",
                    description=(
                        f"The login keychain file at {login_keychain_path} does not exist. "
                        "This is a common cause of repeated password prompts. "
                        "The keychain may be corrupted or in an unexpected location."
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
                        title="Login keychain is locked",
                        description=(
                            "The login keychain is locked. "
                            "A locked keychain is a common cause of repeated password prompts and app crashes. "
                            "Unlock it in Keychain Access or via the security command."
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
                        title="Login keychain is not set as the default",
                        description=(
                            f"Default keychain is: {default_keychain or 'unknown'}. "
                            "When the login keychain is not the default, macOS asks for passwords repeatedly. "
                            "Set login.keychain-db as the default to fix authentication issues."
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
                        title=f"Login keychain has a very short lock timeout ({lock_timeout}s)",
                        description=(
                            f"The login keychain will auto-lock after {lock_timeout} seconds ({lock_timeout/60:.1f} minutes). "
                            "Short timeouts cause repeated password prompts throughout the day. "
                            "Increase the lock timeout to at least 5 minutes (300 seconds) or disable auto-lock."
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
