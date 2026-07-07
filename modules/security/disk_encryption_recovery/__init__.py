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
    name = "disk_encryption_recovery"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 85
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check if FileVault is enabled
        fv_status = self._run_fdesetup_status()
        is_fv_enabled = "on" in fv_status.lower()

        # If FileVault is off, report INFO status
        if not is_fv_enabled:
            findings.append(
                Finding(
                    title="FileVault is disabled",
                    description=(
                        "FileVault encryption is not enabled. Disk encryption recovery "
                        "key checks are not applicable until FileVault is enabled."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "fv_disabled", "fdesetup_output": fv_status.strip()},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # FileVault is ON - check recovery key status
        has_personal_key = self._run_fdesetup_haspersonalrecoverykey()
        has_institutional_key = self._run_fdesetup_hasinstitutionalrecoverykey()

        # Check recovery key status
        if has_personal_key == "unknown" or has_institutional_key == "unknown":
            # Unknown state - could be error or unparseable
            findings.append(
                Finding(
                    title="FileVault recovery key status unknown",
                    description=(
                        "Unable to determine if a FileVault recovery key exists. "
                        "Run `fdesetup hasinstitutionalrecoverykey` and "
                        "`fdesetup haspersonalrecoverykey` in Terminal to verify."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "recovery_key_unknown",
                        "personal": has_personal_key,
                        "institutional": has_institutional_key,
                    },
                )
            )
        elif not has_personal_key and not has_institutional_key:
            # No recovery key at all - CRITICAL data loss risk
            findings.append(
                Finding(
                    title="FileVault enabled but no recovery key found",
                    description=(
                        "FileVault is enabled, but no recovery key (personal or "
                        "institutional) was found. If the encryption password is "
                        "lost, the data is unrecoverable. This is a critical risk."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={
                        "check": "no_recovery_key",
                        "personal": has_personal_key,
                        "institutional": has_institutional_key,
                    },
                )
            )
        elif has_institutional_key and not has_personal_key:
            # Only institutional key exists - might be old MDM setup
            findings.append(
                Finding(
                    title="FileVault has only institutional recovery key",
                    description=(
                        "FileVault is enabled with only an institutional recovery key "
                        "(likely from a Mobile Device Management system). Consider "
                        "generating a personal recovery key as a backup in case the "
                        "institutional key becomes unavailable."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "institutional_key_only",
                        "personal": has_personal_key,
                        "institutional": has_institutional_key,
                    },
                )
            )

        # Check which users are FileVault-enabled
        enabled_users = self._run_fdesetup_list()
        all_users = self._get_all_system_users()

        if enabled_users and all_users:
            # Filter to real accounts (remove system accounts and root)
            real_all_users = {
                u for u in all_users
                if u not in ("root", "_api", "_guest") and not u.startswith("_")
            }
            enabled_set = set(enabled_users) if enabled_users else set()

            if real_all_users and enabled_set != real_all_users:
                disabled_users = real_all_users - enabled_set
                findings.append(
                    Finding(
                        title="Not all user accounts are FileVault-enabled",
                        description=(
                            f"The following user account(s) are not FileVault-enabled: "
                            f"{', '.join(sorted(disabled_users))}. All regular user accounts "
                            f"should be protected by FileVault encryption."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "users_not_all_enabled",
                            "enabled_users": sorted(enabled_set),
                            "disabled_users": sorted(disabled_users),
                        },
                    )
                )

        # Always add INFO status summary
        findings.append(
            Finding(
                title="FileVault disk encryption recovery status",
                description=(
                    f"FileVault is enabled. "
                    f"Personal recovery key: {'present' if has_personal_key else 'not found'}. "
                    f"Institutional recovery key: {'present' if has_institutional_key else 'not found'}. "
                    f"Enabled users: {', '.join(sorted(enabled_set)) if enabled_users else 'none detected'}."
                ),
                severity=Severity.INFO,
                category=self.category,
                data={
                    "check": "disk_encryption_status",
                    "fv_enabled": True,
                    "personal_recovery_key": has_personal_key,
                    "institutional_recovery_key": has_institutional_key,
                    "enabled_users": sorted(enabled_set) if enabled_users else [],
                },
            )
        )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            if finding.data.get("check") == "no_recovery_key":
                actions.append(
                    Action(
                        title="Generate and store FileVault recovery key",
                        description=(
                            "The FileVault recovery key must be generated and stored securely. "
                            "1. Run `sudo fdesetup changerecovery -personal` in Terminal. "
                            "2. A recovery key will be generated. "
                            "3. Store this key in a secure location (password manager, safe, etc.) "
                            "separate from the device. "
                            "4. Never share this key; anyone with it can decrypt the drive."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding.data.get("check") == "recovery_key_unknown":
                actions.append(
                    Action(
                        title="Verify FileVault recovery key status",
                        description=(
                            "Unable to automatically determine recovery key status. "
                            "Run these commands in Terminal to check: "
                            "`fdesetup hasinstitutionalrecoverykey` and "
                            "`fdesetup haspersonalrecoverykey`. "
                            "If both return 'No', generate a personal recovery key with "
                            "`sudo fdesetup changerecovery -personal` and store it securely."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding.data.get("check") == "institutional_key_only":
                actions.append(
                    Action(
                        title="Generate personal backup recovery key",
                        description=(
                            "While an institutional recovery key exists, generate a personal "
                            "backup recovery key for added protection. "
                            "1. Run `sudo fdesetup changerecovery -personal` in Terminal. "
                            "2. Store the generated key securely (password manager, safe, etc.). "
                            "3. This provides a backup if the institutional key becomes unavailable."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding.data.get("check") == "users_not_all_enabled":
                disabled = finding.data.get("disabled_users", [])
                actions.append(
                    Action(
                        title="Enable FileVault for all user accounts",
                        description=(
                            f"The following user(s) need FileVault enabled: {', '.join(disabled)}. "
                            f"Have each user log in and run `fdesetup add -usertoadd username` "
                            f"in Terminal (as an admin). This ensures all accounts are protected "
                            f"by the same encryption."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _run_fdesetup_status(self) -> str:
        """Check if FileVault is enabled."""
        try:
            result = subprocess.run(
                ["fdesetup", "status"],
                capture_output=True,
                text=True,
            )
            return result.stdout
        except Exception:
            return "unknown"

    def _run_fdesetup_haspersonalrecoverykey(self) -> bool:
        """Check if a personal recovery key exists."""
        try:
            result = subprocess.run(
                ["fdesetup", "haspersonalrecoverykey"],
                capture_output=True,
                text=True,
            )
            output = result.stdout.strip().lower()
            if output.startswith("yes"):
                return True
            elif output.startswith("no"):
                return False
            else:
                return "unknown"
        except Exception:
            return "unknown"

    def _run_fdesetup_hasinstitutionalrecoverykey(self) -> bool:
        """Check if an institutional recovery key exists."""
        try:
            result = subprocess.run(
                ["fdesetup", "hasinstitutionalrecoverykey"],
                capture_output=True,
                text=True,
            )
            output = result.stdout.strip().lower()
            if output.startswith("yes"):
                return True
            elif output.startswith("no"):
                return False
            else:
                return "unknown"
        except Exception:
            return "unknown"

    def _run_fdesetup_list(self) -> list[str]:
        """Get list of FileVault-enabled users."""
        try:
            result = subprocess.run(
                ["fdesetup", "list"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                # fdesetup list returns "username,uuid" pairs, one per line
                users = []
                for line in result.stdout.strip().split("\n"):
                    if line:
                        # Extract username (before comma)
                        username = line.split(",")[0].strip()
                        if username:
                            users.append(username)
                return users
            return []
        except Exception:
            return []

    def _get_all_system_users(self) -> list[str]:
        """Get all user accounts on the system."""
        try:
            result = subprocess.run(
                ["dscl", ".", "-list", "/Users"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                users = [u.strip() for u in result.stdout.strip().split("\n") if u.strip()]
                return users
            return []
        except Exception:
            return []
