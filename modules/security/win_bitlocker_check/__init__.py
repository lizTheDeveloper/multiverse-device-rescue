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
    name = "win_bitlocker_check"
    category = "security"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 80
    depends_on = []
    estimated_duration = "5s"

    emits_codes = [
        "security.win_bitlocker_check.os_drive_not_encrypted",
        "security.win_bitlocker_check.encryption_suspended",
        "security.win_bitlocker_check.no_recovery_key",
        "security.win_bitlocker_check.fixed_drive_not_encrypted",
        "security.win_bitlocker_check.status_info",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []
        output = self._run_manage_bde_status()
        if not output:
            return CheckResult(module_name=self.name, findings=findings)

        volumes = _parse_manage_bde_output(output)
        has_os_drive = False
        os_drive_encrypted = False

        for volume in volumes:
            mount_point = volume.get("mount_point", "").strip()
            status = volume.get("status", "").strip().lower()
            protection = volume.get("protection_status", "").strip().lower()
            encryption_method = volume.get("encryption_method", "").strip()
            key_protectors = volume.get("key_protectors", [])

            # Check if OS drive (C:)
            is_os_drive = mount_point.upper().startswith("C:")
            if is_os_drive:
                has_os_drive = True

            # Check if volume is encrypted (fully or partially)
            is_encrypted = status in ["fullyencrypted", "partiallyencrypted"]

            # CRITICAL: OS drive not encrypted
            if is_os_drive and not is_encrypted:
                os_drive_encrypted = False
                findings.append(
                    Finding(
                        title="Your main Windows drive (C:) is not encrypted",
                        description=(
                            "Your main drive (C:) is not protected by BitLocker, Windows' "
                            "built-in encryption. This means that if your computer is "
                            "lost or stolen, anyone who has physical access to the disk "
                            "can read your files.\n\n"
                            "What to do: Search for 'BitLocker' in the Start menu and "
                            "select 'Turn on BitLocker' (on Windows Home, turn on Device "
                            "encryption in Settings > Privacy & security instead). Follow the prompts to encrypt "
                            "your drive. You will be asked to save a recovery key; keep "
                            "it in a safe place, like a password manager or a printed "
                            "copy, but do not store it on the same computer."
                        ),
                        severity=Severity.CRITICAL,
                        category=self.category,
                        code="security.win_bitlocker_check.os_drive_not_encrypted",
                        data={
                            "mount_point": mount_point,
                            "status": status,
                            "is_os_drive": True,
                        },
                    )
                )
            elif is_os_drive and is_encrypted:
                os_drive_encrypted = True

            # WARNING: Encryption suspended
            if status == "encryptionsuspended":
                findings.append(
                    Finding(
                        title=f"BitLocker encryption is paused on {mount_point}",
                        description=(
                            f"BitLocker on {mount_point} is currently paused, so your "
                            "data is not actively protected by encryption. This usually "
                            "happens temporarily during updates or maintenance, but if "
                            "it stays paused, your files are vulnerable if the device "
                            "is lost.\n\n"
                            "What to do: Search for 'BitLocker' in the Start menu, find "
                            f"the entry for {mount_point}, and select 'Resume BitLocker'. "
                            "This will turn the protection back on."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        code="security.win_bitlocker_check.encryption_suspended",
                        data={
                            "mount_point": mount_point,
                            "status": status,
                            "protection_status": protection,
                        },
                    )
                )

            # WARNING: No recovery key protector
            has_recovery_key = any(
                "recovery" in kp.lower() for kp in key_protectors
            )
            if is_encrypted and not has_recovery_key:
                findings.append(
                    Finding(
                        title=f"Missing recovery key for encrypted drive {mount_point}",
                        description=(
                            f"Your drive {mount_point} is encrypted, but there is no backup "
                            "recovery key saved. A recovery key is a long number that "
                            "can unlock your drive if your password is forgotten or your "
                            "computer's security chip fails. Without it, you could lose "
                            "access to your files permanently.\n\n"
                            "What to do: Search for 'BitLocker' in the Start menu, select "
                            "'Manage BitLocker', and look for an option to 'Back up recovery "
                            "key' or 'Save recovery key'. Save it to a USB drive or a "
                            "secure cloud account that only you can access."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        code="security.win_bitlocker_check.no_recovery_key",
                        data={
                            "mount_point": mount_point,
                            "key_protectors": key_protectors,
                        },
                    )
                )

            # WARNING: Fixed drive other than C: not encrypted
            if not is_os_drive and not is_encrypted:
                findings.append(
                    Finding(
                        title=f"Secondary drive {mount_point} is not encrypted",
                        description=(
                            f"Your additional drive {mount_point} is not protected by "
                            "BitLocker encryption. If this drive is removed from the "
                            "computer or the computer is stolen, the files on it can "
                            "be read by anyone. This is less critical than your main "
                            "drive, but still worth fixing for better security.\n\n"
                            "What to do: Search for 'BitLocker' in the Start menu, find "
                            f"{mount_point} in the list, and select 'Turn on BitLocker'."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        code="security.win_bitlocker_check.fixed_drive_not_encrypted",
                        data={
                            "mount_point": mount_point,
                            "status": status,
                        },
                    )
                )

            # INFO: Report encryption status for encrypted volumes
            if is_encrypted:
                protector_list = ", ".join(key_protectors) if key_protectors else "None"
                findings.append(
                    Finding(
                        title=f"Disk encryption: {mount_point}",
                        description=(
                            f"{mount_point} is encrypted using {encryption_method}. "
                            f"Protection: {protection}. "
                            f"Key protectors: {protector_list}"
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        code="security.win_bitlocker_check.status_info",
                        data={
                            "mount_point": mount_point,
                            "status": status,
                            "protection_status": protection,
                            "encryption_method": encryption_method,
                            "key_protectors": key_protectors,
                        },
                    )
                )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            mount_point = finding.data.get("mount_point", "")

            if finding.severity == Severity.CRITICAL:
                actions.append(
                    Action(
                        title=f"Enable BitLocker on {mount_point}",
                        description=(
                            "BitLocker must be enabled via Settings > System > About > Device encryption "
                            "(on supported Windows editions) or via PowerShell with administrator privileges: "
                            f"`Enable-BitLocker -MountPoint {mount_point} -EncryptionMethod Aes256 -UsedSpaceOnly`. "
                            "Store the recovery key in a safe location."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding.severity == Severity.WARNING:
                if finding.code == "security.win_bitlocker_check.encryption_suspended":
                    actions.append(
                        Action(
                            title=f"Resume BitLocker protection on {mount_point}",
                            description=(
                                "Resume encryption via PowerShell: "
                                f"`Resume-BitLocker -MountPoint {mount_point}`. "
                                "Run `manage-bde -status` to verify."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )
                elif finding.code == "security.win_bitlocker_check.no_recovery_key":
                    actions.append(
                        Action(
                            title=f"Add recovery key protector to {mount_point}",
                            description=(
                                "Add a recovery key via PowerShell: "
                                f"`Add-BitLockerKeyProtector -MountPoint {mount_point} -RecoveryPasswordProtector`. "
                                "Store the recovery key in a safe location (not on this device)."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )
                elif finding.code in ("security.win_bitlocker_check.os_drive_not_encrypted", "security.win_bitlocker_check.fixed_drive_not_encrypted"):
                    actions.append(
                        Action(
                            title=f"Enable BitLocker on {mount_point}",
                            description=(
                                "Enable encryption via PowerShell: "
                                f"`Enable-BitLocker -MountPoint {mount_point} -EncryptionMethod Aes256 -UsedSpaceOnly`. "
                                "Run `manage-bde -status` to verify."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )

        return FixResult(module_name=self.name, actions=actions)

    def _run_manage_bde_status(self) -> str:
        try:
            result = subprocess.run(
                ["manage-bde", "-status"],
                capture_output=True,
                text=True,
            )
            return result.stdout
        except (OSError, subprocess.SubprocessError):
            return ""


def _parse_manage_bde_output(output: str) -> list[dict]:
    """Parse `manage-bde -status` output.

    Example::

        C:
            Device Name: C:
            Mount Point: C:\\
            Status: FullyEncrypted
            Protection Status: Protection On
            Encryption Method: AES 256
            Percentage Encrypted: 100.0%
            Encrypted Volume: True
            Key Protectors:
                Numerical Password
                Tpm

        D:
            Device Name: D:
            Mount Point: D:\\
            Status: EncryptionSuspended
            ...
    """
    volumes = []
    current_volume = None
    parsing_protectors = False

    for line in output.splitlines():
        stripped = line.strip()

        # Volume header (e.g., "C:" or "D:")
        if stripped and not line.startswith(" ") and ":" in stripped and len(stripped) == 2:
            if current_volume:
                volumes.append(current_volume)
            current_volume = {
                "mount_point": stripped,
                "status": "",
                "protection_status": "",
                "encryption_method": "",
                "key_protectors": [],
            }
            parsing_protectors = False
        elif current_volume:
            if ":" in stripped:
                key, _, value = stripped.partition(":")
                key = key.strip().lower()
                value = value.strip()

                if key == "mount point":
                    current_volume["mount_point"] = value
                    parsing_protectors = False
                elif key == "status":
                    current_volume["status"] = value
                    parsing_protectors = False
                elif key == "protection status":
                    current_volume["protection_status"] = value
                    parsing_protectors = False
                elif key == "encryption method":
                    current_volume["encryption_method"] = value
                    parsing_protectors = False
                elif key == "key protectors":
                    # Key protectors follow on next lines
                    parsing_protectors = True
            elif parsing_protectors and stripped:
                # This is a key protector (no colon, just the name)
                current_volume["key_protectors"].append(stripped)

    if current_volume:
        volumes.append(current_volume)

    return volumes
