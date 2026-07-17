import subprocess
import plistlib

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
    name = "pram_nvram_check"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check startup disk
        startup_disk = self._get_startup_disk()
        if startup_disk is None:
            findings.append(
                Finding(
                    title="Startup disk not set",
                    description="No startup disk is currently selected. This can cause slow boot times and unexpected behavior.",
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "startup_disk_not_set"},
                )
            )
        elif startup_disk:
            findings.append(
                Finding(
                    title="Startup disk information",
                    description=f"Boot device: {startup_disk}",
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "startup_disk", "disk": startup_disk},
                )
            )

        # Check boot-args
        boot_args = self._get_boot_args()
        if boot_args is not None:
            # Check for unusual kernel flags
            unusual_flags = self._check_unusual_boot_flags(boot_args)
            if unusual_flags:
                findings.append(
                    Finding(
                        title="Unusual boot arguments detected",
                        description=f"Kernel flags detected: {', '.join(unusual_flags)}. These are typically used for debugging and should not be present on a normal system.",
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check": "unusual_boot_args", "flags": unusual_flags},
                    )
                )
            else:
                findings.append(
                    Finding(
                        title="Boot arguments normal",
                        description=f"Boot args: {boot_args if boot_args.strip() else '(none)'}",
                        severity=Severity.INFO,
                        category=self.category,
                        data={"check": "boot_args_normal", "args": boot_args},
                    )
                )

        # Check system audio volume
        audio_volume = self._get_audio_volume()
        if audio_volume is not None:
            findings.append(
                Finding(
                    title="System audio volume setting",
                    description=f"NVRAM SystemAudioVolume: {audio_volume}",
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "audio_volume", "volume": audio_volume},
                )
            )

        # Check for crash/panic indicators
        crash_indicators = self._check_crash_indicators()
        if crash_indicators:
            findings.append(
                Finding(
                    title="Previous system crashes detected",
                    description=f"NVRAM contains indicators of previous crashes: {', '.join(crash_indicators)}. Review system logs for details.",
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "crash_indicators", "indicators": crash_indicators},
                )
            )

        # Report key NVRAM settings
        key_settings = self._get_key_nvram_settings()
        if key_settings:
            findings.append(
                Finding(
                    title="Key NVRAM settings",
                    description=f"Important NVRAM variables: {', '.join(f'{k}={v}' for k, v in key_settings.items())}",
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "key_nvram_settings", "settings": key_settings},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")
            if check == "startup_disk_not_set":
                actions.append(
                    Action(
                        title="Set startup disk",
                        description=(
                            "To set your startup disk, go to System Settings > General > Startup Disk "
                            "and select your desired boot volume. If the startup disk is not set, your Mac may boot slowly or erratically."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check == "unusual_boot_args":
                actions.append(
                    Action(
                        title="Reset NVRAM/PRAM",
                        description=(
                            "Unusual boot arguments have been detected in NVRAM. You can reset the NVRAM (Parameter RAM) by:\n"
                            "1. Shut down your Mac completely\n"
                            "2. Power on and immediately hold Command + Option + P + R\n"
                            "3. Hold these keys until you see the Apple logo and startup screen appear twice, or hear the startup sound twice (on older Macs)\n"
                            "Your NVRAM will be reset to default values, which may resolve boot-related issues."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_startup_disk(self) -> str | None:
        """Get the selected startup disk via bless."""
        try:
            result = subprocess.run(
                ["bless", "--info", "--getBoot"],
                capture_output=True,
                text=True,
            )
            output = result.stdout.strip()
            if output:
                return output
            else:
                return None
        except (OSError, subprocess.SubprocessError):
            return None

    def _get_boot_args(self) -> str | None:
        """Get boot-args from NVRAM."""
        try:
            result = subprocess.run(
                ["nvram", "boot-args"],
                capture_output=True,
                text=True,
            )
            output = result.stdout.strip()
            if output and "boot-args" in output:
                # Parse "boot-args\t<value>"
                parts = output.split("\t", 1)
                if len(parts) > 1:
                    return parts[1]
            return ""
        except (OSError, subprocess.SubprocessError):
            return None

    def _check_unusual_boot_flags(self, boot_args: str) -> list[str]:
        """Check for unusual boot flags like -v, -x, debug, etc."""
        unusual_flags = []
        # List of flags that typically indicate debugging/development
        suspicious_flags = ["-v", "-x", "-s", "debug", "pmuflags"]
        for flag in suspicious_flags:
            if flag in boot_args:
                unusual_flags.append(flag)
        return unusual_flags

    def _get_audio_volume(self) -> str | None:
        """Get SystemAudioVolume from NVRAM."""
        try:
            result = subprocess.run(
                ["nvram", "-xp"],
                capture_output=True,
                text=True,
            )
            # Parse plist output
            if result.stdout:
                try:
                    nvram_dict = plistlib.loads(result.stdout.encode())
                    if isinstance(nvram_dict, dict):
                        return nvram_dict.get("SystemAudioVolume", None)
                except Exception:
                    pass
        except (OSError, subprocess.SubprocessError):
            pass
        return None

    def _check_crash_indicators(self) -> list[str]:
        """Check for NVRAM variables indicating previous crashes."""
        indicators = []
        try:
            result = subprocess.run(
                ["nvram", "-xp"],
                capture_output=True,
                text=True,
            )
            if result.stdout:
                try:
                    nvram_dict = plistlib.loads(result.stdout.encode())
                    if isinstance(nvram_dict, dict):
                        # Check for crash-related keys
                        crash_keys = [
                            "panic-action",
                            "paniclog",
                            "boot-error",
                            "boot-failure",
                        ]
                        for key in crash_keys:
                            if key in nvram_dict:
                                indicators.append(key)
                except Exception:
                    pass
        except (OSError, subprocess.SubprocessError):
            pass
        return indicators

    def _get_key_nvram_settings(self) -> dict[str, str]:
        """Get key NVRAM settings."""
        settings = {}
        try:
            result = subprocess.run(
                ["nvram", "-xp"],
                capture_output=True,
                text=True,
            )
            if result.stdout:
                try:
                    nvram_dict = plistlib.loads(result.stdout.encode())
                    if isinstance(nvram_dict, dict):
                        # Extract commonly important keys
                        important_keys = [
                            "efi-boot-device",
                            "efi-boot-device-data",
                            "SystemAudioVolume",
                            "IOKitPersonalities",
                        ]
                        for key in important_keys:
                            if key in nvram_dict:
                                value = nvram_dict[key]
                                # Convert to string representation
                                if isinstance(value, bytes):
                                    try:
                                        settings[key] = value.decode("utf-8", errors="replace")[:50]
                                    except Exception:
                                        settings[key] = "<binary>"
                                elif isinstance(value, (dict, list)):
                                    settings[key] = f"<{type(value).__name__}>"
                                else:
                                    settings[key] = str(value)[:50]
                except Exception:
                    pass
        except (OSError, subprocess.SubprocessError):
            pass
        return settings
