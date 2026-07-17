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

# RAM threshold for "Best Appearance" warning (8 GB)
RAM_THRESHOLD = 8 * 1024**3


class Module(ModuleBase):
    name = "win_visual_effects"
    category = "performance"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 60
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check visual effects setting
        visual_fx_setting = self._get_visual_fx_setting()
        transparency_enabled = self._get_transparency_enabled()
        animations_enabled = self._get_animations_enabled()

        # Determine RAM in GB for display
        ram_gb = profile.ram_bytes / (1024**3)
        has_low_ram = profile.ram_bytes < RAM_THRESHOLD

        # Create finding for visual effects configuration
        fx_description = self._describe_visual_fx_setting(visual_fx_setting)
        findings.append(
            Finding(
                title="Visual Effects Configuration",
                description=fx_description,
                severity=Severity.INFO,
                category=self.category,
                data={
                    "setting": visual_fx_setting,
                    "transparency": transparency_enabled,
                    "animations": animations_enabled,
                    "ram_gb": ram_gb,
                },
            )
        )

        # Flag warning if "Best Appearance" on low RAM
        if visual_fx_setting == 3 and has_low_ram:
            findings.append(
                Finding(
                    title="Visual Effects may impact performance",
                    description=(
                        f"Visual effects are set to 'Best Appearance' (highest quality) "
                        f"on a system with only {ram_gb:.1f} GB RAM. This can slow down "
                        f"older systems. Consider reducing visual effects for better performance."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "issue": "best_appearance_low_ram",
                        "ram_gb": ram_gb,
                    },
                )
            )

        # Flag warning if transparency is enabled on low RAM
        if transparency_enabled and has_low_ram:
            findings.append(
                Finding(
                    title="Transparency effects enabled on low RAM system",
                    description=(
                        f"Transparency effects are enabled on a system with {ram_gb:.1f} GB RAM. "
                        f"Disabling transparency can improve performance on older hardware."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "issue": "transparency_low_ram",
                        "ram_gb": ram_gb,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            issue_type = finding.data.get("issue")

            if finding.severity == Severity.INFO:
                # Configuration report
                setting = finding.data.get("setting")
                transparency = finding.data.get("transparency")
                animations = finding.data.get("animations")
                ram_gb = finding.data.get("ram_gb", 0)

                setting_name = self._setting_name(setting)
                trans_status = "enabled" if transparency else "disabled"
                anim_status = "enabled" if animations else "disabled"

                actions.append(
                    Action(
                        title="Visual Effects Configuration Report",
                        description=(
                            f"System has {ram_gb:.1f} GB RAM. "
                            f"Current settings: Effects={setting_name}, "
                            f"Transparency={trans_status}, Animations={anim_status}."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif issue_type == "best_appearance_low_ram":
                ram_gb = finding.data.get("ram_gb", 0)
                actions.append(
                    Action(
                        title="Reduce visual effects for better performance",
                        description=(
                            f"Your system has {ram_gb:.1f} GB RAM with visual effects set to maximum. "
                            f"To improve performance, consider changing to 'Best Performance': "
                            f"Settings > System > Display > Advanced display settings > "
                            f"Performance tab > Adjust for best performance."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif issue_type == "transparency_low_ram":
                ram_gb = finding.data.get("ram_gb", 0)
                actions.append(
                    Action(
                        title="Disable transparency effects",
                        description=(
                            f"With {ram_gb:.1f} GB RAM, disabling transparency effects can improve "
                            f"performance. Settings > System > Display > Transparency effects toggle."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_visual_fx_setting(self) -> int:
        """Get visual effects setting via registry.

        Values:
        - 0: Best Performance
        - 1: Custom
        - 2: (unused)
        - 3: Best Appearance
        """
        try:
            result = subprocess.run(
                [
                    "reg",
                    "query",
                    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VisualEffects",
                    "/v",
                    "VisualFXSetting",
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                # Parse output like "    VisualFXSetting    REG_DWORD    0x3"
                for line in result.stdout.splitlines():
                    if "VisualFXSetting" in line:
                        parts = line.split()
                        for i, part in enumerate(parts):
                            if part.startswith("0x"):
                                try:
                                    return int(part, 16)
                                except ValueError:
                                    return -1
            return -1
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            return -1

    def _get_transparency_enabled(self) -> bool:
        """Get transparency effects setting via registry."""
        try:
            result = subprocess.run(
                [
                    "reg",
                    "query",
                    "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
                    "/v",
                    "EnableTransparency",
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                # Parse output like "    EnableTransparency    REG_DWORD    0x1"
                for line in result.stdout.splitlines():
                    if "EnableTransparency" in line:
                        parts = line.split()
                        for i, part in enumerate(parts):
                            if part.startswith("0x"):
                                try:
                                    value = int(part, 16)
                                    return value == 1
                                except ValueError:
                                    return False
            return False
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            return False

    def _get_animations_enabled(self) -> bool:
        """Get animations setting via registry.

        MinAnimate: 1 = animations enabled, 0 = disabled
        """
        try:
            result = subprocess.run(
                [
                    "reg",
                    "query",
                    "HKCU\\Control Panel\\Desktop\\WindowMetrics",
                    "/v",
                    "MinAnimate",
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                # Parse output like "    MinAnimate    REG_SZ    1"
                for line in result.stdout.splitlines():
                    if "MinAnimate" in line:
                        parts = line.split()
                        if len(parts) > 0:
                            # Last part is the value
                            try:
                                value = int(parts[-1])
                                return value == 1
                            except ValueError:
                                return True  # Default to enabled
            return True
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            return True

    def _describe_visual_fx_setting(self, setting: int) -> str:
        """Convert visual effects setting to human-readable description."""
        setting_name = self._setting_name(setting)
        if setting == 0:
            return f"Visual effects set to '{setting_name}' - fastest performance, minimal animations."
        elif setting == 3:
            return f"Visual effects set to '{setting_name}' - full visual enhancements, may impact performance."
        elif setting == 1:
            return f"Visual effects set to '{setting_name}' - custom configuration."
        else:
            return f"Visual effects setting: {setting_name}"

    def _setting_name(self, setting: int) -> str:
        """Get human-readable name for visual effects setting."""
        names = {
            0: "Best Performance",
            1: "Custom",
            3: "Best Appearance",
        }
        return names.get(setting, f"Unknown ({setting})")
