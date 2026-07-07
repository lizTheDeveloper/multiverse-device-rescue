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
    name = "screen_resolution_scaling"
    category = "performance"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 65
    depends_on = []
    estimated_duration = "2s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        try:
            display_info, gpu_info = self._get_display_and_gpu_info()
        except Exception as e:
            return CheckResult(module_name=self.name, findings=findings)

        if not display_info:
            return CheckResult(module_name=self.name, findings=findings)

        has_integrated_gpu = self._has_integrated_gpu(gpu_info)
        gpu_type = gpu_info.get("gpu_type", "Unknown")

        for display in display_info:
            resolution = display.get("resolution", "Unknown")
            native_resolution = display.get("native_resolution", "Unknown")
            is_scaled = display.get("is_scaled", False)
            scaling_mode = display.get("scaling_mode", "Unknown")

            # WARNING: scaled resolution on integrated graphics
            if is_scaled and has_integrated_gpu:
                findings.append(
                    Finding(
                        title="Display scaling may impact performance",
                        description=(
                            f"Display is using a scaled resolution ({resolution}) "
                            f"on a Mac with integrated graphics ({gpu_type}). "
                            "This uses additional GPU memory and can reduce performance, "
                            f"especially on older hardware. Native resolution is {native_resolution}. "
                            "Consider switching to native resolution for better performance."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "scaled_with_integrated_gpu",
                            "resolution": resolution,
                            "native_resolution": native_resolution,
                            "gpu_type": gpu_type,
                        },
                    )
                )

            # INFO: Report current display configuration
            findings.append(
                Finding(
                    title="Display configuration",
                    description=(
                        f"Current resolution: {resolution}, "
                        f"Native resolution: {native_resolution}, "
                        f"Scaling mode: {scaling_mode}, "
                        f"GPU: {gpu_type}. "
                        "If using a scaled (non-native) resolution on older hardware, "
                        "consider switching to native resolution for optimal performance."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "display_info",
                        "resolution": resolution,
                        "native_resolution": native_resolution,
                        "scaling_mode": scaling_mode,
                        "gpu_type": gpu_type,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")
            if check == "scaled_with_integrated_gpu":
                gpu_type = finding.data.get("gpu_type", "Unknown")
                native_res = finding.data.get("native_resolution", "Unknown")
                actions.append(
                    Action(
                        title="Switch to native display resolution",
                        description=(
                            "To improve performance on integrated graphics, "
                            "switch to your display's native resolution:\n"
                            f"1. Go to System Settings > Displays\n"
                            f"2. Look for the Resolution or Scaling option\n"
                            f"3. Select 'Default for display' or native resolution ({native_res})\n"
                            "4. If using an external display, also check the display's native specs\n"
                            "5. Restart your applications if needed for best results.\n\n"
                            "Note: This will increase text/UI size slightly, but provides "
                            "significant performance benefits on older Macs with "
                            f"{gpu_type}."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check == "display_info":
                # Informational only - provide configuration details
                actions.append(
                    Action(
                        title="Review display configuration",
                        description=(
                            "Your display is configured as follows:\n"
                            f"  Resolution: {finding.data.get('resolution', 'Unknown')}\n"
                            f"  Native Resolution: {finding.data.get('native_resolution', 'Unknown')}\n"
                            f"  Scaling Mode: {finding.data.get('scaling_mode', 'Unknown')}\n"
                            f"  GPU: {finding.data.get('gpu_type', 'Unknown')}\n\n"
                            "If your Mac has integrated graphics and you're experiencing "
                            "performance issues, consider switching to the native resolution "
                            "for your display. This is especially important on older Macs."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_display_and_gpu_info(self) -> tuple[list[dict], dict]:
        """Get display resolution, scaling, and GPU information using system_profiler."""
        displays = []
        gpu_info = {}

        try:
            result = subprocess.run(
                ["system_profiler", "SPDisplaysDataType"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                self._parse_display_and_gpu_output(result.stdout, displays, gpu_info)
        except Exception as e:
            pass

        return displays, gpu_info

    def _parse_display_and_gpu_output(self, output: str, displays: list, gpu_info: dict) -> None:
        """Parse system_profiler SPDisplaysDataType output to extract display and GPU info."""
        lines = output.split("\n")
        current_display = None
        in_display_section = False

        for i, line in enumerate(lines):
            line_stripped = line.strip()

            # Extract GPU type from top-level GPU lines
            if any(x in line for x in ["Chip:", "GPU:", "Graphics:", "Chipset Model:"]) and not line.startswith("          "):
                if any(x in line for x in ["M1", "M2", "M3", "M4", "M5"]):
                    gpu_info["gpu_type"] = "Apple Silicon"
                    gpu_info["is_integrated"] = True
                elif "Intel" in line and "Iris" in line:
                    gpu_info["gpu_type"] = "Intel Iris Graphics"
                    gpu_info["is_integrated"] = True
                elif "Intel" in line and "UHD" in line:
                    gpu_info["gpu_type"] = "Intel UHD Graphics"
                    gpu_info["is_integrated"] = True
                elif "Intel" in line and "HD" in line:
                    gpu_info["gpu_type"] = "Intel HD Graphics"
                    gpu_info["is_integrated"] = True
                elif "AMD" in line or "Radeon" in line:
                    gpu_info["gpu_type"] = "AMD Radeon"
                    gpu_info["is_integrated"] = False
                elif "NVIDIA" in line:
                    gpu_info["gpu_type"] = "NVIDIA"
                    gpu_info["is_integrated"] = False

            # Track if we're in the Displays section
            if "Displays:" in line and ":" in line:
                in_display_section = True
                continue

            # Detect actual display entries (those under Displays: with proper indentation)
            if in_display_section and line_stripped and line.startswith("        ") and not line.startswith("          "):
                # This is a display header like "Built-in Retina Display:"
                if current_display and any(
                    current_display.get(k) != "Unknown" for k in ["resolution", "scaling_mode"]
                ):
                    displays.append(current_display)
                current_display = {
                    "resolution": "Unknown",
                    "native_resolution": "Unknown",
                    "is_scaled": False,
                    "scaling_mode": "Unknown",
                }

            if not current_display or not in_display_section:
                continue

            # Extract resolution (looks like "2560 x 1600 Retina")
            if "Resolution:" in line:
                # Extract the resolution pattern
                match = re.search(r"(\d+)\s*x\s*(\d+)", line_stripped)
                if match:
                    width = match.group(1)
                    height = match.group(2)
                    current_display["resolution"] = f"{width}x{height}"

            # Extract scaling mode
            if "Scaling:" in line:
                # Scaling: Off or Scaling: On or similar
                if "Off" in line or "Default" in line:
                    current_display["scaling_mode"] = "Native"
                    current_display["is_scaled"] = False
                elif "On" in line or "Scaled" in line:
                    current_display["scaling_mode"] = "Scaled"
                    current_display["is_scaled"] = True
                elif "More Space" in line:
                    current_display["scaling_mode"] = "More Space (Scaled)"
                    current_display["is_scaled"] = True

            # Native resolution (if listed)
            if "native resolution" in line.lower():
                match = re.search(r"(\d+)\s*x\s*(\d+)", line_stripped)
                if match:
                    width = match.group(1)
                    height = match.group(2)
                    current_display["native_resolution"] = f"{width}x{height}"

        # Don't forget the last display
        if current_display and any(
            current_display.get(k) != "Unknown" for k in ["resolution", "scaling_mode"]
        ):
            displays.append(current_display)

    def _has_integrated_gpu(self, gpu_info: dict) -> bool:
        """Check if the system has integrated graphics."""
        return gpu_info.get("is_integrated", False)
