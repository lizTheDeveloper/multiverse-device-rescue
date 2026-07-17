import re
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
    name = "smcreset_guide"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 40
    depends_on = []
    estimated_duration = "3s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get Mac model and hardware info
        model_info = self._get_mac_model()
        is_apple_silicon = self._is_apple_silicon(profile)

        # Add model information finding
        findings.append(
            Finding(
                title=f"Mac model: {model_info.get('model', 'Unknown')}",
                description=(
                    f"Detected hardware: {model_info.get('hardware_name', 'Unknown')}. "
                    f"Architecture: {'Apple Silicon' if is_apple_silicon else 'Intel'}."
                ),
                severity=Severity.INFO,
                category=self.category,
                data={
                    "check": "model_info",
                    "model": model_info.get("model"),
                    "hardware_name": model_info.get("hardware_name"),
                    "is_apple_silicon": is_apple_silicon,
                },
            )
        )

        # Check for symptoms that suggest SMC reset might help
        symptoms = self._check_symptoms()

        if symptoms:
            symptom_list = ", ".join(symptoms)
            findings.append(
                Finding(
                    title="Symptoms detected that may benefit from SMC reset",
                    description=(
                        f"Detected the following symptoms: {symptom_list}. "
                        "These can often be resolved with an SMC reset."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "symptoms",
                        "symptoms": symptoms,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "model_info":
                model = finding.data.get("model")
                is_apple_silicon = finding.data.get("is_apple_silicon")
                hardware_name = finding.data.get("hardware_name")

                if is_apple_silicon:
                    actions.append(
                        Action(
                            title="Apple Silicon Mac detected",
                            description=(
                                "Your Mac has Apple Silicon and does not have an SMC that "
                                "can be reset like Intel Macs. However, many issues that "
                                "would require SMC reset on Intel Macs can be resolved on "
                                "Apple Silicon by restarting: Hold the power button for 10 "
                                "seconds until the Mac shuts down completely, wait 10 seconds, "
                                "then power on normally."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )
                else:
                    # Intel Mac - provide detailed SMC reset instructions
                    instructions = self._get_smc_reset_instructions(model)
                    actions.append(
                        Action(
                            title=f"SMC Reset Instructions for {hardware_name or model}",
                            description=instructions,
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )
                    # Also suggest NVRAM reset
                    actions.append(
                        Action(
                            title="NVRAM Reset (Optional)",
                            description=(
                                "If the SMC reset does not resolve the issue, you can also "
                                "try resetting NVRAM. Restart your Mac and immediately hold "
                                "Cmd+Option+P+R until you hear the startup sound twice (or "
                                "Apple logo appears and disappears twice). This erases some "
                                "low-level settings but is safe for data."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )

            elif check == "symptoms":
                symptoms = finding.data.get("symptoms", [])
                symptom_description = self._get_symptom_guidance(symptoms)
                actions.append(
                    Action(
                        title="Symptom-specific guidance",
                        description=symptom_description,
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_mac_model(self) -> dict:
        """Get Mac model identifier and hardware name."""
        info = {}

        # Get model identifier via sysctl
        try:
            result = subprocess.run(
                ["sysctl", "hw.model"],
                capture_output=True,
                text=True,
            )
            match = re.search(r"hw\.model:\s*(.+)", result.stdout)
            if match:
                info["model"] = match.group(1).strip()
        except (OSError, subprocess.SubprocessError):
            pass

        # Get hardware name via system_profiler
        system_profiler_output = self._run_system_profiler_hardware()
        if "MacBook Pro" in system_profiler_output:
            info["hardware_name"] = "MacBook Pro"
        elif "MacBook Air" in system_profiler_output:
            info["hardware_name"] = "MacBook Air"
        elif "MacBook" in system_profiler_output:
            info["hardware_name"] = "MacBook"
        elif "Mac mini" in system_profiler_output:
            info["hardware_name"] = "Mac mini"
        elif "Mac Studio" in system_profiler_output:
            info["hardware_name"] = "Mac Studio"
        elif "iMac" in system_profiler_output:
            info["hardware_name"] = "iMac"
        elif "Mac Pro" in system_profiler_output:
            info["hardware_name"] = "Mac Pro"
        elif "Mac" in system_profiler_output:
            info["hardware_name"] = "Mac"

        return info

    def _is_apple_silicon(self, profile: SystemProfile) -> bool:
        """Determine if this is an Apple Silicon Mac."""
        # Check architecture from system profile
        if profile.architecture and "arm" in profile.architecture.lower():
            return True
        # Check CPU model
        if profile.cpu_model and any(
            arch in profile.cpu_model.lower() for arch in ["apple", "m1", "m2", "m3", "m4"]
        ):
            return True
        return False

    def _check_symptoms(self) -> list[str]:
        """Check for symptoms that suggest SMC reset might help."""
        symptoms = []

        # Try to check fan speed via powermetrics
        try:
            result = subprocess.run(
                ["powermetrics", "--samplers", "smc", "-n", "1"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            output = result.stdout
            # Look for high fan speeds
            if re.search(r"Fan\s+\d+\s+speed:\s*(\d+)\s*rpm", output):
                matches = re.findall(r"Fan\s+\d+\s+speed:\s*(\d+)\s*rpm", output)
                if matches:
                    speeds = [int(m) for m in matches]
                    # If any fan is running at very high speed (>5000 RPM is unusual)
                    if any(s > 5000 for s in speeds):
                        symptoms.append("fans running at high speed")
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            pass

        # Check battery charging status if available
        try:
            result = subprocess.run(
                ["system_profiler", "SPPowerDataType"],
                capture_output=True,
                text=True,
            )
            output = result.stdout
            # Look for "Not Charging" or "Not Charging" even when plugged in
            if "Battery Installed: Yes" in output and "Charging: No" in output:
                if "Connected: Yes" in output:
                    symptoms.append("battery not charging despite AC power")
        except (OSError, subprocess.SubprocessError):
            pass

        # Check display brightness issues by looking for relevant system logs
        # (This is more heuristic than definitive)
        try:
            result = subprocess.run(
                ["system_profiler", "SPDisplaysDataType"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            # Just verify display is detected; actual brightness issues are harder to detect
            if result.returncode != 0 or "Display" not in result.stdout:
                symptoms.append("display detection issues")
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            pass

        return symptoms

    def _run_system_profiler_hardware(self) -> str:
        """Run system_profiler SPHardwareDataType and return output."""
        try:
            result = subprocess.run(
                ["system_profiler", "SPHardwareDataType"],
                capture_output=True,
                text=True,
            )
            return result.stdout
        except (OSError, subprocess.SubprocessError):
            return ""

    def _get_smc_reset_instructions(self, model: str) -> str:
        """Get SMC reset instructions based on Mac model."""
        # Categorize by model type
        if not model:
            return self._get_generic_smc_instructions()

        model_lower = model.lower()

        # MacBook Pro with T2 (2018 or later)
        if "macbookpro" in model_lower:
            if any(year in model for year in ["18,", "19,", "20,", "21,", "22,"]):
                return (
                    "SMC Reset for MacBook Pro (2018 or later with T2 chip):\n"
                    "1. Shut down your MacBook Pro completely\n"
                    "2. Press Shift + Control + Option (all on the left side) + Power button\n"
                    "3. Hold all four keys for 10 seconds\n"
                    "4. Release all keys\n"
                    "5. Wait a few seconds, then press Power to restart\n\n"
                    "Your Mac will restart with a black screen briefly—this is normal."
                )
            else:
                return (
                    "SMC Reset for MacBook Pro (2017 or earlier):\n"
                    "1. Shut down your MacBook Pro completely\n"
                    "2. Press Shift + Control + Option (all on the left side) + Power button\n"
                    "3. Hold all four keys for 10 seconds\n"
                    "4. Release all keys\n"
                    "5. Wait a few seconds, then press Power to restart\n\n"
                    "The fan may spin loudly briefly—this is normal and indicates SMC reset."
                )

        # MacBook Air with T2 (2018 or later)
        elif "macbookair" in model_lower:
            if any(year in model for year in ["9,", "10,", "11,", "12,", "13,", "14,", "15,"]):
                return (
                    "SMC Reset for MacBook Air (2018 or later with T2 chip):\n"
                    "1. Shut down your MacBook Air completely\n"
                    "2. Press Shift + Control + Option (all on the left side) + Power button\n"
                    "3. Hold all four keys for 10 seconds\n"
                    "4. Release all keys\n"
                    "5. Wait a few seconds, then press Power to restart"
                )
            else:
                return (
                    "SMC Reset for MacBook Air (2017 or earlier):\n"
                    "1. Shut down your MacBook Air completely\n"
                    "2. Press Shift + Control + Option (all on the left side) + Power button\n"
                    "3. Hold all four keys for 10 seconds\n"
                    "4. Release all keys\n"
                    "5. Wait a few seconds, then press Power to restart"
                )

        # Mac mini with T2 (2018 or later)
        elif "macmini" in model_lower:
            if any(year in model for year in ["8,", "9,"]):
                return (
                    "SMC Reset for Mac mini (2018 or later with T2 chip):\n"
                    "1. Shut down your Mac mini completely\n"
                    "2. Unplug the power cable\n"
                    "3. Wait 30 seconds\n"
                    "4. Plug the power cable back in\n"
                    "5. Wait 5 seconds, then press the power button to restart\n\n"
                    "Note: Mac mini with T2 performs SMC reset automatically when power is restored."
                )
            else:
                return (
                    "SMC Reset for Mac mini (2017 or earlier):\n"
                    "1. Shut down your Mac mini completely\n"
                    "2. Unplug the power cable\n"
                    "3. Wait 15 seconds\n"
                    "4. Plug the power cable back in\n"
                    "5. Wait 5 seconds, then press the power button to restart"
                )

        # iMac with T2 (2019 or later)
        elif "imac" in model_lower:
            if any(year in model for year in ["19,", "20,", "21,"]):
                return (
                    "SMC Reset for iMac (2019 or later with T2 chip):\n"
                    "1. Shut down your iMac completely\n"
                    "2. Unplug the power cable\n"
                    "3. Wait 30 seconds\n"
                    "4. Plug the power cable back in\n"
                    "5. Wait 5 seconds, then press the power button to restart"
                )
            else:
                return (
                    "SMC Reset for iMac (2018 or earlier):\n"
                    "1. Shut down your iMac completely\n"
                    "2. Unplug the power cable\n"
                    "3. Wait 15 seconds\n"
                    "4. Plug the power cable back in\n"
                    "5. Wait 5 seconds, then press the power button to restart"
                )

        # Mac Pro (desktop, usually no T2)
        elif "macpro" in model_lower:
            return (
                "SMC Reset for Mac Pro:\n"
                "1. Shut down your Mac Pro completely\n"
                "2. Unplug the power cable\n"
                "3. Wait 15 seconds\n"
                "4. Plug the power cable back in\n"
                "5. Wait 5 seconds, then press the power button to restart"
            )

        else:
            return self._get_generic_smc_instructions()

    def _get_generic_smc_instructions(self) -> str:
        """Get generic SMC reset instructions."""
        return (
            "SMC Reset Instructions:\n"
            "For laptops (MacBook Pro, Air, etc.):\n"
            "1. Shut down completely\n"
            "2. Press Shift + Control + Option + Power (hold all four keys for 10 seconds)\n"
            "3. Release keys and wait, then press Power to restart\n\n"
            "For desktops (iMac, Mac mini, Mac Pro):\n"
            "1. Shut down completely\n"
            "2. Unplug the power cable and wait 15-30 seconds\n"
            "3. Plug back in and wait 5 seconds, then press Power\n\n"
            "See Apple support for model-specific instructions."
        )

    def _get_symptom_guidance(self, symptoms: list[str]) -> str:
        """Get guidance for specific symptoms."""
        guidance_lines = [
            "Symptoms detected that may benefit from SMC reset:\n"
        ]

        if "fans running at high speed" in symptoms:
            guidance_lines.append(
                "- Fans running at high speed: SMC reset can resolve unnecessary fan "
                "spin-up. This is often caused by SMC miscalculation of thermal conditions."
            )

        if "battery not charging despite AC power" in symptoms:
            guidance_lines.append(
                "- Battery not charging: SMC controls charging behavior. A reset often "
                "resolves charging issues, especially when the battery appears healthy."
            )

        if "display detection issues" in symptoms:
            guidance_lines.append(
                "- Display issues: In rare cases, SMC reset can fix display-related "
                "problems, especially on external displays."
            )

        if not any(s in symptoms for s in ["fans running at high speed", "battery not charging despite AC power", "display detection issues"]):
            for symptom in symptoms:
                guidance_lines.append(f"- {symptom}")

        guidance_lines.append(
            "\nTry the SMC reset using the instructions above. If symptoms persist, "
            "visit support.apple.com or contact Apple Support."
        )

        return "\n".join(guidance_lines)
