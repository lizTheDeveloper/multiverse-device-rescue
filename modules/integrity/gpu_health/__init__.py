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
    name = "gpu_health"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get GPU info from system_profiler
        gpu_info = self._get_gpu_info()

        # Check if GPU info was retrieved
        if not gpu_info:
            findings.append(
                Finding(
                    title="GPU information unavailable",
                    description=(
                        "Unable to retrieve GPU configuration information from "
                        "system_profiler. GPU checks cannot be completed."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "no_gpu_info"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # Report GPU model, VRAM, and configuration
        gpu_summary = f"{gpu_info.get('model', 'Unknown')} with {gpu_info.get('vram', 'Unknown')} VRAM"
        gpu_type = gpu_info.get("type", "Unknown")

        findings.append(
            Finding(
                title="GPU configuration detected",
                description=(
                    f"GPU Model: {gpu_info.get('model', 'Unknown')}. "
                    f"VRAM: {gpu_info.get('vram', 'Unknown')}. "
                    f"Type: {gpu_type}. "
                    f"Metal Support: {gpu_info.get('metal_support', 'Unknown')}. "
                    f"Driver Status: {gpu_info.get('driver_status', 'Unknown')}."
                ),
                severity=Severity.INFO,
                category=self.category,
                data={
                    "check": "gpu_info",
                    "model": gpu_info.get("model"),
                    "vram": gpu_info.get("vram"),
                    "type": gpu_type,
                    "metal_support": gpu_info.get("metal_support"),
                    "driver_status": gpu_info.get("driver_status"),
                },
            )
        )

        # Check Metal support (WARNING if not supported)
        metal_support = gpu_info.get("metal_support", "Unknown")
        if metal_support.lower() == "not supported":
            findings.append(
                Finding(
                    title="GPU does not support Metal",
                    description=(
                        "This GPU does not support Apple Metal, which is required for "
                        "modern macOS compatibility and proper graphics rendering. "
                        "This limits the system's ability to run modern applications and "
                        "may cause graphical issues. Consider GPU upgrade or using compatible "
                        "applications for this GPU."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "no_metal_support"},
                )
            )

        # Check VRAM (WARNING if very low)
        vram_str = gpu_info.get("vram", "")
        vram_mb = self._parse_vram_to_mb(vram_str)
        if vram_mb is not None and vram_mb < 512:
            findings.append(
                Finding(
                    title=f"GPU VRAM is very low ({vram_str})",
                    description=(
                        f"GPU VRAM is only {vram_str}, which is below 512MB. "
                        "This can cause display glitches, freezing, and graphical artifacts "
                        "especially at higher resolutions. Performance may be impacted when "
                        "using modern applications."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "low_vram", "vram_mb": vram_mb},
                )
            )

        # Check for GPU-related kernel panics
        gpu_panics = self._check_gpu_kernel_panics()
        if gpu_panics:
            findings.append(
                Finding(
                    title="GPU-related kernel panics detected",
                    description=(
                        f"Found {len(gpu_panics)} GPU-related kernel panic(s) in the last 7 days. "
                        "These panics may indicate GPU driver issues, hardware problems, or "
                        "incompatibilities. Recent GPU panics can cause system crashes and "
                        "display freezes."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "gpu_kernel_panics",
                        "count": len(gpu_panics),
                        "panics": gpu_panics,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "gpu_info":
                actions.append(
                    Action(
                        title="GPU configuration documented",
                        description=(
                            "GPU configuration has been documented. Monitor the GPU for "
                            "any display issues, freezes, or graphical artifacts. "
                            "If issues occur, consider: (1) Updating GPU drivers through "
                            "macOS updates, (2) Checking System Settings for GPU-related "
                            "options, (3) Resetting NVRAM/PRAM and SMC for GPU reset, "
                            "(4) Consulting GPU compatibility with your macOS version."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "no_gpu_info":
                actions.append(
                    Action(
                        title="GPU information unavailable",
                        description=(
                            "Unable to retrieve GPU configuration. This may occur on "
                            "systems with GPU issues or in certain virtualized environments. "
                            "Visit System Settings > Displays to manually verify GPU settings. "
                            "Run 'system_profiler SPDisplaysDataType' in Terminal to check GPU status."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "no_metal_support":
                actions.append(
                    Action(
                        title="GPU requires Metal support update",
                        description=(
                            "This GPU does not support Apple Metal. Metal is a low-level "
                            "graphics API required for modern macOS applications. "
                            "Options: (1) Update to a supported macOS version, "
                            "(2) Consider GPU upgrade for full modern software support, "
                            "(3) Use legacy applications that support this GPU. "
                            "Check Apple's Metal compatibility documentation for your GPU model."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "low_vram":
                vram_mb = finding.data.get("vram_mb", 0)
                actions.append(
                    Action(
                        title=f"GPU VRAM is very low ({vram_mb}MB)",
                        description=(
                            f"GPU VRAM is only {vram_mb}MB, which is below recommended 512MB. "
                            "This can cause display glitches and freezes, especially at higher "
                            "resolutions with multiple displays. Recommendations: "
                            "(1) Close graphics-intensive applications, (2) Check for GPU driver updates, "
                            "(3) Reduce display resolution or disable scaling if possible, "
                            "(4) Reset GPU via SMC reset if issues persist, (5) Consider GPU upgrade "
                            "if this is a discrete GPU or hardware limitation."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "gpu_kernel_panics":
                panic_count = finding.data.get("count", 0)
                actions.append(
                    Action(
                        title=f"GPU kernel panics detected ({panic_count})",
                        description=(
                            f"Found {panic_count} GPU-related kernel panic(s) in the last 7 days. "
                            "These can cause crashes and freezes. Troubleshooting steps: "
                            "(1) Update macOS to the latest version for GPU driver updates, "
                            "(2) Reset GPU via SMC reset (shutdown, then power on with specific key combination), "
                            "(3) Reset NVRAM/PRAM (older Macs), (4) Disable GPU acceleration in problematic apps, "
                            "(5) Monitor Console.app for detailed panic logs, (6) Check for hardware issues "
                            "if panics persist. Contact Apple Support if issue continues."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_gpu_info(self) -> dict:
        """Get GPU information from system_profiler SPDisplaysDataType."""
        try:
            result = subprocess.run(
                ["system_profiler", "SPDisplaysDataType"],
                capture_output=True,
                text=True,
                errors="replace",
            )
            if result.returncode != 0:
                return {}

            output = result.stdout
            gpu_info = self._parse_gpu_from_system_profiler(output)
            return gpu_info
        except (OSError, subprocess.SubprocessError):
            return {}

    def _parse_gpu_from_system_profiler(self, output: str) -> dict:
        """Parse GPU information from system_profiler output."""
        gpu_info = {}

        lines = output.split("\n")
        for i, line in enumerate(lines):
            line_stripped = line.strip()

            # Look for GPU model
            if "Chipset Model:" in line:
                gpu_info["model"] = line.split(":", 1)[1].strip()
            elif "Chip:" in line:
                gpu_info["model"] = line.split(":", 1)[1].strip()

            # Look for VRAM
            elif "VRAM (Dynamic, Shared):" in line:
                gpu_info["vram"] = line.split(":", 1)[1].strip()
            elif "VRAM (Shared):" in line:
                gpu_info["vram"] = line.split(":", 1)[1].strip()
            elif line_stripped.startswith("VRAM:"):
                gpu_info["vram"] = line.split(":", 1)[1].strip()

            # Look for GPU type (integrated vs discrete)
            elif "GPU Type:" in line:
                gpu_type = line.split(":", 1)[1].strip()
                gpu_info["type"] = gpu_type
            elif "Integrated" in line and "GPU" in line:
                gpu_info["type"] = "Integrated GPU"
            elif "Discrete" in line and "GPU" in line:
                gpu_info["type"] = "Discrete GPU"

            # Look for the Metal capability field. macOS spells this
            # differently depending on OS version:
            #   "Metal Support: Metal 3"                          (Monterey+)
            #   "Metal Family: Supported, Metal GPUFamily macOS 2" (Mojave/Catalina)
            #   "Metal: Supported" / "Metal: Not Supported"        (older releases)
            elif line_stripped.startswith("Metal Support:"):
                gpu_info["metal_raw"] = line.split(":", 1)[1].strip()
            elif line_stripped.startswith("Metal Family:"):
                gpu_info["metal_raw"] = line.split(":", 1)[1].strip()
            elif line_stripped.startswith("Metal:"):
                gpu_info["metal_raw"] = line.split(":", 1)[1].strip()

        # Metal support and driver status are both derived from the same
        # parsed "Metal ..." field reported by system_profiler. If the field
        # can't be found, report "Unknown" rather than guessing - the field
        # can be genuinely absent on some macOS/hardware combos, and treating
        # a parse miss as "Not Supported" (or "Up to date") would just trade
        # one false claim for another.
        metal_raw = gpu_info.get("metal_raw")
        gpu_info["metal_support"] = self._check_metal_support(metal_raw)
        gpu_info["driver_status"] = self._check_driver_status(metal_raw)

        return gpu_info

    def _check_metal_support(self, metal_raw: str | None) -> str:
        """Determine Metal support from the parsed system_profiler field.

        Only ever reports "Not Supported" when the field explicitly says so.
        Absence of the field is reported as "Unknown" rather than assumed to
        mean either "Supported" or "Not Supported".
        """
        if not metal_raw:
            return "Unknown"

        if "not supported" in metal_raw.lower():
            return "Not Supported"

        return "Supported"

    def _check_driver_status(self, metal_raw: str | None) -> str:
        """Report the raw Metal capability string found by system_profiler.

        macOS does not expose a GPU driver version through system_profiler,
        so this surfaces whatever was actually parsed (e.g. "Metal 3" or
        "Supported, Metal GPUFamily macOS 2") instead of a fabricated
        "Up to date" status. Reports "Unknown" when nothing could be parsed.
        """
        if not metal_raw:
            return "Unknown"

        return metal_raw

    def _parse_vram_to_mb(self, vram_str: str) -> int | None:
        """Parse VRAM string like '512 MB' or '2 GB' to megabytes."""
        if not vram_str:
            return None

        vram_lower = vram_str.lower()

        # Try to extract numeric value
        match = re.search(r"([\d.]+)\s*(mb|gb|kb)", vram_lower)
        if not match:
            return None

        value = float(match.group(1))
        unit = match.group(2)

        if unit == "kb":
            return int(value / 1024)
        elif unit == "mb":
            return int(value)
        elif unit == "gb":
            return int(value * 1024)

        return None

    def _check_gpu_kernel_panics(self) -> list[str]:
        """Check for GPU-related kernel panics in the last 7 days."""
        try:
            result = subprocess.run(
                [
                    "log",
                    "show",
                    "--predicate",
                    'eventMessage contains "GPU"',
                    "--last",
                    "7d",
                    "--style",
                    "compact",
                ],
                capture_output=True,
                text=True,
                errors="replace",
                timeout=10,
            )

            if result.returncode != 0:
                return []

            output = result.stdout
            lines = output.split("\n")

            # Filter for panic-related messages
            panic_lines = []
            for line in lines[:20]:  # Head 20 as per requirement
                line_lower = line.lower()
                if any(
                    keyword in line_lower
                    for keyword in [
                        "panic",
                        "crash",
                        "fault",
                        "error",
                        "gpu hang",
                        "device reset",
                    ]
                ):
                    panic_lines.append(line.strip())

            return panic_lines
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            return []
