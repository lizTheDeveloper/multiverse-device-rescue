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
    name = "location_services"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "3s"

    def check(self, profile: SystemProfile) -> CheckResult:
        """Audit Location Services on macOS.

        Checks:
        - Whether Location Services is enabled system-wide
        - Which system services have location access enabled
        - Flags warnings if Location Services is enabled but only for Find My Mac
          on non-laptop desktops
        """
        findings = []

        # Check if Location Services is enabled
        location_enabled = self._is_location_services_enabled()

        if location_enabled is True:
            findings.append(
                Finding(
                    title="Location Services is enabled",
                    description=(
                        "Location Services is enabled system-wide. Your device's location "
                        "data is available to applications and system services that request it. "
                        "Consider disabling if you don't need location-based features."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "location_services_enabled"},
                )
            )

            # Check which system services use location
            system_services = self._get_location_enabled_services()
            if system_services:
                findings.append(
                    Finding(
                        title="System services using Location Services",
                        description=(
                            f"The following system services have location access enabled: "
                            f"{', '.join(system_services)}. These services may use your location "
                            f"for features like Find My Mac, Maps suggestions, or weather updates."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={
                            "check": "location_system_services",
                            "services": system_services,
                        },
                    )
                )

                # Flag warning if only Find My Mac is enabled on non-laptop
                if (
                    self._is_non_laptop_desktop()
                    and len(system_services) == 1
                    and "Find My Mac" in system_services[0]
                ):
                    findings.append(
                        Finding(
                            title="Location Services enabled only for Find My Mac on desktop",
                            description=(
                                "Location Services is enabled on this desktop computer only for "
                                "Find My Mac. If you don't use Find My Mac or rarely move this "
                                "desktop, consider disabling Location Services to improve privacy."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            data={"check": "location_desktop_find_my_only"},
                        )
                    )
        elif location_enabled is False:
            # Location Services is disabled - this is good for privacy
            pass

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        """Provide informational guidance on Location Services.

        This module is informational only - it does not modify Location Services settings,
        as location access preferences are user-specific and should be configured
        according to individual needs.
        """
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")

            guidance_map = {
                "location_services_enabled": (
                    "Disable Location Services",
                    (
                        "To disable Location Services:\n"
                        "1. Open System Settings\n"
                        "2. Go to Privacy & Security > Location Services\n"
                        "3. Toggle the switch to OFF\n\n"
                        "Note: Disabling Location Services will prevent all apps and system "
                        "services from accessing your device's location, including Find My Mac, "
                        "Maps suggestions, and weather features that use your location."
                    ),
                ),
                "location_system_services": (
                    "Review system services using Location",
                    (
                        "To review which services can access location:\n"
                        "1. Open System Settings\n"
                        "2. Go to Privacy & Security > Location Services\n"
                        "3. Scroll to the bottom to see 'System Services'\n"
                        "4. Review and toggle off services you don't need\n\n"
                        "Common system services: Find My (for Find My Mac), Maps, weather, "
                        "and time zone settings."
                    ),
                ),
                "location_desktop_find_my_only": (
                    "Consider disabling Location Services if not needed",
                    (
                        "Location Services is only being used for Find My Mac on this desktop. "
                        "If you don't frequently use Find My Mac or rarely move this computer, "
                        "you can disable Location Services:\n"
                        "1. Open System Settings\n"
                        "2. Go to Privacy & Security > Location Services\n"
                        "3. Toggle the switch to OFF\n\n"
                        "This will improve your privacy while still allowing you to manually "
                        "locate your Mac through iCloud.com if needed."
                    ),
                ),
            }

            if check in guidance_map:
                title, description = guidance_map[check]
                actions.append(
                    Action(
                        title=title,
                        description=description,
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _is_location_services_enabled(self) -> bool | None:
        """Check if Location Services is enabled system-wide.

        Returns:
            True if enabled, False if disabled, None if unable to determine
        """
        # Try reading from locationd defaults (requires sudo in some cases)
        try:
            result = subprocess.run(
                ["defaults", "read", "com.apple.locationd", "LocationServicesEnabled"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                return result.stdout.strip() == "1"
        except OSError:
            pass

        # Try alternative location
        try:
            result = subprocess.run(
                ["defaults", "read", "/Library/Preferences/com.apple.locationmenu.plist"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0 and "ShowSystemServices" in result.stdout:
                # If this returns successfully, Location Services is likely enabled
                return True
        except OSError:
            pass

        return None

    def _get_location_enabled_services(self) -> list[str]:
        """Get list of system services that have location access enabled.

        Returns:
            List of service names with location access
        """
        services = []

        # Try to read system services from defaults
        try:
            result = subprocess.run(
                ["defaults", "read", "com.apple.locationd", "SystemServices"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                # Parse the defaults output for enabled services
                for line in result.stdout.split("\n"):
                    line = line.strip()
                    # Look for lines that indicate a service is enabled
                    if "=" in line and ("1" in line or "true" in line.lower()):
                        # Extract service name (usually before the = sign)
                        service_name = line.split("=")[0].strip()
                        if service_name and service_name not in ["{", "}"]:
                            # Map internal names to user-friendly names
                            if service_name == "FindMyMac":
                                services.append("Find My Mac")
                            elif service_name == "TimeZone":
                                services.append("Setting Time Zone")
                            elif service_name == "Emergency":
                                services.append("Emergency Services")
                            else:
                                services.append(service_name)
        except OSError:
            pass

        # Try reading from the locationd plist directly
        if not services:
            try:
                result = subprocess.run(
                    ["defaults", "read", "com.apple.locationmenu"],
                    capture_output=True,
                    text=True,
                )
                if result.returncode == 0:
                    # Look for common services
                    if "FindMyMac" in result.stdout or "Find My" in result.stdout:
                        services.append("Find My Mac")
                    if "TimeZone" in result.stdout:
                        services.append("Setting Time Zone")
                    if "Emergency" in result.stdout:
                        services.append("Emergency Services")
            except OSError:
                pass

        return services

    def _is_non_laptop_desktop(self) -> bool:
        """Determine if this is a non-laptop desktop computer.

        Returns:
            True if this is a desktop (Mac mini, iMac, Mac Studio, etc.)
            False if this appears to be a laptop (MacBook)
        """
        try:
            # Use system_profiler to get the model identifier
            result = subprocess.run(
                ["system_profiler", "SPHardwareDataType"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                output = result.stdout.lower()
                # MacBook models are laptops
                if "macbook" in output:
                    return False
                # Desktop models (check for model identifier names)
                if any(
                    model in output
                    for model in ["macmini", "imac", "mac studio", "mac pro"]
                ):
                    return True
        except OSError:
            pass

        # Fallback: check model identifier another way
        try:
            result = subprocess.run(
                ["sysctl", "hw.model"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                model = result.stdout.lower()
                # MacBook models: MacBook*, MacBookPro*, MacBookAir*
                if any(
                    mb in model for mb in ["macbook", "machinemodel=macbook"]
                ):
                    return False
                # Desktop models
                if any(
                    desktop in model
                    for desktop in [
                        "macmini",
                        "imac",
                        "mac_studio",
                        "macpro",
                        "machinemodel=mac",
                    ]
                ):
                    return True
        except OSError:
            pass

        # Default to assuming it's not a laptop if we can't determine
        return False
