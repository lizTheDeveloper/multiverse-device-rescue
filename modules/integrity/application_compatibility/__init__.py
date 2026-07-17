import re
import subprocess
from datetime import datetime, timedelta

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
    name = "application_compatibility"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 40
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get system_profiler output
        system_profiler_output = self._run_system_profiler()
        apps_info = _parse_system_profiler(system_profiler_output)

        # Check if we got any app data
        if not apps_info.get("apps"):
            findings.append(
                Finding(
                    title="Unable to analyze applications",
                    description=(
                        "Could not retrieve application data from system_profiler. "
                        "Application compatibility checks were skipped."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "unable_to_retrieve"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        apps_list = apps_info.get("apps", [])

        # Categorize applications by architecture
        bit_32_apps = [app for app in apps_list if app.get("kind") == "Intel (32-bit)"]
        intel_apps = [app for app in apps_list if app.get("kind") == "Intel"]
        arm_apps = [app for app in apps_list if app.get("kind") == "Apple Silicon"]
        universal_apps = [app for app in apps_list if app.get("kind") == "Universal"]

        # Flag 32-bit apps (WARNING: won't run on Catalina+)
        if bit_32_apps:
            app_names = [app.get("name", "Unknown") for app in bit_32_apps]
            findings.append(
                Finding(
                    title=f"Found {len(bit_32_apps)} 32-bit application(s)",
                    description=(
                        f"32-bit applications are no longer supported on macOS Catalina and later. "
                        f"These {len(bit_32_apps)} app(s) will not run on modern macOS versions: "
                        f"{', '.join(app_names[:5])}{'...' if len(app_names) > 5 else ''}. "
                        f"Update or replace these applications with 64-bit versions."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "32bit_apps", "apps": app_names},
                )
            )

        # Check for Intel apps on Apple Silicon without Rosetta 2
        if profile.architecture == "arm64" and intel_apps:
            rosetta_installed = self._check_rosetta_installed()
            if not rosetta_installed:
                app_names = [app.get("name", "Unknown") for app in intel_apps]
                findings.append(
                    Finding(
                        title=f"Intel-only apps found without Rosetta 2",
                        description=(
                            f"This is an Apple Silicon Mac with {len(intel_apps)} Intel-only application(s) "
                            f"installed, but Rosetta 2 is not installed. These apps will not run. "
                            f"Install Rosetta 2 to enable compatibility: "
                            f"Run 'softwareupdate -i -a -R -k -x -b -g' in Terminal, or install via App Store."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check": "intel_without_rosetta", "apps": app_names[:10]},
                    )
                )
            elif intel_apps:
                # Just info: Intel apps present but Rosetta is available
                app_names = [app.get("name", "Unknown") for app in intel_apps]
                findings.append(
                    Finding(
                        title=f"Found {len(intel_apps)} Intel app(s) on Apple Silicon",
                        description=(
                            f"This Apple Silicon Mac has {len(intel_apps)} Intel-only application(s). "
                            f"These apps run via Rosetta 2 translation, which may impact performance. "
                            f"Consider upgrading to native Apple Silicon versions when available."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={"check": "intel_with_rosetta", "apps": app_names[:10]},
                    )
                )

        # Check for outdated applications (>2 years without update)
        outdated_apps = []
        cutoff_date = datetime.now() - timedelta(days=365*2)
        for app in apps_list:
            last_modified = app.get("last_modified")
            if last_modified and last_modified < cutoff_date:
                outdated_apps.append({
                    "name": app.get("name", "Unknown"),
                    "last_modified": last_modified
                })

        if outdated_apps and len(outdated_apps) > 0:
            # Only flag as INFO for now, as old doesn't always mean broken
            app_names = [app["name"] for app in outdated_apps[:5]]
            findings.append(
                Finding(
                    title=f"Found {len(outdated_apps)} application(s) not updated in >2 years",
                    description=(
                        f"These {len(outdated_apps)} application(s) haven't been updated in over 2 years: "
                        f"{', '.join(app_names)}{'...' if len(outdated_apps) > 5 else ''}. "
                        f"While they may still work, consider updating or replacing them for "
                        f"security and compatibility reasons."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "outdated_apps", "apps": app_names, "total_count": len(outdated_apps)},
                )
            )

        # Provide architecture breakdown as INFO
        findings.append(
            Finding(
                title="Application architecture breakdown",
                description=(
                    f"Installed applications: {len(apps_list)} total. "
                    f"Architecture breakdown: {len(universal_apps)} Universal, "
                    f"{len(arm_apps)} Apple Silicon native, "
                    f"{len(intel_apps)} Intel, "
                    f"{len(bit_32_apps)} 32-bit."
                ),
                severity=Severity.INFO,
                category=self.category,
                data={
                    "check": "architecture_breakdown",
                    "total": len(apps_list),
                    "universal": len(universal_apps),
                    "apple_silicon": len(arm_apps),
                    "intel": len(intel_apps),
                    "32bit": len(bit_32_apps),
                },
            )
        )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "unable_to_retrieve":
                actions.append(
                    Action(
                        title="Unable to retrieve application data",
                        description=(
                            "Application compatibility could not be assessed. "
                            "Ensure system_profiler is accessible and try again."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "32bit_apps":
                apps = finding.data.get("apps", [])
                actions.append(
                    Action(
                        title="Update or remove 32-bit applications",
                        description=(
                            f"The following 32-bit application(s) will not run on macOS Catalina or later: "
                            f"{', '.join(apps)}. "
                            f"Visit the developer's website or App Store to download 64-bit versions. "
                            f"If no 64-bit version is available, consider uninstalling the app or finding an alternative."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "intel_without_rosetta":
                apps = finding.data.get("apps", [])
                actions.append(
                    Action(
                        title="Install Rosetta 2 for Intel app compatibility",
                        description=(
                            f"This Apple Silicon Mac has Intel-only app(s) that require Rosetta 2: "
                            f"{', '.join(apps)}. "
                            f"Install Rosetta 2 by: (1) Opening Terminal, (2) Running: "
                            f"softwareupdate -i -a -R -k -x -b -g (3) Follow prompts to install. "
                            f"Or use: /usr/sbin/softwareupdate -i -a to install via System Preferences."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "intel_with_rosetta":
                apps = finding.data.get("apps", [])
                actions.append(
                    Action(
                        title="Consider upgrading Intel apps to Apple Silicon versions",
                        description=(
                            f"These Intel-only application(s) on Apple Silicon Mac run via Rosetta 2 emulation: "
                            f"{', '.join(apps)}. "
                            f"For best performance, check the developer's website for native Apple Silicon versions "
                            f"and upgrade when available. Native apps will run faster with better battery life."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "outdated_apps":
                apps = finding.data.get("apps", [])
                total = finding.data.get("total_count", len(apps))
                actions.append(
                    Action(
                        title="Update outdated applications",
                        description=(
                            f"Found {total} application(s) not updated in >2 years: {', '.join(apps)}. "
                            f"Visit the App Store or developer websites to check for updates. "
                            f"Outdated software may have security vulnerabilities or compatibility issues. "
                            f"To check app version: App > About [App Name]. To check for updates: App Store > Updates."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "architecture_breakdown":
                breakdown = finding.data
                actions.append(
                    Action(
                        title="Application architecture summary",
                        description=(
                            f"Total applications: {breakdown.get('total')}. "
                            f"Universal (native on both architectures): {breakdown.get('universal')}. "
                            f"Apple Silicon native: {breakdown.get('apple_silicon')}. "
                            f"Intel (requires Rosetta 2 on Apple Silicon): {breakdown.get('intel')}. "
                            f"32-bit (deprecated, will not run on Catalina+): {breakdown.get('32bit')}."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _run_system_profiler(self) -> str:
        """Run system_profiler SPApplicationsDataType and return output."""
        try:
            result = subprocess.run(
                ["system_profiler", "SPApplicationsDataType"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            return result.stdout
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            return ""

    def _check_rosetta_installed(self) -> bool:
        """Check if Rosetta 2 is installed on Apple Silicon via arch -x86_64 /usr/bin/true"""
        try:
            result = subprocess.run(
                ["arch", "-x86_64", "/usr/bin/true"],
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            return False


def _parse_system_profiler(output: str) -> dict:
    """Extract application info from system_profiler SPApplicationsDataType output."""
    info = {"apps": []}

    if not output:
        return info

    lines = output.split("\n")
    current_app = None

    for line in lines:
        # Skip empty lines
        if not line.strip():
            continue

        # Skip header
        if line.strip() == "Applications:":
            continue

        # Detect app entry: indented with 4 spaces, ends with colon
        # Example: "    Finder:"
        if line.startswith("    ") and not line.startswith("      ") and ":" in line:
            # Save previous app if we have one
            if current_app and "name" in current_app:
                info["apps"].append(current_app)
            # Start new app
            app_name = line.strip().rstrip(":")
            current_app = {"name": app_name}
        elif current_app is not None and line.startswith("      ") and ":" in line:
            # Parse properties (6 spaces indentation)
            key, value = line.split(":", 1)
            key = key.strip().lower()
            value = value.strip()

            if key == "kind":
                current_app["kind"] = value
            elif key == "version":
                current_app["version"] = value
            elif key == "last modified":
                # Try to parse the date
                try:
                    current_app["last_modified"] = datetime.strptime(value, "%m/%d/%Y, %I:%M:%S %p")
                except ValueError:
                    try:
                        current_app["last_modified"] = datetime.strptime(value, "%m/%d/%Y")
                    except ValueError:
                        current_app["last_modified"] = None
            elif key == "signed by":
                current_app["signed_by"] = value
            elif key == "obtained from":
                current_app["obtained_from"] = value

    # Don't forget the last app
    if current_app and "name" in current_app:
        info["apps"].append(current_app)

    return info
