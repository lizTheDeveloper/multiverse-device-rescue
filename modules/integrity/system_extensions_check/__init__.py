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
    name = "system_extensions_check"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get system extensions list
        output = self._run_systemextensionsctl()
        if not output:
            findings.append(
                Finding(
                    title="Unable to retrieve system extensions",
                    description=(
                        "Could not run systemextensionsctl list. "
                        "This command requires macOS 10.15+."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "unable_to_list"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # Parse extensions
        extensions = _parse_systemextensionsctl(output)

        if not extensions:
            findings.append(
                Finding(
                    title="No system extensions found",
                    description=(
                        "No system extensions are installed on this device. "
                        "If you use third-party endpoint security, networking, or driver software, "
                        "check that their extensions are properly installed."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "no_extensions"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # Count extension types and states
        total_count = len(extensions)
        active_count = sum(1 for e in extensions if e["state"] == "activated_enabled")
        waiting_count = sum(
            1 for e in extensions if e["state"] == "activated_waiting_for_user"
        )
        terminated_count = sum(1 for e in extensions if e["state"] == "terminated")

        # Identify extension types
        endpoint_security_exts = [
            e
            for e in extensions
            if e.get("category")
            == "com.apple.system-extension.endpoint-security"
        ]
        network_exts = [
            e
            for e in extensions
            if e.get("category") == "com.apple.system-extension.network-extension"
        ]
        driver_exts = [
            e
            for e in extensions
            if e.get("category") == "com.apple.system-extension.driver"
        ]

        # Identify known security products
        known_security_products = _identify_known_security_products(extensions)

        # List all extensions as INFO
        all_extensions_text = "\n".join(
            [
                f"  - {e['name']} ({e['state']}, {e.get('category', 'unknown')})"
                for e in extensions
            ]
        )
        findings.append(
            Finding(
                title=f"System extensions installed ({total_count} total, {active_count} active)",
                description=(
                    f"Found {total_count} system extension(s):\n"
                    f"  Active (activated_enabled): {active_count}\n"
                    f"  Waiting for user: {waiting_count}\n"
                    f"  Terminated: {terminated_count}\n"
                    f"  Endpoint Security: {len(endpoint_security_exts)}\n"
                    f"  Network: {len(network_exts)}\n"
                    f"  Driver: {len(driver_exts)}\n\n"
                    f"Extensions:\n{all_extensions_text}"
                ),
                severity=Severity.INFO,
                category=self.category,
                data={
                    "check": "extensions_list",
                    "total_count": total_count,
                    "active_count": active_count,
                    "waiting_count": waiting_count,
                    "terminated_count": terminated_count,
                    "endpoint_security_count": len(endpoint_security_exts),
                    "network_count": len(network_exts),
                    "driver_count": len(driver_exts),
                    "known_security_products": known_security_products,
                },
            )
        )

        # Warning: endpoint security extensions in waiting state
        waiting_endpoint_security = [
            e
            for e in endpoint_security_exts
            if e["state"] == "activated_waiting_for_user"
        ]
        if waiting_endpoint_security:
            ext_names = ", ".join([e["name"] for e in waiting_endpoint_security])
            findings.append(
                Finding(
                    title="Endpoint security extensions awaiting user approval",
                    description=(
                        f"The following endpoint security extension(s) are waiting for user approval:\n"
                        f"  {ext_names}\n\n"
                        "These extensions provide security protection but are not yet active. "
                        "To activate them, open System Settings > Privacy & Security > Extensions and "
                        "approve the pending extension(s)."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "waiting_endpoint_security",
                        "waiting_extensions": [e["name"] for e in waiting_endpoint_security],
                    },
                )
            )

        # Warning: terminated extensions
        if terminated_count > 0:
            terminated_exts = [e for e in extensions if e["state"] == "terminated"]
            ext_names = ", ".join([e["name"] for e in terminated_exts])
            findings.append(
                Finding(
                    title=f"Terminated system extensions ({terminated_count})",
                    description=(
                        f"Found {terminated_count} terminated extension(s):\n"
                        f"  {ext_names}\n\n"
                        "Terminated extensions may indicate failed installation, incompatibility, or "
                        "crashes. If these extensions are from security software, reinstall the software "
                        "or contact the vendor. You can remove them from System Settings > Privacy & Security > Extensions."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "terminated_extensions",
                        "terminated_extensions": [e["name"] for e in terminated_exts],
                    },
                )
            )

        # Warning: no endpoint security extensions
        if not endpoint_security_exts:
            findings.append(
                Finding(
                    title="No endpoint security extensions installed",
                    description=(
                        "No third-party endpoint security extensions are installed. "
                        "macOS includes built-in XProtect and Malware Removal Tool (MRT), but "
                        "many organizations use third-party endpoint security products for enhanced protection. "
                        "If you expect an endpoint security tool to be installed, check that it is properly installed "
                        "and its extension is approved in System Settings > Privacy & Security > Extensions."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "no_endpoint_security"},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "unable_to_list":
                actions.append(
                    Action(
                        title="Unable to retrieve system extensions",
                        description=(
                            "The systemextensionsctl tool is not available on this system. "
                            "System extensions require macOS 10.15 (Catalina) or later. "
                            "If you are running an older version of macOS, please upgrade to check system extensions."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "no_extensions":
                actions.append(
                    Action(
                        title="No system extensions found",
                        description=(
                            "No system extensions are currently installed. "
                            "If you use third-party endpoint security or driver software, "
                            "verify it is installed and check the vendor's documentation for any required approval steps."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "extensions_list":
                known_products = finding.data.get("known_security_products", [])
                if known_products:
                    products_text = "\n  ".join(known_products)
                    actions.append(
                        Action(
                            title="System extensions overview",
                            description=(
                                f"System extensions detected from known security products:\n"
                                f"  {products_text}\n\n"
                                f"Total extensions: {finding.data.get('total_count')}\n"
                                f"Active: {finding.data.get('active_count')}\n"
                                f"Awaiting approval: {finding.data.get('waiting_count')}\n"
                                f"Terminated: {finding.data.get('terminated_count')}\n\n"
                                "To manage system extensions, open System Settings > Privacy & Security > Extensions "
                                "and review the status of installed extensions."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )
                else:
                    actions.append(
                        Action(
                            title="System extensions overview",
                            description=(
                                f"System extensions installed:\n"
                                f"Total: {finding.data.get('total_count')}\n"
                                f"Active: {finding.data.get('active_count')}\n"
                                f"Awaiting approval: {finding.data.get('waiting_count')}\n"
                                f"Terminated: {finding.data.get('terminated_count')}\n\n"
                                "To manage system extensions, open System Settings > Privacy & Security > Extensions "
                                "and review the status of installed extensions."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )

            elif check == "waiting_endpoint_security":
                waiting = finding.data.get("waiting_extensions", [])
                ext_text = "\n  ".join(waiting)
                actions.append(
                    Action(
                        title="Approve pending endpoint security extensions",
                        description=(
                            f"The following endpoint security extension(s) require approval:\n"
                            f"  {ext_text}\n\n"
                            "To activate them:\n"
                            "1. Open System Settings\n"
                            "2. Navigate to Privacy & Security > Extensions\n"
                            "3. Find the pending extension(s)\n"
                            "4. Click the 'Allow' or 'Approve' button if available\n"
                            "5. You may be prompted to restart or re-authenticate\n\n"
                            "If you don't see the extension listed, it may be under a specific category like "
                            "'Endpoint Security' or 'System Extensions'."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "terminated_extensions":
                terminated = finding.data.get("terminated_extensions", [])
                ext_text = "\n  ".join(terminated)
                actions.append(
                    Action(
                        title="Remove or reinstall terminated extensions",
                        description=(
                            f"The following extension(s) are in a terminated state:\n"
                            f"  {ext_text}\n\n"
                            "To resolve this:\n"
                            "1. Open System Settings > Privacy & Security > Extensions\n"
                            "2. Find the terminated extension(s)\n"
                            "3. Click the remove button (usually an 'X' or '-')\n"
                            "4. If the extension is from a security product, reinstall that product\n"
                            "5. If available, update the product to the latest version\n\n"
                            "If you need help, contact the software vendor's support."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "no_endpoint_security":
                actions.append(
                    Action(
                        title="Consider installing endpoint security extension",
                        description=(
                            "No third-party endpoint security extensions are currently installed. "
                            "While macOS provides built-in protection via XProtect and Malware Removal Tool, "
                            "many organizations deploy third-party endpoint detection and response (EDR) solutions. "
                            "\n\n"
                            "Common options include:\n"
                            "  - CrowdStrike Falcon\n"
                            "  - Microsoft Defender for macOS\n"
                            "  - SentinelOne Singularity\n"
                            "  - Carbon Black Cloud (VMware)\n"
                            "  - Sophos Endpoint Protection\n"
                            "  - Jamf Protect\n\n"
                            "If your organization requires endpoint security, contact your IT department "
                            "or security team for deployment instructions."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _run_systemextensionsctl(self) -> str:
        """Run systemextensionsctl list and return output."""
        try:
            result = subprocess.run(
                ["systemextensionsctl", "list"],
                capture_output=True,
                text=True,
                errors="replace",
            )
            return result.stdout
        except (OSError, subprocess.SubprocessError):
            return ""


def _parse_systemextensionsctl(output: str) -> list[dict]:
    """Parse systemextensionsctl list output into extension dictionaries.

    Expected format:
    UUID  BUNDLE_ID  STATE  CATEGORY
    e.g.:
    5A3F1C2D-4E8B-4F2C-A1B3-C4D5E6F7A8B9  com.crowdstrike.falconxf            enabled              com.apple.system-extension.endpoint-security
    """
    extensions = []

    for line in output.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("UUID"):
            continue

        # Parse the line: UUID, bundle_id, state, category
        # Format has multiple spaces between columns
        parts = line.split()
        if len(parts) < 4:
            continue

        uuid = parts[0]
        bundle_id = parts[1]
        state = parts[2]
        category = parts[3]

        # Extract extension name from bundle_id (last component)
        name = bundle_id.split(".")[-1]

        # Normalize state names
        if state == "enabled" or state == "activated_enabled":
            state = "activated_enabled"
        elif state == "waiting" or state == "user" or state == "activated_waiting_for_user":
            state = "activated_waiting_for_user"
        elif state == "terminated":
            state = "terminated"

        extensions.append(
            {
                "name": name,
                "state": state,
                "category": category,
                "bundle_id": bundle_id,
            }
        )

    return extensions


def _identify_known_security_products(extensions: list[dict]) -> list[str]:
    """Identify known security product extensions from the list."""
    known_products = {
        "com.crowdstrike": "CrowdStrike Falcon",
        "com.crowdstrike.falconxf": "CrowdStrike Falcon",
        "com.sentinelone": "SentinelOne Singularity",
        "com.sentinelone.sentinel": "SentinelOne Singularity",
        "com.vmware.carbonblack": "Carbon Black Cloud",
        "com.sophos": "Sophos Endpoint Protection",
        "com.jamf": "Jamf Protect",
        "com.jamf.protect": "Jamf Protect",
        "com.microsoft.wdav": "Microsoft Defender",
        "com.microsoft.wdav.qs": "Microsoft Defender",
        "com.apple.security": "Apple Security Extension",
    }

    detected = []
    for ext in extensions:
        bundle_id = ext.get("bundle_id", "").lower()
        name = ext.get("name", "").lower()

        for key, product in known_products.items():
            if key in bundle_id or key in name:
                if product not in detected:
                    detected.append(product)
                break

    return detected
