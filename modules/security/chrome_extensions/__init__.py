import json
from pathlib import Path

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
    name = "chrome_extensions"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "3s"

    emits_codes = [
        "security.chrome_extensions.broad_permissions",
        "security.chrome_extensions.extension_bloat",
        "security.chrome_extensions.installed_extensions",
    ]

    # Permissions that are considered broad/dangerous
    BROAD_PERMISSIONS = {
        "all_urls",
        "<all_urls>",
        "tabs",
        "webRequest",
        "webRequestBlocking",
        "activeTab",
        "scripting",
    }

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Scan Chrome extensions directory
        extensions = self._scan_chrome_extensions()
        total_count = len(extensions)

        # Build extension info with permissions
        extension_info = {}
        extensions_with_broad_perms = []

        for ext_id, ext_data in extensions.items():
            name = ext_data.get("name", ext_id)
            permissions = ext_data.get("permissions", [])
            extension_info[name] = permissions

            # Check for broad permissions
            broad_perms = [p for p in permissions if p in self.BROAD_PERMISSIONS]
            if broad_perms:
                extensions_with_broad_perms.append((ext_id, name, broad_perms))

        # Flag WARNING for extensions with broad permissions
        for ext_id, ext_name, broad_perms in extensions_with_broad_perms:
            findings.append(
                Finding(
                    title=f"Extension with broad permissions: {ext_name}",
                    description=(
                        f"The extension '{ext_name}' asks for wide access to your browsing "
                        f"data. Specifically, it requests: {', '.join(sorted(broad_perms))}. "
                        "In plain terms, this allows the extension to see what you do "
                        "on almost any website, not just the one it was designed for. "
                        "This is a common feature for useful tools, but it also means "
                        "a compromised or malicious extension could track your activity. "
                        "If you do not recognize this extension or no longer use it, "
                        "it is a good idea to remove it.\n\n"
                        "What to do: Go to chrome://extensions in your browser, find "
                        "the extension, and turn it off or remove it if you don't trust "
                        "it."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.chrome_extensions.broad_permissions",
                    data={
                        "check": "broad_permissions",
                        "extension": ext_name,
                        # The extension's own id: two extensions can share a name.
                        "extension_id": ext_id,
                        "permissions": broad_perms,
                    },
                )
            )

        # Flag WARNING if too many extensions (>10)
        if total_count > 10:
            findings.append(
                Finding(
                    title=f"High number of Chrome extensions: {total_count}",
                    description=(
                        f"You have {total_count} extensions installed in Chrome. Having "
                        "many extensions can slow down your browser and use more memory. "
                        "It also increases the chance that one of them is outdated or "
                        "unsafe. Keeping only the extensions you actually use helps your "
                        "browser run smoothly and securely.\n\n"
                        "What to do: Go to chrome://extensions and remove any you don't "
                        "use or don't recognize."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.chrome_extensions.extension_bloat",
                    data={"check": "extension_bloat", "count": total_count},
                )
            )

        # Flag INFO listing all installed extensions with their permissions
        if extensions:
            ext_list_str = self._format_extensions_list(extension_info)
            findings.append(
                Finding(
                    title=f"Chrome extensions installed: {total_count}",
                    description=(
                        f"Found {total_count} Chrome extension(s) installed:\n"
                        f"{ext_list_str}\n"
                        "Review these extensions regularly to ensure they are trusted and necessary. "
                        "Malicious extensions can steal data, track browsing, and inject unwanted content."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.chrome_extensions.installed_extensions",
                    data={
                        "check": "installed_extensions",
                        "extensions": extension_info,
                        "count": total_count,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "broad_permissions":
                ext_name = finding.data.get("extension", "unknown")
                perms = finding.data.get("permissions", [])
                perm_list = ", ".join(sorted(perms))
                actions.append(
                    Action(
                        title=f"Review or remove extension: {ext_name}",
                        description=(
                            f"Extension '{ext_name}' requests broad permissions: {perm_list}.\n"
                            "To manage Chrome extensions:\n"
                            "1. Click the Extensions icon in Chrome toolbar\n"
                            "2. Find the extension in the list\n"
                            "3. Click the menu icon (...) and select 'Manage extension'\n"
                            "4. Review the permissions it requests\n"
                            "5. If you don't trust it or don't use it, click 'Remove'\n\n"
                            "To view all extensions: chrome://extensions/"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )

            elif check == "extension_bloat":
                count = finding.data.get("count", 0)
                actions.append(
                    Action(
                        title="Reduce number of Chrome extensions",
                        description=(
                            f"You have {count} extensions installed. "
                            "Each extension impacts performance and security. "
                            "Review your extensions and uninstall any that you don't actively use.\n\n"
                            "To manage Chrome extensions:\n"
                            "1. Go to chrome://extensions/\n"
                            "2. For each extension you don't need, click 'Remove'\n"
                            "3. Consider using built-in Chrome features instead of extensions when possible"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )

            elif check == "installed_extensions":
                count = finding.data.get("count", 0)
                actions.append(
                    Action(
                        title="Review installed Chrome extensions",
                        description=(
                            f"You have {count} Chrome extension(s) installed. "
                            "Review each one regularly:\n\n"
                            "Best practices:\n"
                            "- Only install extensions from trusted publishers\n"
                            "- Check extension ratings and reviews in the Chrome Web Store\n"
                            "- Review what permissions each extension requests\n"
                            "- Remove extensions you no longer use\n"
                            "- Check extension update frequency and support\n\n"
                            "To manage: chrome://extensions/"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _scan_chrome_extensions(self) -> dict:
        """Scan Chrome extensions directory and return extension data.

        Returns dict mapping extension_id -> {name, permissions}.
        Returns {} if directory doesn't exist or on any error.
        """
        try:
            extensions_dir = (
                Path.home()
                / "Library"
                / "Application Support"
                / "Google"
                / "Chrome"
                / "Default"
                / "Extensions"
            )
            if not extensions_dir.exists():
                return {}

            extensions = {}
            for ext_dir in extensions_dir.iterdir():
                if not ext_dir.is_dir():
                    continue

                ext_id = ext_dir.name
                # Chrome extension directories can have version subdirectories
                # Find the highest version directory
                version_dirs = [d for d in ext_dir.iterdir() if d.is_dir()]
                if not version_dirs:
                    continue

                # Use the first (usually only) version directory
                version_dir = version_dirs[0]
                manifest_path = version_dir / "manifest.json"

                if manifest_path.exists():
                    try:
                        with open(manifest_path, "r") as f:
                            manifest = json.load(f)
                        name = manifest.get("name", ext_id)
                        permissions = manifest.get("permissions", [])
                        extensions[ext_id] = {
                            "name": name,
                            "permissions": permissions,
                        }
                    except (json.JSONDecodeError, IOError):
                        # If manifest parsing fails, still record the extension
                        extensions[ext_id] = {
                            "name": ext_id,
                            "permissions": [],
                        }

            return extensions
        except OSError:
            return {}
        except Exception:
            return {}

    def _format_extensions_list(self, extension_info: dict) -> str:
        """Format extension info for display.

        Args:
            extension_info: dict mapping extension name -> permissions list

        Returns:
            Formatted string with extension names and permissions.
        """
        lines = []
        for name in sorted(extension_info.keys()):
            perms = extension_info[name]
            if perms:
                perm_str = ", ".join(perms[:3])  # Show first 3 permissions
                if len(perms) > 3:
                    perm_str += f", +{len(perms) - 3} more"
                lines.append(f"  • {name} [{perm_str}]")
            else:
                lines.append(f"  • {name}")
        return "\n".join(lines)
