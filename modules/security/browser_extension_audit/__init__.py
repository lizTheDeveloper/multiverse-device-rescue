import json
import subprocess
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
    name = "browser_extension_audit"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    # Known malicious extensions (flag as CRITICAL)
    MALICIOUS_EXTENSIONS = {
        "superfish",
        "babylon",
        "conduit",
    }

    # Known adware extensions (flag as WARNING)
    ADWARE_EXTENSIONS = {
        "hola vpn",
        "hola",
        "web of trust",
        "wot",
        "stylish",
        "ask toolbar",
        "ask.com",
        "coupon",
        "deal",
        "price",
        "shop assistant",
    }

    # Dangerous permissions that should trigger WARNING
    DANGEROUS_PERMISSIONS = {
        "all_urls",
        "<all_urls>",
        "webRequest",
        "webRequestBlocking",
        "cookies",
        "tabs",
    }

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Scan all browsers
        chrome_exts = self._scan_chrome_extensions()
        firefox_exts = self._scan_firefox_extensions()
        safari_exts = self._scan_safari_extensions()

        all_extensions = {
            "Chrome": chrome_exts,
            "Firefox": firefox_exts,
            "Safari": safari_exts,
        }

        total_count = sum(len(exts) for exts in all_extensions.values())

        # Check for malicious extensions (CRITICAL)
        for browser, exts in all_extensions.items():
            for ext_id, ext_data in exts.items():
                name = ext_data.get("name", ext_id).lower()
                if name in self.MALICIOUS_EXTENSIONS or ext_id.lower() in self.MALICIOUS_EXTENSIONS:
                    findings.append(
                        Finding(
                            title=f"MALICIOUS extension detected: {ext_data.get('name', ext_id)}",
                            description=(
                                f"Detected known malicious extension '{ext_data.get('name', ext_id)}' "
                                f"in {browser}. This extension is known to be malware. "
                                "Remove it immediately from your browser settings."
                            ),
                            severity=Severity.CRITICAL,
                            category=self.category,
                            data={
                                "check": "malicious_extension",
                                "browser": browser,
                                "extension": ext_data.get("name", ext_id),
                                "extension_id": ext_id,
                            },
                        )
                    )

        # Check for adware extensions (WARNING)
        for browser, exts in all_extensions.items():
            for ext_id, ext_data in exts.items():
                name = ext_data.get("name", ext_id).lower()
                if name in self.ADWARE_EXTENSIONS or ext_id.lower() in self.ADWARE_EXTENSIONS:
                    findings.append(
                        Finding(
                            title=f"Known adware extension: {ext_data.get('name', ext_id)}",
                            description=(
                                f"Extension '{ext_data.get('name', ext_id)}' in {browser} is known adware/PUP. "
                                "This extension may display unwanted ads, inject content, or track your browsing. "
                                "Remove it via your browser settings."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            data={
                                "check": "adware_extension",
                                "browser": browser,
                                "extension": ext_data.get("name", ext_id),
                                "extension_id": ext_id,
                            },
                        )
                    )

        # Check for extensions with dangerous permissions (WARNING)
        for browser, exts in all_extensions.items():
            for ext_id, ext_data in exts.items():
                permissions = ext_data.get("permissions", [])
                dangerous_perms = [p for p in permissions if p in self.DANGEROUS_PERMISSIONS]

                # Flag if has 3+ dangerous permissions
                if len(dangerous_perms) >= 3:
                    findings.append(
                        Finding(
                            title=f"Extension with excessive permissions: {ext_data.get('name', ext_id)}",
                            description=(
                                f"'{ext_data.get('name', ext_id)}' in {browser} requests excessive permissions: "
                                f"{', '.join(sorted(dangerous_perms))}. "
                                "This extension can access all websites, monitor tabs, and intercept requests. "
                                "Review whether you trust this extension with such broad access."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            data={
                                "check": "excessive_permissions",
                                "browser": browser,
                                "extension": ext_data.get("name", ext_id),
                                "permissions": dangerous_perms,
                            },
                        )
                    )

        # Check for too many extensions (WARNING)
        if total_count > 15:
            findings.append(
                Finding(
                    title=f"High number of browser extensions: {total_count}",
                    description=(
                        f"You have {total_count} browser extension(s) installed across all browsers, "
                        "which exceeds the recommended limit of 15. Too many extensions can degrade "
                        "performance, increase memory usage, and expand the attack surface. "
                        "Review and uninstall any unused or untrusted extensions."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "extension_bloat", "count": total_count},
                )
            )

        # Build comprehensive extension list for INFO finding
        extension_info = {}
        for browser, exts in all_extensions.items():
            for ext_id, ext_data in exts.items():
                name = ext_data.get("name", ext_id)
                extension_info[f"{browser}: {name}"] = {
                    "browser": browser,
                    "permissions": ext_data.get("permissions", []),
                }

        # List all extensions with permissions (INFO)
        if extension_info:
            ext_list_str = self._format_extensions_list(extension_info)
            findings.append(
                Finding(
                    title=f"Browser extensions installed: {total_count}",
                    description=(
                        f"Found {total_count} extension(s) across all browsers:\n"
                        f"{ext_list_str}\n"
                        "Review these extensions regularly to ensure they are trusted and necessary. "
                        "Malicious extensions can steal data, track browsing, and inject unwanted content."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
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

            if check == "malicious_extension":
                browser = finding.data.get("browser", "unknown")
                ext_name = finding.data.get("extension", "unknown")
                actions.append(
                    Action(
                        title=f"Remove malicious extension: {ext_name} from {browser}",
                        description=(
                            f"Extension '{ext_name}' in {browser} is a known malware threat.\n"
                            f"Remove it immediately:\n\n"
                            f"{self._get_removal_instructions(browser)}"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )

            elif check == "adware_extension":
                browser = finding.data.get("browser", "unknown")
                ext_name = finding.data.get("extension", "unknown")
                actions.append(
                    Action(
                        title=f"Remove adware extension: {ext_name} from {browser}",
                        description=(
                            f"Extension '{ext_name}' in {browser} is known adware/PUP.\n"
                            f"Remove it:\n\n"
                            f"{self._get_removal_instructions(browser)}"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )

            elif check == "excessive_permissions":
                browser = finding.data.get("browser", "unknown")
                ext_name = finding.data.get("extension", "unknown")
                perms = finding.data.get("permissions", [])
                perm_list = ", ".join(sorted(perms))
                actions.append(
                    Action(
                        title=f"Review extension with excessive permissions: {ext_name}",
                        description=(
                            f"Extension '{ext_name}' in {browser} requests dangerous permissions: {perm_list}.\n"
                            f"Review whether you trust this extension:\n\n"
                            f"{self._get_removal_instructions(browser)}"
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
                        title="Reduce number of browser extensions",
                        description=(
                            f"You have {count} extensions installed across browsers. "
                            "Each extension impacts performance and security. "
                            "Review your extensions and uninstall any that you don't actively use.\n\n"
                            "For Chrome: chrome://extensions/\n"
                            "For Firefox: about:addons\n"
                            "For Safari: Safari > Settings > Extensions"
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
                        title="Review installed browser extensions",
                        description=(
                            f"You have {count} extension(s) installed. "
                            "Review each one regularly:\n\n"
                            "Best practices:\n"
                            "- Only install extensions from trusted publishers\n"
                            "- Check extension ratings and reviews\n"
                            "- Review what permissions each extension requests\n"
                            "- Remove extensions you no longer use\n"
                            "- Check for regular updates and active support\n\n"
                            "Management:\n"
                            "Chrome: chrome://extensions/\n"
                            "Firefox: about:addons\n"
                            "Safari: Safari > Settings > Extensions"
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
                # Chrome extension directories have version subdirectories
                version_dirs = [d for d in ext_dir.iterdir() if d.is_dir()]
                if not version_dirs:
                    continue

                # Use the first version directory
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
                        extensions[ext_id] = {
                            "name": ext_id,
                            "permissions": [],
                        }

            return extensions
        except OSError:
            return {}
        except Exception:
            return {}

    def _scan_firefox_extensions(self) -> dict:
        """Scan Firefox extensions directory and return extension data.

        Returns dict mapping extension_id -> {name, permissions}.
        Returns {} if directory doesn't exist or on any error.
        """
        try:
            profiles_dir = (
                Path.home()
                / "Library"
                / "Application Support"
                / "Firefox"
                / "Profiles"
            )
            if not profiles_dir.exists():
                return {}

            extensions = {}
            # Scan all profiles
            for profile_dir in profiles_dir.iterdir():
                if not profile_dir.is_dir():
                    continue

                extensions_dir = profile_dir / "extensions"
                if not extensions_dir.exists():
                    continue

                # Firefox extensions can be .xpi files or folders
                for ext_path in extensions_dir.iterdir():
                    # Skip if already processed with different profile
                    if ext_path.name in extensions:
                        continue

                    ext_id = ext_path.stem if ext_path.is_file() else ext_path.name

                    # Try to read manifest from .xpi or folder
                    manifest_path = None
                    if ext_path.is_file():
                        # .xpi files are zip archives, we'd need to extract
                        # For simplicity, use the filename as extension name
                        extensions[ext_id] = {
                            "name": ext_id,
                            "permissions": [],
                        }
                    else:
                        # Check for manifest.json in folder
                        manifest_path = ext_path / "manifest.json"
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
                                extensions[ext_id] = {
                                    "name": ext_id,
                                    "permissions": [],
                                }
                        else:
                            # No manifest found
                            extensions[ext_id] = {
                                "name": ext_id,
                                "permissions": [],
                            }

            return extensions
        except OSError:
            return {}
        except Exception:
            return {}

    def _scan_safari_extensions(self) -> dict:
        """Scan Safari extensions via pluginkit.

        Returns dict mapping bundle_id -> {name, permissions}.
        Returns {} on any error.
        """
        try:
            result = subprocess.run(
                ["pluginkit", "-mAD", "-p", "com.apple.Safari.extension"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return {}

            extensions = {}
            for line in result.stdout.strip().split("\n"):
                if not line:
                    continue
                # pluginkit output: "/path/to/bundle - description"
                if line.startswith("/"):
                    parts = line.split()
                    if parts:
                        path_part = parts[0]
                        bundle_name = path_part.split("/")[-1]
                        if bundle_name:
                            extensions[bundle_name] = {
                                "name": bundle_name,
                                "permissions": [],  # Safari extensions don't expose permissions easily
                            }

            return extensions
        except OSError:
            return {}
        except Exception:
            return {}

    def _format_extensions_list(self, extension_info: dict) -> str:
        """Format extension info for display.

        Args:
            extension_info: dict mapping "Browser: extension_name" -> {browser, permissions}

        Returns:
            Formatted string with extension names and permissions.
        """
        lines = []
        for display_name in sorted(extension_info.keys()):
            data = extension_info[display_name]
            perms = data.get("permissions", [])
            if perms:
                perm_str = ", ".join(perms[:3])
                if len(perms) > 3:
                    perm_str += f", +{len(perms) - 3} more"
                lines.append(f"  • {display_name} [{perm_str}]")
            else:
                lines.append(f"  • {display_name}")
        return "\n".join(lines)

    def _get_removal_instructions(self, browser: str) -> str:
        """Get browser-specific removal instructions."""
        instructions = {
            "Chrome": (
                "1. Click the Extensions icon in Chrome toolbar\n"
                "2. Find the extension in the list\n"
                "3. Click the menu icon (...) and select 'Remove'\n"
                "Alternatively: chrome://extensions/"
            ),
            "Firefox": (
                "1. Open Firefox and go to about:addons\n"
                "2. Click 'Extensions' in the left sidebar\n"
                "3. Find the extension and click 'Remove'\n"
                "Or use Firefox menu > Add-ons > Extensions"
            ),
            "Safari": (
                "1. Open Safari and go to Settings\n"
                "2. Click the 'Extensions' tab\n"
                "3. Find the extension and click 'Uninstall'"
            ),
        }
        return instructions.get(browser, "Go to your browser's extension/add-ons settings and remove the extension.")
