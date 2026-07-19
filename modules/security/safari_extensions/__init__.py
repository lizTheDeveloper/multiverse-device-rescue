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
    name = "safari_extensions"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "3s"

    emits_codes = [
        "security.safari_extensions.legacy_extensions",
        "security.safari_extensions.app_extensions",
        "security.safari_extensions.extension_bloat",
        "security.safari_extensions.content_blockers_enabled",
        "security.safari_extensions.content_blockers_disabled",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check for legacy .safariextz extensions
        legacy_extensions = self._check_legacy_extensions()
        if legacy_extensions:
            findings.append(
                Finding(
                    title=f"Legacy Safari extensions found: {len(legacy_extensions)}",
                    description=(
                        f"Found {len(legacy_extensions)} legacy .safariextz extension(s): "
                        f"{', '.join(sorted(legacy_extensions))}. "
                        "Legacy .safariextz extensions are deprecated and pose a security risk. "
                        "Safari no longer supports them. Remove them and install modern Safari app extensions instead."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.safari_extensions.legacy_extensions",
                    data={"check": "legacy_extensions", "extensions": legacy_extensions},
                )
            )

        # Check for Safari app extensions via pluginkit
        app_extensions = self._check_safari_app_extensions()
        if app_extensions:
            findings.append(
                Finding(
                    title=f"Safari extensions installed: {len(app_extensions)}",
                    description=(
                        f"Found {len(app_extensions)} Safari extension(s): "
                        f"{', '.join(sorted(app_extensions))}. "
                        "Review these extensions regularly to ensure they are trusted "
                        "and necessary. Malicious extensions can cause popups, redirects, and slowness."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.safari_extensions.app_extensions",
                    data={"check": "app_extensions", "extensions": app_extensions},
                )
            )

            # Flag WARNING if too many extensions (>5)
            if len(app_extensions) > 5:
                findings.append(
                    Finding(
                        title=f"High number of Safari extensions: {len(app_extensions)}",
                        description=(
                            f"You have {len(app_extensions)} Safari extension(s) installed, which exceeds the "
                            "recommended limit of 5. Too many extensions can degrade browsing performance "
                            "and increase security risks. Review and uninstall any unused or untrusted extensions."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        code="security.safari_extensions.extension_bloat",
                        data={"check": "extension_bloat", "count": len(app_extensions)},
                    )
                )

        # Check if Safari content blockers are enabled
        content_blockers_enabled = self._check_content_blockers_enabled()
        if content_blockers_enabled:
            findings.append(
                Finding(
                    title="Safari content blockers are enabled",
                    description=(
                        "Safari content blockers are enabled and helping to improve privacy and performance "
                        "by blocking ads, tracking, and malicious content."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.safari_extensions.content_blockers_enabled",
                    data={"check": "content_blockers", "enabled": True},
                )
            )
        elif content_blockers_enabled is False:
            findings.append(
                Finding(
                    title="Safari content blockers are not enabled",
                    description=(
                        "Safari content blockers are not enabled. Content blockers help improve "
                        "privacy and performance by blocking ads, tracking, and malicious content. "
                        "Enable them in Safari Settings > Extensions > Content Blockers."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.safari_extensions.content_blockers_disabled",
                    data={"check": "content_blockers", "enabled": False},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "legacy_extensions":
                extensions = finding.data.get("extensions", [])
                ext_list = ", ".join(sorted(extensions))
                actions.append(
                    Action(
                        title="Remove legacy Safari extensions",
                        description=(
                            f"Legacy extensions found: {ext_list}\n"
                            "To remove: Open Safari > Settings > Extensions, find the legacy "
                            "extensions listed, and click the remove button (if available). "
                            "If not removable via GUI, manually delete .safariextz files from "
                            "~/Library/Safari/Extensions/"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )

            elif check == "app_extensions":
                extensions = finding.data.get("extensions", [])
                ext_list = ", ".join(sorted(extensions))
                actions.append(
                    Action(
                        title="Review Safari extensions",
                        description=(
                            f"Installed extensions: {ext_list}\n"
                            "Review each extension to ensure it is trusted and necessary. "
                            "Remove any suspicious, outdated, or unused extensions. "
                            "To manage: Safari > Settings > Extensions"
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
                        title="Reduce number of Safari extensions",
                        description=(
                            f"You have {count} extensions installed. "
                            "Each extension can impact browsing performance. "
                            "Review your extensions and uninstall any that you don't actively use. "
                            "To manage: Safari > Settings > Extensions"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )

            elif check == "content_blockers":
                enabled = finding.data.get("enabled", False)
                if not enabled:
                    actions.append(
                        Action(
                            title="Enable Safari content blockers",
                            description=(
                                "Content blockers improve privacy and performance. "
                                "To enable: Safari > Settings > Extensions > Content Blockers, "
                                "then toggle on the content blockers you want to use."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                            error=None,
                        )
                    )

        return FixResult(module_name=self.name, actions=actions)

    def _check_legacy_extensions(self) -> list[str]:
        """Scan ~/Library/Safari/Extensions/ for .safariextz files.

        Returns list of legacy extension names (without .safariextz extension).
        Returns [] if directory doesn't exist or on any error.
        """
        try:
            extensions_dir = Path.home() / "Library" / "Safari" / "Extensions"
            if not extensions_dir.exists():
                return []

            legacy_exts = []
            for extz_file in extensions_dir.glob("*.safariextz"):
                legacy_exts.append(extz_file.stem)

            return legacy_exts
        except OSError:
            return []
        except Exception:
            return []

    def _check_safari_app_extensions(self) -> list[str]:
        """Check Safari app extensions via pluginkit.

        Returns list of extension bundle identifiers.
        Returns [] on any error.
        """
        try:
            result = subprocess.run(
                ["pluginkit", "-mAD", "-p", "com.apple.Safari.extension"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return []

            extensions = []
            for line in result.stdout.strip().split("\n"):
                if not line:
                    continue
                # pluginkit output format: "/path/to/bundle - (extension description)"
                # We extract just the bundle identifier/name
                # Typical format: "/path/com.example.extension - com.apple.Safari.extension"
                if line.startswith("/"):
                    # Extract the last path component or relevant name
                    parts = line.split()
                    if parts:
                        # Take the full path and extract just the bundle name
                        path_part = parts[0]
                        # Get the last component of the path (usually the bundle name)
                        bundle_name = path_part.split("/")[-1]
                        if bundle_name:
                            extensions.append(bundle_name)

            return extensions
        except OSError:
            return []
        except Exception:
            return []

    def _check_content_blockers_enabled(self) -> bool | None:
        """Check if Safari content blockers are enabled.

        Returns True if at least one content blocker extension is found and active.
        Returns None if unable to determine (no extensions found or error).
        """
        try:
            result = subprocess.run(
                ["pluginkit", "-mAD", "-p", "com.apple.Safari.content-blocker"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                # Non-zero return typically means nothing found or error
                return None

            # If there's any output with extensions, content blockers exist
            has_content_blockers = bool(result.stdout.strip())
            return has_content_blockers if has_content_blockers else None
        except OSError:
            return None
        except Exception:
            return None
