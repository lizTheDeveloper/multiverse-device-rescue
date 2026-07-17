import json
import os
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
    name = "homebrew_health"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "15s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check if Homebrew is installed
        if not self._is_homebrew_installed():
            return CheckResult(module_name=self.name, findings=findings)

        # Get brew doctor output
        doctor_issues = self._get_brew_doctor_issues()
        if doctor_issues:
            findings.append(
                Finding(
                    title="Homebrew doctor reported issues",
                    description="Run `brew doctor` for more information: "
                    + " ".join(doctor_issues[:3]),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "brew_doctor_issues",
                        "issues": doctor_issues,
                        "count": len(doctor_issues),
                    },
                )
            )

        # Get outdated packages
        outdated_packages = self._get_outdated_packages()
        if len(outdated_packages) > 20:
            package_list = [p["name"] for p in outdated_packages[:5]]
            findings.append(
                Finding(
                    title=f"{len(outdated_packages)} outdated package(s)",
                    description="Many packages are outdated. Run `brew upgrade` to update them. "
                    f"First few: {', '.join(package_list)}",
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "outdated_packages",
                        "packages": outdated_packages,
                        "count": len(outdated_packages),
                    },
                )
            )

        # Get cache size
        cache_size_bytes = self._get_cache_size()
        cache_size_gb = cache_size_bytes / (1024 ** 3)

        if cache_size_bytes > 2 * (1024 ** 3):  # 2GB
            findings.append(
                Finding(
                    title=f"Homebrew cache is large ({cache_size_gb:.1f}GB)",
                    description="Run `brew cleanup` to remove old versions and free up disk space.",
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "large_cache",
                        "cache_size_bytes": cache_size_bytes,
                        "cache_size_gb": round(cache_size_gb, 2),
                    },
                )
            )

        # Get package count
        package_count = len(self._get_installed_packages())

        # Add info finding with summary
        findings.append(
            Finding(
                title=f"Homebrew status: {package_count} package(s) installed",
                description=f"Installed packages: {package_count}. "
                f"Outdated: {len(outdated_packages)}. "
                f"Cache size: {cache_size_gb:.1f}GB. "
                f"Doctor issues: {len(doctor_issues)}.",
                severity=Severity.INFO,
                category=self.category,
                data={
                    "check": "homebrew_summary",
                    "installed_count": package_count,
                    "outdated_count": len(outdated_packages),
                    "cache_size_gb": round(cache_size_gb, 2),
                    "doctor_issues_count": len(doctor_issues),
                },
            )
        )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "brew_doctor_issues":
                actions.append(
                    Action(
                        title="Address Homebrew doctor issues",
                        description="Run `brew doctor` to identify and resolve configuration issues. "
                        "This may include fixing file permissions or updating dependencies.",
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check == "outdated_packages":
                count = finding.data.get("count", 0)
                actions.append(
                    Action(
                        title=f"Update {count} outdated package(s)",
                        description="Run `brew upgrade` to update all outdated packages to their "
                        "latest versions. This improves security and adds new features.",
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check == "large_cache":
                size_gb = finding.data.get("cache_size_gb", 0)
                actions.append(
                    Action(
                        title=f"Clean up Homebrew cache ({size_gb}GB)",
                        description="Run `brew cleanup` to remove old cached versions of packages. "
                        "This can free up significant disk space without affecting functionality.",
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check == "homebrew_summary":
                actions.append(
                    Action(
                        title="Homebrew status summary",
                        description="Review your Homebrew installation. For best health: "
                        "run `brew doctor`, `brew upgrade` for updates, and `brew cleanup` to remove old versions.",
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _is_homebrew_installed(self) -> bool:
        """Check if Homebrew is installed via which brew."""
        try:
            result = subprocess.run(
                ["which", "brew"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, OSError):
            return False

    def _get_brew_doctor_issues(self) -> list[str]:
        """Run brew doctor and extract warning lines."""
        try:
            result = subprocess.run(
                ["brew", "doctor"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            # brew doctor outputs warnings as lines starting with "Warning:"
            issues = []
            for line in result.stdout.split("\n"):
                if line.strip().startswith("Warning:"):
                    issues.append(line.strip())
            return issues
        except (subprocess.TimeoutExpired, OSError):
            return []

    def _get_outdated_packages(self) -> list[dict]:
        """Get list of outdated packages via brew outdated --json."""
        try:
            result = subprocess.run(
                ["brew", "outdated", "--json=v1"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                return []

            data = json.loads(result.stdout)
            # Output is a dict with "formulae" and "casks" keys
            formulae = data.get("formulae", [])
            casks = data.get("casks", [])
            return formulae + casks
        except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
            return []

    def _get_cache_size(self) -> int:
        """Get Homebrew cache directory size in bytes."""
        cache_path = Path.home() / "Library" / "Caches" / "Homebrew"
        if not cache_path.exists():
            return 0

        total_size = 0
        try:
            for entry in cache_path.rglob("*"):
                if entry.is_file():
                    total_size += entry.stat().st_size
        except (OSError, PermissionError):
            pass

        return total_size

    def _get_installed_packages(self) -> list[str]:
        """Get list of installed Homebrew packages."""
        try:
            result = subprocess.run(
                ["brew", "list", "--json=v1"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                return []

            data = json.loads(result.stdout)
            # Output is a dict with "formulae" and "casks" keys
            formulae = data.get("formulae", [])
            casks = data.get("casks", [])
            return formulae + casks
        except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
            return []
