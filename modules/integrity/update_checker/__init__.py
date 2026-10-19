import os
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

# `softwareupdate -l` asks Apple's servers and took 47 s, then over 60 s, on a
# real Mac. With no timeout it used the engine's whole 60 s limit, so the check
# was reported as "couldn't run" and the Homebrew part never ran. Both commands
# now have their own limit and together stay under 60 s. A run that fails or
# is stopped is reported as not checked, never as "no updates".
_SOFTWAREUPDATE_TIMEOUT = 40
_BREW_TIMEOUT = 15


class Module(ModuleBase):
    name = "update_checker"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "30s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        os_output = self._run_softwareupdate()
        os_updates = _parse_softwareupdate_output(os_output or "")
        if os_output is None:
            findings.append(
                Finding(
                    title="Couldn't check for macOS updates",
                    description=(
                        "Asking Apple for available macOS updates took too long or "
                        "failed, so it was stopped. This doesn't mean your Mac is up to "
                        "date.\n\n"
                        "What to do: Open System Settings > General > Software Update to "
                        "check yourself."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "os_updates_not_checked",
                          "timeout_s": _SOFTWAREUPDATE_TIMEOUT},
                )
            )
        elif os_updates:
            findings.append(
                Finding(
                    title=f"{len(os_updates)} macOS update(s) available",
                    description=(
                        f"Your Mac has {len(os_updates)} updates waiting to be installed. "
                        "These are official updates from Apple that fix security holes "
                        "and bugs: "
                        + ", ".join(os_updates)
                        + "\n\n"
                        "What to do: Open System Settings > General > Software Update "
                        "and install them."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "os_updates", "updates": os_updates},
                )
            )

        brew_output = self._run_brew_outdated()
        if brew_output is _BREW_STOPPED:
            findings.append(
                Finding(
                    title="Couldn't check Homebrew packages",
                    description=(
                        "Asking Homebrew which packages are out of date took too long or "
                        "failed, so it was stopped. This doesn't mean they are up to "
                        "date.\n\n"
                        "What to do: If you use Homebrew, open Terminal and type "
                        "`brew outdated`."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "brew_not_checked", "timeout_s": _BREW_TIMEOUT},
                )
            )
        elif brew_output is not None:
            outdated_packages = _parse_brew_outdated(brew_output)
            if outdated_packages:
                findings.append(
                    Finding(
                        title=f"{len(outdated_packages)} outdated Homebrew package(s)",
                        description=(
                            f"Homebrew (a tool for installing extra software) has {len(outdated_packages)} "
                            "apps that are older than the latest version: "
                            + ", ".join(outdated_packages)
                            + "\n\n"
                            "What to do: Open Terminal and type `brew upgrade` to update "
                            "them, or ignore this if you don't use Homebrew."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check": "brew_outdated", "packages": outdated_packages},
                    )
                )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")
            if check == "os_updates":
                actions.append(
                    Action(
                        title="macOS update guidance",
                        description=(
                            "Run `sudo softwareupdate -i -a` to install all "
                            "pending updates, or open System Settings > "
                            "General > Software Update."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check == "brew_outdated":
                actions.append(
                    Action(
                        title="Homebrew update guidance",
                        description="Run `brew upgrade` to update all outdated packages.",
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
        return FixResult(module_name=self.name, actions=actions)

    def _run_softwareupdate(self) -> str | None:
        """The update list, or None when it could not be read."""
        try:
            result = subprocess.run(
                ["softwareupdate", "-l"],
                capture_output=True,
                text=True,
                timeout=_SOFTWAREUPDATE_TIMEOUT,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        if result.returncode != 0:
            return None
        return result.stdout

    def _run_brew_outdated(self):
        """brew's list; None if Homebrew isn't installed; _BREW_STOPPED if it
        is but the list could not be read."""
        try:
            result = subprocess.run(
                ["brew", "outdated"],
                capture_output=True,
                text=True,
                timeout=_BREW_TIMEOUT,
                env={**os.environ, "HOMEBREW_NO_AUTO_UPDATE": "1"},
            )
        except FileNotFoundError:
            return None
        except (OSError, subprocess.SubprocessError):
            return _BREW_STOPPED
        if result.returncode != 0:
            return _BREW_STOPPED
        return result.stdout


# brew is installed but its answer could not be read (timed out or failed).
_BREW_STOPPED = object()


def _parse_softwareupdate_output(output: str) -> list[str]:
    labels = []
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("* Label:"):
            labels.append(stripped.split("Label:", 1)[1].strip())
    return labels


def _parse_brew_outdated(output: str) -> list[str]:
    packages = []
    for line in output.strip().splitlines():
        line = line.strip()
        if line:
            packages.append(line.split()[0])
    return packages
