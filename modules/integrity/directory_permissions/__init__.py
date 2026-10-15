import os
import stat
from pathlib import Path
from shlex import quote

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
    name = "directory_permissions"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 70
    depends_on = []
    estimated_duration = "3s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []
        current_uid = os.getuid()
        current_user = Path.home().owner()

        # Check user directories (should be owned by current user)
        user_dirs = [
            (Path.home() / "Library", "~/Library"),
            (Path.home() / "Desktop", "~/Desktop"),
            (Path.home() / "Documents", "~/Documents"),
            (Path.home() / "Downloads", "~/Downloads"),
        ]

        for dir_path, label in user_dirs:
            finding = self._check_ownership(dir_path, current_uid, label)
            if finding:
                findings.append(finding)

        # Check /Applications (should be root:admin, mode 775)
        applications = Path("/Applications")
        if applications.exists():
            finding = self._check_ownership(applications, 0, "/Applications (should be root)")
            if finding:
                findings.append(finding)

            finding = self._check_permissions(applications, 0o775, "/Applications", check_sticky=False)
            if finding:
                findings.append(finding)

        # Check /tmp (should have sticky bit 1777)
        tmp_path = Path("/tmp")
        if tmp_path.exists():
            finding = self._check_permissions(tmp_path, 0o777, "/tmp", check_sticky=True)
            if finding:
                findings.append(finding)

        # Check /usr/local if it exists (commonly used by Homebrew)
        usr_local = Path("/usr/local")
        if usr_local.exists():
            # /usr/local should typically be writable by admin group or current user
            # For now, just check if it's readable
            try:
                stat_result = usr_local.stat()
                # /usr/local typically has various ownership patterns, so just verify it's accessible
                if not os.access(usr_local, os.R_OK | os.X_OK):
                    findings.append(
                        Finding(
                            title="Your /usr/local folder is blocked",
                            description=(
                                "The folder /usr/local exists, but your system cannot "
                                "read it. This folder is often used by software like Homebrew "
                                "to store updates. If it is blocked, some apps might fail "
                                "to update or run correctly.\n\n"
                                "What to do: Try restarting your Mac. If the problem persists, "
                                "you may need to adjust the folder's permissions in Terminal, "
                                "but it is safer to ask a tech-savvy friend for help first."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            data={
                                "path": str(usr_local),
                                "issue": "not_readable",
                            },
                        )
                    )
            except (OSError, PermissionError):
                # If we can't even stat it, it's a problem
                findings.append(
                    Finding(
                        title="Your /usr/local folder is inaccessible",
                        description=(
                            "The folder /usr/local exists, but your system cannot access "
                            "it at all. This often happens if a previous installation "
                            "was interrupted or if permissions were changed incorrectly.\n\n"
                            "What to do: Restart your Mac. If the issue remains, you can "
                            "try to fix the permissions in Terminal, but it is best to "
                            "consult a professional if you are not comfortable with command-line "
                            "tools."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "path": str(usr_local),
                            "issue": "not_accessible",
                        },
                    )
                )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            path = finding.data.get("path", "")
            issue = finding.data.get("issue", "")

            if issue == "ownership_mismatch":
                expected = finding.data.get("expected_owner", "current_user")
                if expected == "root":
                    cmd = f"sudo chown root:admin {quote(str(path))}"
                elif expected == "root_only":
                    cmd = f"sudo chown root:root {quote(str(path))}"
                else:
                    cmd = f"chown \"$USER\" {quote(str(path))}"

                actions.append(
                    Action(
                        title=f"Fix ownership of {Path(path).name}",
                        description=(
                            f"Directory {path} has incorrect ownership. "
                            f"To fix, run: {cmd}"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif issue == "permissions_mismatch":
                expected_mode = finding.data.get("expected_mode", "755")
                cmd = f"sudo chmod {quote(str(expected_mode))} {quote(str(path))}"
                actions.append(
                    Action(
                        title=f"Fix permissions of {Path(path).name}",
                        description=(
                            f"Directory {path} has incorrect permissions. "
                            f"To fix, run: {cmd}"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif issue == "sticky_bit_missing":
                cmd = f"sudo chmod 1777 {quote(str(path))}"
                actions.append(
                    Action(
                        title=f"Fix sticky bit on {Path(path).name}",
                        description=(
                            f"Directory {path} is missing the sticky bit, which is required for /tmp. "
                            f"To fix, run: {cmd}"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            else:  # Generic issue like not_readable or not_accessible
                actions.append(
                    Action(
                        title=f"Review {Path(path).name} permissions",
                        description=(
                            f"Directory {path} has an issue: {issue}. "
                            f"Please review manually or consult system logs."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _check_ownership(self, path: Path, expected_uid: int, label: str) -> Finding | None:
        """Check if path is owned by expected_uid. Returns Finding if mismatch, None if OK or inaccessible."""
        if not path.exists():
            return None

        try:
            stat_result = path.stat()
            if stat_result.st_uid != expected_uid:
                expected_name = "root" if expected_uid == 0 else "current user"
                actual_name = Path(path).owner() if expected_uid != 0 else "root"
                return Finding(
                    title=f"{label} is owned by the wrong account",
                    description=(
                        f"We found that {label} ({path}) is owned by {actual_name}, but "
                        f"it should be owned by {expected_name}. Ownership determines "
                        "who has the highest level of control over a folder. If this "
                        "is a system folder, having the wrong owner can sometimes allow "
                        "apps to modify files they shouldn't be able to touch.\n\n"
                        "What to do: If you didn't change this yourself, ask a technical "
                        "helper to reset the owner. To look first, run in Terminal: "
                        f"ls -ld {quote(str(path))}"
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "path": str(path),
                        "issue": "ownership_mismatch",
                        "expected_owner": expected_name,
                        "actual_uid": stat_result.st_uid,
                        "expected_uid": expected_uid,
                    },
                )
        except (OSError, PermissionError, KeyError):
            # Can't read, skip
            pass

        return None

    def _check_permissions(
        self, path: Path, expected_mode: int, label: str, check_sticky: bool = False
    ) -> Finding | None:
        """Check if path has expected permissions. Returns Finding if mismatch, None if OK or inaccessible."""
        if not path.exists():
            return None

        try:
            stat_result = path.stat()
            current_mode = stat.S_IMODE(stat_result.st_mode)
            has_sticky = bool(stat_result.st_mode & stat.S_ISVTX)

            if check_sticky:
                # For /tmp, we need both the mode (777) and sticky bit
                if not has_sticky:
                    return Finding(
                        title=f"{label} is missing a safety setting",
                        description=(
                            f"The folder {label} ({path}, mode {oct(current_mode)}) is "
                            "missing a setting called "
                            "the 'sticky bit.' This setting prevents users from deleting "
                            "files created by other users. Without it, anyone with access "
                            "to this folder could potentially delete temporary files "
                            "belonging to other people or processes.\n\n"
                            "What to do: This is a system setting that usually doesn't "
                            "need manual fixing unless you are running a multi-user server. "
                            "For a personal Mac, this is likely harmless, but you can "
                            f"check the setting in Terminal with: ls -ld {quote(str(path))}"
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "path": str(path),
                            "issue": "sticky_bit_missing",
                            "expected_mode": oct(expected_mode | stat.S_ISVTX),
                            "actual_mode": oct(current_mode),
                        },
                    )
                # Also check base permissions (strip sticky bit from actual mode for comparison)
                base_mode = current_mode & ~stat.S_ISVTX
                if base_mode != expected_mode:
                    return Finding(
                        title=f"{label} has unusual access rights",
                        description=(
                            f"The folder {label} ({path}) has access rights set to {oct(current_mode)}, "
                            f"but they should be {oct(expected_mode | stat.S_ISVTX)}. "
                            "Access rights control who can read, write, or execute files "
                            "in a folder. If these are too open, it might allow other "
                            "apps to modify files they shouldn't.\n\n"
                            "What to do: This is often a minor configuration issue. You "
                            "can check the current settings in Terminal by typing: "
                            f"ls -ld {quote(str(path))}"
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "path": str(path),
                            "issue": "permissions_mismatch",
                            "expected_mode": oct(expected_mode),
                            "actual_mode": oct(current_mode),
                        },
                    )
            else:
                # Just check the mode without sticky bit
                if current_mode != expected_mode:
                    return Finding(
                        title=f"{label} has unusual access rights",
                        description=(
                            f"The folder {label} ({path}) has access rights set to {oct(current_mode)}, "
                            f"but they should be {oct(expected_mode)}. Access rights control "
                            "who can read, write, or execute files in a folder. If these "
                            "are too open, it might allow other apps to modify files "
                            "they shouldn't.\n\n"
                            "What to do: This is often a minor configuration issue. You "
                            "can check the current settings in Terminal by typing: "
                            f"ls -ld {quote(str(path))}"
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "path": str(path),
                            "issue": "permissions_mismatch",
                            "expected_mode": oct(expected_mode),
                            "actual_mode": oct(current_mode),
                        },
                    )

        except (OSError, PermissionError):
            # Can't read, skip
            pass

        return None
