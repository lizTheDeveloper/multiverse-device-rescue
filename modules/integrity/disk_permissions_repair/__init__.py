import os
import stat
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
    name = "disk_permissions_repair"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 65
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []
        current_uid = os.getuid()
        current_user = Path.home().owner()
        home = Path.home()

        # Check home directory ownership via stat -f '%Su' ~
        home_owner = self._get_home_owner()
        if home_owner and home_owner != current_user:
            findings.append(
                Finding(
                    title="Home directory owned by wrong user",
                    description=(
                        f"Home directory ({home}) is owned by {home_owner} "
                        f"but should be owned by {current_user}. "
                        f"This can cause issues with file access and system functionality."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "path": str(home),
                        "issue": "home_ownership_mismatch",
                        "current_owner": home_owner,
                        "expected_owner": current_user,
                    },
                )
            )

        # Check key user directories
        user_dirs = [
            (home / "Library", "~/Library"),
            (home / "Documents", "~/Documents"),
            (home / "Desktop", "~/Desktop"),
        ]

        for dir_path, label in user_dirs:
            finding = self._check_ownership(dir_path, current_uid, label)
            if finding:
                findings.append(finding)

        # Check /tmp permissions (should be 1777)
        tmp_finding = self._check_tmp_permissions()
        if tmp_finding:
            findings.append(tmp_finding)

        # Check /var/tmp permissions (should be 1777)
        var_tmp_finding = self._check_var_tmp_permissions()
        if var_tmp_finding:
            findings.append(var_tmp_finding)

        # Check /usr/local ownership if it exists
        usr_local = Path("/usr/local")
        if usr_local.exists():
            usr_local_finding = self._check_usr_local()
            if usr_local_finding:
                findings.append(usr_local_finding)

        # If no issues found, add an INFO message
        if not findings:
            findings.append(
                Finding(
                    title="Disk permissions look correct",
                    description="All checked disk permissions are correct.",
                    severity=Severity.INFO,
                    category=self.category,
                    data={"status": "healthy"},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            issue = finding.data.get("issue", "")
            path = finding.data.get("path", "")

            if issue == "home_ownership_mismatch":
                cmd = f"sudo chown -R $USER {path}"
                actions.append(
                    Action(
                        title="Fix home directory ownership",
                        description=(
                            f"Home directory is owned by {finding.data.get('current_owner')} "
                            f"but should be owned by {finding.data.get('expected_owner')}. "
                            f"To fix, run: {cmd}"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif issue == "ownership_mismatch":
                expected = finding.data.get("expected_owner", "current_user")
                cmd = f"sudo chown $USER {path}"
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

            elif issue == "tmp_permissions_mismatch":
                cmd = f"sudo chmod 1777 {path}"
                actions.append(
                    Action(
                        title=f"Fix {Path(path).name} permissions",
                        description=(
                            f"Directory {path} has incorrect permissions (should be 1777). "
                            f"To fix, run: {cmd}"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif issue == "usr_local_root_owned":
                cmd = "sudo chown -R $(whoami) /usr/local"
                actions.append(
                    Action(
                        title="Fix /usr/local ownership",
                        description=(
                            f"/usr/local is owned by root, which blocks Homebrew and other package managers. "
                            f"To fix, run: {cmd}"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif issue == "usr_local_not_accessible":
                actions.append(
                    Action(
                        title="Review /usr/local permissions",
                        description=(
                            f"/usr/local is not accessible. This may cause issues with Homebrew. "
                            f"Please review permissions manually or check system logs."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_home_owner(self) -> str | None:
        """Get home directory owner using stat -f '%Su' ~"""
        try:
            result = subprocess.run(
                ["stat", "-f", "%Su", str(Path.home())],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except (subprocess.SubprocessError, FileNotFoundError, OSError):
            pass
        return None

    def _check_ownership(self, path: Path, expected_uid: int, label: str) -> Finding | None:
        """Check if path is owned by expected_uid. Returns Finding if mismatch, None if OK or inaccessible."""
        if not path.exists():
            return None

        try:
            stat_result = path.stat()
            if stat_result.st_uid != expected_uid:
                expected_name = "current user" if expected_uid != 0 else "root"
                try:
                    actual_name = path.owner()
                except (KeyError, OSError):
                    actual_name = f"UID {stat_result.st_uid}"
                return Finding(
                    title=f"{label} has incorrect ownership",
                    description=(
                        f"{label} ({path}) is owned by {actual_name} "
                        f"but should be owned by {expected_name}."
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
        except (OSError, PermissionError):
            pass

        return None

    def _check_tmp_permissions(self) -> Finding | None:
        """Check /tmp permissions (should be 1777)."""
        tmp_path = Path("/tmp")
        if not tmp_path.exists():
            return None

        try:
            stat_result = tmp_path.stat()
            current_mode = stat.S_IMODE(stat_result.st_mode)
            has_sticky = bool(stat_result.st_mode & stat.S_ISVTX)

            # /tmp should have 1777: rwxrwxrwt (sticky bit + 777)
            if not has_sticky or (current_mode & 0o777) != 0o777:
                return Finding(
                    title="/tmp has incorrect permissions",
                    description=(
                        f"/tmp has mode {oct(current_mode)} "
                        f"but should have mode 1777 (rwxrwxrwt with sticky bit). "
                        f"This can allow users to interfere with other users' temporary files."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "path": str(tmp_path),
                        "issue": "tmp_permissions_mismatch",
                        "expected_mode": "1777",
                        "actual_mode": oct(current_mode),
                    },
                )
        except (OSError, PermissionError):
            pass

        return None

    def _check_var_tmp_permissions(self) -> Finding | None:
        """Check /var/tmp permissions (should be 1777)."""
        var_tmp_path = Path("/var/tmp")
        if not var_tmp_path.exists():
            return None

        try:
            stat_result = var_tmp_path.stat()
            current_mode = stat.S_IMODE(stat_result.st_mode)
            has_sticky = bool(stat_result.st_mode & stat.S_ISVTX)

            # /var/tmp should have 1777: rwxrwxrwt (sticky bit + 777)
            if not has_sticky or (current_mode & 0o777) != 0o777:
                return Finding(
                    title="/var/tmp has incorrect permissions",
                    description=(
                        f"/var/tmp has mode {oct(current_mode)} "
                        f"but should have mode 1777 (rwxrwxrwt with sticky bit). "
                        f"This can allow users to interfere with other users' temporary files."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "path": str(var_tmp_path),
                        "issue": "tmp_permissions_mismatch",
                        "expected_mode": "1777",
                        "actual_mode": oct(current_mode),
                    },
                )
        except (OSError, PermissionError):
            pass

        return None

    def _check_usr_local(self) -> Finding | None:
        """Check /usr/local ownership and accessibility."""
        usr_local = Path("/usr/local")
        if not usr_local.exists():
            return None

        try:
            stat_result = usr_local.stat()
            # Check if owned by root (UID 0)
            if stat_result.st_uid == 0:
                return Finding(
                    title="/usr/local owned by root",
                    description=(
                        "/usr/local is owned by root, which prevents non-root users "
                        "from installing packages via Homebrew and other package managers. "
                        "This is a common issue that needs fixing."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "path": str(usr_local),
                        "issue": "usr_local_root_owned",
                    },
                )
            # Check if it's readable and executable
            if not os.access(usr_local, os.R_OK | os.X_OK):
                return Finding(
                    title="/usr/local not accessible",
                    description=(
                        "/usr/local exists but is not readable or executable. "
                        "This may cause issues with Homebrew and other package managers."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "path": str(usr_local),
                        "issue": "usr_local_not_accessible",
                    },
                )
        except (OSError, PermissionError):
            return Finding(
                title="/usr/local not accessible",
                description=(
                    "/usr/local exists but cannot be accessed. "
                    "This may cause issues with Homebrew and other package managers."
                ),
                severity=Severity.WARNING,
                category=self.category,
                data={
                    "path": str(usr_local),
                    "issue": "usr_local_not_accessible",
                },
            )

        return None
