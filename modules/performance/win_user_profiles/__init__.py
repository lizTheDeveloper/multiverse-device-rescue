import subprocess
from datetime import datetime, timedelta, timezone

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

# Thresholds
PROFILE_SIZE_WARNING_THRESHOLD = 10 * 1024**3  # 10 GB
PROFILE_UNUSED_DAYS_THRESHOLD = 180  # days


class Module(ModuleBase):
    name = "win_user_profiles"
    category = "performance"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "30s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get user profiles and corresponding user accounts
        profiles = self._get_user_profiles()
        user_accounts = self._get_user_accounts()

        if not profiles:
            return CheckResult(module_name=self.name, findings=findings)

        # Calculate sizes and analyze profiles
        profile_details = []
        total_size = 0
        orphaned_profiles = []
        temp_profiles = []
        large_profiles = []
        unused_profiles = []

        now = datetime.now(timezone.utc)

        for profile in profiles:
            path = profile.get("LocalPath", "")
            sid = profile.get("SID", "")
            last_use_str = profile.get("LastUseTime", "")
            is_special = profile.get("Special", False)

            # Skip special profiles (System, NetworkService, etc.)
            if is_special:
                continue

            # Calculate profile size
            size = self._get_directory_size_powershell(path)
            total_size += size

            # Check if profile is orphaned (no corresponding user account)
            is_orphaned = sid not in user_accounts

            # Check if profile is temporary (TEMP in path indicates corruption)
            is_temp = "TEMP" in path.upper()

            # Parse last use time
            last_use_time = None
            if last_use_str:
                try:
                    last_use_time = datetime.fromisoformat(last_use_str.replace('Z', '+00:00'))
                except (ValueError, AttributeError):
                    pass

            # Check if profile is unused for > 180 days
            is_unused = False
            days_since_use = None
            if last_use_time:
                days_since_use = (now - last_use_time).days
                is_unused = days_since_use > PROFILE_UNUSED_DAYS_THRESHOLD

            profile_details.append({
                "path": path,
                "sid": sid,
                "size": size,
                "size_formatted": _fmt_bytes(size),
                "last_use": last_use_str,
                "days_since_use": days_since_use,
                "is_orphaned": is_orphaned,
                "is_temp": is_temp,
                "is_large": size > PROFILE_SIZE_WARNING_THRESHOLD,
                "is_unused": is_unused,
            })

            if is_orphaned:
                orphaned_profiles.append(profile_details[-1])
            if is_temp:
                temp_profiles.append(profile_details[-1])
            if size > PROFILE_SIZE_WARNING_THRESHOLD:
                large_profiles.append(profile_details[-1])
            if is_unused:
                unused_profiles.append(profile_details[-1])

        # Add INFO finding listing all profiles
        if profile_details:
            profile_list = "\n".join([
                f"  {d['path']}: {d['size_formatted']} (last used: {d['last_use'] or 'unknown'})"
                for d in profile_details
            ])
            findings.append(
                Finding(
                    title=f"Found {len(profile_details)} user profile(s)",
                    description=(
                        f"User profiles on system:\n{profile_list}\n\n"
                        f"Total space used by user profiles: {_fmt_bytes(total_size)}"
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "type": "profiles_list",
                        "count": len(profile_details),
                        "total_size_bytes": total_size,
                        "total_size_formatted": _fmt_bytes(total_size),
                        "profiles": profile_details,
                    },
                )
            )

        # Flag orphaned profiles
        if orphaned_profiles:
            profile_list = "\n".join([
                f"  {p['path']} (SID: {p['sid']})"
                for p in orphaned_profiles
            ])
            findings.append(
                Finding(
                    title=f"Found {len(orphaned_profiles)} orphaned profile(s)",
                    description=(
                        f"These profiles have no corresponding user account and waste disk space:\n"
                        f"{profile_list}\n\n"
                        f"Orphaned profiles can be safely deleted via System Properties > Advanced > User Profiles."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "type": "orphaned_profiles",
                        "count": len(orphaned_profiles),
                        "profiles": orphaned_profiles,
                    },
                )
            )

        # Flag temporary profiles
        if temp_profiles:
            profile_list = "\n".join([
                f"  {p['path']}"
                for p in temp_profiles
            ])
            findings.append(
                Finding(
                    title=f"Found {len(temp_profiles)} temporary profile(s)",
                    description=(
                        f"These profiles contain TEMP in path, indicating possible corruption:\n"
                        f"{profile_list}\n\n"
                        f"Temporary profiles should be reviewed and deleted to prevent login issues."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "type": "temp_profiles",
                        "count": len(temp_profiles),
                        "profiles": temp_profiles,
                    },
                )
            )

        # Flag large profiles
        if large_profiles:
            profile_list = "\n".join([
                f"  {p['path']}: {p['size_formatted']}"
                for p in large_profiles
            ])
            findings.append(
                Finding(
                    title=f"Found {len(large_profiles)} large profile(s) (>10 GB)",
                    description=(
                        f"These profiles exceed 10 GB and may slow login times:\n"
                        f"{profile_list}\n\n"
                        f"Consider reviewing and cleaning up profile contents."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "type": "large_profiles",
                        "count": len(large_profiles),
                        "profiles": large_profiles,
                    },
                )
            )

        # Flag unused profiles
        if unused_profiles:
            profile_list = "\n".join([
                f"  {p['path']}: unused for {p['days_since_use']} days"
                for p in unused_profiles
            ])
            findings.append(
                Finding(
                    title=f"Found {len(unused_profiles)} unused profile(s) (>180 days)",
                    description=(
                        f"These profiles have not been used in over 180 days:\n"
                        f"{profile_list}\n\n"
                        f"Old profiles can be safely deleted via System Properties > Advanced > User Profiles."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "type": "unused_profiles",
                        "count": len(unused_profiles),
                        "profiles": unused_profiles,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            finding_type = finding.data.get("type", "unknown")

            if finding_type == "profiles_list":
                actions.append(
                    Action(
                        title="User profiles inventory",
                        description=(
                            f"Found {finding.data.get('count', 0)} user profiles using "
                            f"{finding.data.get('total_size_formatted', 'unknown')} of disk space. "
                            f"Review the findings below to identify profiles that can be removed."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "orphaned_profiles":
                profiles = finding.data.get("profiles", [])
                count = len(profiles)
                actions.append(
                    Action(
                        title=f"Orphaned profiles ({count})",
                        description=(
                            f"Found {count} orphaned profile(s) with no corresponding user account. "
                            f"To delete: Open System Properties (sysdm.cpl) > Advanced tab > "
                            f"User Profiles section > select orphaned profile > Delete."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "temp_profiles":
                profiles = finding.data.get("profiles", [])
                count = len(profiles)
                actions.append(
                    Action(
                        title=f"Temporary profiles ({count})",
                        description=(
                            f"Found {count} temporary profile(s) indicating possible corruption. "
                            f"Review via System Properties > User Profiles. "
                            f"Delete if the user account no longer exists or is no longer needed."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "large_profiles":
                profiles = finding.data.get("profiles", [])
                count = len(profiles)
                actions.append(
                    Action(
                        title=f"Large profiles ({count})",
                        description=(
                            f"Found {count} profile(s) exceeding 10 GB. "
                            f"Large profiles slow login. Consider: (1) Cleaning profile cache and temp files, "
                            f"(2) Moving large files to network shares, (3) Deleting old profiles."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "unused_profiles":
                profiles = finding.data.get("profiles", [])
                count = len(profiles)
                actions.append(
                    Action(
                        title=f"Unused profiles ({count})",
                        description=(
                            f"Found {count} profile(s) unused for over 180 days. "
                            f"To delete: Open System Properties (sysdm.cpl) > Advanced tab > "
                            f"User Profiles section > select profile > Delete."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_user_profiles(self) -> list[dict]:
        """Get list of user profiles using PowerShell."""
        try:
            cmd = [
                "powershell",
                "-NoProfile",
                "-Command",
                (
                    "Get-CimInstance Win32_UserProfile | "
                    "Select-Object LocalPath, SID, LastUseTime, Special | "
                    "ConvertTo-Json"
                ),
            ]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15,
            )
            if result.returncode == 0 and result.stdout.strip():
                import json
                try:
                    data = json.loads(result.stdout.strip())
                    # Handle both single profile (dict) and multiple profiles (list)
                    if isinstance(data, dict):
                        return [data]
                    return data if isinstance(data, list) else []
                except json.JSONDecodeError:
                    return []
            return []
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            return []

    def _get_user_accounts(self) -> set[str]:
        """Get set of user account SIDs using PowerShell."""
        try:
            cmd = [
                "powershell",
                "-NoProfile",
                "-Command",
                (
                    "Get-LocalUser | "
                    "Select-Object SID | "
                    "ConvertTo-Json"
                ),
            ]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15,
            )
            if result.returncode == 0 and result.stdout.strip():
                import json
                try:
                    data = json.loads(result.stdout.strip())
                    # Handle both single user (dict) and multiple users (list)
                    if isinstance(data, dict):
                        return {data.get("SID", "")}
                    sids = set()
                    if isinstance(data, list):
                        for user in data:
                            sid = user.get("SID", "")
                            if sid:
                                sids.add(sid)
                    return sids
                except json.JSONDecodeError:
                    return set()
            return set()
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            return set()

    def _get_directory_size_powershell(self, path: str) -> int:
        """Get directory size using PowerShell."""
        try:
            cmd = [
                "powershell",
                "-NoProfile",
                "-Command",
                f"(Get-ChildItem '{path}' -Recurse -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum",
            ]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0 and result.stdout.strip():
                try:
                    return int(result.stdout.strip())
                except ValueError:
                    return 0
            return 0
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            return 0


def _fmt_bytes(n: int) -> str:
    """Format bytes as human-readable string."""
    if n is None or n == 0:
        return "0 B"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"
