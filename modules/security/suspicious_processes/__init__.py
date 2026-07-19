import re
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
    name = "suspicious_processes"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "3s"

    emits_codes = [
        "security.suspicious_processes.known_malware",
        "security.suspicious_processes.suspicious_paths",
        "security.suspicious_processes.suspicious_names",
        "security.suspicious_processes.high_cpu",
        "security.suspicious_processes.unsigned_apps",
        "security.suspicious_processes.all_clean",
    ]

    # Known malware process names
    KNOWN_MALWARE = {
        "genio",
        "vsearch",
        "genieo",
        "conduit",
        "mackeeper",
        "zeobit",
        "advanced_mac_cleaner",
        "mac_auto_fixer",
        "pcvark",
        "tapsnake",
        "crossrider",
        "shlayer",
        "bundlore",
        "adload",
        "pirrit",
        "mughthesec",
    }

    # Suspicious locations
    SUSPICIOUS_PATHS = {
        "/tmp",
        "/var/tmp",
        str(Path.home() / "Downloads"),
        str(Path.home() / "Desktop"),
    }

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get all running processes
        processes = self._get_processes()
        if not processes:
            return CheckResult(module_name=self.name, findings=findings)

        malware_procs = []
        suspicious_path_procs = []
        suspicious_char_procs = []
        high_cpu_procs = []
        unsigned_app_procs = []

        for proc in processes:
            pid, user, cpu, mem, command = proc
            proc_name = Path(command.split()[0]).name if command else ""

            # Check for known malware
            if proc_name.lower() in self.KNOWN_MALWARE:
                malware_procs.append({"pid": pid, "name": proc_name, "command": command})
                continue

            # Check for processes running from suspicious paths
            for suspicious_path in self.SUSPICIOUS_PATHS:
                if command.startswith(suspicious_path):
                    suspicious_path_procs.append(
                        {
                            "pid": pid,
                            "name": proc_name,
                            "path": suspicious_path,
                            "command": command,
                        }
                    )
                    break

            # Check for suspicious characteristics
            if proc_name.startswith(".") or self._is_random_looking(proc_name):
                suspicious_char_procs.append(
                    {"pid": pid, "name": proc_name, "command": command}
                )

            # Check for high CPU processes (potential crypto miners)
            try:
                cpu_percent = float(cpu)
                if cpu_percent > 80:
                    # Further filter: likely mining if it's sustained
                    high_cpu_procs.append(
                        {"pid": pid, "name": proc_name, "cpu": cpu_percent, "command": command}
                    )
            except (ValueError, TypeError):
                pass

        # Check for unsigned apps in /Applications
        unsigned_apps = self._get_unsigned_apps()
        for app_path, app_name in unsigned_apps:
            unsigned_app_procs.append({"path": app_path, "name": app_name})

        # Create findings
        if malware_procs:
            findings.append(
                Finding(
                    title=f"Known malware detected: {len(malware_procs)} process(es)",
                    description=(
                        f"Found {len(malware_procs)} process(es) with known malware names: "
                        f"{', '.join(p['name'] for p in malware_procs)}. "
                        "These should be removed immediately."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    code="security.suspicious_processes.known_malware",
                    data={
                        "check": "known_malware",
                        "processes": malware_procs,
                    },
                )
            )

        if suspicious_path_procs:
            findings.append(
                Finding(
                    title=f"Processes from suspicious locations: {len(suspicious_path_procs)}",
                    description=(
                        f"Found {len(suspicious_path_procs)} process(es) running from suspicious paths "
                        f"(temp directories, Downloads, Desktop): "
                        f"{', '.join(p['name'] for p in suspicious_path_procs)}. "
                        "Review and consider removing these."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.suspicious_processes.suspicious_paths",
                    data={
                        "check": "suspicious_paths",
                        "processes": suspicious_path_procs,
                    },
                )
            )

        if suspicious_char_procs:
            findings.append(
                Finding(
                    title=f"Processes with suspicious names: {len(suspicious_char_procs)}",
                    description=(
                        f"Found {len(suspicious_char_procs)} process(es) with suspicious characteristics "
                        f"(hidden names or random-looking): "
                        f"{', '.join(p['name'] for p in suspicious_char_procs)}. "
                        "Review these processes."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.suspicious_processes.suspicious_names",
                    data={
                        "check": "suspicious_names",
                        "processes": suspicious_char_procs,
                    },
                )
            )

        if high_cpu_procs:
            proc_info = ", ".join(f"{p['name']} ({p['cpu']:.1f}%)" for p in high_cpu_procs)
            findings.append(
                Finding(
                    title=f"High-CPU processes detected: {len(high_cpu_procs)}",
                    description=(
                        f"Found {len(high_cpu_procs)} process(es) consuming >80% CPU. "
                        f"These may be crypto miners or other resource-intensive malware: "
                        f"{proc_info}. "
                        "Review and consider terminating."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.suspicious_processes.high_cpu",
                    data={
                        "check": "high_cpu",
                        "processes": high_cpu_procs,
                    },
                )
            )

        if unsigned_app_procs:
            findings.append(
                Finding(
                    title=f"Unsigned apps in /Applications: {len(unsigned_app_procs)}",
                    description=(
                        f"Found {len(unsigned_app_procs)} app(s) in /Applications without a bundle ID "
                        f"(unsigned or suspicious): "
                        f"{', '.join(p['name'] for p in unsigned_app_procs)}. "
                        "Consider verifying or removing these."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.suspicious_processes.unsigned_apps",
                    data={
                        "check": "unsigned_apps",
                        "apps": unsigned_app_procs,
                    },
                )
            )

        # If no issues found, report clean status
        if not findings:
            findings.append(
                Finding(
                    title="No suspicious processes detected",
                    description="Process scan completed successfully with no suspicious activity found.",
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.suspicious_processes.all_clean",
                    data={"check": "all_clean"},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")
            processes = finding.data.get("processes", [])
            apps = finding.data.get("apps", [])

            if check == "known_malware":
                proc_names = ", ".join(p["name"] for p in processes)
                actions.append(
                    Action(
                        title=f"Remove known malware: {proc_names}",
                        description=(
                            f"Kill processes with known malware names: {proc_names}\n"
                            "Commands to run:\n"
                            + "\n".join(
                                f"  killall -9 {p['name']}" for p in processes
                            )
                            + "\n\n"
                            "Then locate and delete the application files from "
                            "/Applications, ~/Library/Application Support, or other system locations."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=False,
                        error=None,
                    )
                )

            elif check == "suspicious_paths":
                proc_names = ", ".join(p["name"] for p in processes)
                actions.append(
                    Action(
                        title=f"Remove processes from suspicious paths: {proc_names}",
                        description=(
                            f"Kill and remove processes running from temp/Downloads/Desktop: {proc_names}\n"
                            "Commands to kill:\n"
                            + "\n".join(
                                f"  kill {p['pid']}" for p in processes
                            )
                            + "\n\n"
                            "Then delete the source files from the suspicious paths."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=False,
                        error=None,
                    )
                )

            elif check == "suspicious_names":
                proc_names = ", ".join(p["name"] for p in processes)
                actions.append(
                    Action(
                        title=f"Investigate suspicious process names: {proc_names}",
                        description=(
                            f"Review these processes with suspicious names: {proc_names}\n"
                            "Use Activity Monitor or `lsof -p <pid>` to investigate what they're doing. "
                            "If confirmed malicious, kill the process and delete the application."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=False,
                        error=None,
                    )
                )

            elif check == "high_cpu":
                proc_names = ", ".join(
                    f"{p['name']} ({p['cpu']:.1f}%)" for p in processes
                )
                actions.append(
                    Action(
                        title=f"Investigate high-CPU processes: {proc_names}",
                        description=(
                            f"These processes are consuming excessive CPU: {proc_names}\n"
                            "Use Activity Monitor to confirm the activity. "
                            "If confirmed to be malware, kill the process and remove the application."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=False,
                        error=None,
                    )
                )

            elif check == "unsigned_apps":
                app_names = ", ".join(a["name"] for a in apps)
                actions.append(
                    Action(
                        title=f"Review unsigned apps: {app_names}",
                        description=(
                            f"These apps in /Applications lack proper bundle IDs: {app_names}\n"
                            "Verify these applications through their publishers. "
                            "If untrusted, delete them from /Applications."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=False,
                        error=None,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_processes(self) -> list[tuple[str, str, str, str, str]]:
        """Get all running processes from ps aux.

        Returns list of (pid, user, cpu, mem, command) tuples.
        Returns [] on any failure.
        """
        try:
            result = subprocess.run(
                ["ps", "aux"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return []

            processes = []
            lines = result.stdout.strip().split("\n")
            for line in lines[1:]:  # Skip header
                if not line:
                    continue
                parts = line.split(None, 10)  # Split on first 10 whitespace occurrences
                if len(parts) >= 11:
                    pid = parts[1]
                    user = parts[0]
                    cpu = parts[2]
                    mem = parts[3]
                    command = parts[10]
                    processes.append((pid, user, cpu, mem, command))
            return processes
        except OSError:
            return []
        except Exception:
            return []

    def _is_random_looking(self, name: str) -> bool:
        """Check if a process name looks random or obfuscated."""
        if len(name) < 3:
            return False
        # Count non-ASCII or unusual characters
        unusual = 0
        for char in name:
            if not (char.isalnum() or char in "_-"):
                unusual += 1
        # If more than 30% unusual characters, it's suspicious
        if len(name) > 0 and unusual / len(name) > 0.3:
            return True
        # Check for names that look like hex strings (very random)
        if re.match(r"^[a-f0-9]{8,}$", name, re.IGNORECASE):
            return True
        return False

    def _get_unsigned_apps(self) -> list[tuple[str, str]]:
        """Check for unsigned apps in /Applications.

        Returns list of (path, app_name) tuples.
        """
        unsigned_apps = []
        try:
            apps_dir = Path("/Applications")
            if not apps_dir.exists():
                return unsigned_apps

            for app_path in apps_dir.glob("*.app"):
                # Check if app has a bundle ID by looking at Info.plist
                info_plist = app_path / "Contents" / "Info.plist"
                if info_plist.exists():
                    try:
                        result = subprocess.run(
                            [
                                "defaults",
                                "read",
                                str(info_plist.parent.parent),
                                "CFBundleIdentifier",
                            ],
                            capture_output=True,
                            text=True,
                        )
                        if result.returncode != 0:
                            unsigned_apps.append((str(app_path), app_path.name))
                    except OSError:
                        # If we can't read it, consider it unsigned
                        unsigned_apps.append((str(app_path), app_path.name))
        except OSError:
            pass
        except Exception:
            pass

        return unsigned_apps
