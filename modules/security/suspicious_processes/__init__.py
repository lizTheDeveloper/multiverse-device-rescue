import re
import plistlib
import subprocess
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
                    title=f"Known malware is running: {len(malware_procs)} process(es)",
                    description=(
                        f"We found {len(malware_procs)} program(s) running on your Mac "
                        f"that match known malware names: {', '.join(p['name'] for p in malware_procs)}. "
                        "This is a serious sign that your computer is compromised. These "
                        "programs can steal passwords, watch your activity, or damage "
                        "your files.\n\n"
                        "What to do: Do not use this computer for banking or sensitive "
                        "accounts until it is cleaned. Connect a different, safe device "
                        "to a trusted antivirus website to download a removal tool, or "
                        "take your Mac to a professional for a full clean."
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
                    title=(
                        f"Programs running from unusual folders: {len(suspicious_path_procs)}"
                    ),
                    description=(
                        f"We found {len(suspicious_path_procs)} program(s) running from "
                        "folders where they usually don't belong (like Downloads or Desktop): "
                        f"{', '.join(p['name'] for p in suspicious_path_procs)}. Legitimate "
                        "apps usually live in the Applications folder. Running from other "
                        "spots can be a sign of a hidden or unauthorized program.\n\n"
                        "What to do: Check if you recognize these names. If you don't, "
                        "quit them in Activity Monitor (search 'Activity Monitor' in "
                        "Spotlight, select the process, and click the X button). Then, "
                        "move the original files to a safe folder on your desktop so "
                        "they can't run, but don't delete them yet in case you need to "
                        "show them to a professional."
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
                    title=f"Apps with unusual names: {len(suspicious_char_procs)}",
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
                    title=f"Programs using a lot of power: {len(high_cpu_procs)}",
                    description=(
                        f"We found {len(high_cpu_procs)} program(s) using over 80% of "
                        f"your processor: {proc_info}. This can make your Mac hot, slow, "
                        "and drain your battery. While this might just be a heavy task, "
                        "it can also be a sign of a hidden 'crypto miner' using your "
                        "computer for someone else's benefit.\n\n"
                        "What to do: Open Activity Monitor (search 'Activity Monitor' "
                        "in Spotlight) and look for these names. If you don't recognize "
                        "them, select the process and click the X button to quit it. "
                        "If they keep coming back, your Mac may need a professional check."
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
                    title=f"Apps without a bundle ID: {len(unsigned_app_procs)}",
                    description=(
                        f"Found {len(unsigned_app_procs)} app(s) in /Applications without a bundle ID "
                        f"(an app's name for itself; signed apps always have one): "
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

        unreadable = getattr(self, "_unreadable_apps", None) or []
        if unreadable:
            # "Couldn't read …" at info: the screens count it as partly checked,
            # never clean (desktop/renderer/not-checked.js isPartlyChecked).
            findings.append(
                Finding(
                    title=f"Couldn't read the settings of {len(unreadable)} app(s)",
                    description=(
                        f"The settings file (Info.plist) of {len(unreadable)} app(s) in /Applications "
                        f"couldn't be read, so this check couldn't tell whether they have a bundle ID: "
                        f"{', '.join(a['name'] for a in unreadable[:20])}"
                        f"{f', and {len(unreadable) - 20} more' if len(unreadable) > 20 else ''}. "
                        "That isn't a sign of a problem by itself, but these apps weren't checked."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "unreadable_apps", "apps": unreadable, "incomplete": True},
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
                                f"  killall -9 {quote(str(p['name']))}" for p in processes
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
        # Apps whose Info.plist couldn't be read: not evidence either way, but
        # not checked either, so the scan says so (check()).
        self._unreadable_apps = []
        try:
            apps_dir = Path("/Applications")
            if not apps_dir.exists():
                return unsigned_apps

            for app_path in apps_dir.glob("*.app"):
                # Check if app has a bundle ID by looking at Info.plist
                info_plist = app_path / "Contents" / "Info.plist"
                if info_plist.exists():
                    # Read the app's Info.plist itself. (`defaults read` was
                    # given the Contents folder, not the plist, so it failed
                    # for every app and called all of them unsigned.)
                    try:
                        with open(info_plist, "rb") as fh:
                            info = plistlib.load(fh)
                    except (OSError, plistlib.InvalidFileException, ValueError):
                        # Couldn't read it: not evidence of anything, but not checked.
                        self._unreadable_apps.append({"path": str(app_path), "name": app_path.name})
                        continue
                    bundle_id = info.get("CFBundleIdentifier") if isinstance(info, dict) else None
                    if not isinstance(bundle_id, str) or not bundle_id.strip():
                        unsigned_apps.append((str(app_path), app_path.name))
        except OSError:
            pass
        except Exception:
            pass

        return unsigned_apps
