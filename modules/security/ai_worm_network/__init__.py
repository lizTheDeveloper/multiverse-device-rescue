import ctypes
import ctypes.util
import os
import re
import shutil
import signal
import subprocess
import time
from pathlib import Path

from rescue.models import (
    Action,
    ActionKind,
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

# Warm the shared IOC database cache at import time (not lazily inside
# check()). The loader caches its parsed result keyed by data_dir, so this
# eager load ensures real IOC data is cached before check()/fix() run —
# which matters because check() may execute under test mocks (e.g. patched
# Path.exists / subprocess.run) that would otherwise interfere with the
# loader's own internal file-existence checks.
def _load_iocs():
    try:
        from modules.security.ai_worm_iocs.loader import load_iocs

        return load_iocs()
    except Exception:
        return None


_iocs_cache = _load_iocs()

# Gap between the two connection samples used for beaconing detection.
# _check_beaconing() only sleeps when the first sample already has active
# connections to compare (an empty first sample returns immediately), so
# this does not slow down the common "nothing suspicious" case.
_BEACON_GAP_SECONDS = 5

_CONN_DEST_RE = re.compile(r"->\s*([\w.\-]+):(\d+)")


class Module(ModuleBase):
    name = "ai_worm_network"
    category = "security"
    platforms = [Platform.DARWIN, Platform.LINUX, Platform.WIN32]
    risk_level = RiskLevel.MODERATE
    priority = 56
    depends_on = []
    estimated_duration = "10s"

    emits_codes = [
        "security.ai_worm_network.known_malicious_connection",
        "security.ai_worm_network.stepsecurity_bypass",
        "security.ai_worm_network.beaconing_detected",
        "security.ai_worm_network.token_harvesting_subprocess",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings: list[Finding] = []

        for hit in self._check_active_connections(profile):
            severity, confidence = self._severity_and_confidence(
                hit.get("ioc_severity")
            )
            findings.append(
                Finding(
                    title=(
                        f"Your computer is talking to a known malware address: {hit.get('match_value', hit.get('dest'))}"
                    ),
                    description=(
                        f"The program {hit.get('process')} is connected right now to {hit.get('dest')}. "
                        "That address is on a list of servers that worm-style malware aimed at "
                        "developers uses to send stolen data out or take orders "
                        f"(threat: {hit.get('threat', 'unknown')}).\n\n"
                        "What to do: Disconnect this computer from the internet. Then, from a "
                        "different computer or your phone, change the passwords and revoke the "
                        "access tokens (GitHub, npm, cloud) that were saved on this one. "
                        "The steps "
                        "below go through it in order."
                    ),
                    severity=severity,
                    category=self.category,
                    code="security.ai_worm_network.known_malicious_connection",
                    data={
                        "check": "known_malicious_connection",
                        "confidence": confidence,
                        "pid": hit.get("pid"),
                        "process": hit.get("process"),
                        "dest": hit.get("dest"),
                        "match_type": hit.get("match_type"),
                        "match_value": hit.get("match_value"),
                    },
                )
            )

        for hit in self._check_stepsecurity_bypass():
            findings.append(
                Finding(
                    title="Your hosts file was changed to switch off a security service",
                    description=(
                        "Your hosts file, which tells your computer where to find websites, has a "
                        "line that sends agent.stepsecurity.io nowhere. StepSecurity watches "
                        "software builds for attacks, and worm-style malware adds this line to "
                        f"blind it: {hit.get('line')}\n\n"
                        "What to do: Disconnect from the internet, then follow the steps below to "
                        "remove the line and change the passwords and tokens saved on "
                        "this computer."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    code="security.ai_worm_network.stepsecurity_bypass",
                    data={
                        "check": "stepsecurity_bypass",
                        "confidence": "high",
                        "line": hit.get("line"),
                    },
                )
            )

        familiar_hits = []
        for hit in self._check_beaconing(profile):
            if hit.get("familiar"):
                familiar_hits.append(hit)
                continue
            # An identical connection seen in two samples only shows that a
            # connection stayed open, which every API client does. Escalate
            # only when there is evidence beyond that (binary in a temp or
            # download folder). Hits without that information are treated as
            # strong so a signal is never silently downgraded.
            strong = hit.get("odd_location", True)
            if strong:
                findings.append(
                    Finding(
                        title=(
                            f"{hit.get('process')} keeps checking in with an unknown server"
                        ),
                        description=(
                            f"The program {hit.get('process')} connects to {hit.get('dest')} "
                            "again and "
                            "again at regular intervals, and it runs from an unusual folder "
                            f"({hit.get('binary') or 'unknown'}). Malware often 'checks "
                            "in' like this to "
                            "get instructions, but some ordinary apps do too, so this "
                            "needs a look rather "
                            "than panic.\n\n"
                            "If you think someone close to you may have put monitoring "
                            "software on this "
                            "computer, removing it can alert them. Talk to an advocate "
                            "first (US National "
                            "Domestic Violence Hotline: 1-800-799-7233, or text START "
                            "to 88788).\n\n"
                            "What to do: Look up the program's name. If you don't recognize "
                            "it, follow "
                            "the steps below before removing anything."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        code="security.ai_worm_network.beaconing_detected",
                        data={
                            "check": "beaconing_detected",
                            "confidence": "medium",
                            "pid": hit.get("pid"),
                            "process": hit.get("process"),
                            "dest": hit.get("dest"),
                            "binary": hit.get("binary"),
                            "interval_seconds": hit.get("interval_seconds"),
                        },
                    )
                )
            else:
                findings.append(
                    Finding(
                        title=f"Steady connection: {hit.get('process')} to {hit.get('dest')}",
                        description=(
                            f"Process {hit.get('process')} (pid {hit.get('pid')}) kept a "
                            f"connection to {hit.get('dest')} open between two checks "
                            f"~{hit.get('interval_seconds')}s apart. Developer tools, "
                            f"AI coding assistants and many apps do this routinely, and "
                            f"nothing else about this program looks unusual."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        code="security.ai_worm_network.beaconing_detected",
                        data={
                            "check": "beaconing_detected",
                            "confidence": "low",
                            "pid": hit.get("pid"),
                            "process": hit.get("process"),
                            "dest": hit.get("dest"),
                            "binary": hit.get("binary"),
                            "interval_seconds": hit.get("interval_seconds"),
                        },
                    )
                )

        if familiar_hits:
            names = sorted({str(h.get("process")) for h in familiar_hits})
            findings.append(
                Finding(
                    title=f"Steady connections from {len(names)} familiar program(s)",
                    description=(
                        "These programs kept connections open between two checks: "
                        f"{', '.join(names)}. Browsers, chat apps, cloud-sync and developer "
                        "tools do this routinely. They run from a normal install folder, "
                        "but this tool has not verified who made them."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.ai_worm_network.beaconing_detected",
                    data={
                        "check": "beaconing_detected",
                        "confidence": "low",
                        "processes": names,
                        "count": len(familiar_hits),
                    },
                )
            )

        for hit in self._check_token_harvesting_subprocess():
            findings.append(
                Finding(
                    title=f"A program read your saved GitHub sign-in: {hit.get('process')}",
                    description=(
                        f"The program {hit.get('process')} ran 'gh auth token', which prints the "
                        "GitHub access token saved on this computer. Worm-style malware does this "
                        "to take over GitHub accounts and spread through their projects. "
                        f"The command was: {hit.get('command')}\n\n"
                        "What to do: From a different computer or your phone, go to GitHub > "
                        "Settings > Applications and revoke this computer's tokens, then change "
                        "your GitHub password. The steps below cover the rest."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    code="security.ai_worm_network.token_harvesting_subprocess",
                    data={
                        "check": "token_harvesting_subprocess",
                        "confidence": "high",
                        "pid": hit.get("pid"),
                        "process": hit.get("process"),
                        "command": hit.get("command"),
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions: list[Action] = []

        for finding in findings.findings:
            confidence = finding.data.get("confidence", "low")
            check = finding.data.get("check")

            if confidence == "high" and check in (
                "known_malicious_connection",
                "token_harvesting_subprocess",
            ):
                actions.append(self._fix_kill_process(finding))
            elif confidence == "high" and check == "stepsecurity_bypass":
                actions.append(self._fix_remove_hosts_bypass(finding))
            else:
                actions.append(
                    Action(
                        title=f"Investigate: {finding.title}",
                        description=(
                            f"Manual investigation recommended. "
                            f"Confidence: {confidence}. {finding.description}"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    # -- fix actions -------------------------------------------------

    def _fix_kill_process(self, finding: Finding) -> Action:
        pid = finding.data.get("pid")
        process = finding.data.get("process", "process")
        try:
            if pid is None:
                raise ValueError("no pid available for finding")
            os.kill(pid, signal.SIGTERM)
            return Action(
                title=f"Terminate malicious process: {process} (pid {pid})",
                description=f"Sent SIGTERM to {process} (pid {pid}).",
                risk_level=RiskLevel.MODERATE,
                kind=ActionKind.MUTATION,
                executed=True,
                success=True,
            )
        except (ProcessLookupError, PermissionError, ValueError, OSError) as e:
            return Action(
                title=f"Terminate malicious process: {process} (pid {pid})",
                description=f"Failed to terminate {process} (pid {pid}).",
                risk_level=RiskLevel.MODERATE,
                kind=ActionKind.MUTATION,
                executed=True,
                success=False,
                error=str(e),
            )

    def _fix_remove_hosts_bypass(self, finding: Finding) -> Action:
        hosts_path = self._hosts_path()
        line = finding.data.get("line", "")
        try:
            content = hosts_path.read_text()
            remaining = [
                l for l in content.splitlines() if l.strip() != line.strip()
            ]
            hosts_path.write_text("\n".join(remaining) + "\n")
            return Action(
                title="Remove StepSecurity bypass entry",
                description=f"Removed hosts entry: {line}",
                risk_level=RiskLevel.MODERATE,
                kind=ActionKind.MUTATION,
                executed=True,
                success=True,
            )
        except OSError as e:
            return Action(
                title="Remove StepSecurity bypass entry",
                description=f"Failed to remove hosts entry: {line}",
                risk_level=RiskLevel.MODERATE,
                kind=ActionKind.MUTATION,
                executed=True,
                success=False,
                error=str(e),
            )

    # -- detection: active connections vs. IOC database --------------

    def _get_iocs(self):
        global _iocs_cache
        if _iocs_cache is not None:
            return _iocs_cache
        _iocs_cache = _load_iocs()
        return _iocs_cache

    def _hosts_path(self) -> Path:
        if os.name == "nt":
            system_root = os.environ.get("SystemRoot", "C:\\Windows")
            return Path(system_root) / "System32" / "drivers" / "etc" / "hosts"
        return Path("/etc/hosts")

    def _get_connection_records(self, profile: SystemProfile) -> list[dict]:
        """Run the platform connection-listing tool and parse basic
        process/pid/destination records from its output."""
        records: list[dict] = []

        if profile.platform == Platform.WIN32:
            cmd = ["netstat", "-b"]
        else:
            cmd = ["lsof", "-i", "-n", "-P"]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        except (subprocess.TimeoutExpired, OSError):
            return records

        output = result.stdout or ""
        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("COMMAND") or stripped.startswith("Proto"):
                continue

            match = _CONN_DEST_RE.search(line)
            if not match:
                continue

            parts = line.split()
            if len(parts) < 2:
                continue
            process = parts[0]
            try:
                pid = int(parts[1])
            except ValueError:
                continue

            host, port = match.group(1), match.group(2)
            records.append(
                {
                    "process": process,
                    "pid": pid,
                    "host": host,
                    "port": port,
                    "dest": f"{host}:{port}",
                }
            )

        return records

    @staticmethod
    def _severity_and_confidence(ioc_severity: str | None) -> tuple[Severity, str]:
        """Map an IOC's declared severity to a Finding severity/confidence pair."""
        if ioc_severity == "critical":
            return Severity.CRITICAL, "high"
        if ioc_severity == "warning":
            return Severity.WARNING, "medium"
        if ioc_severity == "info":
            return Severity.WARNING, "low"
        # Unknown/missing severity: treat conservatively as low confidence.
        return Severity.WARNING, "low"

    def _check_active_connections(self, profile: SystemProfile) -> list[dict]:
        hits: list[dict] = []
        iocs = self._get_iocs()
        if iocs is None:
            return hits

        domains_by_value = {d.value: d for d in iocs.domains}
        ips_by_value = {ip.value: ip for ip in iocs.ips}

        for record in self._get_connection_records(profile):
            host = record["host"]
            if host in domains_by_value:
                ioc = domains_by_value[host]
                hits.append(
                    {
                        **record,
                        "match_type": "domain",
                        "match_value": host,
                        "ioc_severity": ioc.severity,
                        "threat": ioc.threat,
                    }
                )
            elif host in ips_by_value:
                ioc = ips_by_value[host]
                hits.append(
                    {
                        **record,
                        "match_type": "ip",
                        "match_value": host,
                        "ioc_severity": ioc.severity,
                        "threat": ioc.threat,
                    }
                )

        return hits

    # -- detection: /etc/hosts StepSecurity bypass --------------------

    def _check_stepsecurity_bypass(self) -> list[dict]:
        hits: list[dict] = []
        hosts_path = self._hosts_path()
        try:
            if not hosts_path.exists():
                return hits
            with open(hosts_path, "r") as f:
                content = f.read()
        except OSError:
            return hits

        for line in content.splitlines():
            if "agent.stepsecurity.io" in line:
                hits.append({"line": line.strip()})

        return hits

    # -- detection: beaconing (repeat-sample connection comparison) ---

    _BEACON_NAME_ALLOWLIST = {
        "google", "chrome", "firefox", "safari", "brave", "arc", "edge",
        "opera", "vivaldi", "chromium",
        "dropbox", "dropboxfi", "onedrive", "icloud",
        "slack", "discord", "teams", "zoom", "telegram", "signal", "element",
        "messages", "facetime", "whatsapp",
        "spotify", "music", "apple music",
        "claude", "codex", "cursor", "copilot",
        "postgres", "mysql", "redis", "mongo", "mysqld", "mongod",
        "docker", "containerd", "colima",
        "cloudd", "nsurlsessiond", "trustd", "rapportd", "sharingd",
        "apsd", "assistantd", "bird", "callservicesd", "identityservicesd",
        "imtransferagent", "mds_stores", "netbiosd", "remoted",
        "com.apple", "apple",
        "loom", "loom-reco", "figma", "notion", "linear", "obsidian",
        "1password", "bitwarden", "lastpass", "dashlane",
        "backblaze", "carbonite", "timemachine",
        "wireguard", "tailscale", "mullvad", "nordvpn",
        "git", "ssh", "scp", "rsync", "wget", "curl",
    }

    _BEACON_PATH_ALLOWLIST = (
        "/Applications/",
        "/System/",
        "/usr/",
        "/Library/",
        "/opt/homebrew/",
        "/snap/",
        "/.local/share/claude/",
        "/.claude/",
        "/.volta/",
        "/.nvm/",
        "/node_modules/.bin/",
    )

    def _resolve_binary_path(self, pid: int) -> str | None:
        """Executable path as reported by the kernel, with symlinks resolved.

        ps/argv[0] are set by the process itself and can say anything, so they
        are not used. None means unknown (callers must not treat it as safe).
        """
        try:
            exe = f"/proc/{int(pid)}/exe"
            if os.path.islink(exe):
                return os.path.realpath(exe)
        except (OSError, ValueError):
            pass
        try:
            lib = ctypes.CDLL(
                ctypes.util.find_library("proc") or "/usr/lib/libproc.dylib", use_errno=True
            )
            buf = ctypes.create_string_buffer(4096)
            n = lib.proc_pidpath(int(pid), buf, ctypes.c_uint32(len(buf)))
            if n > 0:
                return os.path.realpath(buf.value.decode("utf-8", "surrogateescape"))
        except Exception:
            pass
        return None

    _ODD_LOCATION_MARKERS = (
        "/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/",
        "/var/folders/", "/Downloads/", "/dev/shm/",
    )

    def _is_odd_location(self, binary: str | None) -> bool:
        """True when the program is in a temp/download folder, or its location is unknown."""
        if not binary:
            return True
        return any(m in binary for m in self._ODD_LOCATION_MARKERS)

    def _is_allowlisted_beacon(self, process_name: str, pid: int, binary: str | None = None) -> bool:
        name = process_name.lower().strip()
        for allowed in self._BEACON_NAME_ALLOWLIST:
            if allowed in name:
                return True

        if binary is None:
            binary = self._resolve_binary_path(pid)
        if binary:
            for allowed_path in self._BEACON_PATH_ALLOWLIST:
                if allowed_path in binary:
                    return True

        return False

    def _check_beaconing(self, profile: SystemProfile) -> list[dict]:
        first = self._get_connection_records(profile)
        if not first:
            return []

        time.sleep(_BEACON_GAP_SECONDS)
        second = self._get_connection_records(profile)

        first_keys = {(r["pid"], r["dest"]) for r in first}
        seen = set()
        hits: list[dict] = []
        for r in second:
            key = (r["pid"], r["dest"])
            if key in first_keys and key not in seen:
                seen.add(key)
                if r["host"] in ("127.0.0.1", "::1", "localhost") or r["host"].startswith("[::1"):
                    continue  # talking to itself, not the network
                binary = self._resolve_binary_path(r["pid"])
                odd = self._is_odd_location(binary)
                # A familiar name or install folder is chosen by the program, so
                # it can lower the concern (info) but never hides the connection,
                # and never overrides a temp/download location.
                familiar = (not odd) and self._is_allowlisted_beacon(
                    r["process"], r["pid"], binary
                )
                hits.append(
                    {
                        "process": r["process"],
                        "pid": r["pid"],
                        "dest": r["dest"],
                        "binary": binary,
                        "odd_location": odd,
                        "familiar": familiar,
                        "interval_seconds": _BEACON_GAP_SECONDS,
                    }
                )

        return hits

    # -- detection: gh auth token harvesting subprocess ---------------

    def _check_token_harvesting_subprocess(self) -> list[dict]:
        hits: list[dict] = []
        try:
            result = subprocess.run(
                ["ps", "aux"], capture_output=True, text=True, timeout=10
            )
        except (subprocess.TimeoutExpired, OSError):
            return hits

        output = result.stdout or ""
        for line in output.splitlines():
            if "gh auth token" not in line:
                continue
            if line.strip().startswith("USER") and "PID" in line:
                continue

            parts = line.split(None, 10)
            if len(parts) < 11:
                continue
            try:
                pid = int(parts[1])
            except ValueError:
                continue

            command = parts[10]
            process = command.split()[0] if command else parts[0]
            hits.append({"process": process, "pid": pid, "command": command})

        return hits
