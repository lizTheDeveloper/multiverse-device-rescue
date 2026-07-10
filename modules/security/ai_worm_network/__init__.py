import os
import re
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

    def check(self, profile: SystemProfile) -> CheckResult:
        findings: list[Finding] = []

        for hit in self._check_active_connections(profile):
            severity, confidence = self._severity_and_confidence(
                hit.get("ioc_severity")
            )
            findings.append(
                Finding(
                    title=(
                        f"Connection to known malicious "
                        f"{hit.get('match_type', 'host')}: {hit.get('match_value', hit.get('dest'))}"
                    ),
                    description=(
                        f"Process {hit.get('process')} (pid {hit.get('pid')}) has an "
                        f"active connection to {hit.get('dest')}, which matches a known "
                        f"AI worm C2/exfiltration indicator of compromise "
                        f"(threat: {hit.get('threat', 'unknown')})."
                    ),
                    severity=severity,
                    category=self.category,
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
                    title="StepSecurity agent bypass in hosts file",
                    description=(
                        "The hosts file contains an entry redirecting "
                        "agent.stepsecurity.io, which can disable StepSecurity's "
                        f"CI/CD security monitoring: {hit.get('line')}"
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={
                        "check": "stepsecurity_bypass",
                        "confidence": "high",
                        "line": hit.get("line"),
                    },
                )
            )

        for hit in self._check_beaconing(profile):
            findings.append(
                Finding(
                    title=f"Beaconing pattern detected: {hit.get('process')}",
                    description=(
                        f"Process {hit.get('process')} (pid {hit.get('pid')}) maintained "
                        f"an identical connection to {hit.get('dest')} across repeated "
                        f"samples ~{hit.get('interval_seconds')}s apart, suggesting "
                        f"periodic C2 polling."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "beaconing_detected",
                        "confidence": "medium",
                        "pid": hit.get("pid"),
                        "process": hit.get("process"),
                        "dest": hit.get("dest"),
                        "interval_seconds": hit.get("interval_seconds"),
                    },
                )
            )

        for hit in self._check_token_harvesting_subprocess():
            findings.append(
                Finding(
                    title=f"Token harvesting subprocess detected: {hit.get('process')}",
                    description=(
                        f"Process {hit.get('process')} (pid {hit.get('pid')}) executed "
                        f"'gh auth token' — a known technique for harvesting GitHub "
                        f"credentials used by AI worm malware: {hit.get('command')}"
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
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

    _BEACON_PROCESS_ALLOWLIST = {
        "google", "chrome", "firefox", "safari", "brave", "arc", "edge",
        "opera", "vivaldi", "chromium",
        "dropbox", "dropboxfi", "onedrive", "icloud",
        "slack", "discord", "teams", "zoom", "telegram", "signal", "element",
        "messages", "facetime", "whatsapp",
        "spotify", "music", "apple music",
        "claude", "codex", "cursor", "code", "copilot",
        "postgres", "mysql", "redis", "mongo", "mysqld", "mongod",
        "node", "python", "ruby", "java", "go", "deno", "bun",
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

    def _is_allowlisted_beacon(self, process_name: str) -> bool:
        name = process_name.lower().strip()
        for allowed in self._BEACON_PROCESS_ALLOWLIST:
            if allowed in name:
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
                if self._is_allowlisted_beacon(r["process"]):
                    continue
                hits.append(
                    {
                        "process": r["process"],
                        "pid": r["pid"],
                        "dest": r["dest"],
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
