"""Record what this machine looks like, then report only what changed.

docs/ROADMAP.md P2, "Baselines and differential scans": *a single snapshot
cannot identify what changed*. Every other module in this toolkit answers "does
this look bad right now", which forces it to guess at intent — is that launch
agent malware, or something you installed on purpose? A baseline sidesteps the
guess. A launch agent that has been there since the first scan is part of the
machine. One that appeared this week is a question.

What is captured: the persistence surface (launch agents/daemons, scheduled
tasks), listening network ports, installed browser extensions, and the on/off
state of the main protections. All of it comes from the already-gathered
SystemProfile or a small number of bounded commands.

Two properties matter more than the diffing itself:

**Trust on first use.** If the machine was already compromised when the baseline
was taken, the compromise is baked into the baseline and this module will never
mention it again. That is a real limitation, not a footnote, so it is stated in
the finding text every time rather than buried here.

**Asymmetric severity.** A protection turning *off* is a warning; turning *on*
is not. A new listening port is a warning; one that closed is not. Reporting
every difference symmetrically would bury the four that matter under forty that
do not, which is how differential tools get ignored.
"""

import json
from datetime import datetime, timezone
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
from rescue.command import run
from rescue.fsbounds import is_dir_nofollow

_COMMAND_TIMEOUT = 20
_BASELINE_VERSION = 1

# Matches rescue/update/config.py's data directory convention.
_DEFAULT_STATE_DIR = Path.home() / ".local" / "share" / "rescue"

_TOFU_CAVEAT = (
    "This comparison is only as trustworthy as the first scan. If this machine "
    "was already compromised when the baseline was captured, whatever was "
    "already present is recorded as normal and will not be reported here."
)

_DARWIN_PERSISTENCE_DIRS = [
    "~/Library/LaunchAgents",
    "/Library/LaunchAgents",
    "/Library/LaunchDaemons",
]

_DARWIN_EXTENSION_DIRS = [
    "~/Library/Application Support/Google/Chrome/Default/Extensions",
    "~/Library/Application Support/BraveSoftware/Brave-Browser/Default/Extensions",
    "~/Library/Application Support/Microsoft Edge/Default/Extensions",
]

_WIN_EXTENSION_DIRS = [
    "~/AppData/Local/Google/Chrome/User Data/Default/Extensions",
    "~/AppData/Local/Microsoft/Edge/User Data/Default/Extensions",
]


class Module(ModuleBase):
    name = "security_baseline_diff"
    category = "security"
    platforms = [Platform.DARWIN, Platform.WIN32, Platform.LINUX]
    risk_level = RiskLevel.SAFE
    priority = 74
    depends_on = []
    estimated_duration = "20s"

    emits_codes = [
        "security.security_baseline_diff.baseline_established",
        "security.security_baseline_diff.new_persistence",
        "security.security_baseline_diff.new_listening_port",
        "security.security_baseline_diff.new_browser_extension",
        "security.security_baseline_diff.protection_disabled",
        "security.security_baseline_diff.no_change",
    ]

    # Overridable so tests never write to the real user state directory.
    state_dir: Path | None = None
    persistence_dirs: list[str] | None = None
    extension_dirs: list[str] | None = None

    def check(self, profile: SystemProfile) -> CheckResult:
        current = self._capture(profile)
        previous = self._load_baseline()

        if previous is None:
            saved = self._save_baseline(current)
            return CheckResult(
                module_name=self.name,
                findings=[
                    Finding(
                        title="Security baseline established",
                        description=(
                            "This is the first run, so there was nothing to compare "
                            "against. A baseline has been recorded and future scans will "
                            "report only what changed since now.\n\n"
                            f"Recorded: {len(current['persistence'])} persistence item(s), "
                            f"{len(current['listening_ports'])} listening port(s), "
                            f"{len(current['browser_extensions'])} browser extension(s), "
                            f"{len(current['protections'])} protection setting(s).\n\n"
                            + _TOFU_CAVEAT
                            + "\n\nIf you have any reason to think this machine is already "
                            "compromised, deal with that first — run the "
                            "digital_security_reset profile — and re-baseline afterwards."
                            + (
                                f"\n\nBaseline stored at: {saved}"
                                if saved
                                else "\n\nThe baseline could not be written to disk, so the "
                                "next run will start over."
                            )
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        code="security.security_baseline_diff.baseline_established",
                        data={
                            "check": "baseline_established",
                            "counts": {k: len(v) for k, v in current.items() if isinstance(v, (list, dict))},
                            "baseline_path": str(saved) if saved else None,
                        },
                    )
                ],
            )

        findings = self._diff(previous, current)

        if not findings:
            findings.append(
                Finding(
                    title="No security-relevant changes since the last baseline",
                    description=(
                        "Nothing was added to the persistence surface, no new port "
                        "started listening, no new browser extension appeared, and no "
                        "protection was turned off since "
                        f"{previous.get('captured_at', 'the baseline')}.\n\n"
                        + _TOFU_CAVEAT
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.security_baseline_diff.no_change",
                    data={
                        "check": "no_change",
                        "baseline_captured_at": previous.get("captured_at"),
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions: list[Action] = []
        checks = {f.data.get("check") for f in findings.findings}

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "new_persistence":
                actions.append(
                    Action(
                        title="Account for the new persistence items",
                        description=(
                            "These arrived since the baseline:\n\n"
                            + "\n".join(f"  {i}" for i in finding.data.get("added", []))
                            + "\n\nPersistence items run automatically. Ask what you "
                            "installed or updated around this time — a new app "
                            "legitimately adds one. If you cannot account for an entry, "
                            "that is the one to investigate: look at what it runs, and "
                            "when the file was created.\n\n"
                            "Do not delete entries you merely do not recognise; plenty of "
                            "legitimate software uses obscure names. Identify first."
                        ),
                        risk_level=RiskLevel.SAFE,
                        kind=ActionKind.GUIDANCE,
                        success=True,
                        data={"check": check},
                    )
                )

            elif check == "new_listening_port":
                actions.append(
                    Action(
                        title="Account for the newly listening ports",
                        description=(
                            "These are accepting connections and were not doing so at "
                            "baseline:\n\n"
                            + "\n".join(f"  {p}" for p in finding.data.get("added", []))
                            + "\n\nA listening port is a way in. Match each one to "
                            "software you deliberately run. Pay particular attention to "
                            "any bound to 0.0.0.0 rather than 127.0.0.1 — those are "
                            "reachable from the network, not just this machine."
                        ),
                        risk_level=RiskLevel.SAFE,
                        kind=ActionKind.GUIDANCE,
                        success=True,
                        data={"check": check},
                    )
                )

            elif check == "new_browser_extension":
                actions.append(
                    Action(
                        title="Review the new browser extensions",
                        description=(
                            "New since baseline:\n\n"
                            + "\n".join(f"  {e}" for e in finding.data.get("added", []))
                            + "\n\nExtensions can read and change every page you visit, "
                            "including your email and your bank. Remove any you did not "
                            "install yourself. An extension you did not add is a strong "
                            "signal — it usually means something else installed it."
                        ),
                        risk_level=RiskLevel.SAFE,
                        kind=ActionKind.GUIDANCE,
                        success=True,
                        data={"check": check},
                    )
                )

            elif check == "protection_disabled":
                actions.append(
                    Action(
                        title="Turn the disabled protections back on",
                        description=(
                            "These were on at baseline and are off now:\n\n"
                            + "\n".join(
                                f"  {p}" for p in finding.data.get("disabled", [])
                            )
                            + "\n\nIf you turned one off deliberately, turn it back on "
                            "when you are done. If you did not, this is the most "
                            "important finding in this report: disabling protection is "
                            "something malware does early, and something an attacker with "
                            "access does before anything else."
                        ),
                        risk_level=RiskLevel.SAFE,
                        kind=ActionKind.GUIDANCE,
                        success=True,
                        data={"check": check},
                    )
                )

        if "baseline_established" in checks or "no_change" in checks:
            actions.append(
                Action(
                    title="Re-baseline deliberately after changes you made",
                    description=(
                        "When you have installed something new and confirmed the changes "
                        "it made are expected, delete the baseline file so the next scan "
                        "records a fresh one. Otherwise your own software keeps being "
                        "reported as a change.\n\n"
                        "Only re-baseline when you are confident the current state is "
                        "clean. Re-baselining a compromised machine tells this module to "
                        "treat the compromise as normal from then on.\n\n"
                        + _TOFU_CAVEAT
                    ),
                    risk_level=RiskLevel.SAFE,
                    kind=ActionKind.GUIDANCE,
                    success=True,
                    data={"check": "rebaseline"},
                )
            )

        return FixResult(module_name=self.name, actions=actions)

    # -- capture -----------------------------------------------------------

    def _capture(self, profile: SystemProfile) -> dict:
        return {
            "version": _BASELINE_VERSION,
            "captured_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "platform": profile.platform.value,
            "persistence": sorted(self._capture_persistence(profile)),
            "listening_ports": sorted(self._capture_listening_ports(profile)),
            "browser_extensions": sorted(self._capture_extensions(profile)),
            "protections": self._capture_protections(profile),
        }

    def _persistence_dirs(self) -> list[str]:
        if self.persistence_dirs is not None:
            return self.persistence_dirs
        return _DARWIN_PERSISTENCE_DIRS

    def _capture_persistence(self, profile: SystemProfile) -> list[str]:
        if profile.platform == Platform.WIN32:
            result = run(["schtasks", "/query", "/fo", "csv"], timeout=_COMMAND_TIMEOUT)
            if not result.ok:
                return []
            names = []
            for line in result.stdout.splitlines()[1:]:
                parts = line.split(",")
                if len(parts) > 1:
                    names.append(parts[1].strip().strip('"'))
            return [n for n in names if n]

        items: list[str] = []
        for raw_dir in self._persistence_dirs():
            directory = Path(raw_dir).expanduser()
            if not is_dir_nofollow(directory):
                continue
            try:
                entries = list(directory.iterdir())
            except OSError:
                continue
            items.extend(
                f"{directory}/{e.name}" for e in entries if e.suffix == ".plist"
            )
        return items

    def _capture_listening_ports(self, profile: SystemProfile) -> list[str]:
        """Listening sockets, as 'address:port'. Never records process arguments."""
        if profile.platform == Platform.WIN32:
            result = run(["netstat", "-an"], timeout=_COMMAND_TIMEOUT)
        else:
            result = run(["netstat", "-an"], timeout=_COMMAND_TIMEOUT)
        if not result.ok:
            return []

        ports = set()
        for line in result.stdout.splitlines():
            if "LISTEN" not in line.upper():
                continue
            parts = line.split()
            for token in parts:
                if (":" in token or "." in token) and any(c.isdigit() for c in token):
                    ports.add(token)
                    break
        return sorted(ports)

    def _extension_dirs(self, profile: SystemProfile) -> list[str]:
        if self.extension_dirs is not None:
            return self.extension_dirs
        return (
            _WIN_EXTENSION_DIRS
            if profile.platform == Platform.WIN32
            else _DARWIN_EXTENSION_DIRS
        )

    def _capture_extensions(self, profile: SystemProfile) -> list[str]:
        found: list[str] = []
        for raw_dir in self._extension_dirs(profile):
            directory = Path(raw_dir).expanduser()
            if not is_dir_nofollow(directory):
                continue
            try:
                entries = list(directory.iterdir())
            except OSError:
                continue
            found.extend(f"{directory.name}/{e.name}" for e in entries if is_dir_nofollow(e))
        return found

    def _capture_protections(self, profile: SystemProfile) -> dict:
        """On/off state of the main protections, as a name -> bool map."""
        protections: dict[str, bool] = {}

        if profile.platform == Platform.DARWIN:
            firewall = run(
                ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
                timeout=_COMMAND_TIMEOUT,
            )
            if firewall.ok:
                protections["Application firewall"] = "enabled" in firewall.stdout.lower()

            filevault = run(["fdesetup", "status"], timeout=_COMMAND_TIMEOUT)
            if filevault.ok:
                protections["FileVault"] = "is on" in filevault.stdout.lower()

            sip = run(["csrutil", "status"], timeout=_COMMAND_TIMEOUT)
            if sip.ok:
                protections["System Integrity Protection"] = "enabled" in sip.stdout.lower()

        elif profile.platform == Platform.WIN32:
            defender = run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "(Get-MpComputerStatus).RealTimeProtectionEnabled",
                ],
                timeout=_COMMAND_TIMEOUT,
            )
            if defender.ok:
                protections["Defender real-time protection"] = (
                    "true" in defender.stdout.strip().lower()
                )

        return protections

    # -- storage -----------------------------------------------------------

    def _baseline_path(self) -> Path:
        root = Path(self.state_dir) if self.state_dir is not None else _DEFAULT_STATE_DIR
        return root / "security_baseline.json"

    def _load_baseline(self) -> dict | None:
        path = self._baseline_path()
        try:
            data = json.loads(path.read_text())
        except (OSError, ValueError):
            return None
        if not isinstance(data, dict) or data.get("version") != _BASELINE_VERSION:
            # An unreadable or older-format baseline is treated as absent rather
            # than half-compared against a schema it does not match.
            return None
        return data

    def _save_baseline(self, snapshot: dict) -> Path | None:
        path = self._baseline_path()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(snapshot, indent=2, sort_keys=True))
        except OSError:
            return None
        return path

    # -- diff --------------------------------------------------------------

    def _diff(self, previous: dict, current: dict) -> list[Finding]:
        findings: list[Finding] = []
        when = previous.get("captured_at", "the baseline")

        # Written as `code="..."` keyword literals, not built from `check`:
        # test_module_code_consistency matches emits_codes against the code=
        # string literals in this file, and an f-string is invisible to it.
        additions = [
            dict(
                key="persistence",
                check="new_persistence",
                code="security.security_baseline_diff.new_persistence",
                label="persistence item",
                severity=Severity.WARNING,
            ),
            dict(
                key="listening_ports",
                check="new_listening_port",
                code="security.security_baseline_diff.new_listening_port",
                label="listening port",
                severity=Severity.WARNING,
            ),
            dict(
                key="browser_extensions",
                check="new_browser_extension",
                code="security.security_baseline_diff.new_browser_extension",
                label="browser extension",
                severity=Severity.WARNING,
            ),
        ]

        for spec in additions:
            key, check = spec["key"], spec["check"]
            code, label, severity = spec["code"], spec["label"], spec["severity"]
            before = set(previous.get(key) or [])
            after = set(current.get(key) or [])
            added = sorted(after - before)
            if not added:
                continue
            findings.append(
                Finding(
                    title=f"{len(added)} new {label}(s) since {when}",
                    description=(
                        f"These were not present at the baseline taken {when}:\n\n"
                        + "\n".join(f"  {item}" for item in added)
                        + "\n\nA new entry is not automatically bad — installing software "
                        "adds them. It is worth checking because you can now ask a much "
                        "sharper question than 'does this look suspicious': did you "
                        "install something around this time?\n\n"
                        + _TOFU_CAVEAT
                    ),
                    severity=severity,
                    category=self.category,
                    code=code,
                    data={
                        "check": check,
                        "added": added,
                        "baseline_captured_at": when,
                    },
                )
            )

        before_prot = previous.get("protections") or {}
        after_prot = current.get("protections") or {}
        disabled = sorted(
            name
            for name, was_on in before_prot.items()
            # Only a genuine on -> off transition. A protection that has vanished
            # from the current capture (command unavailable) is not "disabled".
            if was_on and after_prot.get(name) is False
        )
        if disabled:
            findings.append(
                Finding(
                    title=f"{len(disabled)} protection(s) turned off since {when}",
                    description=(
                        "These were enabled at the baseline and are disabled now:\n\n"
                        + "\n".join(f"  {name}" for name in disabled)
                        + "\n\nIf you did not turn these off yourself, treat it as the "
                        "most serious item in this report. Disabling protection is an "
                        "early step for both malware and a person with access to the "
                        "machine.\n\n"
                        + _TOFU_CAVEAT
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    code="security.security_baseline_diff.protection_disabled",
                    data={
                        "check": "protection_disabled",
                        "disabled": disabled,
                        "baseline_captured_at": when,
                    },
                )
            )

        return findings
