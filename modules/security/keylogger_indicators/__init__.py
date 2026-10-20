import re
import subprocess
import time
from pathlib import Path

from rescue.attribution import maker_for_signer
from rescue.code_requirement import APPLE, signer_for
from rescue.command import run
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

# The removal warning every keyboard-access warning carries (never weaken it).
_REMOVAL_WARNING = (
    "If you think someone close to you set this up to monitor you, "
    "removing it can alert them. Talk to an advocate first (US National "
    "Domestic Violence Hotline: 1-800-799-7233, or text START to "
    "88788).\n\n"
)

# The signers macOS's own permission record must name for an app using one
# of these familiar names. Each Team ID is in rescue/attribution_names.json
# (a test keeps them there); APPLE is Apple's own anchor. A familiar name
# signed by anyone else is an impostor signal. Names not listed here stay
# unverified whatever the record says.
FAMILIAR_SIGNERS = (
    ("com.apple.", frozenset({APPLE, "74J34U3R6X"})),
    ("com.microsoft.", frozenset({"UBF8T346G9"})),
    ("com.google.", frozenset({"EQHXZ8M8AV"})),
    ("com.valvesoftware.", frozenset({"MXGJJ98X76"})),
)

# Familiar apps that start other programs: a terminal, a script runner, a code
# editor with a built-in terminal. macOS lets what they start use their
# keyboard access, so a confirmed maker doesn't vouch for what runs inside.
RUNS_OTHER_PROGRAMS = frozenset({
    "com.apple.Terminal",
    "com.apple.ScriptEditor2",
    "com.apple.Automator",
    "com.apple.shortcuts",
    "com.microsoft.VSCode",
    "com.microsoft.VSCodeInsiders",
})

# Reading a grant's code requirement: one small csreq call per row, bounded.
CSREQ_TIMEOUT = 3.0
CSREQ_BUDGET_SECONDS = 15.0
CSREQ_MAX_CALLS = 40
_CSREQ_MAX_BYTES = 4096
_CSREQ_MAGIC = bytes.fromhex("fade0c00")
SQLITE_TIMEOUT = 5.0


def expected_signers(bundle_id: str) -> frozenset:
    for prefix, signers in FAMILIAR_SIGNERS:
        if bundle_id.startswith(prefix):
            return signers
    return frozenset()


class Module(ModuleBase):
    name = "keylogger_indicators"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "10s"

    emits_codes = [
        "security.keylogger_indicators.input_monitoring_access",
        "security.keylogger_indicators.known_keyloggers",
        "security.keylogger_indicators.suspicious_input_monitoring",
        "security.keylogger_indicators.cgeventtap_usage",
    ]

    # Known keylogger process names to flag as CRITICAL
    KNOWN_KEYLOGGERS = {
        "aobo",
        "kidlogger",
        "spyrix",
        "cocospy",
        "mspy",
        "flexispy",
        "hoverwatch",
        "refog",
        "elite_keylogger",
        "perfect_keylogger",
        "ardamax",
    }

    # Well-known apps that legitimately need Input Monitoring
    WELL_KNOWN_INPUT_MONITORING_APPS = {
        "com.apple.Finder",
        "com.apple.systempreferences",
        "com.apple.Systempreferences",
        "com.apple.systemsettings",
        "com.apple.dt.Xcode",
        "com.apple.Terminal",
        "com.googlecode.iterm2",
        "com.sublimetext.3",
        "com.microsoft.VSCode",
        "org.gnu.emacs",
        "org.alacritty",
        "io.wezfurlong.wezterm",
        "com.apple.Automator",
        "com.apple.Script Editor",
        "org.hammerspoon.Hammerspoon",
    }

    # Well-known vendors whose apps legitimately ask for Input Monitoring
    # (game controllers, gaming keyboards/mice, remappers, password managers).
    # These are reported as informational, not as suspicious.
    WELL_KNOWN_VENDOR_PREFIXES = (
        "com.valvesoftware.",  # Steam (controller / Steam Input)
        "com.logitech.",
        "com.logi.",
        "com.razer.",
        "com.corsair.",
        "com.steelseries.",
        "com.elgato.",
        "org.pqrs.",  # Karabiner-Elements
        "com.hegenberg.",  # BetterTouchTool
        "com.1password.",
        "com.agilebits.",
        "com.microsoft.",
        "com.google.",
    )

    def _is_well_known(self, app: str) -> bool:
        return (
            app in self.WELL_KNOWN_INPUT_MONITORING_APPS
            or app.startswith("com.apple.")
            or app.startswith(self.WELL_KNOWN_VENDOR_PREFIXES)
        )

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check 1: Query TCC database for Input Monitoring permissions
        grants = self._get_input_monitoring_grants()
        input_monitoring_apps = list(grants)

        if input_monitoring_apps:
            findings.append(
                Finding(
                    title=f"Keyboard access: {len(input_monitoring_apps)} app(s)",
                    description=(
                        f"{len(input_monitoring_apps)} app(s) have been granted Input Monitoring "
                        f"access: {', '.join(sorted(input_monitoring_apps))}. "
                        "Input Monitoring allows apps to capture keyboard and mouse input. "
                        "Review to ensure only trusted apps have this access."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.keylogger_indicators.input_monitoring_access",
                    data={"check": "input_monitoring_access", "apps": sorted(input_monitoring_apps)},
                )
            )

        # Check 2: Flag known keyloggers as CRITICAL
        known_keyloggers_found = []
        for app in input_monitoring_apps:
            for keylogger in self.KNOWN_KEYLOGGERS:
                if keylogger.lower() in app.lower():
                    known_keyloggers_found.append(app)
                    break

        if known_keyloggers_found:
            findings.append(
                Finding(
                    title=f"Known keylogger app found: {', '.join(known_keyloggers_found)}",
                    description=(
                        f"We found {len(known_keyloggers_found)} app(s) with keyboard "
                        f"access that match known spyware: {', '.join(known_keyloggers_found)}. "
                        "These apps can secretly record everything you type, including "
                        "passwords and private messages. This is a serious sign that "
                        "someone may be spying on you.\n\n"
                        "If you think a partner, ex, or family member set this up to "
                        "monitor you, removing it can alert them. Talk to an advocate "
                        "first (US National Domestic Violence Hotline: 1-800-799-7233, "
                        "or text START to 88788).\n\n"
                        "What to do: If you are safe to proceed, go to System Settings "
                        "> Privacy & Security > Input Monitoring and turn off access "
                        "for these apps. Then, move the app folders to a safe location "
                        "to keep as evidence."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    code="security.keylogger_indicators.known_keyloggers",
                    data={"check": "known_keyloggers", "apps": known_keyloggers_found},
                )
            )

        # Check 3: Flag suspicious apps with Input Monitoring access
        suspicious_apps = []
        claimed_known_apps = []
        for app in input_monitoring_apps:
            if not self._is_well_known(app):
                suspicious_apps.append(app)
            else:
                claimed_known_apps.append(app)

        # A bundle ID is just a string any app can choose, so a familiar-looking
        # ID is never proof of who made the app. What macOS itself enforces is
        # the grant's code requirement: when it pins the expected company's
        # Team ID, that company's code is the only code that can use the
        # access. Anything else stays visible (info), never dropped.
        verified, impostors = [], []
        for app in claimed_known_apps:
            status, signer = self._familiar_status(app, grants.get(app))
            if status == "verified":
                verified.append({
                    "bundle_id": app,
                    "team_id": signer,
                    "maker": maker_for_signer(signer),
                    "verified_by": "macos_code_requirement",
                    **({"runs_other_programs": True} if app in RUNS_OTHER_PROGRAMS else {}),
                })
            elif status == "impostor":
                impostors.append({"bundle_id": app, "team_id": signer, "maker": maker_for_signer(signer)})
        verified_ids = {v["bundle_id"] for v in verified}
        impostor_ids = {i["bundle_id"] for i in impostors}
        unverified_known = [a for a in claimed_known_apps if a not in verified_ids and a not in impostor_ids]

        if verified:
            verified.sort(key=lambda v: v["bundle_id"])
            named = ", ".join(f"{v['bundle_id']} ({v['maker']})" for v in verified)
            hosts = [v["bundle_id"] for v in verified if v.get("runs_other_programs")]
            shared = (
                f" Programs started from {', '.join(hosts)} can use the same access, so "
                "a script run there can read keys too."
                if hosts else ""
            )
            findings.append(
                Finding(
                    title=(
                        f"Keyboard access: {len(verified)} app(s) with familiar names, "
                        "maker confirmed by macOS"
                    ),
                    description=(
                        f"These app(s) have Input Monitoring access: {named}. macOS's own "
                        "permission record says only code signed by the company named can "
                        "use this access." + shared + " If you don't remember installing "
                        "one, turn its access off in System Settings > Privacy & Security > "
                        "Input Monitoring."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.keylogger_indicators.suspicious_input_monitoring",
                    data={
                        "check": "claimed_vendor_input_monitoring",
                        "apps": [v["bundle_id"] for v in verified],
                        "verified_apps": verified,
                    },
                )
            )

        if unverified_known:
            findings.append(
                Finding(
                    title=(
                        f"Keyboard access: {len(unverified_known)} app(s) with familiar names"
                    ),
                    description=(
                        f"These app(s) have Input Monitoring access and use the name of a "
                        f"familiar company or app: {', '.join(sorted(unverified_known))}. "
                        "This tool has not verified who actually made them, because an app can "
                        "pick any name. If you don't remember installing one, turn its access "
                        "off in System Settings > Privacy & Security > Input Monitoring."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.keylogger_indicators.suspicious_input_monitoring",
                    data={
                        "check": "claimed_vendor_input_monitoring",
                        "apps": sorted(unverified_known),
                    },
                )
            )

        if impostors:
            impostors.sort(key=lambda i: i["bundle_id"])
            names = ", ".join(i["bundle_id"] for i in impostors)
            signed_by = ", ".join(
                f"{i['bundle_id']}: {i['maker'] or 'an unknown developer'} (Team ID {i['team_id']})"
                for i in impostors
            )
            findings.append(
                Finding(
                    title=f"Apps with borrowed names have keyboard access: {names}",
                    description=(
                        f"{len(impostors)} app(s) have permission to see your keyboard input "
                        f"and use the name of a familiar company: {names}. But macOS's own "
                        "permission record says the code allowed to use that access was "
                        f"signed by someone else ({signed_by}). Borrowing a familiar name is "
                        "a common disguise for spying software.\n\n"
                        + _REMOVAL_WARNING
                        + "What to do: Go to System Settings > Privacy & Security > Input "
                        "Monitoring. Turn off access for any app you don't recognize "
                        "or didn't install yourself."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.keylogger_indicators.suspicious_input_monitoring",
                    data={
                        "check": "familiar_name_other_signer",
                        "apps": [i["bundle_id"] for i in impostors],
                        "signers": impostors,
                    },
                )
            )

        if suspicious_apps:
            findings.append(
                Finding(
                    title=(
                        f"Unrecognized apps have keyboard access: {', '.join(sorted(suspicious_apps))}"
                    ),
                    description=(
                        f"{len(suspicious_apps)} app(s) have permission to see your keyboard "
                        f"input, but we don't recognize them: {', '.join(sorted(suspicious_apps))}. "
                        "Many normal tools (like keyboard remappers or game launchers) "
                        "ask for this, so it is not automatically a sign of spying. However, "
                        "if you do not remember installing one, it is worth checking.\n\n"
                        + _REMOVAL_WARNING
                        + "What to do: Go to System Settings > Privacy & Security > Input "
                        "Monitoring. Turn off access for any app you don't recognize "
                        "or didn't install yourself."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.keylogger_indicators.suspicious_input_monitoring",
                    data={"check": "suspicious_input_monitoring", "apps": suspicious_apps},
                )
            )

        # Check 4: Check for CGEventTap usage
        cgeventtap_processes = self._check_cgeventtap_usage()
        if cgeventtap_processes:
            findings.append(
                Finding(
                    title=(
                        f"Apps are actively capturing your keystrokes: {', '.join(sorted(cgeventtap_processes))}"
                    ),
                    description=(
                        f"{len(cgeventtap_processes)} running process(es) are currently "
                        f"using a system tool to capture your keyboard and mouse: {', '.join(sorted(cgeventtap_processes))}. "
                        "This means these programs are actively listening to your input "
                        "right now. While some legitimate tools do this, it is a common "
                        "method for spyware to steal passwords.\n\n"
                        "If you think someone close to you set this up to monitor you, "
                        "removing it can alert them. Talk to an advocate first (US National "
                        "Domestic Violence Hotline: 1-800-799-7233, or text START to "
                        "88788).\n\n"
                        "What to do: Check if you recognize these names. If not, go to "
                        "System Settings > Privacy & Security > Input Monitoring and "
                        "turn off access for the corresponding apps to stop the capture."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.keylogger_indicators.cgeventtap_usage",
                    data={"check": "cgeventtap_usage", "processes": sorted(cgeventtap_processes)},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "input_monitoring_access":
                apps = finding.data.get("apps", [])
                app_list = ", ".join(sorted(apps))
                actions.append(
                    Action(
                        title="Review and manage Input Monitoring access",
                        description=(
                            f"Apps with Input Monitoring access: {app_list}.\n"
                            "To manage Input Monitoring permissions, open System Settings > "
                            "Privacy & Security > Input Monitoring. Review each app and "
                            "toggle off access for apps you don't trust or don't need."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "known_keyloggers":
                apps = finding.data.get("apps", [])
                app_list = ", ".join(sorted(apps))
                actions.append(
                    Action(
                        title="Remove known keyloggers immediately",
                        description=(
                            f"Known keylogger application(s) found: {app_list}.\n"
                            "IMMEDIATE ACTION REQUIRED:\n"
                            "1. Disconnect from the internet to prevent data exfiltration\n"
                            "2. Boot into Safe Mode or Safe Boot\n"
                            "3. Use Malwarebytes, CleanMyMac, or similar anti-malware to remove\n"
                            "4. Revoke all permissions in System Settings > Privacy & Security\n"
                            "5. Change all passwords from a clean device\n"
                            "6. Consider professional help if the malware persists\n\n"
                            "These applications steal passwords, credit cards, and private messages."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check in ("suspicious_input_monitoring", "familiar_name_other_signer"):
                apps = finding.data.get("apps", [])
                app_list = ", ".join(sorted(apps))
                actions.append(
                    Action(
                        title="Revoke Input Monitoring access from suspicious apps",
                        description=(
                            f"Suspicious apps with Input Monitoring access: {app_list}.\n"
                            "To revoke access, open System Settings > Privacy & Security > "
                            "Input Monitoring and remove these apps from the list. If you "
                            "installed any of these apps, consider uninstalling them using "
                            "System Settings > General > Software > AppName > Remove, or "
                            "by dragging the app to Trash."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "cgeventtap_usage":
                processes = finding.data.get("processes", [])
                processes_list = ", ".join(processes)
                actions.append(
                    Action(
                        title="Investigate CGEventTap usage",
                        description=(
                            f"Processes using CGEventTap: {processes_list}.\n"
                            "CGEventTap allows capturing keyboard and mouse events. To investigate:\n"
                            "1. Research these processes to understand their legitimate purpose\n"
                            "2. Use Activity Monitor to examine process details\n"
                            "3. Check System Settings > Privacy & Security for Input Monitoring access\n"
                            "4. Uninstall or disable applications using CGEventTap if not trusted\n"
                            "5. Consider running anti-malware scans if usage is suspicious"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _exec(self, args: list[str], timeout: float, input: bytes | None = None):
        """One bounded command (rescue.command.run); None if it failed or timed out."""
        try:
            res = run(args, timeout=timeout, input=input)
        except Exception:
            return None
        if getattr(res, "returncode", None) != 0 or getattr(res, "timed_out", False) is True:
            return None
        return res

    def _familiar_status(self, app: str, grant_rows) -> tuple[str, str | None]:
        """("verified" | "impostor" | "unverified", signer) for a familiar name.

        Verified: every TCC row for it is a bundle-id row whose code requirement
        pins one signer, and that signer is the one expected for the name.
        Impostor: some row's requirement pins a signer that isn't. Anything we
        can't read stays unverified, as before.
        """
        expected = expected_signers(app)
        rows = grant_rows or []
        signers = [r.get("signer") for r in rows]
        wrong = [s for s in signers if s is not None and s not in expected]
        if expected and wrong:
            return "impostor", wrong[0]
        if (expected and rows and all(r.get("client_type") == 0 for r in rows)
                and len(set(signers)) == 1 and signers[0] in expected
                and maker_for_signer(signers[0])):
            return "verified", signers[0]
        return "unverified", None

    def _requirement_text(self, blob: bytes) -> str | None:
        """A csreq blob as text, via /usr/bin/csreq reading it from stdin."""
        if not blob or len(blob) > _CSREQ_MAX_BYTES or not blob.startswith(_CSREQ_MAGIC):
            return None
        res = self._exec(["/usr/bin/csreq", "-r", "-", "-t"], timeout=CSREQ_TIMEOUT, input=blob)
        if res is None:
            return None
        text = res.stdout if isinstance(res.stdout, str) else None
        return text.strip() if text else None

    def _get_input_monitoring_grants(self) -> dict[str, list[dict]]:
        """Apps with Input Monitoring access, each with its TCC rows.

        {client: [{"client_type": int | None, "signer": str | None}, ...]},
        in first-seen order. ``signer`` is the Team ID (or Apple) that the row's
        code requirement pins for that client, or None when there is none or
        it can't be read. Read-only; {} on any failure.
        """
        system_db = "/Library/Application Support/com.apple.TCC/TCC.db"
        user_db = str(Path.home() / "Library/Application Support/com.apple.TCC/TCC.db")
        grants: dict[str, list[dict]] = {}
        deadline = time.monotonic() + CSREQ_BUDGET_SECONDS
        calls = 0
        for db_path in [system_db, user_db]:
            rows = self._read_rows(db_path)
            for client, client_type, blob in rows:
                signer = None
                if blob and client_type == 0 and calls < CSREQ_MAX_CALLS and time.monotonic() < deadline:
                    calls += 1
                    signer = signer_for(self._requirement_text(blob), client)
                grants.setdefault(client, []).append({"client_type": client_type, "signer": signer})
        return grants

    def _read_rows(self, db_path: str) -> list[tuple[str, int | None, bytes]]:
        """(client, client_type, csreq bytes) rows; hex() keeps the output unambiguous."""
        res = self._exec(
            [
                "sqlite3",
                db_path,
                "SELECT hex(client), client_type, hex(csreq) FROM access "
                "WHERE service='kTCCServiceListenEvent' AND auth_value=2",
            ],
            timeout=SQLITE_TIMEOUT,
        )
        if res is not None:
            return _parse_rows(res.stdout)
        # An older database without these columns: names only, nothing verified.
        res = self._exec(
            [
                "sqlite3",
                db_path,
                "SELECT client FROM access WHERE service='kTCCServiceListenEvent' AND auth_value=2",
            ],
            timeout=SQLITE_TIMEOUT,
        )
        if res is None:
            return []
        return [(line, None, b"") for line in (res.stdout or "").split("\n") if line.strip()]

    def _check_cgeventtap_usage(self) -> list[str]:
        """Check for CGEventTap usage in system logs.

        Returns list of processes using CGEventTap.
        Returns [] on any failure.
        """
        try:
            result = subprocess.run(
                [
                    "log",
                    "show",
                    "--last",
                    "1h",
                    "--predicate",
                    # Leave out the system log tool's record of this very query,
                    # by path so that a process merely named "log" still counts.
                    "eventMessage CONTAINS 'CGEventTap' "
                    "AND processImagePath != '/usr/bin/log'",
                    "--style",
                    "compact",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return []

            return _cgeventtap_processes(result.stdout)
        except Exception:
            return []


# `log show --style compact` lines look like
#   2026-10-15 04:10:01.123 Df loginwindow[123:456] message ...
# after a "Timestamp  Ty  Process[PID:TID]" header. The process name sits
# between the type column and "[pid", and may contain spaces.
_COMPACT_LOG_LINE = re.compile(r"^\d{4}-\d{2}-\d{2}\s+\S+\s+\S+\s+(.+?)\[\d+")


def _cgeventtap_processes(output: str) -> list[str]:
    """Process names from compact log lines; headers and noise are skipped."""
    names = set()
    for line in (output or "").splitlines():
        m = _COMPACT_LOG_LINE.match(line.strip())
        if m:
            names.add(m.group(1).strip())
    return sorted(names)


def _parse_rows(output) -> list[tuple[str, int | None, bytes]]:
    """Rows of "HEXCLIENT|client_type|HEXCSREQ"; malformed rows are skipped."""
    rows = []
    for line in (output or "").splitlines():
        parts = line.strip().split("|")
        if len(parts) != 3:
            continue
        try:
            client = bytes.fromhex(parts[0]).decode("utf-8")
            blob = bytes.fromhex(parts[2])
        except ValueError:
            continue
        if not client or "\n" in client:
            continue
        client_type = int(parts[1]) if parts[1].isdigit() else None
        rows.append((client, client_type, blob))
    return rows
