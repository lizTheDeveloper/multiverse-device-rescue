"""rootkit_scanners: rkhunter and chkrootkit, when they're installed.

Runs the two long-standing open-source rootkit scanners, read-only:

    rkhunter --check --sk --rwo --nocolors --nolog --nomow
    chkrootkit -q

Each is used only from a fixed system location (never from PATH), only when
the file and every folder above it are real folders (no links) that belong to
root and no one else can change, checked again right before it runs, and only
when the checkup itself runs as root. Each runs in a folder only root can
change (chkrootkit in its helper folder, which it runs ./chkproc and the
other helpers from; rkhunter in /), never in the scan's own working folder,
and only as root, which both tools need. Without
root they don't run, and the finding says so: couldn't run is not clean.
``--nolog`` keeps rkhunter from writing its log; neither tool is asked to
update anything (no ``--update``, no ``--propupd``).

Both read many files and are slow, so they're opt-in: a plain checkup
only says whether they're installed. A profile turns them on with
``module_config: {rootkit_scanners: {run_scanners: true}}`` (the
deep_startup_check, linux_security_checkup and infected_device profiles).

Both tools are known for false alarms. Each warning is matched against the
well-known harmless causes (a command a distribution ships as a script,
network tools that open raw sockets, files changed by ordinary updates,
hidden files packages leave in /usr/lib, SSH settings...) and explained in
plain words in one note. Only what is left becomes a lead.

On macOS both run, but see so little that they're no substitute for the Mac
checks: rkhunter's last release (1.4.6) is from 2018, its Mac signatures stop
at malware from about 2016, and it doesn't know about background items,
system extensions or configuration profiles. The files it fingerprints (/bin,
/usr/bin, /sbin) are on the sealed system volume, which macOS itself checks at
every start. chkrootkit's Mac support is a handful of old checks.
"""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from typing import Any

from rescue.command import run
from rescue.models import (
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

TOOL_TIMEOUT = 600
# Fixed places each tool is installed by distribution packages, Homebrew or
# `make install`. PATH is never searched: under sudo it is whatever the caller had.
CANDIDATES = {
    "rkhunter": ("/usr/bin/rkhunter", "/usr/sbin/rkhunter", "/usr/local/bin/rkhunter",
                 "/usr/local/sbin/rkhunter", "/opt/homebrew/bin/rkhunter"),
    "chkrootkit": ("/usr/sbin/chkrootkit", "/usr/bin/chkrootkit", "/usr/local/sbin/chkrootkit",
                   "/usr/local/bin/chkrootkit", "/opt/homebrew/bin/chkrootkit",
                   "/opt/homebrew/sbin/chkrootkit"),
}
# Where distribution packages put chkrootkit's helper programs.
CHKROOTKIT_HELPER_DIRS = ("/usr/lib/chkrootkit", "/usr/libexec/chkrootkit", "/usr/lib64/chkrootkit")
_TOOL = object()  # filled in at run time (shown as "…" in docs/commands.md)
RKHUNTER_ARGS = [_TOOL, "--check", "--sk", "--rwo", "--nocolors", "--nolog", "--nomow"]
CHKROOTKIT_ARGS = [_TOOL, "-q"]
MAX_LEADS = 30
MAX_DETAIL_LINES = 20

# --- what the warnings mean --------------------------------------------------
#
# Each entry: a key, a pattern matched against the warning and its detail
# lines, and the plain explanation shown to the person. Order matters: the
# first match wins.

FALSE_ALARMS: list[tuple[str, re.Pattern, str]] = [
    ("script_command", re.compile(r"has been replaced by a script", re.I),
     "Some Linux systems ship a few everyday commands as small scripts on purpose "
     "(Debian and Ubuntu do this for lwp-request, egrep, fgrep, which and ldd, for "
     "example). rkhunter expects them to be programs and warns about each one. This "
     "is the most common false alarm it gives."),
    ("no_baseline", re.compile(r"rkhunter\.dat|no copy of the (passwd|group) file|"
                               r"file properties (check has been disabled|database)", re.I),
     "rkhunter compares system files with a snapshot it takes when it's set up "
     "(`rkhunter --propupd`). There is no snapshot on this computer yet, so it can't "
     "make that comparison. This is about how rkhunter was set up, not about an "
     "infection. Reclaim City doesn't take the snapshot for you: a snapshot of a "
     "computer that may already be infected would make the infection look normal."),
    ("properties_changed", re.compile(r"file properties have changed|"
                                      r"(passwd|group) file (changes|has changed)", re.I),
     "rkhunter compares files with the snapshot it took when it was set up. Ordinary "
     "system updates (and adding a user account) change those files, and rkhunter "
     "can't tell an update from tampering. If you've installed updates since it was "
     "set up, this is expected. To check the files against your distribution's own "
     "records instead, run `sudo debsums -c` (Debian, Ubuntu) or `sudo rpm -Va` "
     "(Fedora, openSUSE)."),
    ("network_tools", re.compile(r"packet cap|listening on the network|raw socket|"
                                 r"PACKET SNIFFER|PF_PACKET|is PROMISC", re.I),
     "Programs that set up your network connection (NetworkManager, dhclient, "
     "dhcpcd, wpa_supplicant, systemd-networkd) open the same kind of low-level "
     "network connection that eavesdropping tools use, so both scanners flag them. "
     "If the program named is one of those, it's harmless."),
    ("shared_memory", re.compile(r"shared memory segment|/dev/shm", re.I),
     "Desktop programs (the display server, browsers, sound and database servers) "
     "keep large blocks of shared memory, which rkhunter reports as suspicious. "
     "Names like pulse-shm, PostgreSQL, chromium or Xorg are expected."),
    ("ssh_setting", re.compile(r"\bSSH\b|PermitRootLogin|sshd", re.I),
     "This is about a setting in the SSH server (remote login), not something "
     "installed. Whether it matters depends on whether you use SSH; the SSH "
     "hardening check covers it."),
    ("config_quirk", re.compile(r"configuration option|Invalid .*option|WEB_CMD|"
                                r"egrep is obsolescent", re.I),
     "rkhunter's own settings file has an entry it doesn't accept (some "
     "distributions ship one like this). It's about rkhunter, not about this "
     "computer."),
    ("syslog", re.compile(r"syslog", re.I),
     "This is about how system logs are configured, not about an infection."),
    ("never_logged", re.compile(r"never logged|lastlog|were not found in .*utmp|"
                                r"deletion\(s\) between", re.I),
     "chkrootkit compares login records. Accounts that have never logged in, "
     "terminals inside tmux or a desktop terminal, and log rotation all make these "
     "records disagree a little; it's a common false alarm."),
]
# Hidden files packages leave on purpose (chkrootkit and rkhunter both list
# hidden files in system folders).
_KNOWN_HIDDEN = re.compile(
    r"/(\.build-id|\.gitignore|\.htaccess|\.packlist|\.placeholder|\.keep|\.java|"
    r"\.[\w.-]+\.jinfo|\.git|\.etckeeper|\.updated|\.pwd\.lock|\.udev|\.initramfs|"
    r"\.lxc|\.mdadm|\.k5identity[\w.]*|\.k5login[\w.]*|\.security|\.path|"
    r"\.mailcap|\.cvsignore|\.dockerenv|\.npmignore)(/|$)")
HIDDEN_EXPLANATION = (
    "Some software packages put hidden files and folders inside system folders on "
    "purpose: .build-id (debugging data on Fedora), .gitignore and .packlist (left "
    "by programming tools), .java, .udev. The scanners list every hidden file they "
    "see there, and these are the usual ones."
)
# Network programs that legitimately open raw sockets.
_NETWORK_PROGRAMS = re.compile(
    r"NetworkManager|dhclient|dhcpcd|wpa_supplicant|systemd-networkd|"
    r"systemd-network|dhcpd|tcpdump|wireshark|dumpcap|avahi|lldpd|keepalived|"
    r"connmand|iwd|udhcpc|netplan|pppd", re.I)
_EXPECTED_SHM = re.compile(r"pulse-shm|PostgreSQL|chromium|chrome|firefox|Xorg|Xwayland|"
                           r"wayland|pipewire|gnome-shell|plasmashell|kwin|mutter|"
                           r"/dev/shm/sem\.|mono\.|jack", re.I)
# Ports chkrootkit's bindshell test lists that ordinary servers use (465 is secure mail).
_ORDINARY_PORTS = {"465"}
LKM_RACE = re.compile(r"process hidden for|Possible LKM Trojan", re.I)
XOR_TMP = re.compile(r"Linux\.Xor\.DDoS", re.I)
ROOTKIT_WORDS = re.compile(r"rootkit|INFECTED|trojan|backdoor|worm|malware|"
                           r"ld\.so\.preload|preload|suspect|hidden process|LKM", re.I)

_START_CHK = re.compile(
    r"^(INFECTED|Warning|WARNING|Suspect|Checking `|You have\s|chkproc:|chkdirs:|"
    r"The tty of|=> possibly|\S+: (PACKET SNIFFER|PF_PACKET)|\S+ is PROMISC|user \S+ deleted)")

_COULD_NOT_CHECK = {
    "timed_out": "{tool} took longer than the time we allow, so we stopped it. What it "
                 "found before then wasn't used.",
    "tool_failed": "{tool} stopped with an error before it finished, so we couldn't use "
                   "what it found.",
    "unsafe_owner": "{tool} is installed in a place that programs running as an "
                    "ordinary user can change, or that is reached through a link ({path}). Running it with administrator "
                    "rights could let such a program run in its place, so we didn't. "
                    "This is common for tools installed with Homebrew. Installing it "
                    "from your system's own package manager avoids this.",
}


def find_tools(candidates: dict[str, tuple[str, ...]] = CANDIDATES) -> dict[str, str]:
    found = {}
    for tool, paths in candidates.items():
        for path in paths:
            if os.path.isfile(path) and os.access(path, os.X_OK):
                found[tool] = path
                break
    return found


def owned_by_root(path: str) -> bool:
    """``path`` and every folder above it are real (no links), belong to root, and only root can change them.

    Each part is looked at with lstat, so a link anywhere along the way is
    refused rather than followed: the path checked is the path that runs.
    """
    if not os.path.isabs(path) or os.path.normpath(path) != path:
        return False
    try:
        here = Path(path)
        for part in (here, *here.parents):
            st = os.lstat(part)
            if stat.S_ISLNK(st.st_mode):
                return False
            # A sticky, world-writable folder (/tmp) still lets anyone add files.
            if st.st_uid != 0 or st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                return False
    except OSError:
        return False
    return True


def work_dir(tool: str, path: str, trusted=owned_by_root) -> str:
    """The folder a tool runs in: one only root can change.

    chkrootkit runs its helpers (./chkproc, ./ifpromisc, ./chkutmp...) from the
    folder it is started in, and adds "." to the places it looks for commands.
    Distribution packages keep the helpers in a library folder; a source
    install keeps them next to the script. rkhunter needs no particular folder,
    so it runs in /.
    """
    if tool == "chkrootkit":
        for folder in (*CHKROOTKIT_HELPER_DIRS, os.path.dirname(path)):
            if os.path.isfile(os.path.join(folder, "chkproc")) and trusted(folder):
                return folder
    return "/"


def parse_rkhunter(output: str) -> list[dict]:
    """--rwo output: each warning starts 'Warning: ', its detail lines are indented."""
    blocks: list[dict] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        if line.startswith("Warning: "):
            blocks.append({"tool": "rkhunter", "text": line[len("Warning: "):].strip(), "details": []})
        elif blocks and line[:1].isspace():
            blocks[-1]["details"].append(line.strip())
    return blocks


def parse_chkrootkit(output: str) -> list[dict]:
    """-q output: a line naming a problem starts a block; the lines after it are its files."""
    blocks: list[dict] = []
    for raw in output.splitlines():
        line = raw.strip()
        if not line or line.startswith("not tested") or line.endswith(("not tested", "not found")):
            continue
        if line.startswith("!"):  # chkutmp's table under "The tty of ..."
            if blocks:
                blocks[-1]["details"].append(line)
            continue
        if _START_CHK.match(line):
            if line.startswith("Checking `") and blocks and blocks[-1]["text"].startswith("INFECTED PORTS"):
                # "INFECTED PORTS: (465)" comes before its "Checking `bindshell'... INFECTED".
                blocks[-1]["details"].append(line)
                continue
            blocks.append({"tool": "chkrootkit", "text": line, "details": []})
        elif blocks and blocks[-1]["text"].startswith(("INFECTED", "Suspect")):
            blocks[-1]["details"].extend(line.split())
        else:
            # A bare list of paths: the hidden files chkrootkit found in system folders.
            blocks.append({"tool": "chkrootkit", "text": "hidden files", "details": line.split()})
    return blocks


def classify(block: dict) -> tuple[str, str]:
    """('false_alarm', key) | ('warning', key) | ('critical', key)."""
    text = block["text"]
    whole = " ".join([text, *block["details"]])
    if text == "hidden files" or re.search(r"Hidden (file|directory)", text, re.I):
        paths = [p for p in re.findall(r"(/[^\s:']+)", whole)]
        if paths and all(_KNOWN_HIDDEN.search(p) for p in paths):
            return "false_alarm", "known_hidden"
        return "warning", "hidden_files"
    if text.startswith("INFECTED PORTS"):
        ports = set(re.findall(r"\d+", text))
        if ports and ports <= _ORDINARY_PORTS:
            return "false_alarm", "ordinary_port"
        return "critical", "bindshell"
    if LKM_RACE.search(whole):
        return "warning", "hidden_process_count"
    if XOR_TMP.search(text):
        return "warning", "program_in_tmp"
    for key, pattern, _ in FALSE_ALARMS:
        if not pattern.search(whole):
            continue
        if key == "network_tools":
            programs = re.findall(r"(/[^\s,()\[\]']+)", whole)
            if programs and all(_NETWORK_PROGRAMS.search(p) for p in programs):
                return "false_alarm", key
            return "warning", "network_listener"
        if key == "shared_memory":
            # Every file or program named must be an expected one.
            names = re.findall(r"(/[^\s:,()']+)", whole)
            names = [n for n in names if n not in ("/dev", "/dev/shm")]
            if names and all(_EXPECTED_SHM.search(n) for n in names):
                return "false_alarm", key
            return "warning", "unusual_dev_file"
        if key == "ssh_setting" and ROOTKIT_WORDS.search(text):
            break  # e.g. "Ebury - SSH Rootkit": a real rootkit check, not a setting
        return "false_alarm", key
    if ROOTKIT_WORDS.search(whole):
        return "critical", "rootkit_signs"
    return "warning", "unexplained"


EXPLANATIONS = {key: text for key, _, text in FALSE_ALARMS}
EXPLANATIONS["known_hidden"] = HIDDEN_EXPLANATION
EXPLANATIONS["ordinary_port"] = (
    "chkrootkit warns when certain network ports are open because some old "
    "backdoors used them. Port 465 is also the standard port for sending email "
    "securely, so a mail server or mail relay on this computer triggers it."
)


class Module(ModuleBase):
    name = "rootkit_scanners"
    category = "security"
    platforms = [Platform.LINUX, Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 59
    depends_on = []
    estimated_duration = "off unless a profile turns it on; slow when on, and needs root"

    emits_codes = [
        "security.rootkit_scanners.possible_rootkit",
        "security.rootkit_scanners.scanner_warning",
        "security.rootkit_scanners.known_false_alarms",
        "security.rootkit_scanners.ran_clean",
        "security.rootkit_scanners.not_run",
        "security.rootkit_scanners.not_installed",
        "security.rootkit_scanners.needs_admin",
        "security.rootkit_scanners.could_not_check",
    ]

    run_scanners: bool = False
    tool_timeout: int = TOOL_TIMEOUT
    # Seams for tests: None = the real defaults.
    candidates: dict[str, tuple[str, ...]] | None = None
    elevated: bool | None = None
    # (path) -> bool: owned_by_root, unless a test stands in.
    root_owned: Any = None

    def configure(self, config: dict[str, Any]) -> None:
        config = config or {}
        self.run_scanners = bool(config.get("run_scanners", False))
        if "tool_timeout" in config:
            self.tool_timeout = int(config["tool_timeout"])
        if self.run_scanners:
            self.check_timeout = 2 * self.tool_timeout + 30

    def check(self, profile: SystemProfile) -> CheckResult:
        tools = find_tools(self.candidates if self.candidates is not None else CANDIDATES)
        mac = profile.platform == Platform.DARWIN
        if not self.run_scanners:
            return CheckResult(module_name=self.name, findings=[self._not_run(tools, mac)])
        if not tools:
            return CheckResult(module_name=self.name, findings=[self._not_installed(mac)])
        if not self._is_elevated():
            return CheckResult(module_name=self.name, findings=[self._needs_admin(tools, mac)])

        findings: list[Finding] = []
        blocks: list[dict] = []
        ran: list[str] = []
        candidates = self.candidates if self.candidates is not None else CANDIDATES
        safe = self.root_owned if self.root_owned is not None else owned_by_root
        for tool, first in tools.items():
            # The first installed copy that only root can change, reached without links.
            path = next((p for p in candidates[tool] if os.path.isfile(p) and safe(p)), None)
            if path is None:
                findings.append(self._could_not_check(tool, "unsafe_owner", first))
                continue
            cwd = work_dir(tool, path, safe)
            template = RKHUNTER_ARGS if tool == "rkhunter" else CHKROOTKIT_ARGS
            argv = [path if a is _TOOL else a for a in template]
            # Checked again right before it runs, with its folder.
            if not (safe(path) and safe(cwd)):
                findings.append(self._could_not_check(tool, "unsafe_owner", path))
                continue
            res = run(argv, timeout=self.tool_timeout, env=_tool_env(), cwd=cwd)
            if res.timed_out:
                findings.append(self._could_not_check(tool, "timed_out", path))
                continue
            parse = parse_rkhunter if tool == "rkhunter" else parse_chkrootkit
            found = parse(res.stdout or "")
            # rkhunter exits 1 when it has warnings; anything else without
            # output means it didn't get through its checks.
            if res.returncode not in (0, 1) and not found:
                findings.append(self._could_not_check(tool, "tool_failed", path,
                                                      (res.stderr or res.error or "")[:200]))
                continue
            ran.append(tool)
            blocks.extend(found)

        false_alarms: dict[str, list[dict]] = {}
        leads: list[Finding] = []
        for block in blocks:
            kind, key = classify(block)
            if kind == "false_alarm":
                false_alarms.setdefault(key, []).append(block)
            else:
                leads.append(self._lead(block, kind, key, mac))
        leads.sort(key=lambda f: 0 if f.severity == Severity.CRITICAL else 1)
        findings.extend(leads[:MAX_LEADS])
        if false_alarms:
            findings.append(self._false_alarms(false_alarms, mac))
        if ran and not leads:
            findings.append(self._ran_clean(ran, bool(false_alarms), mac))
        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        # What to do about a warning depends on what it is; the walkthrough
        # covers it, and nothing is changed from here.
        return FixResult(module_name=self.name, actions=[])

    def _is_elevated(self) -> bool:
        if self.elevated is not None:
            return bool(self.elevated)
        geteuid = getattr(os, "geteuid", None)
        return bool(geteuid is not None and geteuid() == 0)

    # --- findings -------------------------------------------------------------------

    @staticmethod
    def _mac_limits() -> str:
        return (
            "\n\nOn a Mac these scanners see very little: their Mac checks are for "
            "malware from years ago, and they don't look at background items, system "
            "extensions or configuration profiles. The core system files they "
            "fingerprint are on a sealed part of the disk that macOS checks itself at "
            "every start. The Mac's own checks in this checkup (and KnockKnock) look "
            "much further."
        )

    def _lead(self, block: dict, kind: str, key: str, mac: bool) -> Finding:
        tool = block["tool"]
        details = block["details"][:MAX_DETAIL_LINES]
        shown = block["text"] + ("\n" + "\n".join(details) if details else "")
        if kind == "critical":
            return Finding(
                title=f"{tool} found signs that may mean hidden malware",
                description=(
                    f"{tool}, a rootkit scanner, reported this:\n\n{shown}\n\n"
                    "A rootkit is malware that hides itself and gives someone else "
                    "control of the computer. Scanners sometimes match an ordinary "
                    "file by mistake, so this is a lead, not a verdict. Don't delete "
                    "anything yet.\n\n"
                    "What to do: Keep this computer off the internet if you can, and "
                    "ask someone who helps with Linux or computer security to look at "
                    "the lines above. The steps below say what they'll check. If you "
                    "think someone close to you may have put monitoring software on "
                    "this computer, read the safety note first: removing it can alert "
                    "them." + (self._mac_limits() if mac else "")
                ),
                severity=Severity.CRITICAL,
                category=self.category,
                code="security.rootkit_scanners.possible_rootkit",
                data={"tool": tool, "warning": block["text"], "details": details, "kind": key},
                confidence=0.5,
            )
        about = {
            "hidden_files": "It found hidden files or folders in system folders that "
                            "aren't among the ones packages usually leave.",
            "hidden_process_count": "Two ways of listing running programs disagreed. "
                                    "Programs start and stop all the time, so this is "
                                    "often a coincidence of timing; if it shows up again "
                                    "on a second run, take it seriously.",
            "program_in_tmp": "chkrootkit reports any program in /tmp under this name "
                              "(Linux.Xor.DDoS is real malware that hides there). "
                              "Installers and some apps also put programs in /tmp, so "
                              "check the file names below.",
            "network_listener": "A program is watching network traffic at a low level, "
                                "and it isn't one of the usual network-setup programs.",
            "unusual_dev_file": "There are unusual files where the system keeps device "
                                "and shared-memory files.",
            "unexplained": "We don't have a plain explanation for this warning.",
        }.get(key, "We don't have a plain explanation for this warning.")
        return Finding(
            title=f"{tool} warned about something worth a look",
            description=(
                f"{tool}, a rootkit scanner, reported this:\n\n{shown}\n\n{about} "
                "On its own this doesn't mean the computer is infected.\n\n"
                "What to do: Read the steps below. If the lines above don't match "
                "something you recognise, ask someone who helps with Linux or "
                "computer security to look at them before changing anything."
                + (self._mac_limits() if mac else "")
            ),
            severity=Severity.WARNING,
            category=self.category,
            code="security.rootkit_scanners.scanner_warning",
            data={"tool": tool, "warning": block["text"], "details": details, "kind": key},
            confidence=0.3,
        )

    def _false_alarms(self, groups: dict[str, list[dict]], mac: bool) -> Finding:
        parts = []
        for key, blocks in groups.items():
            lines = "\n".join(f"  {b['tool']}: {b['text']}" for b in blocks[:5])
            if len(blocks) > 5:
                lines += f"\n  ...and {len(blocks) - 5} more like this"
            parts.append(f"{EXPLANATIONS[key]}\n{lines}")
        count = sum(len(b) for b in groups.values())
        return Finding(
            title=f"Scanner warnings that are usually false alarms ({count})",
            description=(
                "The rootkit scanners warned about these, but each one matches a "
                "well-known harmless cause. Here is what each means:\n\n"
                + "\n\n".join(parts)
                + (self._mac_limits() if mac else "")
            ),
            severity=Severity.INFO,
            category=self.category,
            code="security.rootkit_scanners.known_false_alarms",
            data={"explained": {k: [{"tool": b["tool"], "warning": b["text"],
                                     "details": b["details"][:MAX_DETAIL_LINES]} for b in v]
                                for k, v in groups.items()}},
        )

    def _ran_clean(self, ran: list[str], had_false_alarms: bool, mac: bool) -> Finding:
        names = " and ".join(ran)
        extra = " Apart from the false alarms explained in the note above, " if had_false_alarms else " "
        return Finding(
            title=f"Rootkit scanners found nothing ({names})",
            description=(
                f"{names} ran with administrator rights.{extra}they found no signs of "
                "a rootkit. That lowers the odds of one without ruling it out: these "
                "scanners know the rootkits that have been written about, and a new "
                "one could be missed." + (self._mac_limits() if mac else "")
            ),
            severity=Severity.INFO,
            category=self.category,
            code="security.rootkit_scanners.ran_clean",
            data={"ran": ran},
        )

    def _not_run(self, tools: dict[str, str], mac: bool) -> Finding:
        if tools:
            names = " and ".join(tools)
            text = (
                f"{names} {'is' if len(tools) == 1 else 'are'} installed on this "
                "computer. These rootkit scanners read a lot of files and need "
                "administrator rights, so they weren't part of this checkup and "
                "checked nothing. To run them: sudo rescue scan --profile "
                "deep_startup_check"
            )
        else:
            text = (
                "rkhunter and chkrootkit, two free rootkit scanners, aren't installed, "
                "and they weren't part of this checkup anyway: they read a lot of "
                "files and need administrator rights. Nothing was checked by them."
            )
        return Finding(
            title="Rootkit scanners weren't run in this checkup",
            description=text + (self._mac_limits() if mac else ""),
            severity=Severity.INFO,
            category=self.category,
            code="security.rootkit_scanners.not_run",
            data={"reason": "not_enabled", "installed": sorted(tools)},
        )

    def _not_installed(self, mac: bool) -> Finding:
        how = (
            "They can be installed with Homebrew (brew install rkhunter chkrootkit), "
            "but Reclaim City won't run a Homebrew copy with administrator rights, and "
            "on a Mac they add little."
            if mac else
            "To install them: sudo apt install rkhunter chkrootkit (Debian, Ubuntu), "
            "or sudo dnf install rkhunter chkrootkit (Fedora). Then run this check "
            "again with sudo."
        )
        return Finding(
            title="Couldn't run the rootkit scanners: they aren't installed",
            description=(
                "rkhunter and chkrootkit, two free rootkit scanners, aren't installed, "
                f"so nothing was checked by them. {how}\n\nThis doesn't mean the "
                "computer is clean or infected." + (self._mac_limits() if mac else "")
            ),
            severity=Severity.INFO,
            category=self.category,
            code="security.rootkit_scanners.not_installed",
            data={"reason": "not_installed"},
        )

    def _needs_admin(self, tools: dict[str, str], mac: bool) -> Finding:
        names = " and ".join(tools)
        return Finding(
            title="Couldn't run the rootkit scanners: they need administrator rights",
            description=(
                f"{names} {'is' if len(tools) == 1 else 'are'} installed, but "
                f"{'it needs' if len(tools) == 1 else 'they need'} administrator (root) "
                "rights to look at the whole system, and this checkup doesn't have "
                "them, so nothing was checked by them. This doesn't mean the computer "
                "is clean or infected.\n\nTo run them: sudo rescue scan --profile "
                "deep_startup_check" + (self._mac_limits() if mac else "")
            ),
            severity=Severity.INFO,
            category=self.category,
            code="security.rootkit_scanners.needs_admin",
            data={"reason": "needs_admin", "installed": sorted(tools)},
        )

    def _could_not_check(self, tool: str, reason: str, path: str, detail: str = "") -> Finding:
        text = _COULD_NOT_CHECK[reason].format(tool=tool, path=path)
        return Finding(
            title=f"Couldn't finish the {tool} rootkit scan",
            description=(
                f"{text}\n\nThis means {tool} didn't check this computer; it doesn't "
                "mean the computer is clean or infected."
            ),
            severity=Severity.INFO,
            category=self.category,
            code="security.rootkit_scanners.could_not_check",
            data={"reason": reason, "tool": tool, "path": path,
                  **({"detail": detail} if detail else {})},
        )


def _tool_env() -> dict[str, str]:
    # A fixed PATH: both tools find the commands they compare against by name.
    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}
    if os.environ.get("TMPDIR"):
        env["TMPDIR"] = os.environ["TMPDIR"]
    return env
