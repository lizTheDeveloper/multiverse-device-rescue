"""Remote-access tools: software that lets someone else see and control this computer.

TeamViewer, AnyDesk, ScreenConnect, RustDesk and the rest are ordinary IT
software, and also how most tech-support scams get in. Finding one proves
nothing on its own, so this check reports, for each tool, the evidence a
person needs to decide whose it is: when it was added, whether it can let
someone in without a click (a part of it that starts by itself), whether it's
running now, and when it last let someone in (from TeamViewer's and AnyDesk's
connection logs: dates and a count only, never who connected).

Every piece of evidence is read-only, bounded, and fits one time budget. What
couldn't be read is ``None`` and says "Couldn't tell", never "no". The removal
warning comes from ``rescue.safety_scope`` by code, like every other check
that reports something someone else may have installed.
"""

from __future__ import annotations

import os
import plistlib
import re
import sys
import time
from datetime import date, datetime
from pathlib import Path, PureWindowsPath

from rescue.command import run
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
from rescue.runtime import load_content_module

_tools = load_content_module("modules/security/remote_access_tools/tools.py", "rescue_remote_access_tools_tools")
_ev = load_content_module("modules/security/remote_access_tools/evidence.py", "rescue_remote_access_tools_evidence")

EVIDENCE_BUDGET_SECONDS = 20.0
MAX_DIR_ENTRIES = 500
MAX_PLIST_BYTES = 1_048_576
MDLS_TIMEOUT = 5
REG_TIMEOUT = 10.0
RECENT_DAYS = 30

WIN_UNINSTALL_KEYS = [
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall",
    r"HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall",
]
WIN_SERVICES_KEY = r"HKLM\SYSTEM\CurrentControlSet\Services"
# A service's Start value: 0 boot, 1 system, 2 automatic, 3 manual, 4 disabled.
_START_TYPES = {0: "boot", 1: "system", 2: "automatic", 3: "manual", 4: "disabled"}
_AUTO_START = {"boot", "system", "automatic"}
_REG_VALUE = re.compile(r"^\s{2,}(\S.*?)\s{2,}(REG_[A-Z_]+)(?:\s{2,}(.*?))?\s*$")

_MONTHS = ("January", "February", "March", "April", "May", "June", "July", "August", "September",
           "October", "November", "December")


def _read_plist(path: Path) -> dict | None:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_PLIST_BYTES:
            return None
        with open(path, "rb") as fh:
            data = plistlib.load(fh)
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def _bounded_listing(directory: Path) -> list[Path] | None:
    """Up to MAX_DIR_ENTRIES entries, [] when the folder doesn't exist, None when it can't be read."""
    try:
        if not directory.exists():
            return []
        out = []
        with os.scandir(directory) as it:
            for entry in it:
                out.append(Path(entry.path))
                if len(out) >= MAX_DIR_ENTRIES:
                    break
        return sorted(out)
    except OSError:
        return None


def _human_date(d: date) -> str:
    return f"{d.day} {_MONTHS[d.month - 1]} {d.year}"


def _iso(d: date | None) -> str | None:
    return d.isoformat() if d is not None else None


_DRIVE = re.compile(r"^[A-Za-z]:$")


def _local_path(path, windows_host: bool = sys.platform == "win32") -> str | None:
    """`path` when it is safe to touch on this computer, else None.

    On Windows only a path on a local drive letter (``C:\\...``) is used. A UNC
    path (``\\\\host\\share``, ``//host``) makes Windows sign in to that host,
    which can hand over the person's password hash; a device path (``\\\\?\\``,
    ``\\\\.\\``) reaches a device. Registry values (HKCU is writable by any
    program), service and process paths, and %Name% expansions can all be
    pointed at one, so every path from them goes through here before anything
    reads or stats it. On other systems (the tests) an absolute POSIX path is
    also accepted. A rejected path means "Couldn't tell".
    """
    if not isinstance(path, (str, os.PathLike)):
        return None
    text = os.fspath(path)
    if not isinstance(text, str) or not text or "\0" in text:
        return None
    if text.startswith(("\\\\", "//", "\\/", "/\\")):
        return None
    win = PureWindowsPath(text)
    if _DRIVE.match(win.drive or "") and win.root == "\\":
        return text
    if not windows_host and text.startswith("/"):
        return text
    return None


def _created_on(path) -> date | None:
    """A file or folder's creation date: birth time where the system keeps one
    (macOS, Windows on Python 3.12+), else Windows' st_ctime (creation there)."""
    try:
        st = os.stat(path)
    except (OSError, ValueError):
        return None
    when = getattr(st, "st_birthtime", None)
    if not when and sys.platform == "win32":
        when = st.st_ctime
    if not when:
        return None
    try:
        return datetime.fromtimestamp(when).date()
    except (OverflowError, OSError, ValueError):
        return None


def _exe_from_command(command: str) -> str | None:
    """The program path at the start of a Windows command line, or None."""
    command = (command or "").strip()
    if not command:
        return None
    if command.startswith('"'):
        end = command.find('"', 1)
        return command[1:end] if end > 1 else None
    low = command.lower()
    at = low.find(".exe")
    return command[: at + 4] if at >= 0 else command.split(" ", 1)[0]


# macOS's own programs: a system daemon that shares a tool's name (Apple's
# CoreParsec "parsecd") is never that tool.
_MAC_SYSTEM_PREFIXES = ("/System/", "/usr/libexec/", "/usr/sbin/", "/usr/bin/", "/sbin/", "/bin/")


def _proc_names(profile: SystemProfile, skip_system: bool = False) -> set[str] | None:
    procs = getattr(profile, "processes", None) or []
    if not procs:
        return None
    names = set()
    for p in procs:
        if skip_system and str(getattr(p, "command", "") or "").startswith(_MAC_SYSTEM_PREFIXES):
            continue
        name = str(getattr(p, "name", "") or "").strip().lower()
        if name:
            names.add(name)
            if name.endswith(".exe"):
                names.add(name[:-4])
    return names


def _running(names: set[str] | None, patterns) -> bool | None:
    if names is None or not patterns:
        return None
    for pattern in patterns:
        p = pattern.lower()
        if p in names or (p.endswith(".exe") and p[:-4] in names):
            return True
    return False


class Module(ModuleBase):
    name = "remote_access_tools"
    category = "security"
    platforms = [Platform.DARWIN, Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 56
    depends_on = []
    estimated_duration = "10s"
    emits_codes = [
        "security.remote_access_tools.tool_found",
        "security.remote_access_tools.several_tools",
        "security.remote_access_tools.unattended_recent",
        "security.remote_access_tools.running_now",
    ]

    MAC_APP_DIRS = [Path("/Applications"), Path.home() / "Applications", Path.home() / "Downloads"]
    MAC_LAUNCHD_DIRS = [Path("/Library/LaunchDaemons"), Path("/Library/LaunchAgents"),
                        Path.home() / "Library/LaunchAgents"]
    HOME = Path.home()
    # %ProgramData%-style names in log paths; tests replace it.
    ENV = os.environ
    # Whether paths are judged as Windows paths only (see _local_path); tests set it.
    WINDOWS_HOST = sys.platform == "win32"
    now = staticmethod(lambda: datetime.now())
    clock = staticmethod(time.monotonic)

    # ---------------- check ----------------

    def check(self, profile: SystemProfile) -> CheckResult:
        if _tools is None or _ev is None:
            return CheckResult(module_name=self.name, error="The remote access tool helpers could not be loaded.")
        try:
            self._tool_list = _tools.load_tools()
        except ValueError as exc:
            return CheckResult(module_name=self.name, error=str(exc))
        self._deadline = self.clock() + EVIDENCE_BUDGET_SECONDS
        if profile.platform == Platform.DARWIN:
            sightings = self._mac_sightings(profile)
        elif profile.platform == Platform.WIN32:
            sightings = self._win_sightings(profile)
        else:
            return CheckResult(module_name=self.name, supported=False,
                               unsupported_reason="This check runs on macOS and Windows.")
        return CheckResult(module_name=self.name, findings=self._findings(sightings, profile.platform.value))

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        """Guidance only: what to check and how to remove it is the person's call."""
        actions: list[Action] = []
        for finding in findings.findings:
            data = finding.data or {}
            if data.get("check") == "several_tools":
                names = ", ".join(str(n) for n in data.get("tools") or [])
                actions.append(Action(
                    title="Check each remote-access tool",
                    description=(
                        f"These tools can each let someone control this computer: {names}. Scammers often "
                        "install a second one, so removing one doesn't lock them out. Go through each one's "
                        "card, and run the checkup again after you remove one."
                    ),
                    risk_level=RiskLevel.SAFE,
                    kind=ActionKind.GUIDANCE,
                    success=True,
                    data={"tools": list(data.get("tools") or [])},
                ))
                continue
            name = data.get("tool") or "this tool"
            steps = [
                "1. Think back to around when it was added. Did you install it, or did a shop or IT person "
                "you contacted? If you still use it, it's yours, and you can mark it as yours.",
                "2. If someone who called, emailed, texted or showed a pop-up asked you to install it, "
                "treat it as a scam: from another phone or computer if you can, call your bank on the "
                "number on your card, then change your email password.",
                f"3. If you keep {name}, turn off unattended access in its own settings and set a new "
                "password for it.",
                f"4. If you don't need {name}, uninstall it, then run the checkup again to make sure it "
                "and any second tool are gone.",
            ]
            if data.get("running_now") is True:
                steps.insert(0, "First: it's running now. Turn off Wi-Fi or unplug the network cable, so "
                                "nobody can watch while you check.")
            actions.append(Action(
                title=f"Decide whether {name} is yours",
                description="\n".join(steps),
                risk_level=RiskLevel.SAFE,
                kind=ActionKind.GUIDANCE,
                success=True,
                data={"tool_id": data.get("tool_id")},
            ))
        return FixResult(module_name=self.name, actions=actions)

    # ---------------- budget ----------------

    def _in_budget(self) -> bool:
        deadline = getattr(self, "_deadline", None)
        if deadline is None:
            self._deadline = deadline = self.clock() + EVIDENCE_BUDGET_SECONDS
        return self.clock() < deadline

    def _tool_entries(self):
        tools = getattr(self, "_tool_list", None)
        if tools is None:
            tools = self._tool_list = _tools.load_tools()
        return tools

    # ---------------- macOS ----------------

    def _downloads_dir(self) -> Path:
        return self.HOME / "Downloads"

    def _mac_apps(self) -> dict[str, list[Path]]:
        """tool id -> .app bundles found, by name or by bundle id."""
        by_name, by_bundle = {}, {}
        for tool in self._tool_entries():
            for n in tool.mac_app_names:
                by_name.setdefault(n.lower(), tool.id)
            for b in tool.mac_bundle_ids:
                by_bundle.setdefault(b.lower(), tool.id)
        found: dict[str, list[Path]] = {}
        for directory in self.MAC_APP_DIRS:
            for path in _bounded_listing(Path(directory)) or []:
                if path.suffix.lower() != ".app" or path.is_symlink():
                    continue
                tool_id = by_name.get(path.name.lower())
                if tool_id is None and by_bundle:
                    info = _read_plist(path / "Contents" / "Info.plist")
                    bundle = info.get("CFBundleIdentifier") if info else None
                    if isinstance(bundle, str):
                        tool_id = by_bundle.get(bundle.lower())
                if tool_id is not None:
                    found.setdefault(tool_id, []).append(path)
        return found

    def _mac_launchd(self) -> tuple[dict[str, list[tuple[str, Path]]], bool]:
        """(tool id -> [(label, plist)], whether every folder could be read)."""
        prefixes = [(p.lower(), tool.id) for tool in self._tool_entries() for p in tool.mac_launchd]
        found: dict[str, list[tuple[str, Path]]] = {}
        readable = True
        for directory in self.MAC_LAUNCHD_DIRS:
            listing = _bounded_listing(Path(directory))
            if listing is None:
                readable = False
                continue
            for path in listing:
                if path.suffix != ".plist":
                    continue
                data = _read_plist(path)
                label = data.get("Label") if data else None
                if not isinstance(label, str) or not label:
                    label = path.stem
                low = label.lower()
                for prefix, tool_id in prefixes:
                    if low.startswith(prefix):
                        found.setdefault(tool_id, []).append((label, path))
                        break
        return found, readable

    def _added_on_mac(self, app: Path) -> date | None:
        """When it arrived: Spotlight's "date added", else the file's birth time."""
        if not self._in_budget():
            return None
        res = run(["mdls", "-raw", "-name", "kMDItemDateAdded", str(app)], timeout=MDLS_TIMEOUT)
        if res.ok:
            when = _ev.date_from_mdls(res.stdout)
            if when is not None:
                return when
        try:
            birth = getattr(os.stat(app, follow_symlinks=False), "st_birthtime", None)
        except OSError:
            return None
        if not birth:
            return None
        try:
            return datetime.fromtimestamp(birth).date()
        except (OverflowError, OSError, ValueError):
            return None

    def _expand(self, raw: str) -> Path | None:
        """A log path with ``~`` or ``%Name%`` filled in, or None when a name isn't set."""
        if raw.startswith("~"):
            return self.HOME / raw[1:].lstrip("/\\")
        env = {str(k).lower(): v for k, v in dict(self.ENV).items()}
        missing = False

        def fill(m):
            nonlocal missing
            value = env.get(m.group(1).lower())
            if not value:
                missing = True
                return ""
            return value

        expanded = re.sub(r"%([^%]+)%", fill, raw)
        if missing:
            return None
        # A Windows path, read on any system (the tests run on macOS and Linux too).
        return Path(expanded.replace("\\", os.sep))

    def _log_evidence(self, tool, platform: str) -> tuple[date | None, int | None]:
        """(last incoming date, count) over the tool's logs; (None, None) if none could be read."""
        results = []
        for log in tool.logs:
            if log.platform != platform:
                continue
            if not self._in_budget():
                break
            path = self._expand(log.path)
            if path is None:
                continue
            if platform == "win32" and _local_path(str(path), self.WINDOWS_HOST) is None:
                continue
            got = _ev.read_log(path, log.format)
            if got is not None:
                results.append(got)
        if not results:
            return None, None
        dates = [d for ds, _ in results for d in ds]
        count = sum(n for _, n in results)
        return (max(dates) if dates else None), count

    def _mac_sightings(self, profile: SystemProfile) -> list:
        apps = self._mac_apps()
        if self._in_budget():
            launchd, launchd_readable = self._mac_launchd()
        else:
            launchd, launchd_readable = {}, False
        names = _proc_names(profile, skip_system=True)
        downloads = self._downloads_dir()
        out = []
        for tool in self._tool_entries():
            if tool.presence_only:
                continue
            found_apps = apps.get(tool.id, [])
            jobs = launchd.get(tool.id, [])
            running = _running(names, tool.mac_processes)
            if not found_apps and not jobs and running is not True:
                continue
            installed = [a for a in found_apps if a.parent != downloads]
            app = (installed or found_apps or [None])[0]
            if jobs:
                unattended, via = True, jobs[0][0]
            elif launchd_readable:
                unattended, via = False, None
            else:
                unattended, via = None, None
            path = app if app is not None else (jobs[0][1] if jobs else None)
            last, count = self._log_evidence(tool, "darwin")
            out.append(_ev.Sighting(
                tool=tool,
                path=str(path) if path is not None else None,
                added_on=self._added_on_mac(path) if path is not None else None,
                lets_in_unattended=unattended,
                unattended_via=via,
                running_now=running,
                last_incoming=last,
                incoming_count=count,
                one_off=bool(found_apps) and not installed and unattended is False,
            ))
        return out

    # ---------------- Windows ----------------

    def _reg_timeout(self) -> float | None:
        """A timeout that keeps the registry reads inside the budget, or None when it's spent."""
        deadline = getattr(self, "_deadline", None)
        if deadline is None:
            self._deadline = deadline = self.clock() + EVIDENCE_BUDGET_SECONDS
        left = deadline - self.clock()
        if left <= 0:
            return None
        return max(1.0, min(REG_TIMEOUT, left))

    def _reg_query(self, args: list[str]) -> str | None:
        timeout = self._reg_timeout()
        if timeout is None:
            return None
        res = run(["reg", "query", *args], timeout=timeout)
        if not res.ok or res.truncated:
            return None
        return res.stdout or ""

    def _win_uninstall_entries(self) -> list[dict] | None:
        """{display_name, install_location, install_date} for every uninstall entry,
        or None when the main (64-bit HKLM) list couldn't be read."""
        entries: list[dict] = []
        for index, key in enumerate(WIN_UNINSTALL_KEYS):
            out = self._reg_query([key, "/s"])
            if out is None:
                if index == 0:
                    return None
                continue
            current: dict | None = None
            for line in out.splitlines():
                if line.startswith("HKEY_"):
                    if current and current.get("display_name"):
                        entries.append(current)
                    current = {"display_name": "", "install_location": "", "install_date": ""}
                    continue
                m = _REG_VALUE.match(line)
                if m is None or current is None:
                    continue
                name, value = m.group(1).strip().lower(), (m.group(3) or "").strip()
                if name == "displayname":
                    current["display_name"] = value
                elif name == "installlocation":
                    current["install_location"] = value.strip('"')
                elif name == "installdate":
                    current["install_date"] = value
            if current and current.get("display_name"):
                entries.append(current)
        return entries

    def _win_services(self) -> dict[str, str] | None:
        """Service name -> start type ("automatic", "manual", ...), or None when unreadable."""
        out = self._reg_query([WIN_SERVICES_KEY, "/s", "/v", "Start"])
        if out is None:
            return None
        services: dict[str, str] = {}
        prefix = "services\\"
        current: str | None = None
        for line in out.splitlines():
            if line.startswith("HKEY_"):
                low = line.lower()
                at = low.rfind(prefix)
                rest = line[at + len(prefix):].strip() if at >= 0 else ""
                current = rest if rest and "\\" not in rest else None
                continue
            m = _REG_VALUE.match(line)
            if m is None or current is None or m.group(1).strip().lower() != "start":
                continue
            try:
                start = int((m.group(3) or "").strip(), 0)
            except ValueError:
                continue
            services[current] = _START_TYPES.get(start, "unknown")
        return services

    def _in_downloads(self, path: str | None) -> bool:
        if not path:
            return False
        downloads = str(self._downloads_dir()).rstrip("/\\").lower()
        for parent in (str(Path(path).parent), str(PureWindowsPath(path).parent)):
            if parent.rstrip("/\\").lower() == downloads:
                return True
        return False

    def _win_downloads(self) -> dict[str, list[Path]]:
        """tool id -> programs sitting in Downloads, by program name (TeamViewerQS.exe...)."""
        found: dict[str, list[Path]] = {}
        if _local_path(str(self._downloads_dir()), self.WINDOWS_HOST) is None:
            return found
        listing = _bounded_listing(self._downloads_dir()) or []
        for tool in self._tool_entries():
            if tool.presence_only:
                continue
            stems = [p.lower()[:-4] for p in tool.win_processes if p.lower().endswith(".exe")]
            for path in listing:
                low = path.name.lower()
                if not low.endswith(".exe"):
                    continue
                if any(low[:-4] == stem or low.startswith(stem + "_") or low.startswith(stem + "-")
                       or low.startswith(stem + " ") for stem in stems):
                    found.setdefault(tool.id, []).append(path)
        return found

    def _process_paths(self, profile: SystemProfile, patterns) -> list[str]:
        wanted = {p.lower() for p in patterns}
        out = []
        for proc in getattr(profile, "processes", None) or []:
            if str(getattr(proc, "name", "") or "").lower() not in wanted:
                continue
            exe = _exe_from_command(str(getattr(proc, "command", "") or ""))
            if exe and PureWindowsPath(exe).name.lower() in wanted | {Path(exe).name.lower()}:
                out.append(exe)
        return out

    def _win_sightings(self, profile: SystemProfile) -> list:
        entries = self._win_uninstall_entries()
        services = self._win_services()
        downloads = self._win_downloads()
        names = _proc_names(profile)
        out = []
        for tool in self._tool_entries():
            running = _running(names, tool.win_processes)
            proc_paths = [p for p in (self._process_paths(profile, tool.win_processes) if running else [])
                          if _local_path(p, self.WINDOWS_HOST)]
            if tool.presence_only:
                # Built into Windows: reported only while it's running, and it
                # can't let anyone in without the person sharing a code.
                if running is True:
                    out.append(_ev.Sighting(tool=tool, path=(proc_paths or [None])[0], running_now=True,
                                            lets_in_unattended=False))
                continue
            patterns = [re.compile(p, re.I) for p in tool.win_display_names]
            matched = [e for e in entries or [] if any(p.search(e["display_name"]) for p in patterns)]
            svc_prefixes = [s.lower() for s in tool.win_services]
            svcs = sorted((n, start) for n, start in (services or {}).items()
                          if any(n.lower().startswith(p) for p in svc_prefixes))
            dl = downloads.get(tool.id, [])
            if not matched and not svcs and not dl and running is not True:
                continue
            auto = [n for n, start in svcs if start in _AUTO_START]
            if services is None:
                unattended, via = None, None
            elif auto:
                unattended, via = True, auto[0]
            else:
                unattended, via = False, None
            entry = matched[0] if matched else None
            location = _local_path(entry["install_location"], self.WINDOWS_HOST) if entry else None
            path = location or (str(dl[0]) if dl else None) or (proc_paths[0] if proc_paths else None)
            added = None
            if entry is not None:
                added = _ev.date_from_install_date(entry.get("install_date"))
            if added is None and _local_path(path, self.WINDOWS_HOST) and self._in_budget():
                added = _created_on(path)
            last, count = self._log_evidence(tool, "win32")
            loose = not matched and not svcs and (bool(dl) or any(self._in_downloads(p) for p in proc_paths))
            out.append(_ev.Sighting(
                tool=tool,
                path=path,
                added_on=added,
                lets_in_unattended=unattended,
                unattended_via=via,
                running_now=running,
                last_incoming=last,
                incoming_count=count,
                one_off=loose and unattended is False,
            ))
        return out

    # ---------------- findings ----------------

    def _verified_maker(self, path: str | None, platform: str) -> bool:
        """Whether the program at `path` has a verified maker (signature checked)."""
        if not path:
            return False
        if platform == "win32" and _local_path(path, self.WINDOWS_HOST) is None:
            return False
        try:
            from rescue.attribution import identify

            made = identify(path, platform)
        except Exception:
            return False
        return bool(made is not None and getattr(made, "verified", False))

    def _quiet(self, s, platform: str) -> bool:
        """Info only when every fact is known and none of them is a reason to look."""
        return (s.one_off is True and s.running_now is False and s.incoming_count == 0
                and s.lets_in_unattended is False and bool(s.path) and self._verified_maker(s.path, platform))

    @staticmethod
    def _evidence_lines(s) -> list[str]:
        lines = []
        lines.append(f"Added on {_human_date(s.added_on)}." if s.added_on else "Couldn't tell when this was added.")
        if s.lets_in_unattended is True:
            via = f" ({s.unattended_via})" if s.unattended_via else ""
            lines.append(f"It can let someone in without you clicking yes: part of it starts by itself{via}.")
        elif s.lets_in_unattended is False:
            lines.append("We didn't find a part of it that starts by itself, so it most likely works only while "
                         "it's open.")
        else:
            lines.append("Couldn't tell whether it can let someone in without you clicking yes.")
        if s.running_now is True:
            lines.append("It's running now.")
        elif s.running_now is False:
            lines.append("It isn't running right now.")
        else:
            lines.append("Couldn't tell whether it's running now.")
        if s.incoming_count and s.last_incoming:
            times = "1 time" if s.incoming_count == 1 else f"{s.incoming_count} times"
            lines.append(f"It last let someone in on {_human_date(s.last_incoming)} ({times} in its log).")
        elif s.incoming_count == 0:
            lines.append("Its connection log shows nobody has connected in.")
        else:
            lines.append("Couldn't tell when it last let someone in.")
        if s.one_off:
            lines.append("It looks like a one-off download: it's in your Downloads folder and doesn't start by "
                         "itself.")
        return lines

    def _describe(self, s) -> str:
        return (
            f"{s.tool.name} lets someone else see and control this computer. "
            + " ".join(self._evidence_lines(s))
            + "\n\nScammers who call or show a pop-up often ask people to install tools like this, then use "
            "it to get into bank accounts or take payments. If you installed it yourself and still use it, "
            "that's fine. If you don't remember how it got here, think back to around when it was added."
            + "\n\nWhat to do: "
            + ("first turn off Wi-Fi or unplug the network cable, so nobody can watch while you check. Then "
               if s.running_now is True else "")
            + "decide whether it's yours. If it is, you can mark it as yours. If it isn't, or someone who "
            "contacted you asked you to install it, follow the steps for this card."
        )

    @staticmethod
    def _data(s, check: str) -> dict:
        return {
            "check": check,
            "tool": s.tool.name,
            "tool_id": s.tool.id,
            "path": s.path,
            "added_on": _iso(s.added_on),
            "lets_in_unattended": s.lets_in_unattended,
            "unattended_via": s.unattended_via,
            "running_now": s.running_now,
            "last_incoming": _iso(s.last_incoming),
            "incoming_count": s.incoming_count,
            "one_off": bool(s.one_off),
            "known_item_kind": "remote_tool",
        }

    def _tool_finding(self, s, platform: str, today: date) -> Finding:
        title = f"{s.tool.name} can let someone control this computer"
        description = self._describe(s)
        recent = (s.lets_in_unattended is True and s.added_on is not None
                  and (today - s.added_on).days <= RECENT_DAYS)
        if recent:
            return Finding(
                title=title, description=description, severity=Severity.CRITICAL, category=self.category,
                code="security.remote_access_tools.unattended_recent",
                data=self._data(s, "unattended_recent"),
            )
        if s.running_now is True:
            return Finding(
                title=title, description=description, severity=Severity.WARNING, category=self.category,
                code="security.remote_access_tools.running_now",
                data=self._data(s, "running_now"),
            )
        severity = Severity.INFO if self._quiet(s, platform) else Severity.WARNING
        return Finding(
            title=title, description=description, severity=severity, category=self.category,
            code="security.remote_access_tools.tool_found",
            data=self._data(s, "tool_found"),
        )

    def _findings(self, sightings, platform: str) -> list[Finding]:
        today = self.now().date()
        findings = [self._tool_finding(s, platform, today) for s in sightings]
        names = sorted({s.tool.name for s in sightings})
        if len(names) >= 2:
            findings.append(Finding(
                title="More than one remote-access tool is on this computer",
                description=(
                    f"We found {len(names)} tools that each let someone else control this computer: "
                    f"{', '.join(names)}. Tech-support scammers often install a second tool, so that removing "
                    "one doesn't lock them out. Each tool has its own card with what we could see about it. "
                    "Check each one, and run the checkup again after removing one.\n\n"
                    "What to do: go through each tool's card. If someone who contacted you asked you to "
                    "install any of them, call your bank on the number on your card, from another phone if "
                    "you can."
                ),
                severity=Severity.CRITICAL,
                category=self.category,
                code="security.remote_access_tools.several_tools",
                data={"check": "several_tools", "tools": names},
            ))
        return findings
