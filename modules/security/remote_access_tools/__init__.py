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
import time
from datetime import date, datetime
from pathlib import Path

from rescue.command import run
from rescue.models import (
    CheckResult,
    FixResult,
    Mode,
    Platform,
    RiskLevel,
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


def _proc_names(profile: SystemProfile) -> set[str] | None:
    procs = getattr(profile, "processes", None) or []
    if not procs:
        return None
    names = set()
    for p in procs:
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
    emits_codes: list[str] = []

    MAC_APP_DIRS = [Path("/Applications"), Path.home() / "Applications", Path.home() / "Downloads"]
    MAC_LAUNCHD_DIRS = [Path("/Library/LaunchDaemons"), Path("/Library/LaunchAgents"),
                        Path.home() / "Library/LaunchAgents"]
    HOME = Path.home()
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
        else:
            return CheckResult(module_name=self.name, supported=False,
                               unsupported_reason="This check runs on macOS and Windows.")
        return CheckResult(module_name=self.name, findings=self._findings(sightings, profile.platform.value))

    def _findings(self, sightings, platform: str) -> list:
        return []

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        return FixResult(module_name=self.name, actions=[])

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
        if raw.startswith("~"):
            return self.HOME / raw[1:].lstrip("/\\")
        expanded = os.path.expandvars(raw)
        if "%" in expanded:
            return None
        return Path(expanded)

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
        names = _proc_names(profile)
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
