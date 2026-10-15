"""Trace every third-party launchd job that starts by itself.

One ``launchctl list`` call plus a few plist reads. Nothing is executed,
signature-checked or modified here; "who made it" is added centrally after the
scan from each item's ``program`` path. Judging whether a job is *safe* is the
job of launch_agent_audit / launchd_persistence_audit, not this check.
"""

import os
import plistlib
import re
import shutil
import stat
from pathlib import Path

from rescue.attribution import is_interpreter
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

# Fewer than this many third-party items is normal; say nothing.
REPORT_COUNT = 3
# At or above this many, it is worth a WARNING. Never CRITICAL: this is
# tidiness, not security.
WARNING_COUNT = 25
# How many items to name in the plain-language description.
DESCRIBE_COUNT = 5

SCOPE_USER = "you"
SCOPE_ALL_USERS = "all users"
SCOPE_SYSTEM = "system-wide background service"

NO_PLIST_NOTE = "registered by an app, no settings file"


class Module(ModuleBase):
    name = "startup_optimizer"
    category = "performance"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 65
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        entries = _parse_launchctl_list(self._run_launchctl_list())
        apps = [e for e in entries if e["label"].startswith("application.")]
        startup = [
            e for e in entries
            if not e["label"].startswith(("application.", "com.apple."))
        ]

        findings = []
        if len(startup) >= REPORT_COUNT:
            items = [_trace_item(e) for e in startup]
            severity = (
                Severity.WARNING if len(startup) >= WARNING_COUNT else Severity.INFO
            )
            findings.append(self._make_finding(items, len(apps), severity))
        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            data = finding.data
            labels = data.get("third_party_labels", [])
            count = data.get("count", len(labels))
            preview = ", ".join(labels[:DESCRIBE_COUNT])
            if count > DESCRIBE_COUNT:
                preview += ", ..."
            actions.append(
                Action(
                    title="Startup items report",
                    description=(
                        f"{count} third-party startup item(s) detected: "
                        f"{preview}. Nothing was changed. Run the "
                        "startup_auditor module to review and disable the "
                        "ones you don't need."
                    ),
                    risk_level=RiskLevel.SAFE,
                    success=True,
                )
            )
        return FixResult(module_name=self.name, actions=actions)

    def _make_finding(
        self, items: list[dict], apps_registered: int, severity: Severity
    ) -> Finding:
        n = len(items)
        stale = sum(1 for i in items if i["plist"] and not i["program_exists"])
        named = "; ".join(_describe_item(i) for i in items[:DESCRIBE_COUNT])
        description = (
            "These are programs that macOS starts for you in the background, "
            "which can slow down startup and use memory. "
            f"Including: {named}."
        )
        if n > DESCRIBE_COUNT:
            description += f" Plus {n - DESCRIBE_COUNT} more."
        if stale:
            description += (
                f" {stale} of them point to a program that is no longer "
                "there (left over from something that was removed)."
            )
        description += (
            "\n\nWhat to do: Open System Settings > General > Login Items & "
            "Extensions and, under Allow in the Background, turn off anything you "
            "don't use. Turning one off doesn't uninstall the app."
        )
        return Finding(
            title=f"{n} apps start automatically in the background",
            description=description,
            severity=severity,
            category=self.category,
            data={
                "items": items,
                "third_party_labels": [i["label"] for i in items],
                "count": n,
                "stale_count": stale,
                "apps_registered": apps_registered,
            },
        )

    def _run_launchctl_list(self) -> str:
        return run(["launchctl", "list"]).stdout or ""


def _parse_launchctl_list(output: str) -> list[dict]:
    """Rows of ``PID Status Label`` -> dicts. PID is ``-`` when not running."""
    entries = []
    for line in output.strip().split("\n")[1:]:  # skip header row
        parts = line.split()
        if len(parts) < 3:
            continue
        entries.append(
            {
                "label": parts[-1],
                "pid": _to_int(parts[0]),
                "last_exit": _to_int(parts[1]),
            }
        )
    return entries


def _to_int(text: str):
    try:
        return int(text)
    except ValueError:
        return None


def _plist_dirs() -> list[tuple[Path, str]]:
    return [
        (Path.home() / "Library" / "LaunchAgents", SCOPE_USER),
        (Path("/Library/LaunchAgents"), SCOPE_ALL_USERS),
        (Path("/Library/LaunchDaemons"), SCOPE_SYSTEM),
    ]


def _find_plist(label: str):
    """(path, scope) of ``<label>.plist``, or (None, None). Regular files only."""
    if not label or "/" in label or "\0" in label or label.startswith("."):
        return None, None
    for directory, scope in _plist_dirs():
        path = directory / f"{label}.plist"
        try:
            if stat.S_ISREG(os.lstat(path).st_mode):
                return path, scope
        except (OSError, ValueError):
            continue
    return None, None


def _read_plist(path: Path) -> dict:
    try:
        with open(path, "rb") as fh:
            data = plistlib.load(fh)
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _program_of(plist: dict):
    prog = plist.get("Program")
    if isinstance(prog, str) and prog:
        return prog
    args = plist.get("ProgramArguments")
    if isinstance(args, list) and args and isinstance(args[0], str) and args[0]:
        return args[0]
    return None


def _arg_count(plist: dict) -> int:
    args = plist.get("ProgramArguments")
    if isinstance(args, list):
        return len(args)
    return 1 if isinstance(plist.get("Program"), str) else 0


def _program_exists(program) -> bool:
    if not program:
        return False
    if os.path.isabs(program):
        return os.path.exists(program)
    return shutil.which(program) is not None


def _every(seconds: int) -> str:
    for size, unit in ((86400, "day"), (3600, "hour"), (60, "minute")):
        if seconds >= size and seconds % size == 0:
            n = seconds // size
            return f"every {unit}" if n == 1 else f"every {n} {unit}s"
    return f"every {seconds} seconds"


def _when(plist: dict, scope: str) -> list[str]:
    when = []
    if plist.get("RunAtLoad") is True:
        when.append("at startup" if scope == SCOPE_SYSTEM else "at login")
    keep = plist.get("KeepAlive")
    if keep is True or (isinstance(keep, dict) and keep):
        when.append("kept running")
    interval = plist.get("StartInterval")
    if isinstance(interval, int) and not isinstance(interval, bool) and interval > 0:
        when.append(_every(interval))
    if plist.get("StartCalendarInterval"):
        when.append("on a schedule")
    if plist.get("WatchPaths") or plist.get("QueueDirectories"):
        when.append("when a file changes")
    return when or ["only when needed"]


def _trace_item(entry: dict) -> dict:
    label = entry["label"]
    path, scope = _find_plist(label)
    item = {
        "label": label,
        "running": entry["pid"] is not None,
        "pid": entry["pid"],
        "last_exit": entry["last_exit"],
        "plist": str(path) if path else None,
        "scope": scope,
        "program": None,
        "program_exists": False,
        "arg_count": 0,
        "when": [],
    }
    if path is None:
        return item
    plist = _read_plist(path)
    if plist and plist.get("Label") != label:
        # A file named after the job that doesn't declare it isn't its settings.
        item.update(plist=None, scope=None)
        return item
    program = _program_of(plist)
    item.update(
        program=program,
        program_exists=_program_exists(program),
        arg_count=_arg_count(plist),
        when=_when(plist, scope),
    )
    return item


# Labels and program names are chosen by whoever installed the job, and the
# description is read by people and by AI helpers. Only plain name characters
# go into it; anything else becomes "?", and long names are cut.
_UNSAFE_TEXT = re.compile(r"[^A-Za-z0-9._+-]")
_MAX_NAME = 60


def _safe_name(text: str) -> str:
    text = _UNSAFE_TEXT.sub("?", str(text))
    return text if len(text) <= _MAX_NAME else text[: _MAX_NAME - 1] + "…"


def _describe_item(item: dict) -> str:
    label = _safe_name(item["label"])
    if not item["plist"]:
        return f"{label} — {NO_PLIST_NOTE}"
    program = item["program"]
    if not program:
        return f"{label} — settings file names no program"
    name = os.path.basename(program) or program
    if is_interpreter(name):
        runs = f"runs a script with {_safe_name(name)}"
    else:
        runs = f"runs {_safe_name(name)}"
    if not item["program_exists"]:
        runs += " (program missing)"
    return f"{label} — {runs}, {', '.join(item['when'])}"
