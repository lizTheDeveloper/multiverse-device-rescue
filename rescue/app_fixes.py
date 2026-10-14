"""The allowlist behind the desktop app's "Fix it for me" button.

Device Rescue promises never to change anything without the person's explicit
OK, and a wrong automatic fix on a frightened person's computer is worse than
none. So the app may only offer a fix for a module that:

* was individually audited (see docs/fix-audit.md), and
* is listed in rescue/app_fixes.json with plain-language text for what it will
  change and how to undo it.

This module loads and validates that list. It never runs a module's check() or
fix(); detecting a "mutating" fix() is done by reading the module's source.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

from rescue.models import RiskLevel
from rescue.registry import discover_modules

DEFAULT_APP_FIXES_PATH = Path(__file__).parent / "app_fixes.json"

ACTIONS_KEY = "actions"
_ALLOWED_KEYS = {"will_change", "how_to_undo", "needs_admin"}

# Calls that change something outside the process. Reading the source for these
# (rather than trusting a flag) is deliberately conservative: a fix() that is
# not provably guidance-only is treated as mutating and must be audited.
_MUTATING_CALLS = {
    "run", "Popen", "call", "check_call", "check_output", "kill", "unlink",
    "rmtree", "write_text", "write_bytes", "move", "copy2", "copytree",
    "rename", "mkdir", "touch", "system", "chmod", "chown", "makedirs",
    "truncate",
}


class AppFixesError(Exception):
    """The allowlist file is missing or unreadable. Never treated as 'allow all'."""


def load_app_fixes(path: Path | None = None) -> dict[str, dict]:
    path = Path(path) if path is not None else DEFAULT_APP_FIXES_PATH
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise AppFixesError(f"cannot read app fix list {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise AppFixesError(f"app fix list {path} must be a JSON object keyed by module name")
    # "actions" is reserved for engine-level actions; it is never a module name.
    return {k: v for k, v in data.items() if k != ACTIONS_KEY}


def load_app_actions(path: Path | None = None) -> dict[str, dict]:
    """Engine-level actions (not module fix()es) the app may offer. Empty on any problem."""
    path = Path(path) if path is not None else DEFAULT_APP_FIXES_PATH
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    actions = data.get(ACTIONS_KEY) if isinstance(data, dict) else None
    return actions if isinstance(actions, dict) else {}


_ACTION_KEYS = _ALLOWED_KEYS | {"audit", "modules", "severities"}
KNOWN_ACTIONS = {"disable_launch_agent"}


def validate_app_actions(actions: dict[str, dict]) -> list[str]:
    """Problems with the `actions` section (empty = valid)."""
    problems: list[str] = []
    for name, entry in actions.items():
        if name not in KNOWN_ACTIONS:
            problems.append(f"{name}: no such action is implemented")
        if not isinstance(entry, dict):
            problems.append(f"{name}: entry must be an object")
            continue
        for key in entry:
            if key not in _ACTION_KEYS:
                problems.append(f"{name}: unknown key {key!r}")
        problems.extend(p for p in _entry_problems(name, entry) if "unknown key" not in p)
        if entry.get("audit") != "OFFER":
            problems.append(f"{name}: audit verdict must be OFFER")
        mods = entry.get("modules")
        if not isinstance(mods, list) or not mods or not all(isinstance(m, str) for m in mods):
            problems.append(f"{name}: modules must be a non-empty list of module names")
    return problems


def _function_table(tree: ast.AST) -> dict[str, ast.FunctionDef]:
    funcs: dict[str, ast.FunctionDef] = {}
    for node in tree.body:  # type: ignore[attr-defined]
        if isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, ast.FunctionDef):
                    funcs[item.name] = item
        elif isinstance(node, ast.FunctionDef):
            funcs[node.name] = node
    return funcs


def fix_is_mutating(module_file: Path) -> bool:
    """True if fix() (or any helper reachable from it) can change the system."""
    tree = ast.parse(Path(module_file).read_text(encoding="utf-8"))
    funcs = _function_table(tree)
    if "fix" not in funcs:
        return False
    seen: set[str] = set()
    stack = ["fix"]
    while stack:
        name = stack.pop()
        if name in seen or name not in funcs:
            continue
        seen.add(name)
        for node in ast.walk(funcs[name]):
            if isinstance(node, ast.Attribute) and node.attr == "MUTATION":
                return True
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            called = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
            if called in _MUTATING_CALLS:
                return True
            # os.remove / os.replace (but not list.remove or str.replace).
            if (
                isinstance(fn, ast.Attribute)
                and called in {"remove", "replace"}
                and isinstance(fn.value, ast.Name)
                and fn.value.id == "os"
            ):
                return True
            if called == "open":
                modes = node.args[1:2] + [k.value for k in node.keywords if k.arg == "mode"]
                for m in modes:
                    if isinstance(m, ast.Constant) and any(c in str(m.value) for c in "wax+"):
                        return True
            if called in funcs:
                stack.append(called)
    return False


def mutating_fix_modules(modules_dir: Path) -> list[str]:
    """Names of every module under modules_dir whose fix() can change something."""
    names = []
    for init in sorted(Path(modules_dir).glob("*/*/__init__.py")):
        if init.parent.name.startswith("_"):
            continue
        if fix_is_mutating(init):
            names.append(init.parent.name)
    return names


def _entry_problems(name: str, entry: object) -> list[str]:
    if not isinstance(entry, dict):
        return [f"{name}: entry must be an object"]
    problems = []
    for key in entry:
        if key not in _ALLOWED_KEYS:
            problems.append(f"{name}: unknown key {key!r}")
    will = entry.get("will_change")
    if not isinstance(will, str) or not will.strip():
        problems.append(f"{name}: will_change must be a non-empty sentence")
    undo = entry.get("how_to_undo")
    if (
        not isinstance(undo, list)
        or not undo
        or not all(isinstance(s, str) and s.strip() for s in undo)
    ):
        problems.append(f"{name}: how_to_undo must be a non-empty list of plain-language steps")
    if "needs_admin" in entry and entry["needs_admin"] is not False:
        problems.append(f"{name}: needs_admin may only be false; fixes that need admin are not offered")
    return problems


def validate_app_fixes(fixes: dict[str, dict], modules_dir: Path) -> list[str]:
    """Return a list of problems (empty = valid). Never raises, never runs a module."""
    modules_dir = Path(modules_dir)
    by_name = {m.name: m for m in discover_modules(modules_dir)}
    files = {p.parent.name: p for p in modules_dir.glob("*/*/__init__.py")}
    problems: list[str] = []
    for name, entry in fixes.items():
        problems.extend(_entry_problems(name, entry))
        mod = by_name.get(name)
        if mod is None:
            problems.append(f"{name}: module does not exist")
            continue
        if mod.risk_level == RiskLevel.DESTRUCTIVE:
            problems.append(f"{name}: destructive modules are never offered in the app")
        init = files.get(name)
        if init is None or not fix_is_mutating(init):
            problems.append(f"{name}: fix() does not change anything (guidance only), so there is nothing to offer")
    return problems
