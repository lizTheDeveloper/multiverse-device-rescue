#!/usr/bin/env python3
"""Generate docs/commands.md: every external command each check can run.

Read straight from the module source with ``ast``, so the page cannot drift
from the code. A command whose arguments are all literals is shown in full;
one built at runtime shows its literal parts and ``…`` for the rest, and one
with no literal program name is counted as "built at runtime".

For what a scan *actually* ran on a given machine, use ``rescue scan --trace``.

Usage:
    python scripts/generate_command_catalog.py           # write docs/commands.md
    python scripts/generate_command_catalog.py --check   # exit 1 if stale
"""

from __future__ import annotations

import ast
import sys
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MODULES_DIR = REPO_ROOT / "modules"
OUTPUT_PATH = REPO_ROOT / "docs" / "commands.md"

SUBPROCESS_FUNCS = {"run", "check_output", "check_call", "call", "Popen"}

HEADER = """# What each check runs

!!! info "This page is generated"
    Written by `python scripts/generate_command_catalog.py` from the module
    source code. CI runs it with `--check`, so it cannot drift from what ships.
    Do not edit it by hand.

Every check in Device Rescue is a Python file under `modules/`. Most of them
gather evidence by running ordinary system commands — the same ones you could
type yourself. This page lists, for every check, each command it can run.

- `…` marks an argument filled in at runtime (a path, a user name, a value
  read from an earlier command).
- **Built at runtime** counts calls whose program name itself is computed, so
  it cannot be shown here.
- Which commands actually run depends on the platform and on what each earlier
  command returned. To see exactly what ran on *your* machine, with exit codes
  and timings:

```console
$ rescue scan --trace --json > results.json      # commands stream to stderr
$ rescue scan --trace --profile digital_security_reset --json 2> trace.jsonl >/dev/null
```

In the desktop app, open **Show technical details** while a checkup runs.

Besides commands, checks read files (launch agents, browser profiles, logs)
directly; read a module's `__init__.py` for the full picture. No check writes
anything — `fix()` is separate and always asks first.

"""


def _bounded_run_names(tree: ast.Module) -> set[str]:
    """Local names bound to rescue.command.run (the project's bounded runner)."""
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "rescue.command":
            for alias in node.names:
                if alias.name == "run":
                    names.add(alias.asname or "run")
    return names


def _is_command_call(node: ast.Call, bounded: set[str]) -> bool:
    func = node.func
    if isinstance(func, ast.Attribute) and func.attr in SUBPROCESS_FUNCS:
        return isinstance(func.value, ast.Name) and func.value.id == "subprocess"
    return isinstance(func, ast.Name) and func.id in bounded


def _render_argv(arg: ast.expr) -> str | None:
    """Return a shell-like rendering of a literal-ish argv, or None if unknown."""
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        return arg.value  # shell=True string
    if not isinstance(arg, (ast.List, ast.Tuple)) or not arg.elts:
        return None
    first = arg.elts[0]
    if not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
        return None
    parts = []
    for elt in arg.elts:
        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
            value = elt.value
            parts.append(value if value and all(c.isalnum() or c in "-_./:=@%+," for c in value) else repr(value))
        elif isinstance(elt, ast.Starred):
            parts.append("…")
        else:
            parts.append("…")
    # Collapse runs of "…" so dynamic tails read cleanly.
    collapsed = []
    for part in parts:
        if part == "…" and collapsed and collapsed[-1] == "…":
            continue
        collapsed.append(part)
    return " ".join(collapsed)


def commands_for(module_dir: Path) -> tuple[list[str], int]:
    found: set[str] = set()
    dynamic = 0
    for path in sorted(module_dir.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        bounded = _bounded_run_names(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and _is_command_call(node, bounded) and node.args:
                rendered = _render_argv(node.args[0])
                if rendered is None:
                    dynamic += 1
                else:
                    found.add(rendered)
    return sorted(found), dynamic


def render() -> str:
    by_category: dict[str, list[tuple[str, list[str], int]]] = defaultdict(list)
    for module_py in sorted(MODULES_DIR.glob("*/*/__init__.py")):
        module_dir = module_py.parent
        category = module_dir.parent.name
        commands, dynamic = commands_for(module_dir)
        by_category[category].append((module_dir.name, commands, dynamic))

    out = [HEADER]
    for category in sorted(by_category):
        out.append(f"## {category.capitalize()}\n")
        for name, commands, dynamic in by_category[category]:
            out.append(f"### `{name}`\n")
            if not commands and not dynamic:
                out.append("Runs no external commands; reads files and system APIs only.\n")
                continue
            if commands:
                out.append("```text")
                out.extend(commands)
                out.append("```")
            if dynamic:
                out.append(f"\nPlus {dynamic} command(s) built at runtime.")
            out.append("")
    return "\n".join(out).rstrip() + "\n"


def main() -> int:
    content = render()
    if "--check" in sys.argv:
        current = OUTPUT_PATH.read_text(encoding="utf-8") if OUTPUT_PATH.exists() else ""
        if current != content:
            print(f"{OUTPUT_PATH.relative_to(REPO_ROOT)} is stale; run scripts/generate_command_catalog.py", file=sys.stderr)
            return 1
        return 0
    OUTPUT_PATH.write_text(content, encoding="utf-8")
    print(f"Wrote {OUTPUT_PATH.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
