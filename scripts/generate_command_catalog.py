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
WHOIS_PY = REPO_ROOT / "rescue" / "whois.py"
OUTPUT_PATH = REPO_ROOT / "docs" / "commands.md"

SUBPROCESS_FUNCS = {"run", "check_output", "check_call", "call", "Popen"}

SOCKETS_LINE = "Also opens network connections directly from Python (sockets), without an external command."

HEADER = """# What each check runs

!!! info "This page is generated"
    Written by `python scripts/generate_command_catalog.py` from the module
    source code. CI runs it with `--check`, so it cannot drift from what ships.
    Do not edit it by hand.

Every check in Reclaim City is a Python file under `modules/`. Most of them
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


def _param_names(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    """Positional parameter names as a caller counts them (``self``/``cls`` dropped)."""
    names = [a.arg for a in fn.args.posonlyargs + fn.args.args]
    if names and names[0] in {"self", "cls"}:
        names = names[1:]
    return names


def _runner_helpers(tree: ast.Module) -> dict[str, int]:
    """Functions that forward one of their parameters as a command's argv.

    Maps function name to the index of the parameter passed as ``args[0]`` to a
    command call, so literal argv lists given to the helper can be listed.
    """
    bounded = _bounded_run_names(tree)
    helpers: dict[str, int] = {}
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        params = _param_names(fn)
        for node in ast.walk(fn):
            if (
                isinstance(node, ast.Call)
                and _is_command_call(node, bounded)
                and node.args
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id in params
            ):
                helpers[fn.name] = params.index(node.args[0].id)
    return helpers


def _content_module_paths(tree: ast.Module) -> list[Path]:
    """Files named by string literals passed to ``load_content_module(...)``."""
    paths: list[Path] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and node.args):
            continue
        func = node.func
        name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
        first = node.args[0]
        if name == "load_content_module" and isinstance(first, ast.Constant) and isinstance(first.value, str):
            paths.append(REPO_ROOT / first.value)
    return paths


def _uses_sockets(tree: ast.Module) -> bool:
    """True if the file calls ``socket.socket(...)`` or ``socket.create_connection(...)``."""
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"socket", "create_connection"}
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "socket"
        ):
            return True
    return False


def _helper_name(node: ast.Call, helpers: dict[str, int]) -> str | None:
    """Name of the runner helper this call invokes (``f(...)`` or ``self.f(...)``)."""
    func = node.func
    if isinstance(func, ast.Name) and func.id in helpers:
        return func.id
    if (
        isinstance(func, ast.Attribute)
        and func.attr in helpers
        and isinstance(func.value, ast.Name)
        and func.value.id in {"self", "cls"}
    ):
        return func.attr
    return None


def _scan_tree(tree: ast.Module, found: set[str]) -> tuple[int, bool]:
    """Add the commands in ``tree`` to ``found``; return (dynamic count, sockets)."""
    bounded = _bounded_run_names(tree)
    helpers = _runner_helpers(tree)
    # Command calls whose argv is a helper's own parameter are accounted for
    # at the helper's call sites, not counted as built at runtime.
    forwarded: set[int] = set()
    for fn in ast.walk(tree):
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) and fn.name in helpers:
            params = _param_names(fn)
            for node in ast.walk(fn):
                if (
                    isinstance(node, ast.Call)
                    and _is_command_call(node, bounded)
                    and node.args
                    and isinstance(node.args[0], ast.Name)
                    and node.args[0].id in params
                ):
                    forwarded.add(id(node))
    dynamic = 0
    # Module-level ``NAME_ARGS = [...]`` constants are argv lists that a runner
    # passed in as a parameter will execute (e.g. conn_common/collect.py).
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id.endswith("_ARGS")
        ):
            rendered = _render_argv(node.value)
            if rendered is not None:
                found.add(rendered)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if _is_command_call(node, bounded) and node.args:
            if id(node) in forwarded:
                continue
            rendered = _render_argv(node.args[0])
            if rendered is None:
                dynamic += 1
            else:
                found.add(rendered)
        elif _helper_name(node, helpers) is not None:
            index = helpers[_helper_name(node, helpers)]
            if index < len(node.args):
                rendered = _render_argv(node.args[index])
                if rendered is None:
                    dynamic += 1
                else:
                    found.add(rendered)
            else:
                dynamic += 1
    return dynamic, _uses_sockets(tree)


def commands_for(module_dir: Path) -> tuple[list[str], int, bool]:
    found: set[str] = set()
    dynamic = 0
    sockets = False
    parsed: set[Path] = set()
    pending = [p for p in sorted(module_dir.rglob("*.py")) if "__pycache__" not in p.parts]
    while pending:
        path = pending.pop(0)
        if path in parsed:
            continue
        parsed.add(path)
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, OSError):
            continue
        extra_dynamic, extra_sockets = _scan_tree(tree, found)
        dynamic += extra_dynamic
        sockets = sockets or extra_sockets
        for target in _content_module_paths(tree):
            if target.suffix == ".py" and target not in parsed:
                pending.append(target)
    return sorted(found), dynamic, sockets


def _https_urls(tree: ast.Module) -> list[str]:
    """Every ``https://`` URL written in the file, with runtime parts shown as ``…``."""
    urls = set()
    # The literal pieces of an f-string are Constants too; only the whole counts.
    pieces = {id(part) for node in ast.walk(tree) if isinstance(node, ast.JoinedStr)
              for part in node.values}
    for node in ast.walk(tree):
        if id(node) in pieces:
            continue
        if isinstance(node, ast.JoinedStr):
            text = "".join(
                part.value if isinstance(part, ast.Constant) else "…" for part in node.values
            )
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            text = node.value
        else:
            continue
        if text.startswith("https://") and " " not in text:
            urls.add(text)
    return sorted(urls)


def watch_section() -> list[str]:
    """The connection watch's network use: the lookups of who runs each address."""
    tree = ast.parse(WHOIS_PY.read_text(encoding="utf-8"))
    commands: set[str] = set()
    _scan_tree(tree, commands)
    out = [
        "## The connection watch (`rescue watch`) and `rescue lookup`\n",
        "The watch is not part of a scan. It reads connections with the commands",
        "listed under `conn_common` above. When it finishes, unless `--no-lookups`",
        "is given, it looks up who runs each public address it saw (never a private,",
        "local or reserved one); `rescue lookup` does the same for addresses you",
        "name. Only the address is sent, to these services over HTTPS. rdap.org",
        "passes the request on to the regional registry that holds the address",
        "(ARIN, RIPE NCC, APNIC, LACNIC or AFRINIC), so that registry receives it",
        "too:\n",
        "```text",
        *_https_urls(tree),
        "```\n",
        "Plus reverse DNS for each address, and a lookup of the name that comes",
        "back to confirm it, both through this computer's own resolver.",
        "Nothing about the addresses is written to disk.",
    ]
    if commands:
        out += [
            "\nTo check the services' certificates on a Mac, it also runs:\n",
            "```text",
            *sorted(commands),
            "```",
        ]
    out.append("")
    return out


def render() -> str:
    by_category: dict[str, list[tuple[str, list[str], int, bool]]] = defaultdict(list)
    for module_py in sorted(MODULES_DIR.glob("*/*/__init__.py")):
        module_dir = module_py.parent
        category = module_dir.parent.name
        commands, dynamic, sockets = commands_for(module_dir)
        by_category[category].append((module_dir.name, commands, dynamic, sockets))

    out = [HEADER]
    for category in sorted(by_category):
        out.append(f"## {category.capitalize()}\n")
        for name, commands, dynamic, sockets in by_category[category]:
            out.append(f"### `{name}`\n")
            if not commands and not dynamic:
                if sockets:
                    out.append(f"Runs no external commands. {SOCKETS_LINE}\n")
                else:
                    out.append("Runs no external commands; reads files and system APIs only.\n")
                continue
            if commands:
                out.append("```text")
                out.extend(commands)
                out.append("```")
            if dynamic:
                out.append(f"\nPlus {dynamic} command(s) built at runtime.")
            if sockets:
                out.append(f"\n{SOCKETS_LINE}")
            out.append("")
    out.extend(watch_section())
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
