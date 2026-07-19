"""Gate: a module's declared `emits_codes` must exactly match the `code="..."`
literals its source actually attaches to findings.

This catches the drift the per-module `test_emitted_codes_are_declared` tests
miss: a `Finding(code=...)` whose code was never added to `emits_codes` (so it
gets no walkthrough button and no catalog row), or a declared code that no
finding ever emits (a typo or stale entry).
"""

import re
from pathlib import Path

from rescue.cli import _get_modules_dir
from rescue.registry import discover_modules

_CODE_LITERAL = re.compile(r'code\s*=\s*["\'](security\.[a-z0-9_.]+)["\']')


def _module_source(modules_dir: Path, mod) -> str:
    src = modules_dir / mod.category / mod.name / "__init__.py"
    return src.read_text() if src.exists() else ""


def test_emits_codes_match_code_literals():
    modules_dir = _get_modules_dir()
    problems: list[str] = []
    checked = 0
    for mod in discover_modules(modules_dir):
        declared = set(getattr(mod, "emits_codes", []))
        if not declared:
            continue
        checked += 1
        literals = set(_CODE_LITERAL.findall(_module_source(modules_dir, mod)))
        missing = declared - literals
        undeclared = literals - declared
        if missing:
            problems.append(
                f"{mod.name}: emits_codes entries with no matching code= literal: {sorted(missing)}")
        if undeclared:
            problems.append(
                f"{mod.name}: code= literals not in emits_codes: {sorted(undeclared)}")
    assert checked, "no modules declare emits_codes"
    assert not problems, "code=/emits_codes drift:\n" + "\n".join(problems)
