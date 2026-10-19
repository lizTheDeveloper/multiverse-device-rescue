#!/usr/bin/env python3
"""Write every finding description the monitoring checks can produce.

The desktop app's city mode shows a monitoring finding with the hold line and
nothing to act on, so its tests need the real text these checks write, not a
made-up sample. This reads the three modules' source (it never imports or runs
them), finds every ``Finding(description=...)`` and spells out each variant:
both sides of an ``x if c else y``, every known product's description from
``known_stalkerware.json``, and ``ExampleApp`` for any other value filled in at
run time.

Usage::

    python scripts/monitoring_descriptions.py           # write the fixture
    python scripts/monitoring_descriptions.py --check   # exit 1 if stale

``tests/test_monitoring_descriptions.py`` runs the check, so a changed
description fails CI until the fixture is regenerated.
"""

from __future__ import annotations

import argparse
import ast
import itertools
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MODULES = ["stalkerware_scan", "mvt_spyware_scan", "keylogger_indicators"]
OUTPUT_PATH = REPO_ROOT / "desktop" / "test" / "fixtures" / "monitoring-descriptions.json"
FILLER = "ExampleApp"


def _known_products() -> list[str]:
    data = json.loads((REPO_ROOT / "modules" / "security" / "stalkerware_scan" / "data" / "known_stalkerware.json").read_text())
    entries = data["entries"] if isinstance(data, dict) else data
    return sorted({e["description"] for e in entries})


def _constants(tree: ast.Module) -> dict[str, ast.expr]:
    out = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            out[node.targets[0].id] = node.value
    return out


def _variants(node: ast.expr, consts: dict[str, ast.expr], products: list[str]) -> list[str]:
    def go(n: ast.expr) -> list[str]:
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            return [n.value]
        if isinstance(n, ast.JoinedStr):
            parts = [go(v) for v in n.values]
            return ["".join(p) for p in itertools.product(*parts)]
        if isinstance(n, ast.FormattedValue):
            v = n.value
            if isinstance(v, ast.Subscript) and isinstance(v.slice, ast.Constant) and v.slice.value == "description":
                return products
            if isinstance(v, ast.Name) and v.id in consts:
                return go(consts[v.id])
            return [FILLER]
        if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add):
            return [a + b for a, b in itertools.product(go(n.left), go(n.right))]
        if isinstance(n, ast.IfExp):
            return go(n.body) + go(n.orelse)
        if isinstance(n, ast.Name) and n.id in consts:
            return go(consts[n.id])
        return [FILLER]

    return go(node)


def collect() -> list[dict]:
    products = _known_products()
    out = []
    for name in MODULES:
        tree = ast.parse((REPO_ROOT / "modules" / "security" / name / "__init__.py").read_text())
        consts = _constants(tree)
        for call in ast.walk(tree):
            if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id == "Finding"):
                continue
            kw = {k.arg: k.value for k in call.keywords}
            if "description" not in kw:
                continue
            code = kw["code"].value if isinstance(kw.get("code"), ast.Constant) else None
            for text in dict.fromkeys(_variants(kw["description"], consts, products)):
                out.append({"module": name, "code": code, "description": text})
    return out


def render() -> str:
    return json.dumps(collect(), indent=1, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="exit 1 if the fixture is stale")
    args = parser.parse_args()
    text = render()
    if args.check:
        if not OUTPUT_PATH.exists() or OUTPUT_PATH.read_text() != text:
            print(f"{OUTPUT_PATH.relative_to(REPO_ROOT)} is stale; run python scripts/monitoring_descriptions.py", file=sys.stderr)
            return 1
        return 0
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
