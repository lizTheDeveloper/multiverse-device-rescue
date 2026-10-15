"""Module logic must not branch on a finding's wording.

Titles and descriptions are written for people and get reworded. A fix()
that picks its action with `"disabled" in finding.title` silently stops
working when the title changes. Branch on finding.code or
finding.data["check"] instead.
"""
import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _reads_wording(node: ast.AST) -> bool:
    """True for x.title / x.description, or a method call on one (x.title.lower())."""
    while isinstance(node, ast.Call):
        node = node.func
        if isinstance(node, ast.Attribute):
            node = node.value
    return isinstance(node, ast.Attribute) and node.attr in ("title", "description")


def test_no_module_compares_finding_wording():
    problems = []
    for path in sorted((ROOT / "modules").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Compare):
                continue
            sides = [node.left, *node.comparators]
            if any(_reads_wording(side) for side in sides):
                problems.append(f"{path.relative_to(ROOT)}:{node.lineno}")
    assert not problems, "Branch on code or data['check'], not wording:\n" + "\n".join(problems)
