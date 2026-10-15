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


def _wording_aliases(tree: ast.AST) -> set[str]:
    """Names assigned straight from a wording attribute: `title = finding.title`."""
    return {
        target.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign) and _reads_wording(node.value)
        for target in node.targets
        if isinstance(target, ast.Name)
    }


def _uses(node: ast.AST, aliases: set[str]) -> bool:
    if _reads_wording(node):
        return True
    while isinstance(node, (ast.Call, ast.Attribute)):
        node = node.func if isinstance(node, ast.Call) else node.value
    return isinstance(node, ast.Name) and node.id in aliases


def test_no_module_compares_finding_wording():
    problems = []
    for path in sorted((ROOT / "modules").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        aliases = _wording_aliases(tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Compare):
                continue
            sides = [node.left, *node.comparators]
            if any(_uses(side, aliases) for side in sides):
                problems.append(f"{path.relative_to(ROOT)}:{node.lineno}")
    assert not problems, "Branch on code or data['check'], not wording:\n" + "\n".join(problems)
