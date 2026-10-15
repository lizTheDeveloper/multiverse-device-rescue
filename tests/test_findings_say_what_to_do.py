"""Every warning and critical finding ends with a plain next step.

The app shows a paragraph starting "What to do:" in bold under the
explanation. A warning without one leaves a worried person knowing what's
wrong but not what to do about it. Descriptions assembled elsewhere (a
variable or a helper call) are checked where they're built, not here.
"""
import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Findings whose "What to do:" comes from a lookup table in the same module.
_FROM_TABLE: set[str] = set()


def _literal_text(node: ast.AST) -> str:
    return "".join(
        n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str)
    )


def test_warning_and_critical_findings_say_what_to_do():
    missing = []
    for path in sorted((ROOT / "modules").rglob("*.py")):
        src = path.read_text(encoding="utf-8")
        for node in ast.walk(ast.parse(src)):
            if not (isinstance(node, ast.Call)
                    and getattr(node.func, "id", getattr(node.func, "attr", "")) == "Finding"):
                continue
            kw = {k.arg: k.value for k in node.keywords}
            if ast.get_source_segment(src, kw.get("severity")) == "Severity.INFO":
                continue
            desc = kw.get("description")
            if desc is None or isinstance(desc, (ast.Name, ast.Call)):
                continue
            if path.relative_to(ROOT).as_posix() in _FROM_TABLE:
                continue
            if "What to do" not in _literal_text(desc) and "what_to_do" not in ast.unparse(desc):
                missing.append(f"{path.relative_to(ROOT)}:{node.lineno}")
    assert not missing, "Add a 'What to do:' paragraph:\n" + "\n".join(missing)
