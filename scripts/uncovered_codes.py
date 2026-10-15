"""List finding codes in modules/ that no remediation walkthrough covers.

Usage: uv run python scripts/uncovered_codes.py
Static (AST) scan: finds ``code=`` keywords on calls, with the severity given
in the same call when it is a literal ``Severity.X``. f-string codes are
reported with ``{}`` placeholders.
"""
import ast
from pathlib import Path

import frontmatter

ROOT = Path(__file__).resolve().parent.parent


def covered_codes() -> set[str]:
    out: set[str] = set()
    for p in (ROOT / "guides" / "remediation").glob("*.md"):
        meta = frontmatter.loads(p.read_text(encoding="utf-8")).metadata
        out |= set(meta.get("remediates") or [])
    return out


def _sev(node):
    if (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
            and node.value.id == "Severity"):
        return node.attr
    return None


def _code_str(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(v.value if isinstance(v, ast.Constant) else "{}" for v in node.values)
    return None


def scan() -> dict[str, tuple[set, set]]:
    """Return {code: (severities, files)} for every call site passing code=."""
    found: dict[str, tuple[set, set]] = {}
    for f in sorted((ROOT / "modules").rglob("*.py")):
        tree = ast.parse(f.read_text(encoding="utf-8"))
        rel = str(f.relative_to(ROOT))
        for n in ast.walk(tree):
            if isinstance(n, ast.Call):
                kw = {k.arg: k.value for k in n.keywords if k.arg}
                if "code" in kw:
                    c = _code_str(kw["code"])
                    if c:
                        s = _sev(kw.get("severity")) or "?"
                        found.setdefault(c, (set(), set()))
                        found[c][0].add(s)
                        found[c][1].add(rel)
    return found


if __name__ == "__main__":
    cov = covered_codes()
    for c, (sev, files) in sorted(scan().items()):
        if c not in cov:
            print(f"{c}\t{','.join(sorted(sev))}\t{';'.join(sorted(files))}")
