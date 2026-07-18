from pathlib import Path

from rescue.cli import _get_guides_dir, _get_modules_dir
from rescue.guides import load_guide
from rescue.registry import discover_modules

REM_DIR = _get_guides_dir() / "remediation"


def test_every_remediates_code_is_declared_by_some_module():
    declared = set()
    for mod in discover_modules(_get_modules_dir()):
        declared.update(getattr(mod, "emits_codes", []))
    if not REM_DIR.is_dir():
        return
    for path in REM_DIR.glob("*.md"):
        for code in load_guide(path).remediates:
            assert code in declared, f"{path.name}: code {code} not in any emits_codes"


def test_no_two_walkthroughs_claim_the_same_code():
    if not REM_DIR.is_dir():
        return
    seen: dict[str, str] = {}
    for path in sorted(REM_DIR.glob("*.md")):
        for code in load_guide(path).remediates:
            assert code not in seen, f"{code} claimed by both {seen[code]} and {path.name}"
            seen[code] = path.name


def test_all_walkthroughs_parse_and_have_steps():
    if not REM_DIR.is_dir():
        return
    for path in REM_DIR.glob("*.md"):
        g = load_guide(path)
        assert g.remediates, f"{path.name} declares no remediates codes"
        assert g.steps, f"{path.name} has no steps"
