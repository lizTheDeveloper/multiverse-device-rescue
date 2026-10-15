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


def test_steps_for_names_only_remediated_codes_and_real_steps():
    if not REM_DIR.is_dir():
        return
    for path in REM_DIR.glob("*.md"):
        g = load_guide(path)
        numbers = {s.number for s in g.steps}
        for code, wanted in g.steps_for.items():
            assert code in g.remediates, f"{path.name}: steps_for names {code}, not remediated"
            assert wanted, f"{path.name}: steps_for {code} is empty"
            assert set(wanted) <= numbers, f"{path.name}: steps_for {code} -> {wanted}"


_TWO_CODE_GUIDE = """---
title: "Firewall"
estimated_time: "5 minutes"
remediates: [a.off, a.loose]
steps_for:
  a.off: [1, 3]
---

## Step 1: Turn it on

on

## Step 2: Tighten it

tight

## Step 3: Check it worked

check
"""


def test_a_finding_gets_only_its_own_steps():
    from rescue.guides import parse_guide_markdown
    from rescue.serialize import _remediation

    g = parse_guide_markdown(_TWO_CODE_GUIDE)
    assert [s["number"] for s in _remediation(g, "a.off")["steps"]] == [1, 3]
    assert _remediation(g, "a.off")["all_steps"] is False
    # A code with no steps_for entry still gets the whole guide.
    assert [s["number"] for s in _remediation(g, "a.loose")["steps"]] == [1, 2, 3]
    assert _remediation(g, "a.loose")["all_steps"] is True


def test_monitoring_risk_guides_carry_the_safety_note():
    from rescue.guides import parse_guide_markdown
    from rescue.serialize import _remediation

    flagged = parse_guide_markdown(_TWO_CODE_GUIDE.replace("---\n\n", "monitoring_risk: true\n---\n\n", 1))
    note = _remediation(flagged, "a.off").get("safety_note", "")
    assert "1-800-799-7233" in note
    assert "safety_note" not in _remediation(parse_guide_markdown(_TWO_CODE_GUIDE), "a.off")
