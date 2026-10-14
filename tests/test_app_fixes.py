"""The allowlist behind the app's "Fix it for me" button.

The button may only ever appear for modules that were individually audited
(docs/fix-audit.md) and listed in rescue/app_fixes.json. These tests are the
gate that keeps that list honest.
"""

import json
import re
from pathlib import Path

import pytest

from rescue.app_fixes import (
    DEFAULT_APP_FIXES_PATH,
    AppFixesError,
    fix_is_mutating,
    load_app_fixes,
    mutating_fix_modules,
    validate_app_fixes,
)

ROOT = Path(__file__).resolve().parent.parent
MODULES_DIR = ROOT / "modules"
AUDIT_DOC = ROOT / "docs" / "fix-audit.md"

GOOD = {
    "will_change": "Turns on your Mac's firewall.",
    "how_to_undo": ["Open System Settings.", "Choose Network, then Firewall, and turn it off."],
}


def _write_module(tmp_path, category, name, fix_body, risk="SAFE"):
    d = tmp_path / category / name
    d.mkdir(parents=True)
    (d / "__init__.py").write_text(
        "import subprocess\n"
        "from rescue.models import *\n"
        "from rescue.module_base import ModuleBase\n"
        "class Module(ModuleBase):\n"
        f"    name = '{name}'\n"
        f"    category = '{category}'\n"
        "    platforms = [Platform.DARWIN, Platform.LINUX, Platform.WIN32]\n"
        f"    risk_level = RiskLevel.{risk}\n"
        "    def check(self, profile):\n"
        "        return CheckResult(module_name=self.name)\n"
        "    def fix(self, findings, mode):\n"
        f"{fix_body}\n"
    )
    return tmp_path


MUTATING = "        subprocess.run(['true'])\n        return FixResult(module_name=self.name)"
GUIDANCE = "        return FixResult(module_name=self.name, actions=[Action(title='t', description='d', risk_level=RiskLevel.SAFE)])"
HELPER = (
    "        self._go()\n        return FixResult(module_name=self.name)\n"
    "    def _go(self):\n        import os\n        os.remove('/nonexistent')"
)


def test_shipped_allowlist_loads():
    fixes = load_app_fixes()
    assert isinstance(fixes, dict)
    assert DEFAULT_APP_FIXES_PATH.is_file()


def test_shipped_allowlist_passes_its_own_validation():
    assert validate_app_fixes(load_app_fixes(), MODULES_DIR) == []


def test_validate_flags_a_module_that_does_not_exist(tmp_path):
    _write_module(tmp_path, "security", "real_one", MUTATING)
    problems = validate_app_fixes({"ghost": GOOD}, tmp_path)
    assert any("ghost" in p and "does not exist" in p for p in problems)


def test_validate_flags_a_guidance_only_fix(tmp_path):
    _write_module(tmp_path, "security", "guidance_only", GUIDANCE)
    problems = validate_app_fixes({"guidance_only": GOOD}, tmp_path)
    assert any("guidance_only" in p and "does not change anything" in p for p in problems)


def test_validate_accepts_a_mutating_fix(tmp_path):
    _write_module(tmp_path, "security", "changer", MUTATING)
    assert validate_app_fixes({"changer": GOOD}, tmp_path) == []


def test_validate_follows_helpers_called_from_fix(tmp_path):
    _write_module(tmp_path, "security", "helper_changer", HELPER)
    assert validate_app_fixes({"helper_changer": GOOD}, tmp_path) == []


def test_validate_refuses_destructive_modules(tmp_path):
    _write_module(tmp_path, "security", "scary", MUTATING, risk="DESTRUCTIVE")
    problems = validate_app_fixes({"scary": GOOD}, tmp_path)
    assert any("scary" in p and "destructive" in p.lower() for p in problems)


@pytest.mark.parametrize(
    "entry",
    [
        {"how_to_undo": ["x"]},
        {"will_change": "", "how_to_undo": ["x"]},
        {"will_change": "x"},
        {"will_change": "x", "how_to_undo": []},
        {"will_change": "x", "how_to_undo": [""]},
        {"will_change": "x", "how_to_undo": "just a string"},
        {"will_change": "x", "how_to_undo": ["x"], "needs_admin": True},
        {"will_change": "x", "how_to_undo": ["x"], "surprise_key": 1},
        "not a dict",
    ],
)
def test_validate_flags_malformed_entries(tmp_path, entry):
    _write_module(tmp_path, "security", "changer", MUTATING)
    assert validate_app_fixes({"changer": entry}, tmp_path) != []


def test_needs_admin_false_is_allowed(tmp_path):
    _write_module(tmp_path, "security", "changer", MUTATING)
    assert validate_app_fixes({"changer": dict(GOOD, needs_admin=False)}, tmp_path) == []


def test_load_rejects_non_object_json(tmp_path):
    p = tmp_path / "f.json"
    p.write_text("[1, 2]")
    with pytest.raises(AppFixesError):
        load_app_fixes(p)


def test_load_rejects_invalid_json(tmp_path):
    p = tmp_path / "f.json"
    p.write_text("{nope")
    with pytest.raises(AppFixesError):
        load_app_fixes(p)


def test_load_missing_file_is_an_error_not_an_empty_list(tmp_path):
    # A missing allowlist must never silently become "everything allowed".
    with pytest.raises(AppFixesError):
        load_app_fixes(tmp_path / "absent.json")


def test_fix_is_mutating_detects_real_modules():
    assert fix_is_mutating(MODULES_DIR / "security" / "firewall_audit" / "__init__.py")
    assert not fix_is_mutating(MODULES_DIR / "integrity" / "time_sync_check" / "__init__.py")


def test_every_mutating_module_has_been_audited():
    """A new mutating fix() cannot ship unaudited: it must appear in the audit doc."""
    audited = set(re.findall(r"^\| `([a-z0-9_]+)` \|", AUDIT_DOC.read_text(), flags=re.M))
    mutating = set(mutating_fix_modules(MODULES_DIR))
    assert mutating - audited == set(), f"unaudited mutating fix(): {sorted(mutating - audited)}"
    assert audited - mutating == set(), f"audit lists non-mutating modules: {sorted(audited - mutating)}"


def test_every_allowlisted_module_is_marked_offerable_in_the_audit():
    text = AUDIT_DOC.read_text()
    for name in load_app_fixes():
        row = re.search(rf"^\| `{name}` \|.*$", text, flags=re.M)
        assert row, f"{name} missing from audit"
        assert "OFFER" in row.group(0), f"{name} is on the allowlist but the audit does not say OFFER"


def test_default_file_is_plain_json_object():
    assert isinstance(json.loads(DEFAULT_APP_FIXES_PATH.read_text()), dict)
