"""remote_access_tools: findings, severity, codes and the "mine" mark kind."""

import ast
import importlib.util
import re
import sys
from datetime import date, datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import ActionKind, CheckResult, Mode, Severity

ROOT = Path(__file__).parent.parent
SOURCE = ROOT / "modules/security/remote_access_tools/__init__.py"
_spec = importlib.util.spec_from_file_location("rescue_modules.remote_access_tools_findings_test", SOURCE)
MOD = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(MOD)
EV = MOD._ev
TOOLS = {t.id: t for t in MOD._tools.load_tools()}

RELATIONSHIP_WORDS = re.compile(r"\b(partner\w*|ex|exes|abuser\w*|stalk\w*|spy\w*)\b", re.I)


def _module(verified=False):
    m = MOD.Module()
    m.now = lambda: datetime(2026, 3, 12, 12, 0, 0)
    m._verified_maker = lambda path, platform: verified
    return m


def _s(tool="anydesk", **kw):
    base = dict(path="/Applications/AnyDesk.app", added_on=None, lets_in_unattended=None, unattended_via=None,
                running_now=None, last_incoming=None, incoming_count=None, one_off=False)
    base.update(kw)
    return EV.Sighting(tool=TOOLS[tool], **base)


def _one(m, s, platform="darwin"):
    findings = m._findings([s], platform)
    assert len(findings) == 1
    return findings[0]


def test_unattended_added_9_days_ago_is_critical():
    f = _one(_module(), _s(added_on=date(2026, 3, 3), lets_in_unattended=True,
                           unattended_via="com.philandro.anydesk.service"))
    assert f.severity == Severity.CRITICAL
    assert f.code == "security.remote_access_tools.unattended_recent"
    assert f.data["added_on"] == "2026-03-03"
    assert f.data["unattended_via"] == "com.philandro.anydesk.service"


def test_unattended_added_40_days_ago_is_warning_tool_found():
    f = _one(_module(), _s(added_on=date(2026, 1, 31), lets_in_unattended=True))
    assert f.severity == Severity.WARNING
    assert f.code == "security.remote_access_tools.tool_found"


def test_unattended_with_unknown_date_is_not_called_recent():
    f = _one(_module(), _s(added_on=None, lets_in_unattended=True))
    assert f.code == "security.remote_access_tools.tool_found"
    assert f.severity == Severity.WARNING


def test_running_now_code():
    f = _one(_module(), _s(running_now=True, lets_in_unattended=False, added_on=date(2025, 1, 1)))
    assert f.severity == Severity.WARNING
    assert f.code == "security.remote_access_tools.running_now"
    recent = _one(_module(), _s(running_now=True, lets_in_unattended=True, added_on=date(2026, 3, 10)))
    assert recent.code == "security.remote_access_tools.unattended_recent"


def test_two_tools_add_several_tools_critical():
    m = _module()
    findings = m._findings([_s("anydesk"), _s("teamviewer", path="/Applications/TeamViewer.app")], "darwin")
    several = [f for f in findings if f.code == "security.remote_access_tools.several_tools"]
    assert len(several) == 1
    assert several[0].severity == Severity.CRITICAL
    assert several[0].data == {"check": "several_tools", "tools": ["AnyDesk", "TeamViewer"]}
    per_tool = [f for f in findings if f.code != "security.remote_access_tools.several_tools"]
    assert {f.data["tool_id"] for f in per_tool} == {"anydesk", "teamviewer"}


def test_one_tool_has_no_several_tools():
    findings = _module()._findings([_s("anydesk")], "darwin")
    assert not [f for f in findings if f.code == "security.remote_access_tools.several_tools"]


QUIET = dict(one_off=True, running_now=False, incoming_count=0, lets_in_unattended=False)


def test_info_only_when_every_fact_is_known_and_quiet():
    f = _one(_module(verified=True), _s(**QUIET))
    assert f.severity == Severity.INFO
    assert f.code == "security.remote_access_tools.tool_found"


@pytest.mark.parametrize("change", [
    {"incoming_count": None}, {"running_now": None}, {"lets_in_unattended": None},
    {"one_off": False}, {"incoming_count": 1}, {"path": None},
])
def test_any_unknown_or_active_fact_keeps_it_a_warning(change):
    f = _one(_module(verified=True), _s(**dict(QUIET, **change)))
    assert f.severity == Severity.WARNING


def test_unverified_maker_keeps_it_a_warning():
    assert _one(_module(verified=False), _s(**QUIET)).severity == Severity.WARNING


def test_data_fields():
    f = _one(_module(), _s(added_on=date(2026, 1, 2), lets_in_unattended=False, running_now=False,
                           last_incoming=date(2026, 2, 3), incoming_count=4))
    assert f.data == {
        "check": "tool_found", "tool": "AnyDesk", "tool_id": "anydesk", "path": "/Applications/AnyDesk.app",
        "added_on": "2026-01-02", "lets_in_unattended": False, "unattended_via": None, "running_now": False,
        "last_incoming": "2026-02-03", "incoming_count": 4, "one_off": False, "known_item_kind": "remote_tool",
    }
    assert f.title == "AnyDesk can let someone control this computer"


def test_description_says_couldnt_tell_for_missing_evidence():
    f = _one(_module(), _s())
    first = f.description.split("\n\n")[0]
    assert "Couldn't tell when this was added" in first
    assert "Couldn't tell whether it can let someone in without you clicking yes" in first
    assert "Couldn't tell whether it's running now" in first
    assert "Couldn't tell when it last let someone in" in first
    assert " no " not in f"{first.lower()} "


def test_description_states_known_evidence():
    f = _one(_module(), _s(added_on=date(2026, 3, 3), lets_in_unattended=True, unattended_via="com.x.service",
                           running_now=True, last_incoming=date(2026, 3, 12), incoming_count=4))
    first = f.description.split("\n\n")[0]
    assert "Added on 3 March 2026" in first
    assert "without you clicking yes" in first and "com.x.service" in first
    assert "running now" in first
    assert "12 March 2026" in first and "4 times" in first
    assert "Scammers who call or show a pop-up often ask people to install tools like this" in f.description


def test_zero_connections_says_so():
    f = _one(_module(), _s(incoming_count=0))
    assert "nobody" in f.description.split("\n\n")[0].lower()


def _texts(m, findings):
    out = []
    for f in findings:
        out += [f.title, f.description]
    for a in m.fix(CheckResult(module_name=m.name, findings=findings), Mode.MANUAL).actions:
        out += [a.title, a.description]
    return out


def test_no_relationship_words_in_any_text():
    m = _module()
    sightings = [
        _s(), _s("teamviewer", **QUIET),
        _s("rustdesk", added_on=date(2026, 3, 3), lets_in_unattended=True, running_now=True,
           last_incoming=date(2026, 3, 4), incoming_count=2),
        _s("quick_assist", path=None, running_now=True, lets_in_unattended=False),
    ]
    for text in _texts(m, m._findings(sightings, "darwin")):
        assert not RELATIONSHIP_WORDS.search(text), text


def test_fix_is_guidance_only():
    m = _module()
    findings = m._findings([_s(), _s("teamviewer")], "darwin")
    actions = m.fix(CheckResult(module_name=m.name, findings=findings), Mode.MANUAL).actions
    assert actions
    assert all(a.kind == ActionKind.GUIDANCE for a in actions)


def _code_literals():
    tree = ast.parse(SOURCE.read_text())
    return {kw.value.value for node in ast.walk(tree) if isinstance(node, ast.Call)
            for kw in node.keywords if kw.arg == "code" and isinstance(kw.value, ast.Constant)}


def test_emitted_codes_are_declared():
    expected = {
        "security.remote_access_tools.tool_found",
        "security.remote_access_tools.several_tools",
        "security.remote_access_tools.unattended_recent",
        "security.remote_access_tools.running_now",
    }
    assert set(MOD.Module.emits_codes) == expected
    assert _code_literals() == expected


def test_mark_kind_known():
    from rescue import known_items
    from rescue.models import Finding

    assert "remote_tool" in known_items.ITEM_KINDS
    assert known_items.ITEM_KINDS["remote_tool"]["modules"] == ("remote_access_tools",)
    assert known_items.item_kind_for("security.remote_access_tools.tool_found") == "remote_tool"
    assert known_items.item_kind_for("security.remote_access_tools.running_now") == "remote_tool"
    assert known_items.item_kind_for("security.remote_access_tools.several_tools") is None
    f = _one(_module(), _s(lets_in_unattended=True, last_incoming=date(2026, 3, 1), incoming_count=2))
    kind, ident = known_items.item_identity(f)
    assert kind == "remote_tool"
    assert ident["tool_id"] == "anydesk" and ident["path"] == "/Applications/AnyDesk.app"
    markable = known_items.item_markable(f, "remote_access_tools")
    assert markable and markable["kind"] == "remote_tool" and markable["monitoring"] is True
    # A newer connection is the same item with changed evidence.
    newer = _one(_module(), _s(lets_in_unattended=True, last_incoming=date(2026, 3, 9), incoming_count=3))
    _, ident2 = known_items.item_identity(newer)
    assert known_items.base_identity("remote_tool", ident) == known_items.base_identity("remote_tool", ident2)
    assert known_items.item_id("remote_tool", ident) != known_items.item_id("remote_tool", ident2)
    # No path: nothing to pin, so it can't be marked.
    assert known_items.item_identity(_one(_module(), _s(path=None))) is None
    assert isinstance(f, Finding)


def test_mark_kind_known_to_the_desktop():
    for rel in ("desktop/mark-policy.js", "desktop/engine-runner.js", "desktop/renderer/mark-flow.js"):
        assert "'remote_tool'" in (ROOT / rel).read_text(), rel
