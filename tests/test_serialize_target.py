"""A disk checked from outside gets no fix, action or "It's mine" offers."""

import json

import rescue.serialize as serialize
from rescue.models import CheckResult, Finding, Severity
from rescue.serialize import checks_to_json


class _Mod:
    name = "linux_ssh_hardening"
    category = "security"


def _results():
    finding = Finding(title="t", description="d", severity=Severity.WARNING, category="security")
    return [(_Mod(), CheckResult(module_name=_Mod.name, findings=[finding]))]


def _doc(monkeypatch, target):
    monkeypatch.setattr(serialize, "_action_fixable", lambda *a: {"action": "a", "target": "t"})
    monkeypatch.setattr(serialize, "_markable", lambda *a: {"kind": "k", "id": "i"})
    app_fixes = {_Mod.name: {"will_change": "x", "how_to_undo": ["y"]}}
    return json.loads(checks_to_json(_results(), "linux", app_fixes=app_fixes, app_actions={}, target=target))


def test_live_findings_keep_their_offers(monkeypatch):
    f = _doc(monkeypatch, None)["modules"][0]["findings"][0]
    assert "fixable" in f and "markable" in f


def test_target_findings_have_no_offers(monkeypatch):
    target = {"root": "/mnt/disk", "os": "linux", "read_only": True}
    f = _doc(monkeypatch, target)["modules"][0]["findings"][0]
    assert "fixable" not in f and "markable" not in f
