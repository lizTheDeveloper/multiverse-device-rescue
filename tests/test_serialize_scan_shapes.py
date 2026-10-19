"""The final scan document is written for every data shape the modules emit.

tests/fixtures/scan_shapes.json holds each module's finding data shapes from one
real macOS scan (every string scrubbed, structure and types kept). One shape
the serializer didn't expect (suspicious_processes listing apps as {path, name}
dicts) once crashed the engine after a full checkup, so the person lost it all.
"""
import json
from pathlib import Path
from types import SimpleNamespace

from rescue.attribution import subjects_for_finding
from rescue.models import CheckResult, Finding, Severity
from rescue.serialize import WRITE_FAILED, _makers_verified, checks_to_json, safe_module_entry

SHAPES = json.loads((Path(__file__).parent / "fixtures" / "scan_shapes.json").read_text())


def _results():
    out = []
    for m in SHAPES["modules"]:
        findings = [
            Finding(
                title=f"Finding {i} of {m['name']}", description="What the check saw.",
                severity=Severity(f["severity"]), category=f["category"] or "general",
                data=f["data"], confidence=f["confidence"], code=f["code"],
            )
            for i, f in enumerate(m["findings"])
        ]
        check = CheckResult(module_name=m["name"], findings=findings, error=m["error"],
                            supported=m["supported"], complete=m["complete"])
        out.append((SimpleNamespace(name=m["name"], category=m["category"]), check))
    return out


def _made_by(results, verified=True):
    return {
        id(f): [{"subject": s, "name": "Example Maker", "verified": verified, "how": "test", "location_note": ""}
                for s in subjects_for_finding(f)]
        for _mod, check in results for f in check.findings if subjects_for_finding(f)
    }


def test_every_module_shape_serializes_with_and_without_makers():
    results = _results()
    assert len(results) == len(SHAPES["modules"]) > 150
    for made_by in (None, _made_by(results), _made_by(results, verified=False)):
        doc = json.loads(checks_to_json(results, "darwin", made_by=made_by))
        assert [m["name"] for m in doc["modules"]] == [m["name"] for m in SHAPES["modules"]]
        for m in doc["modules"]:
            assert m["error"] != WRITE_FAILED, m["name"]
            assert not any(f.get("serialize_error") for f in m["findings"]), m["name"]


def test_apps_as_path_name_dicts_match_their_makers():
    apps = [{"path": "/Applications/A.app", "name": "A.app"}, {"path": "/Applications/B.app", "name": "B.app"}]
    entries = [{"subject": "/Applications/A.app", "verified": True}, {"subject": "/Applications/B.app", "verified": True}]
    assert _makers_verified(entries, {"apps": apps}) is True
    assert _makers_verified(entries[:1], {"apps": apps}) is False
    assert _makers_verified(entries, {"apps": ["/Applications/A.app", {"weird": 1}, 3]}) is False


def test_an_app_cannot_borrow_a_verified_maker_by_what_it_calls_itself():
    vscode = [{"subject": "/Applications/Visual Studio Code.app", "verified": True}]
    for named in ("Code", "Visual Studio Code.app", "/Applications/Visual Studio Code.app"):
        evil = {"name": named, "bundle_id": "com.microsoft.VSCode", "app": named, "path": "/tmp/evil"}
        assert _makers_verified(vscode, {"apps": [evil]}) is False
    # No path to look up: never verified, whatever it is named.
    assert _makers_verified(vscode, {"apps": [{"name": "/Applications/Visual Studio Code.app"}]}) is False
    assert _makers_verified(vscode, {"apps": [{"path": "/Applications/Visual Studio Code.app", "name": "x"}]}) is True


def test_a_check_that_cannot_be_written_becomes_an_error_entry_not_a_crash():
    class Boom:
        name = "boom_check"
        category = "security"

    class BadCheck:
        error = None
        supported = True
        complete = True

        @property
        def findings(self):
            raise RuntimeError("odd")

    good_mod = SimpleNamespace(name="good_check", category="general")
    good = CheckResult(module_name="good_check", findings=[
        Finding(title="Fine", description="d", severity=Severity.INFO, category="general")])
    doc = json.loads(checks_to_json([(Boom(), BadCheck()), (good_mod, good)], "darwin"))
    bad, ok = doc["modules"]
    assert bad["name"] == "boom_check" and bad["status"] == "error" and bad["complete"] is False
    assert bad["error"] == WRITE_FAILED and bad["error_kind"] == "error" and bad["findings"] == []
    assert ok["status"] == "ok" and ok["findings"][0]["title"] == "Fine"
    # The streamed entry uses the same guard.
    assert safe_module_entry(Boom(), BadCheck())["status"] == "error"


def test_one_unwritable_finding_keeps_its_title_and_marks_the_check_unfinished(monkeypatch):
    import rescue.serialize as ser

    real = ser._finding

    def flaky(finding, *args):
        if finding.title == "Bad":
            raise TypeError("unhashable type: 'dict'")
        return real(finding, *args)

    monkeypatch.setattr(ser, "_finding", flaky)
    check = CheckResult(module_name="x", findings=[
        Finding(title="Bad", description="d", severity=Severity.CRITICAL, category="security", code="security.x.y"),
        Finding(title="Good", description="d", severity=Severity.INFO, category="security"),
    ])
    entry = ser.safe_module_entry(SimpleNamespace(name="x", category="security"), check)
    assert entry["status"] == "ok" and entry["complete"] is False
    bad, good = entry["findings"]
    assert bad["title"] == "Bad" and bad["severity"] == "critical" and bad["serialize_error"] is True
    assert "serialize_error" not in good


def test_list_entries_carry_the_maker_looked_up_for_them():
    from rescue.serialize import _items_made_by

    markable = {"items": [{"key": "com.getdropbox.dropbox", "label": "Dropbox"}, {"key": "com.apple.Terminal"}, "odd"]}
    made_by = [{"subject": "com.getdropbox.dropbox", "name": "Dropbox, Inc.", "verified": True}]
    _items_made_by(markable, made_by)
    assert markable["items"][0]["made_by"]["name"] == "Dropbox, Inc."
    assert "made_by" not in markable["items"][1]
    _items_made_by(None, made_by)  # nothing to do, no crash
