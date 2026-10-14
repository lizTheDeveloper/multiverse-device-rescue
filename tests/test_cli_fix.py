"""`rescue fix <module> --json --i-understand`: the engine side of "Fix it for me".

Every module here is a mock. No real fix() is ever executed by these tests.
"""

import json
from unittest.mock import patch

from click.testing import CliRunner

from rescue.cli import main
from rescue.models import (
    Action,
    ActionKind,
    CheckResult,
    Finding,
    FixResult,
    Platform,
    RiskLevel,
    Severity,
)

ALLOW = {
    "mock_fw": {
        "will_change": "Turns on the firewall.",
        "how_to_undo": ["Open Settings.", "Turn the firewall off."],
    }
}


def _finding(code="x.y.z", title="Firewall is off"):
    return Finding(title=title, description="d", severity=Severity.WARNING, category="security", code=code)


class MockModule:
    name = "mock_fw"
    platforms = [Platform.DARWIN, Platform.LINUX, Platform.WIN32]
    risk_level = RiskLevel.MODERATE

    def __init__(self, checks, fix_result=None, fix_raises=None, prints=False):
        self._checks = list(checks)
        self._fix_result = fix_result
        self._fix_raises = fix_raises
        self._prints = prints
        self.fix_calls = []
        self.check_calls = 0

    def check(self, profile):
        self.check_calls += 1
        item = self._checks.pop(0) if len(self._checks) > 1 else self._checks[0]
        if isinstance(item, Exception):
            raise item
        return item

    def fix(self, findings, mode):
        if self._prints:
            print("NOISE FROM MODULE")
        self.fix_calls.append((findings, mode))
        if self._fix_raises:
            raise self._fix_raises
        return self._fix_result


def _mutation(success=True, error=None):
    return Action(
        title="Enable firewall",
        description="Ran the command.",
        risk_level=RiskLevel.MODERATE,
        kind=ActionKind.MUTATION,
        executed=True,
        success=success,
        error=error,
    )


def _run(module, args=("mock_fw", "--json", "--i-understand"), allow=ALLOW, modules=None):
    mods = [module] if modules is None else modules
    with patch("rescue.cli.load_app_fixes", return_value=allow), \
         patch("rescue.cli.discover_modules", return_value=mods), \
         patch("rescue.cli.gather_profile", return_value=object()), \
         patch("rescue.cli.detect_platform", return_value=Platform.DARWIN):
        res = CliRunner().invoke(main, ["fix", *args])
    return res


def _doc(res):
    return json.loads(res.stdout)


def test_success_reports_applied_and_verified():
    mod = MockModule(
        [CheckResult("mock_fw", [_finding()]), CheckResult("mock_fw", [])],
        FixResult("mock_fw", [_mutation()]),
    )
    res = _run(mod)
    assert res.exit_code == 0, res.output
    doc = _doc(res)
    assert doc["module"] == "mock_fw"
    assert doc["applied"] is True
    assert doc["verified"] is True
    assert doc["status"] == "fixed"
    assert doc["how_to_undo"] == ALLOW["mock_fw"]["how_to_undo"]
    assert doc["changes"] == [
        {"title": "Enable firewall", "description": "Ran the command.", "success": True, "error": None}
    ]
    assert len(mod.fix_calls) == 1
    assert mod.check_calls == 2  # before and after


def test_fix_is_called_with_an_explicit_mode():
    from rescue.models import Mode

    mod = MockModule(
        [CheckResult("mock_fw", [_finding()]), CheckResult("mock_fw", [])],
        FixResult("mock_fw", [_mutation()]),
    )
    _run(mod)
    assert isinstance(mod.fix_calls[0][1], Mode)


def test_applied_but_problem_still_showing_is_not_verified():
    mod = MockModule(
        [CheckResult("mock_fw", [_finding()]), CheckResult("mock_fw", [_finding()])],
        FixResult("mock_fw", [_mutation()]),
    )
    res = _run(mod)
    doc = _doc(res)
    assert doc["applied"] is True
    assert doc["verified"] is False
    assert doc["status"] == "not_fixed"
    assert res.exit_code == 1


def test_unrelated_new_finding_does_not_block_verification():
    mod = MockModule(
        [CheckResult("mock_fw", [_finding("a.b.c")]), CheckResult("mock_fw", [_finding("other.code", "Other")])],
        FixResult("mock_fw", [_mutation()]),
    )
    doc = _doc(_run(mod))
    assert doc["verified"] is True


def test_failed_mutation_is_not_applied():
    mod = MockModule(
        [CheckResult("mock_fw", [_finding()]), CheckResult("mock_fw", [_finding()])],
        FixResult("mock_fw", [_mutation(success=False, error="must be root")]),
    )
    res = _run(mod)
    doc = _doc(res)
    assert doc["applied"] is False
    assert doc["verified"] is False
    assert doc["status"] == "failed"
    assert "must be root" in doc["message"]
    assert res.exit_code == 1


def test_guidance_only_result_is_never_reported_as_applied():
    guidance = Action(title="t", description="d", risk_level=RiskLevel.SAFE, kind=ActionKind.GUIDANCE,
                      executed=True, success=True)
    mod = MockModule(
        [CheckResult("mock_fw", [_finding()]), CheckResult("mock_fw", [_finding()])],
        FixResult("mock_fw", [guidance]),
    )
    doc = _doc(_run(mod))
    assert doc["applied"] is False
    assert doc["verified"] is False


def test_nothing_to_fix_does_not_call_fix():
    mod = MockModule([CheckResult("mock_fw", [])], FixResult("mock_fw", [_mutation()]))
    res = _run(mod)
    assert res.exit_code == 0
    doc = _doc(res)
    assert doc["applied"] is False
    assert doc["status"] == "nothing_to_fix"
    assert mod.fix_calls == []


def test_module_not_on_allowlist_is_refused_before_anything_runs():
    mod = MockModule([CheckResult("mock_fw", [_finding()])], FixResult("mock_fw", [_mutation()]))
    res = _run(mod, allow={})
    assert res.exit_code == 2
    doc = _doc(res)
    assert doc["error"] == "not_allowed"
    assert doc["applied"] is False
    assert mod.check_calls == 0
    assert mod.fix_calls == []


def test_missing_acknowledgement_flag_is_refused():
    mod = MockModule([CheckResult("mock_fw", [_finding()])], FixResult("mock_fw", [_mutation()]))
    res = _run(mod, args=("mock_fw", "--json"))
    assert res.exit_code == 2
    assert _doc(res)["error"] == "not_confirmed"
    assert mod.check_calls == 0 and mod.fix_calls == []


def test_destructive_module_is_refused_even_if_listed():
    mod = MockModule([CheckResult("mock_fw", [_finding()])], FixResult("mock_fw", [_mutation()]))
    mod.risk_level = RiskLevel.DESTRUCTIVE
    res = _run(mod)
    assert res.exit_code == 2
    assert _doc(res)["error"] == "not_allowed"
    assert mod.fix_calls == []


def test_listed_but_missing_module_is_an_error():
    res = _run(None, modules=[])
    assert res.exit_code == 3
    assert _doc(res)["error"] == "unknown_module"


def test_module_for_another_platform_is_refused():
    mod = MockModule([CheckResult("mock_fw", [_finding()])], FixResult("mock_fw", [_mutation()]))
    mod.platforms = [Platform.WIN32]
    res = _run(mod)
    assert res.exit_code == 3
    assert _doc(res)["error"] == "unsupported_platform"
    assert mod.fix_calls == []


def test_check_error_stops_before_fix():
    mod = MockModule([CheckResult("mock_fw", [], error="boom")], FixResult("mock_fw", [_mutation()]))
    res = _run(mod)
    assert res.exit_code == 4
    assert _doc(res)["error"] == "check_failed"
    assert mod.fix_calls == []


def test_check_exception_stops_before_fix():
    mod = MockModule([RuntimeError("kaboom")], FixResult("mock_fw", [_mutation()]))
    res = _run(mod)
    assert res.exit_code == 4
    assert mod.fix_calls == []


def test_unsupported_check_stops_before_fix():
    mod = MockModule(
        [CheckResult("mock_fw", [], supported=False, unsupported_reason="no")],
        FixResult("mock_fw", [_mutation()]),
    )
    res = _run(mod)
    assert res.exit_code == 4
    assert mod.fix_calls == []


def test_fix_exception_is_reported_and_rechecked():
    mod = MockModule(
        [CheckResult("mock_fw", [_finding()]), CheckResult("mock_fw", [_finding()])],
        fix_raises=RuntimeError("it broke"),
    )
    res = _run(mod)
    assert res.exit_code == 1
    doc = _doc(res)
    assert doc["applied"] is False
    assert doc["verified"] is False
    assert doc["status"] == "failed"
    assert "it broke" in doc["message"]


def test_module_chatter_never_corrupts_the_json_on_stdout():
    mod = MockModule(
        [CheckResult("mock_fw", [_finding()]), CheckResult("mock_fw", [])],
        FixResult("mock_fw", [_mutation()]),
        prints=True,
    )
    res = _run(mod)
    assert _doc(res)["applied"] is True
    assert "NOISE" not in res.stdout


def test_unreadable_allowlist_refuses():
    from rescue.app_fixes import AppFixesError

    mod = MockModule([CheckResult("mock_fw", [_finding()])], FixResult("mock_fw", [_mutation()]))
    with patch("rescue.cli.load_app_fixes", side_effect=AppFixesError("gone")), \
         patch("rescue.cli.discover_modules", return_value=[mod]):
        res = CliRunner().invoke(main, ["fix", "mock_fw", "--json", "--i-understand"])
    assert res.exit_code == 2
    assert json.loads(res.stdout)["error"] == "not_allowed"
    assert mod.fix_calls == []


def test_module_name_must_be_a_plain_identifier():
    mod = MockModule([CheckResult("mock_fw", [_finding()])], FixResult("mock_fw", [_mutation()]))
    res = _run(mod, args=("../etc/passwd", "--json", "--i-understand"))
    assert res.exit_code == 2
    assert mod.fix_calls == []


def test_only_one_module_may_be_named():
    mod = MockModule([CheckResult("mock_fw", [_finding()])], FixResult("mock_fw", [_mutation()]))
    res = _run(mod, args=("mock_fw", "other", "--json", "--i-understand"))
    assert res.exit_code != 0
    assert mod.fix_calls == []


# --- scan JSON advertises which findings can be fixed ---------------------------------

def test_scan_json_marks_findings_of_allowlisted_modules_as_fixable():
    mod = type("M", (), {"name": "mock_fw", "report": lambda self, c, f=None: ""})()
    other = type("M", (), {"name": "other", "report": lambda self, c, f=None: ""})()
    with patch("rescue.cli.Orchestrator") as orch, patch("rescue.cli.load_app_fixes", return_value=ALLOW):
        orch.return_value.run_checks.return_value = [
            (mod, CheckResult("mock_fw", [_finding()])),
            (other, CheckResult("other", [_finding()])),
        ]
        res = CliRunner().invoke(main, ["scan", "--json"])
    doc = json.loads(res.stdout)
    assert doc["modules"][0]["findings"][0]["fixable"] == {
        "will_change": "Turns on the firewall.",
        "how_to_undo": ["Open Settings.", "Turn the firewall off."],
    }
    assert "fixable" not in doc["modules"][1]["findings"][0]


def test_scan_json_survives_an_unreadable_allowlist_with_no_fixable_flags():
    from rescue.app_fixes import AppFixesError

    mod = type("M", (), {"name": "mock_fw", "report": lambda self, c, f=None: ""})()
    with patch("rescue.cli.Orchestrator") as orch, patch("rescue.cli.load_app_fixes", side_effect=AppFixesError("x")):
        orch.return_value.run_checks.return_value = [(mod, CheckResult("mock_fw", [_finding()]))]
        res = CliRunner().invoke(main, ["scan", "--json"])
    assert res.exit_code == 0
    assert "fixable" not in json.loads(res.stdout)["modules"][0]["findings"][0]
