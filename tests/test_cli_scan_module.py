import json
from unittest.mock import patch

from click.testing import CliRunner

from rescue.cli import main
from rescue.models import CheckResult


def _mock_module(name, category="security"):
    return type("MockModule", (), {"name": name, "category": category,
                                   "report": lambda self, check, fix=None: ""})()


def test_module_option_builds_a_profile_with_only_those_modules():
    mod = _mock_module("launch_agent_audit")
    with patch("rescue.cli.discover_modules") as disc, patch("rescue.cli.Orchestrator") as Orch:
        disc.return_value = [mod, _mock_module("disk_space", "performance")]
        Orch.return_value.run_checks.return_value = [(mod, CheckResult(module_name=mod.name, findings=[]))]
        result = CliRunner().invoke(main, ["scan", "--json", "--module", "launch_agent_audit"])
    assert result.exit_code == 0, result.output
    profile = Orch.call_args.kwargs["profile"]
    assert profile.include_modules == ["launch_agent_audit"]
    doc = json.loads(result.stdout)
    assert [m["name"] for m in doc["modules"]] == ["launch_agent_audit"]


def test_module_option_repeats_and_dedupes_in_order():
    a, b = _mock_module("a_mod"), _mock_module("b_mod")
    with patch("rescue.cli.discover_modules") as disc, patch("rescue.cli.Orchestrator") as Orch:
        disc.return_value = [a, b]
        Orch.return_value.run_checks.return_value = []
        result = CliRunner().invoke(main, ["scan", "--json", "--module", "b_mod", "--module", "a_mod", "--module", "b_mod"])
    assert result.exit_code == 0, result.output
    assert Orch.call_args.kwargs["profile"].include_modules == ["b_mod", "a_mod"]


def test_unknown_module_exits_1_and_lists_available_names():
    with patch("rescue.cli.discover_modules") as disc:
        disc.return_value = [_mock_module("disk_space")]
        result = CliRunner().invoke(main, ["scan", "--json", "--module", "nope"])
    assert result.exit_code == 1
    assert "Unknown module" in result.stderr
    assert "disk_space" in result.stderr
    assert result.stdout == ""


def test_module_and_profile_together_is_a_usage_error():
    result = CliRunner().invoke(main, ["scan", "--json", "--module", "disk_space", "--profile", "digital_security_reset"])
    assert result.exit_code == 2
    assert "not both" in result.stderr


def test_module_entries_carry_their_category():
    mod = _mock_module("launch_agent_audit", "security")
    with patch("rescue.cli.Orchestrator") as Orch:
        Orch.return_value.run_checks.return_value = [(mod, CheckResult(module_name=mod.name, findings=[]))]
        result = CliRunner().invoke(main, ["scan", "--json"])
    doc = json.loads(result.stdout)
    assert doc["modules"][0]["category"] == "security"


def test_module_without_category_attribute_serializes_null():
    mod = type("Bare", (), {"name": "bare", "report": lambda self, check, fix=None: ""})()
    with patch("rescue.cli.Orchestrator") as Orch:
        Orch.return_value.run_checks.return_value = [(mod, CheckResult(module_name="bare", findings=[]))]
        result = CliRunner().invoke(main, ["scan", "--json"])
    assert json.loads(result.stdout)["modules"][0]["category"] is None


def test_real_single_module_scan_is_read_only(monkeypatch):
    # A real, cheap, cross-platform module. run_fixes must never be reached.
    monkeypatch.setenv("RESCUE_TEST_MODE", "1")
    with patch("rescue.orchestrator.Orchestrator.run_fixes", side_effect=AssertionError("scan must not fix")):
        result = CliRunner().invoke(main, ["scan", "--json", "--no-attribution", "--module", "disk_space"])
    assert result.exit_code == 0, result.output
    doc = json.loads(result.stdout)
    assert [m["name"] for m in doc["modules"]] == ["disk_space"]
    assert doc["modules"][0]["category"] == "performance"
