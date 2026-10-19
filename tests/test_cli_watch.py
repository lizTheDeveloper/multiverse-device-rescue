import json
import sys
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from rescue.cli import main
from rescue.models import CheckResult, Finding, Severity
from rescue.remediation import build_catalog, load_remediation_walkthroughs
from rescue.watch import WATCH_CODES


def _finding(stopped=False):
    return Finding(
        title="Watched", description="d", severity=Severity.INFO, category="network",
        data={"stopped_early": stopped}, code="network.connection_watch.watch_summary",
    )


def _fake(calls=None):
    def run_watch(platform, minutes, interval, **kw):
        if calls is not None:
            calls.append((minutes, interval, kw))
        on_progress = kw.get("on_progress")
        if on_progress:
            on_progress({"phase": "watch", "elapsed": 2, "total": minutes * 60, "snapshots": 1})
        # Wait for the stop flag the way the real loop does.
        while not kw["should_stop"]():
            kw["sleep"](0.05)
        return CheckResult(module_name="connection_watch", findings=[_finding(True)])

    return run_watch


def _run(args, stdin="stop\n", calls=None):
    with patch("rescue.cli.run_watch", _fake(calls)):
        return CliRunner().invoke(main, ["watch", *args], input=stdin)


@pytest.mark.parametrize("args", [["--minutes", "0"], ["--minutes", "31"], ["--interval", "1"], ["--interval", "61"]])
def test_out_of_range_arguments_exit_2(args):
    result = _run(args)
    assert result.exit_code == 2
    assert "Invalid value" in result.output


def test_json_document_has_the_module_and_schema():
    calls = []
    result = _run(["--json", "--minutes", "1", "--interval", "5"], calls=calls)
    assert result.exit_code == 0, result.output
    doc = json.loads(result.stdout)
    assert doc["schema_version"]
    assert doc["modules"][0]["name"] == "connection_watch"
    assert doc["modules"][0]["findings"][0]["data"]["stopped_early"] is True
    assert calls[0][:2] == (1, 5)
    verdict = calls[0][2]["verdict"]
    assert verdict.__name__ == "listening_verdict"
    assert verdict.__self__.name == "suspicious_connections"


def test_lookups_on_by_default_with_the_real_lookup():
    from rescue.whois import look_up_all

    calls = []
    _run(["--json"], calls=calls)
    assert calls[0][2]["lookups"] is look_up_all


def test_no_lookups_flag():
    calls = []
    result = _run(["--json", "--no-lookups"], calls=calls)
    assert result.exit_code == 0, result.output
    assert calls[0][2]["lookups"] is None


def test_human_summary_names_the_services_asked():
    from rescue.whois import SOURCES

    result = _run([])
    assert all(source in result.output for source in SOURCES)
    result = _run(["--no-lookups"])
    assert "not looked up" in result.output


def test_lookup_command_prints_who_for_public_and_refuses_private():
    seen = []

    def look_up_all(ips):
        seen.append(list(ips))
        return {"results": {ip: {"asn": 15169} for ip in ips}, "skipped": 0, "failed": 0,
                "over_budget": False}

    with patch("rescue.cli.look_up_all", look_up_all):
        result = CliRunner().invoke(main, ["lookup", "8.8.8.8", "192.168.1.1", "1.1.1.1"])
    assert result.exit_code == 0, result.output
    assert seen == [["8.8.8.8", "1.1.1.1"]]
    assert json.loads(result.stdout) == {
        "8.8.8.8": {"asn": 15169}, "192.168.1.1": None, "1.1.1.1": {"asn": 15169}}
    assert "192.168.1.1" in result.stderr
    assert "never looked up" in result.stderr


def test_lookup_command_with_only_private_addresses_asks_nobody():
    def look_up_all(ips):
        raise AssertionError("nothing public to look up")

    with patch("rescue.cli.look_up_all", look_up_all):
        result = CliRunner().invoke(main, ["lookup", "10.0.0.1"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == {"10.0.0.1": None}


def test_lookup_command_needs_an_address():
    result = CliRunner().invoke(main, ["lookup"])
    assert result.exit_code == 2


def test_progress_lines_are_json_on_stderr():
    result = _run(["--json", "--progress", "--minutes", "1"])
    lines = [json.loads(x) for x in result.stderr.splitlines() if x.startswith("{")]
    assert lines[0] == {"progress": {"phase": "watch", "elapsed": 2, "total": 60, "snapshots": 1}}
    json.loads(result.stdout)  # stdout stays pure JSON


def test_no_progress_without_the_flag():
    result = _run(["--json", "--minutes", "1"])
    assert "progress" not in result.stderr


def test_end_of_input_is_not_a_stop():
    ran = []

    def run_watch(platform, minutes, interval, **kw):
        kw["sleep"](0.3)
        ran.append(kw["should_stop"]())
        return CheckResult(module_name="connection_watch", findings=[_finding()])

    with patch("rescue.cli.run_watch", run_watch):
        result = CliRunner().invoke(main, ["watch", "--json"], input="")
    assert result.exit_code == 0, result.output
    assert ran == [False]


def test_human_summary_without_json():
    result = _run([])
    assert result.exit_code == 0
    assert "Watched" in result.output


# On Windows os.kill(..., SIGTERM) is TerminateProcess: it ends pytest itself.
# The desktop app stops a watch through stdin there, which other tests cover.
@pytest.mark.skipif(sys.platform == "win32", reason="SIGTERM terminates the process on Windows")
def test_signals_set_the_stop_flag_and_handlers_are_restored():
    import os
    import signal

    before = signal.getsignal(signal.SIGTERM)

    def run_watch(platform, minutes, interval, **kw):
        os.kill(os.getpid(), signal.SIGTERM)
        kw["sleep"](5)  # returns at once because the signal set the flag
        assert kw["should_stop"]()
        return CheckResult(module_name="connection_watch", findings=[_finding(True)])

    with patch("rescue.cli.run_watch", run_watch):
        result = CliRunner().invoke(main, ["watch", "--json"], input="")
    assert result.exit_code == 0, result.output
    assert signal.getsignal(signal.SIGTERM) is before


def test_every_watch_code_is_in_the_catalog():
    rows = build_catalog([], {})
    assert {r["code"] for r in rows} == set(WATCH_CODES)
    assert {r["module"] for r in rows} == {"connection_watch"}


def test_every_watch_code_has_a_walkthrough():
    from rescue.cli import _get_guides_dir

    index = load_remediation_walkthroughs(_get_guides_dir() / "remediation")
    assert set(WATCH_CODES) <= set(index)


def test_defaults_are_five_minutes_and_five_seconds():
    calls = []
    _run(["--json"], calls=calls)
    assert calls[0][:2] == (5, 5)


def test_guide_validation_knows_every_watch_code(tmp_path):
    from rescue.validate import validate_guides

    remediation = tmp_path / "remediation"
    remediation.mkdir()
    codes = "\n".join(f"  - {c}" for c in WATCH_CODES)
    (remediation / "w.md").write_text(
        f'---\ntitle: "W"\nplatforms: [macos]\nremediates:\n{codes}\n---\n\n## Step 1\n\nx\n',
        encoding="utf-8",
    )
    problems = validate_guides(tmp_path, [])
    assert not [p for p in problems if "no module declares" in str(p)], problems


def test_threat_remediation_knows_every_watch_code():
    seen = {}

    def fake_validate(threats, profiles, all_codes, all_modules):
        seen["codes"] = set(all_codes)
        return ["stop here"]  # exit before anything is written

    with patch("rescue.threat_map.validate_threat_map", fake_validate):
        result = CliRunner().invoke(main, ["threat-remediation"])
    assert result.exit_code == 1
    assert set(WATCH_CODES) <= seen["codes"]
