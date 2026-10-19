import json
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
    assert "verdict" in calls[0][2]


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


@pytest.mark.xfail(strict=True, reason="Task 6 writes read_a_connection_watch.md")
def test_every_watch_code_has_a_walkthrough():
    from rescue.cli import _get_guides_dir

    index = load_remediation_walkthroughs(_get_guides_dir() / "remediation")
    assert set(WATCH_CODES) <= set(index)
