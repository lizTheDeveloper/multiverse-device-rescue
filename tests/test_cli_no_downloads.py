"""--no-downloads works on every command AGENTS.md tells assistants to run."""

import os
from unittest.mock import patch

from click.testing import CliRunner

from rescue.cli import main


def test_run_no_downloads_skips_the_ai_tools_download(monkeypatch):
    monkeypatch.delenv("RESCUE_NO_DOWNLOADS", raising=False)
    out = CliRunner().invoke(main, ["run", "ai_agent_audit", "--no-downloads"], input="")
    # (run then asks whether to apply fixes; with no answer it stops there)
    assert "Downloads are turned off" in out.output


def test_export_no_downloads_sets_the_switch_before_checks_run(monkeypatch):
    monkeypatch.delenv("RESCUE_NO_DOWNLOADS", raising=False)
    seen = {}

    def run_checks(self, *a, **k):
        seen["value"] = os.environ.get("RESCUE_NO_DOWNLOADS")
        return []

    with patch("rescue.cli.Orchestrator.run_checks", run_checks):
        out = CliRunner().invoke(main, ["export", "--stdout", "--no-downloads"])
    assert out.exit_code == 0, out.output
    assert seen["value"] == "1"


def test_every_assistant_command_documents_it():
    for command in ("scan", "export", "run"):
        out = CliRunner().invoke(main, [command, "--help"])
        assert "--no-downloads" in out.output, command
