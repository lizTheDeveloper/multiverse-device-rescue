import json
import subprocess
import sys

from rescue.trace import trace_commands


def test_trace_reports_every_command_with_its_module():
    events = []
    with trace_commands(events.append, current_module=lambda: "disk_space"):
        subprocess.run([sys.executable, "-c", "pass"], check=True)
    assert len(events) == 1
    ev = events[0]
    assert ev["module"] == "disk_space"
    assert ev["argv"][0] == sys.executable
    assert ev["returncode"] == 0
    assert isinstance(ev["seconds"], float)


def test_trace_restores_subprocess_afterwards():
    original = subprocess.Popen
    with trace_commands(lambda e: None, current_module=lambda: None):
        assert subprocess.Popen is not original
    assert subprocess.Popen is original


def test_trace_survives_a_command_that_cannot_start():
    events = []
    with trace_commands(events.append, current_module=lambda: "x"):
        try:
            subprocess.run(["/nonexistent/definitely-not-here"])
        except FileNotFoundError:
            pass
    assert events[0]["returncode"] is None
    assert "error" in events[0]
    json.dumps(events)
