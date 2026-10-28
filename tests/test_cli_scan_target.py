import json

from click.testing import CliRunner

from rescue.cli import main
from rescue.orchestrator import OFFLINE_UNSUPPORTED_REASON


def run_scan(*args):
    return CliRunner().invoke(main, ["scan", "--json", "--no-downloads", *map(str, args)])


def _doc(linux_disk, *extra):
    r = run_scan("--target-root", linux_disk, "--target-os", "linux", *extra)
    assert r.exit_code == 0, r.stderr
    return json.loads(r.stdout)


def test_scan_target_json_has_target_block(linux_disk):
    doc = _doc(linux_disk)
    assert doc["target"]["os"] == "linux" and doc["platform"] == "linux"
    assert doc["target"]["root"] == str(linux_disk)
    assert all("not_checked" in m for m in doc["modules"])


def test_scan_target_reports_live_only_modules_unsupported(linux_disk):
    mods = {m["name"]: m for m in _doc(linux_disk)["modules"]}
    assert mods["open_ports_scan"]["supported"] is False
    assert mods["open_ports_scan"]["unsupported_reason"] == OFFLINE_UNSUPPORTED_REASON


def test_target_live_lines_carry_not_checked(linux_disk):
    r = run_scan("--target-root", linux_disk, "--target-os", "linux", "--progress", "--live")
    assert r.exit_code == 0, r.stderr
    lines = [json.loads(x)["progress"] for x in r.stderr.splitlines() if x.startswith('{"progress"')]
    results = [p["result"] for p in lines if "result" in p]
    assert results and all("not_checked" in x for x in results)
    assert json.loads(r.stdout)["target"]["os"] == "linux"


def test_target_flags_go_together(linux_disk):
    assert run_scan("--target-root", linux_disk).exit_code == 2
    assert run_scan("--target-os", "linux").exit_code == 2


def test_target_root_slash_refused():
    r = run_scan("--target-root", "/", "--target-os", "linux")
    assert r.exit_code == 2 and "is the running system" in r.stderr


def test_target_root_not_linux_refused(tmp_path):
    r = run_scan("--target-root", tmp_path, "--target-os", "linux")
    assert r.exit_code == 2 and "doesn't look like a Linux system disk" in r.stderr


def test_target_os_windows_not_built_yet(linux_disk):
    r = run_scan("--target-root", linux_disk, "--target-os", "windows")
    assert r.exit_code == 2 and "isn't built yet" in r.stderr


def test_scan_warns_when_target_writable(linux_disk):
    r = run_scan("--target-root", linux_disk, "--target-os", "linux")
    assert "mounted read-write" in r.stderr
    assert json.loads(r.stdout)["target"]["read_only"] is False


def test_plain_scan_has_no_target_key_but_has_not_checked():
    from unittest.mock import patch

    from rescue.models import CheckResult

    mod = type("M", (), {"name": "m", "report": lambda self, c, fix=None: ""})()
    with patch("rescue.cli.Orchestrator") as MockOrch:
        MockOrch.return_value.run_checks.return_value = [(mod, CheckResult(module_name="m", findings=[]))]
        r = CliRunner().invoke(main, ["scan", "--json"])
    doc = json.loads(r.stdout)
    assert "target" not in doc
    assert doc["modules"][0]["not_checked"] == []
