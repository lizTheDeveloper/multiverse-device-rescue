import os

import pytest
import json

from click.testing import CliRunner

from rescue.cli import main
from rescue.orchestrator import OFFLINE_UNSUPPORTED_REASON

# Disk checks read Linux and macOS layouts (symlinks, FIFOs, POSIX modes) and
# only run from those hosts, so these tests do too.
pytestmark = pytest.mark.skipif(os.name != "posix", reason="offline disk checks run on POSIX hosts")



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


_ADMIN_WARNING = (
    "Warning: not running as an administrator, so files only an administrator can "
    "read on that disk won't be checked. Run with sudo for a full check."
)


def test_target_scan_warns_when_not_administrator(linux_disk, monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 1000, raising=False)
    r = run_scan("--target-root", linux_disk, "--target-os", "linux")
    assert r.exit_code == 0, r.stderr
    assert _ADMIN_WARNING in r.stderr


def test_target_scan_as_administrator_has_no_admin_warning(linux_disk, monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 0, raising=False)
    r = run_scan("--target-root", linux_disk, "--target-os", "linux")
    assert r.exit_code == 0, r.stderr
    assert "not running as an administrator" not in r.stderr


def test_target_scan_without_geteuid_has_no_admin_warning(linux_disk, monkeypatch):
    monkeypatch.delattr("os.geteuid", raising=False)
    r = run_scan("--target-root", linux_disk, "--target-os", "linux")
    assert r.exit_code == 0, r.stderr
    assert "not running as an administrator" not in r.stderr


def test_relative_target_root_is_made_absolute(linux_disk, monkeypatch):
    monkeypatch.chdir(linux_disk)
    doc = _doc(".")
    assert doc["target"]["root"] == str(linux_disk)
    assert doc["target"]["root"].startswith("/")
    ssh = {m["name"]: m for m in doc["modules"]}["linux_ssh_hardening"]
    assert ssh["supported"] is True and ssh["status"] == "ok"


def _offer_everything(monkeypatch):
    """Every module offered a fix, every finding an action and an "It's mine"."""
    import rescue.cli as cli
    import rescue.serialize as serialize

    walkthroughs, _, _ = cli._json_extras()
    names = ["linux_ssh_hardening", "linux_account_audit", "linux_persistence_audit", "stalkerware_scan"]
    fix = {"will_change": "x", "how_to_undo": ["y"]}
    monkeypatch.setattr(cli, "_json_extras", lambda: (walkthroughs, {n: fix for n in names}, {}))
    monkeypatch.setattr(serialize, "_action_fixable", lambda *a: {"action": "a", "target": "t"})
    monkeypatch.setattr(serialize, "_markable", lambda *a: {"kind": "k", "id": "i"})


def _assert_no_offers(modules):
    findings = [f for m in modules for f in m["findings"]]
    assert findings
    assert not [f for f in findings if "fixable" in f or "markable" in f]


def test_offline_json_offers_no_fix_or_mark(linux_disk, monkeypatch):
    _offer_everything(monkeypatch)
    (linux_disk / "etc/ssh").mkdir(parents=True)
    (linux_disk / "etc/ssh/sshd_config").write_text("PermitRootLogin yes\n")
    _assert_no_offers(_doc(linux_disk)["modules"])


def test_offline_live_lines_offer_no_fix_or_mark(linux_disk, monkeypatch):
    _offer_everything(monkeypatch)
    r = run_scan("--target-root", linux_disk, "--target-os", "linux", "--progress", "--live")
    assert r.exit_code == 0, r.stderr
    lines = [json.loads(x)["progress"] for x in r.stderr.splitlines() if x.startswith('{"progress"')]
    _assert_no_offers([p["result"] for p in lines if "result" in p])
    _assert_no_offers(json.loads(r.stdout)["modules"])
