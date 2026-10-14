"""disable_launch_agent: validation, the disable/restore round trip, the scan offer, the CLI.

Everything runs in a temporary HOME with launchctl mocked. No real plist is
touched and no real launchctl command is run.
"""

import hashlib
import json
import os
import plistlib
import sys

import pytest
from click.testing import CliRunner

from rescue.actions import launch_agent as la
from rescue.app_fixes import load_app_actions
from rescue.cli import main
from rescue.command import CommandResult
from rescue.models import CheckResult, Finding, Severity
from rescue.serialize import checks_to_json

LABEL = "com.morgan.bluesky-poster"
ACTIONS = load_app_actions()

# The action is a macOS feature that leans on POSIX semantics (os.getuid, HOME,
# symlinks, mode bits). It runs on macOS and Linux (launchctl is mocked); on
# Windows none of that exists, so the suite is skipped there and
# test_unsupported_off_mac covers what the action does instead.
pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="launch agent action needs POSIX uid/HOME/symlink semantics"
)


def _res(code=0, out="", err=""):
    return CommandResult(args=[], returncode=code, stdout=out, stderr=err, timed_out=False, error=None, duration_s=0, truncated=False)


@pytest.fixture
def env(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / "Library" / "LaunchAgents").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(la, "_supported", lambda: True)
    calls = []
    answers = {"bootout": _res(), "bootstrap": _res()}

    def fake_run(args, **kw):
        assert isinstance(args, list)
        calls.append(list(args))
        return answers[args[1]]

    monkeypatch.setattr(la, "run", fake_run)
    return type("Env", (), {"home": home, "agents": home / "Library" / "LaunchAgents", "calls": calls, "answers": answers})


def _plist(env, label=LABEL, name=None, **extra):
    p = env.agents / (name or f"{label}.plist")
    p.write_bytes(plistlib.dumps({"Label": label, "Program": "/tmp/morgan-local-post.sh", **extra}))
    return p


# ---- validation refusals ----

def test_valid_plist_passes(env):
    p = _plist(env)
    info = la.validate(str(p))
    assert info["label"] == LABEL


def test_refuses_symlink(env, tmp_path):
    real = tmp_path / "elsewhere.plist"
    real.write_bytes(plistlib.dumps({"Label": LABEL}))
    link = env.agents / f"{LABEL}.plist"
    link.symlink_to(real)
    with pytest.raises(la.Refused, match="shortcut"):
        la.validate(str(link))


def test_refuses_other_users_file(env, monkeypatch):
    p = _plist(env)
    monkeypatch.setattr(la, "_uid", lambda: os.getuid() + 1)
    with pytest.raises(la.Refused, match="different user"):
        la.validate(str(p))


def test_refuses_path_outside_launch_agents(env, tmp_path):
    p = tmp_path / f"{LABEL}.plist"
    p.write_bytes(plistlib.dumps({"Label": LABEL}))
    with pytest.raises(la.Refused, match="LaunchAgents"):
        la.validate(str(p))


def test_refuses_subfolder_of_launch_agents(env):
    sub = env.agents / "nested"
    sub.mkdir()
    p = sub / f"{LABEL}.plist"
    p.write_bytes(plistlib.dumps({"Label": LABEL}))
    with pytest.raises(la.Refused, match="LaunchAgents"):
        la.validate(str(p))


def test_refuses_dotdot_escape(env, tmp_path):
    p = tmp_path / f"{LABEL}.plist"
    p.write_bytes(plistlib.dumps({"Label": LABEL}))
    sneaky = str(env.agents / ".." / ".." / ".." / f"{LABEL}.plist")
    with pytest.raises(la.Refused):
        la.validate(sneaky)


def test_refuses_mismatched_label(env):
    p = _plist(env, label="com.other.thing", name=f"{LABEL}.plist")
    with pytest.raises(la.Refused, match="does not match"):
        la.validate(str(p))


@pytest.mark.parametrize("path", ["/Library/LaunchAgents/com.apple.x.plist", "/Library/LaunchDaemons/a.plist", "/System/Library/LaunchAgents/com.apple.Finder.plist"])
def test_refuses_system_paths(env, path):
    with pytest.raises(la.Refused):
        la.validate(path)


def test_refuses_unparseable_and_missing_and_relative(env):
    bad = env.agents / "com.bad.plist"
    bad.write_text("not a plist")
    with pytest.raises(la.Refused, match="could not be read"):
        la.validate(str(bad))
    with pytest.raises(la.Refused, match="does not exist"):
        la.validate(str(env.agents / "nope.plist"))
    with pytest.raises(la.Refused, match="full file path"):
        la.validate("com.x.plist")
    for junk in (None, "", "   ", 5):
        with pytest.raises(la.Refused):
            la.validate(junk)


def test_refuses_directory(env):
    d = env.agents / "dir.plist"
    d.mkdir()
    with pytest.raises(la.Refused, match="ordinary file"):
        la.validate(str(d))


def test_disable_refusal_changes_nothing(env, tmp_path):
    p = tmp_path / "x.plist"
    p.write_bytes(plistlib.dumps({"Label": "x"}))
    doc = la.disable(str(p))
    assert doc["status"] == "refused" and doc["applied"] is False and doc["error"] == "not_allowed"
    assert env.calls == [] and p.exists()


def test_unsupported_platform(env, monkeypatch):
    monkeypatch.setattr(la, "_supported", lambda: False)
    p = _plist(env)
    d = la.disable(str(p))
    assert d["status"] == "unsupported" and "supported" in d["message"] and p.exists()
    assert la.restore("20260101T000000Z-x")["status"] == "unsupported"
    assert env.calls == []


# ---- round trip ----

def test_disable_then_restore_round_trip(env):
    p = _plist(env)
    original_bytes = p.read_bytes()
    doc = la.disable(str(p))
    assert doc["status"] == "fixed" and doc["applied"] and doc["verified"]
    assert doc["message"] == "Done. Nothing was deleted."
    assert doc["how_to_undo"] == la.UNDO_STEPS
    assert not p.exists()
    qid = doc["quarantine_id"]
    assert qid.endswith("-" + LABEL) and la.QUARANTINE_ID.match(qid)
    qdir = env.home / "Library" / "Application Support" / "Device Rescue" / "Quarantine"
    assert (qdir / f"{qid}.plist").read_bytes() == original_bytes
    assert env.calls == [["launchctl", "bootout", f"gui/{os.getuid()}/{LABEL}"]]

    back = la.restore(qid)
    assert back["status"] == "restored" and back["applied"] and back["started"]
    assert p.read_bytes() == original_bytes
    assert not (qdir / f"{qid}.plist").exists()
    assert env.calls[-1] == ["launchctl", "bootstrap", f"gui/{os.getuid()}", str(env.agents / f"{LABEL}.plist")]


def test_manifest_contents(env):
    p = _plist(env)
    digest = hashlib.sha256(p.read_bytes()).hexdigest()
    doc = la.disable(str(p))
    qdir = env.home / "Library" / "Application Support" / "Device Rescue" / "Quarantine"
    m = json.loads((qdir / f"{doc['quarantine_id']}.json").read_text())
    assert m["original_path"] == str(p)
    assert m["label"] == LABEL
    assert m["sha256"] == digest
    assert m["quarantined_at"].endswith("+00:00")
    assert m["quarantine_path"] == str(qdir / f"{doc['quarantine_id']}.plist")
    assert (qdir.stat().st_mode & 0o777) == 0o700


def test_not_loaded_is_tolerated(env):
    env.answers["bootout"] = _res(113, err="Boot-out failed: 113: Could not find service")
    p = _plist(env)
    assert la.disable(str(p))["status"] == "fixed"
    env.answers["bootout"] = _res(3, err="No such process")
    p = _plist(env, label="com.second.job")
    assert la.disable(str(p))["status"] == "fixed"


def test_stop_failure_changes_nothing(env):
    env.answers["bootout"] = _res(1, err="Operation not permitted")
    p = _plist(env)
    doc = la.disable(str(p))
    assert doc["status"] == "failed" and doc["error"] == "stop_failed" and not doc["applied"]
    assert p.exists()
    qdir = env.home / "Library" / "Application Support" / "Device Rescue" / "Quarantine"
    assert list(qdir.glob("*")) == []


def test_restore_refuses_when_original_exists(env):
    p = _plist(env)
    qid = la.disable(str(p))["quarantine_id"]
    p.write_bytes(b"something new")
    doc = la.restore(qid)
    assert doc["status"] == "refused" and doc["error"] == "exists"
    assert p.read_bytes() == b"something new"
    assert [c[1] for c in env.calls] == ["bootout"]


def test_restore_refuses_tampered_file_and_bad_ids(env):
    p = _plist(env)
    qid = la.disable(str(p))["quarantine_id"]
    qdir = env.home / "Library" / "Application Support" / "Device Rescue" / "Quarantine"
    (qdir / f"{qid}.plist").write_bytes(b"changed")
    assert la.restore(qid)["error"] == "tampered"
    assert not p.exists()
    for bad in ("../../etc/passwd", "", None, "x", "20260101T000000Z-../x"):
        assert la.restore(bad)["status"] == "refused"
    assert la.restore("20260101T000000Z-com.nothing")["error"] == "unknown_item"


def test_restore_twice_is_refused(env):
    p = _plist(env)
    qid = la.disable(str(p))["quarantine_id"]
    assert la.restore(qid)["status"] == "restored"
    assert la.restore(qid)["status"] == "refused"


def test_restore_ignores_edited_manifest_path(env, tmp_path):
    p = _plist(env)
    qid = la.disable(str(p))["quarantine_id"]
    qdir = env.home / "Library" / "Application Support" / "Device Rescue" / "Quarantine"
    mf = qdir / f"{qid}.json"
    m = json.loads(mf.read_text())
    m["original_path"] = str(tmp_path / "evil.plist")
    mf.write_text(json.dumps(m))
    assert la.restore(qid)["status"] == "restored"
    assert p.exists() and not (tmp_path / "evil.plist").exists()


def test_bootstrap_failure_still_restores_file(env):
    p = _plist(env)
    qid = la.disable(str(p))["quarantine_id"]
    env.answers["bootstrap"] = _res(5, err="Bootstrap failed: 5: Input/output error")
    doc = la.restore(qid)
    assert doc["status"] == "restored" and doc["started"] is False and "log out" in doc["message"]
    assert p.exists()


# ---- scan offer ----

def _scan(env_, finding, module="launchd_persistence_audit", actions=ACTIONS):
    mod = type("M", (), {"name": module})()
    out = checks_to_json([(mod, CheckResult(module_name=module, findings=[finding]))], "darwin", app_actions=actions)
    return json.loads(out)["modules"][0]["findings"][0]


def _f(data, severity=Severity.WARNING):
    return Finding(title="t", description="d", severity=severity, category="security", code="c", data=data)


def test_offer_exact_shape(env):
    p = _plist(env)
    f = _scan(env, _f({"plist": str(p)}))
    assert f["fixable"] == {
        "action": "disable_launch_agent",
        "target": str(p),
        "will_change": "Stops the background job 'com.morgan.bluesky-poster' and moves its settings file to Device Rescue's quarantine folder. Nothing is deleted.",
        "how_to_undo": [
            "Open Device Rescue and choose Undo on this item",
            "Or move the file from ~/Library/Application Support/Device Rescue/Quarantine back to ~/Library/LaunchAgents and log out and back in",
        ],
    }


def test_offer_from_each_key(env):
    p = _plist(env)
    assert "fixable" in _scan(env, _f({"plist_path": str(p)}))
    assert _scan(env, _f({"label": LABEL}))["fixable"]["target"] == str(p)


def test_no_offer_cases(env, tmp_path):
    p = _plist(env)
    assert "fixable" not in _scan(env, _f({"plist": str(p)}, Severity.INFO))
    assert "fixable" not in _scan(env, _f({"plist": str(p)}), module="disk_space")
    assert "fixable" not in _scan(env, _f({"plist": str(p)}), actions=None)
    assert "fixable" not in _scan(env, _f({"label": "com.nothing.here"}))
    assert "fixable" not in _scan(env, _f({"plist": "/Library/LaunchAgents/x.plist"}))
    assert "fixable" not in _scan(env, _f({"label": "../../etc/x"}))
    assert "fixable" not in _scan(env, _f({}))
    assert "fixable" not in _scan(env, _f({"plist": 5, "label": ["x"]}))


def test_critical_is_offered_and_other_module_names(env):
    p = _plist(env)
    for mod in la.MODULES_OFFERING:
        assert "fixable" in _scan(env, _f({"plist": str(p)}, Severity.CRITICAL), module=mod)


# ---- CLI ----

def test_cli_fix_action_and_undo_json(env):
    p = _plist(env)
    r = CliRunner().invoke(main, ["fix", "--action", "disable_launch_agent", "--target", str(p), "--json", "--i-understand"])
    assert r.exit_code == 0, r.output
    doc = json.loads(r.stdout)
    for key in ("module", "applied", "message", "changes", "how_to_undo", "verified", "status"):
        assert key in doc
    assert doc["status"] == "fixed" and doc["quarantine_id"]
    assert not p.exists()
    r2 = CliRunner().invoke(main, ["undo", "--quarantine-id", doc["quarantine_id"], "--json"])
    assert r2.exit_code == 0, r2.output
    assert json.loads(r2.stdout)["status"] == "restored"
    assert p.exists()


def test_cli_fix_action_requires_acknowledgement_and_revalidates(env, tmp_path):
    p = _plist(env)
    r = CliRunner().invoke(main, ["fix", "--action", "disable_launch_agent", "--target", str(p), "--json"])
    assert r.exit_code == 2 and json.loads(r.stdout)["error"] == "not_confirmed" and p.exists()
    outside = tmp_path / "o.plist"
    outside.write_bytes(plistlib.dumps({"Label": "o"}))
    r = CliRunner().invoke(main, ["fix", "--action", "disable_launch_agent", "--target", str(outside), "--json", "--i-understand"])
    assert r.exit_code == 2 and json.loads(r.stdout)["error"] == "not_allowed" and outside.exists()
    assert env.calls == []


def test_cli_rejects_unknown_action_and_mixed_args(env):
    p = _plist(env)
    r = CliRunner().invoke(main, ["fix", "--action", "rm_rf", "--target", str(p), "--json", "--i-understand"])
    assert r.exit_code == 2 and json.loads(r.stdout)["error"] == "not_allowed"
    r = CliRunner().invoke(main, ["fix", "firewall_audit", "--action", "disable_launch_agent", "--json", "--i-understand"])
    assert r.exit_code == 2
    r = CliRunner().invoke(main, ["fix", "--json", "--i-understand"])
    assert r.exit_code == 2
    r = CliRunner().invoke(main, ["fix", "--action", "disable_launch_agent", "--json", "--i-understand"])
    assert r.exit_code == 2 and p.exists()


def test_cli_undo_bad_id(env):
    r = CliRunner().invoke(main, ["undo", "--quarantine-id", "../x", "--json"])
    assert r.exit_code == 2 and json.loads(r.stdout)["status"] == "refused"
