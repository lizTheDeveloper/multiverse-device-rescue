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


# ---- races between validation and the move (found in review) ----

def test_disable_does_not_move_a_file_swapped_in_after_validation(env, tmp_path):
    # validate() sees a regular plist; while the job is being stopped, the plist
    # is replaced with a symlink to a private file. The private file must stay
    # where it is and nothing may land in quarantine.
    secret = tmp_path / "id_ed25519"
    secret.write_text("PRIVATE")
    p = _plist(env)

    def swap_then_ok(args, **kw):
        env.calls.append(list(args))
        p.unlink()
        p.symlink_to(secret)
        return _res()

    import rescue.actions.launch_agent as mod
    mod.run = swap_then_ok
    doc = la.disable(str(p))
    assert not doc.get("applied")
    assert secret.read_text() == "PRIVATE"
    qdir = env.home / "Library" / "Application Support" / "Device Rescue" / "Quarantine"
    assert not any(qdir.glob("*.plist")) if qdir.exists() else True


def test_restore_never_follows_a_symlink_planted_at_the_destination(env, tmp_path, monkeypatch):
    # The existence check passes, then a symlink to a directory appears where
    # the plist belongs. The file must not end up inside that directory.
    p = _plist(env)
    qid = la.disable(str(p))["quarantine_id"]
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    real_lexists = os.path.lexists

    def lexists_then_plant(path):
        result = real_lexists(path)
        if str(path) == str(p) and not real_lexists(p):
            p.symlink_to(elsewhere)
        return result

    monkeypatch.setattr(la.os.path, "lexists", lexists_then_plant)
    doc = la.restore(qid)
    assert not doc.get("applied")
    assert list(elsewhere.iterdir()) == []


# ---- the same job on more than one card (reported bug) ----
#
# launchd_persistence_audit ("points to a file that is missing") and
# launch_agent_audit ("points to a missing file") both report a user agent whose
# program is gone, and both cards were offered "Fix it for me" for the same file.
# After the first card turned it off, the second card's button came back with
# "We can't do this one for you", because the engine refused a file that no
# longer existed as not_allowed.

def _missing_program_plist(env, label="ai.openclaw.gateway"):
    p = env.agents / f"{label}.plist"
    p.write_bytes(plistlib.dumps({
        "Label": label,
        "ProgramArguments": [str(env.home / ".nvm" / "versions" / "node" / "v22.16.0" / "bin" / "node"), "x.js"],
        "KeepAlive": True,
        "RunAtLoad": True,
    }))
    return p


def _module(name):
    from pathlib import Path
    from rescue.registry import discover_modules

    return next(m for m in discover_modules(Path(__file__).parent.parent / "modules") if m.name == name)


def _scan_modules(env, names):
    """Run the real checks against the fixture HOME only (no system folders)."""
    from unittest.mock import patch

    from rescue.models import Platform, SystemProfile

    profile = SystemProfile(
        platform=Platform.DARWIN, os_name="macOS", os_version="15.0", architecture="arm64",
        cpu_model="Apple M1", cpu_cores=8, ram_bytes=16 * 1024**3,
    )
    results = []
    for name in names:
        mod = _module(name)
        scan_attr = "_scan_launchd_dir" if hasattr(mod, "_scan_launchd_dir") else "_scan_launch_agents_dir"
        real = getattr(mod, scan_attr)

        def only_home(directory, _real=real):
            return _real(directory) if directory == env.agents else []

        with patch.object(mod, scan_attr, side_effect=only_home):
            results.append((mod, mod.check(profile)))
    return json.loads(checks_to_json(results, "darwin", app_actions=ACTIONS))


def _offers(doc):
    return [
        (m["name"], f["fixable"]["target"], f["data"].get("plist"))
        for m in doc["modules"] for f in m["findings"] if "fixable" in f
    ]


@pytest.mark.skipif(sys.platform != "darwin", reason="both background-task audits run only on macOS")
def test_both_missing_program_cards_offer_the_same_exact_file(env):
    p = _missing_program_plist(env)
    doc = _scan_modules(env, ["launchd_persistence_audit", "launch_agent_audit"])
    offers = _offers(doc)
    assert sorted(o[0] for o in offers) == ["launch_agent_audit", "launchd_persistence_audit"]
    assert {o[1] for o in offers} == {str(p)}
    # The finding names its own file, so the offer is not guessed from the label.
    assert {o[2] for o in offers} == {str(p)}


def test_second_card_after_first_fix_is_nothing_to_fix_not_a_refusal(env):
    p = _missing_program_plist(env)
    first = la.disable(str(p))
    assert first["status"] == "fixed" and not p.exists()
    calls_after_first = list(env.calls)

    second = la.disable(str(p))
    assert second["status"] == "nothing_to_fix"
    assert second["error"] is None and second["applied"] is False
    assert second["quarantine_id"] == first["quarantine_id"]
    assert "already turned off" in second["message"] and "Nothing was changed" in second["message"]
    assert la.exit_code(second) == 0
    assert env.calls == calls_after_first  # launchctl was not run again


def test_second_card_through_the_cli_exits_zero(env):
    p = _missing_program_plist(env)
    args = ["fix", "--action", "disable_launch_agent", "--target", str(p), "--json", "--i-understand"]
    assert CliRunner().invoke(main, args).exit_code == 0
    r = CliRunner().invoke(main, args)
    assert r.exit_code == 0, r.output
    assert json.loads(r.stdout)["status"] == "nothing_to_fix"


def test_removed_by_hand_since_the_scan_is_nothing_to_fix(env):
    p = _missing_program_plist(env)
    p.unlink()
    doc = la.disable(str(p))
    assert doc["status"] == "nothing_to_fix" and doc["error"] is None
    assert "already gone" in doc["message"] and "quarantine_id" not in doc
    assert env.calls == []


def test_after_undo_the_job_can_be_turned_off_again(env, monkeypatch):
    from datetime import datetime as real_datetime, timedelta

    p = _missing_program_plist(env)
    qid = la.disable(str(p))["quarantine_id"]
    assert la.restore(qid)["status"] == "restored"
    # A put-back record is not "already turned off". (A minute later, so the new
    # quarantine id cannot collide with the first one.)
    later = real_datetime.now(la.timezone.utc) + timedelta(minutes=1)
    monkeypatch.setattr(la, "datetime", type("D", (), {"now": staticmethod(lambda tz=None: later)}))
    again = la.disable(str(p))
    assert again["status"] == "fixed" and not p.exists()


def test_missing_file_outside_launch_agents_is_still_refused(env, tmp_path):
    for target in (
        str(tmp_path / "gone.plist"),
        "/Library/LaunchDaemons/com.nothing.here.plist",
        str(env.agents / "sub" / "x.plist"),
        str(env.agents / "x.txt"),
        "x.plist",
    ):
        doc = la.disable(target)
        assert doc["status"] == "refused" and doc["error"] == "not_allowed", target
    assert env.calls == []


def test_a_named_plist_is_never_swapped_for_a_same_label_user_agent(env):
    """A finding about /Library/LaunchDaemons/x.plist must not offer to move ~/Library/LaunchAgents/x.plist."""
    _plist(env)
    f = _f({"plist": f"/Library/LaunchDaemons/{LABEL}.plist", "label": LABEL})
    assert "fixable" not in _scan(env, f)
    # Without a named file the label still finds the user's own agent.
    assert _scan(env, _f({"label": LABEL}))["fixable"]["target"] == str(env.agents / f"{LABEL}.plist")
    assert "fixable" in _scan(env, _f({"plist": None, "label": LABEL}))


def test_scheduled_tasks_warning_names_its_own_file(env):
    p = env.agents / "com.x.y.plist"
    p.write_bytes(plistlib.dumps({"Label": "com.x.y", "Program": "/tmp/x.sh"}))
    mod = _module("scheduled_tasks_audit")
    warnings = [f for f in mod._scan_launch_agents(env.agents, "user") if f.severity == Severity.WARNING]
    assert warnings and all(f.data["plist"] == str(p) for f in warnings)
