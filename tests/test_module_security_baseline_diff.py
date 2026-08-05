import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import (
    ActionKind,
    Mode,
    Platform,
    RiskLevel,
    Severity,
    SystemProfile,
)
from rescue.registry import discover_modules

MODULE_NAME = "security_baseline_diff"


def _module_object(mod):
    return sys.modules[type(mod).__module__]


def _make_profile(platform=Platform.DARWIN):
    return SystemProfile(
        platform=platform,
        os_name="macOS",
        os_version="15.2",
        architecture="arm64",
        cpu_model="Apple M2",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    return next(m for m in discover_modules(modules_dir) if m.name == MODULE_NAME)


class _Result:
    def __init__(self, ok=False, stdout=""):
        self.ok = ok
        self.stdout = stdout
        self.stderr = ""
        self.timed_out = False
        self.error = None


@pytest.fixture
def mod(tmp_path):
    m = _get_module()
    m.state_dir = tmp_path / "state"
    persistence = tmp_path / "LaunchAgents"
    persistence.mkdir()
    extensions = tmp_path / "Extensions"
    extensions.mkdir()
    m.persistence_dirs = [str(persistence)]
    m.extension_dirs = [str(extensions)]
    m._persistence = persistence
    m._extensions = extensions
    m._tmp = tmp_path
    return m


def _finding(result, check):
    return next((f for f in result.findings if f.data.get("check") == check), None)


def _check(mod, commands=None):
    """Run check() with all external commands stubbed."""
    handler = commands or (lambda args, **kw: _Result(ok=False))
    with patch.object(_module_object(mod), "run", side_effect=handler):
        return mod.check(_make_profile())


def test_discovered_with_expected_metadata():
    m = _get_module()
    assert m.name == MODULE_NAME
    assert m.category == "security"
    assert m.risk_level == RiskLevel.SAFE
    assert getattr(m, "auto_apply", False) is False
    assert Platform.LINUX in m.platforms


def test_first_run_establishes_baseline_as_info_not_warning(mod):
    """Nothing is wrong on a first run; it must not read as an alert."""
    result = _check(mod)
    finding = _finding(result, "baseline_established")
    assert finding is not None
    assert finding.severity == Severity.INFO
    assert not any(f.severity == Severity.WARNING for f in result.findings)


def test_first_run_writes_a_baseline_file(mod):
    _check(mod)
    path = mod.state_dir / "security_baseline.json"
    assert path.is_file()
    data = json.loads(path.read_text())
    assert data["version"] == 1
    assert "captured_at" in data


def test_baseline_is_written_outside_the_repository(mod):
    _check(mod)
    path = (mod.state_dir / "security_baseline.json").resolve()
    repo_root = Path(__file__).parent.parent.resolve()
    assert repo_root not in path.parents


def test_second_run_with_no_changes_reports_no_change(mod):
    _check(mod)
    result = _check(mod)
    assert _finding(result, "no_change") is not None
    assert not any(f.severity == Severity.WARNING for f in result.findings)


def test_new_persistence_item_is_reported(mod):
    _check(mod)
    (mod._persistence / "com.suspicious.agent.plist").write_text("")
    result = _check(mod)

    finding = _finding(result, "new_persistence")
    assert finding is not None
    assert finding.severity == Severity.WARNING
    assert any("com.suspicious.agent.plist" in a for a in finding.data["added"])


def test_removed_persistence_item_is_not_reported(mod):
    """Only additions matter; reporting removals symmetrically buries the signal."""
    (mod._persistence / "com.existing.plist").write_text("")
    _check(mod)
    (mod._persistence / "com.existing.plist").unlink()
    result = _check(mod)

    assert _finding(result, "new_persistence") is None
    assert _finding(result, "no_change") is not None


def test_new_browser_extension_is_reported(mod):
    _check(mod)
    (mod._extensions / "abcdefghijklmnop").mkdir()
    result = _check(mod)

    finding = _finding(result, "new_browser_extension")
    assert finding is not None
    assert finding.severity == Severity.WARNING


def test_new_listening_port_is_reported(mod):
    def no_ports(args, **kw):
        if args[0] == "netstat":
            return _Result(ok=True, stdout="Proto Local Address State\n")
        return _Result(ok=False)

    def one_port(args, **kw):
        if args[0] == "netstat":
            return _Result(
                ok=True,
                stdout="Proto Local Address State\ntcp4 0.0.0.0.4444 LISTEN\n",
            )
        return _Result(ok=False)

    _check(mod, no_ports)
    result = _check(mod, one_port)

    finding = _finding(result, "new_listening_port")
    assert finding is not None
    assert finding.severity == Severity.WARNING


def test_protection_turned_off_is_critical(mod):
    def firewall_on(args, **kw):
        if args and args[0].endswith("socketfilterfw"):
            return _Result(ok=True, stdout="Firewall is enabled. (State = 1)")
        return _Result(ok=False)

    def firewall_off(args, **kw):
        if args and args[0].endswith("socketfilterfw"):
            return _Result(ok=True, stdout="Firewall is disabled. (State = 0)")
        return _Result(ok=False)

    _check(mod, firewall_on)
    result = _check(mod, firewall_off)

    finding = _finding(result, "protection_disabled")
    assert finding is not None
    assert finding.severity == Severity.CRITICAL
    assert "Application firewall" in finding.data["disabled"]


def test_protection_turned_on_is_not_reported(mod):
    """Asymmetry is deliberate: enabling a protection is not a finding."""
    def firewall_off(args, **kw):
        if args and args[0].endswith("socketfilterfw"):
            return _Result(ok=True, stdout="Firewall is disabled. (State = 0)")
        return _Result(ok=False)

    def firewall_on(args, **kw):
        if args and args[0].endswith("socketfilterfw"):
            return _Result(ok=True, stdout="Firewall is enabled. (State = 1)")
        return _Result(ok=False)

    _check(mod, firewall_off)
    result = _check(mod, firewall_on)

    assert _finding(result, "protection_disabled") is None


def test_protection_becoming_unqueryable_is_not_reported_as_disabled(mod):
    """A command that stops working must not masquerade as a disabled protection."""
    def firewall_on(args, **kw):
        if args and args[0].endswith("socketfilterfw"):
            return _Result(ok=True, stdout="Firewall is enabled. (State = 1)")
        return _Result(ok=False)

    _check(mod, firewall_on)
    result = _check(mod, lambda args, **kw: _Result(ok=False))

    assert _finding(result, "protection_disabled") is None


def test_corrupt_baseline_is_treated_as_absent(mod):
    _check(mod)
    (mod.state_dir / "security_baseline.json").write_text("{not json")
    result = _check(mod)
    # Re-establishes rather than half-comparing against an unreadable file.
    assert _finding(result, "baseline_established") is not None


def test_baseline_of_a_different_version_is_treated_as_absent(mod):
    _check(mod)
    path = mod.state_dir / "security_baseline.json"
    data = json.loads(path.read_text())
    data["version"] = 999
    path.write_text(json.dumps(data))
    result = _check(mod)
    assert _finding(result, "baseline_established") is not None


def test_unwritable_state_dir_is_tolerated(mod):
    # A file where the directory should be: writing the baseline must fail
    # gracefully rather than raising out of check().
    blocked = mod._tmp / "blocked"
    blocked.write_text("")
    mod.state_dir = blocked / "nested"
    result = _check(mod)
    finding = _finding(result, "baseline_established")
    assert finding is not None
    assert finding.data["baseline_path"] is None


def test_every_finding_states_the_trust_on_first_use_limit(mod):
    """The limitation must be visible in the report, not just the source."""
    result = _check(mod)
    assert "already compromised" in result.findings[0].description

    (mod._persistence / "com.new.plist").write_text("")
    result = _check(mod)
    for finding in result.findings:
        assert "already compromised" in finding.description


def test_fix_is_guidance_only(mod):
    _check(mod)
    (mod._persistence / "com.new.plist").write_text("")
    check = _check(mod)
    fix = mod.fix(check, Mode.AUTO)

    assert fix.actions
    for action in fix.actions:
        assert action.kind == ActionKind.GUIDANCE
        assert action.executed is False


def test_fix_warns_against_rebaselining_a_compromised_machine(mod):
    check = _check(mod)
    fix = mod.fix(check, Mode.AUTO)
    action = next(a for a in fix.actions if a.data.get("check") == "rebaseline")
    assert "compromised machine" in action.description


def test_fix_does_not_tell_users_to_delete_unrecognised_entries(mod):
    """Guidance must be identify-first; blind deletion breaks working systems."""
    _check(mod)
    (mod._persistence / "com.new.plist").write_text("")
    check = _check(mod)
    fix = mod.fix(check, Mode.AUTO)
    action = next(a for a in fix.actions if a.data.get("check") == "new_persistence")
    assert "Identify first" in action.description
