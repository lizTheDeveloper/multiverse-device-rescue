import os
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

MODULE_NAME = "code_signature_audit"


def _module_object(mod):
    return sys.modules[type(mod).__module__]


def _make_profile(platform=Platform.DARWIN):
    return SystemProfile(
        platform=platform,
        os_name="macOS" if platform == Platform.DARWIN else "Windows 11",
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
    """Stand-in for rescue.command.CommandResult."""

    def __init__(self, ok=True, stdout="", stderr="", timed_out=False, error=None):
        self.ok = ok
        self.stdout = stdout
        self.stderr = stderr
        self.timed_out = timed_out
        self.error = error


@pytest.fixture
def mod(tmp_path):
    m = _get_module()
    apps = tmp_path / "Applications"
    apps.mkdir()
    m.app_dirs = [str(apps)]
    m.max_binaries = 60
    m._apps_dir = apps
    m._tmp = tmp_path
    return m


def _install(mod, name):
    (mod._apps_dir / f"{name}.app").mkdir()


def _finding(result, check):
    return next((f for f in result.findings if f.data.get("check") == check), None)


def _findings(result, check):
    return [f for f in result.findings if f.data.get("check") == check]


def _run_with(mod, handler, platform=Platform.DARWIN):
    with patch.object(_module_object(mod), "run", side_effect=handler):
        return mod.check(_make_profile(platform))


def test_discovered_with_expected_metadata():
    m = _get_module()
    assert m.name == MODULE_NAME
    assert m.category == "security"
    assert m.risk_level == RiskLevel.SAFE
    assert getattr(m, "auto_apply", False) is False
    for code in (
        "security.code_signature_audit.tampered_binary",
        "security.code_signature_audit.unsigned_system_app",
        "security.code_signature_audit.gatekeeper_rejected",
        "security.code_signature_audit.inventory",
    ):
        assert code in m.emits_codes


def test_all_valid_signatures_produce_no_warnings(mod):
    _install(mod, "Safari")
    _install(mod, "Mail")

    result = _run_with(mod, lambda args, **kw: _Result(ok=True))

    assert not any(f.severity == Severity.CRITICAL for f in result.findings)
    assert not any(f.severity == Severity.WARNING for f in result.findings)
    inventory = _finding(result, "inventory")
    assert inventory.data["examined"] == 2
    assert inventory.data["tampered"] == 0


def test_broken_signature_is_critical(mod):
    _install(mod, "Tampered")

    def handler(args, **kw):
        if args[0] == "codesign":
            return _Result(ok=False, stderr="a sealed resource is missing or invalid")
        return _Result(ok=True)

    result = _run_with(mod, handler)

    finding = _finding(result, "tampered_binary")
    assert finding is not None
    assert finding.severity == Severity.CRITICAL
    assert "Tampered" in finding.title


@pytest.mark.skipif(
    os.name != "posix",
    reason=(
        "asserts on the macOS /Applications prefix; on Windows a PurePath "
        "renders it with backslashes and the system-wide check cannot match"
    ),
)
def test_unsigned_app_in_system_location_is_a_warning(mod):
    """An unsigned app is WARNING, never CRITICAL: it has benign explanations."""
    mod.app_dirs = ["/Applications"]

    def handler(args, **kw):
        if args[0] == "codesign":
            return _Result(ok=False, stderr="code object is not signed at all")
        return _Result(ok=True)

    with patch.object(type(mod), "_collect_darwin_apps", lambda self: [Path("/Applications/Sketchy.app")]):
        result = _run_with(mod, handler)

    finding = _finding(result, "unsigned_system_app")
    assert finding is not None
    assert finding.severity == Severity.WARNING
    # It must not overclaim: the text has to leave room for legitimate cases.
    assert "evidence, not a verdict" in finding.description


def test_unsigned_app_in_user_location_is_not_flagged(mod):
    """~/Applications is the user's own business; flagging it would be noise."""
    _install(mod, "MyOwnBuild")

    def handler(args, **kw):
        if args[0] == "codesign":
            return _Result(ok=False, stderr="code object is not signed at all")
        return _Result(ok=True)

    result = _run_with(mod, handler)

    assert _finding(result, "unsigned_system_app") is None
    assert _finding(result, "tampered_binary") is None


def test_gatekeeper_rejection_is_a_warning(mod):
    _install(mod, "NotNotarised")

    def handler(args, **kw):
        if args[0] == "codesign":
            return _Result(ok=True)
        return _Result(ok=False, stderr="rejected (the code is valid but does not seem to be an app)")

    result = _run_with(mod, handler)

    finding = _finding(result, "gatekeeper_rejected")
    assert finding is not None
    assert finding.severity == Severity.WARNING


def test_timed_out_check_is_not_reported_as_tampering(mod):
    """A check that did not complete must never be presented as a failure."""
    _install(mod, "Slow")

    def handler(args, **kw):
        if args[0] == "codesign":
            return _Result(ok=False, timed_out=True)
        return _Result(ok=True)

    result = _run_with(mod, handler)

    assert _finding(result, "tampered_binary") is None
    assert _finding(result, "unsigned_system_app") is None


def test_scan_is_capped_and_says_so(mod):
    for i in range(10):
        _install(mod, f"App{i}")
    mod.max_binaries = 4

    result = _run_with(mod, lambda args, **kw: _Result(ok=True))

    inventory = _finding(result, "inventory")
    assert inventory.data["examined"] == 4
    assert inventory.data["total_present"] == 10
    assert inventory.data["coverage_capped"] is True
    assert "COVERAGE LIMIT" in inventory.description


def test_uncapped_scan_states_full_coverage(mod):
    _install(mod, "OnlyOne")
    result = _run_with(mod, lambda args, **kw: _Result(ok=True))
    inventory = _finding(result, "inventory")
    assert inventory.data["coverage_capped"] is False
    assert "All applications in the scanned locations were checked" in inventory.description


def test_missing_application_directory_is_tolerated(mod):
    mod.app_dirs = [str(mod._tmp / "absent")]
    result = _run_with(mod, lambda args, **kw: _Result(ok=True))
    inventory = _finding(result, "inventory")
    assert inventory.data["examined"] == 0


def test_windows_hashmismatch_is_critical(mod):
    def handler(args, **kw):
        return _Result(
            ok=True,
            stdout=(
                "C:\\Program Files\\Good\\good.exe|Valid|CN=Vendor\n"
                "C:\\Program Files\\Bad\\bad.exe|HashMismatch|CN=Vendor\n"
                "C:\\Program Files\\Plain\\plain.exe|NotSigned|\n"
            ),
        )

    mod.app_dirs = [r"C:\Program Files"]
    result = _run_with(mod, handler, Platform.WIN32)

    tampered = _finding(result, "tampered_binary")
    assert tampered is not None
    assert tampered.severity == Severity.CRITICAL
    assert _finding(result, "unsigned_system_app") is not None


def test_windows_powershell_failure_is_tolerated(mod):
    mod.app_dirs = [r"C:\Program Files"]
    result = _run_with(mod, lambda args, **kw: _Result(ok=False), Platform.WIN32)
    inventory = _finding(result, "inventory")
    assert inventory.data["examined"] == 0


def test_unsupported_platform_says_so(mod):
    result = mod.check(_make_profile(Platform.LINUX))
    assert result.supported is False
    assert result.unsupported_reason
    assert result.findings == []


def test_fix_is_guidance_only(mod):
    _install(mod, "Tampered")

    def handler(args, **kw):
        if args[0] == "codesign":
            return _Result(ok=False, stderr="a sealed resource is missing or invalid")
        return _Result(ok=True)

    check = _run_with(mod, handler)
    fix = mod.fix(check, Mode.AUTO)

    assert fix.actions
    for action in fix.actions:
        assert action.kind == ActionKind.GUIDANCE
        assert action.executed is False


def test_fix_for_tampering_says_do_not_run_it(mod):
    _install(mod, "Tampered")

    def handler(args, **kw):
        if args[0] == "codesign":
            return _Result(ok=False, stderr="a sealed resource is missing or invalid")
        return _Result(ok=True)

    check = _run_with(mod, handler)
    fix = mod.fix(check, Mode.AUTO)

    action = next(a for a in fix.actions if a.data.get("check") == "tampered_binary")
    assert "do not run it again" in action.description.lower()


def test_capped_scan_warns_against_reading_it_as_all_clear(mod):
    for i in range(6):
        _install(mod, f"App{i}")
    mod.max_binaries = 2

    check = _run_with(mod, lambda args, **kw: _Result(ok=True))
    fix = mod.fix(check, Mode.AUTO)

    action = next(a for a in fix.actions if a.data.get("check") == "coverage_limit")
    assert "everything is signed" in action.description
