import plistlib
import shutil
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


_POSIX_ONLY = pytest.mark.skipif(
    sys.platform == "win32", reason="needs POSIX symlinks (symlink_to needs privileges on Windows)"
)


@pytest.fixture
def tmp_path(tmp_path):
    """On Linux, a scratch dir that is not under /tmp.

    This module flags programs in world-writable folders (/tmp, /var/tmp) as
    suspicious, and pytest's tmp_path is /tmp/pytest-of-... on Linux, so a
    "healthy" fixture program there would be flagged. On macOS tmp_path is
    under /private/var/folders and is used unchanged, as on Windows.
    """
    if not sys.platform.startswith("linux"):
        yield tmp_path
        return
    d = Path(tempfile.mkdtemp(prefix="rescue-test-", dir=Path.home()))
    try:
        yield d
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _make_profile():
    return SystemProfile(
        platform=Platform.DARWIN,
        os_name="macOS",
        os_version="13.0",
        architecture="arm64",
        cpu_model="Apple M1",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "launchd_persistence_audit")


def _check(tmp_path, plists):
    """Write real plists into tmp_path (the user LaunchAgents dir) and run check()."""
    mod = _get_module()
    for name, data in plists.items():
        with open(tmp_path / f"{name}.plist", "wb") as f:
            plistlib.dump(data, f)
    real_scan = mod._scan_launchd_dir

    def scan(directory):
        if directory == Path.home() / "Library" / "LaunchAgents":
            return real_scan(tmp_path)
        return []

    with patch.object(mod, "_scan_launchd_dir", side_effect=scan):
        return mod, mod.check(_make_profile())


def _by_check(result, check):
    return [f for f in result.findings if f.data.get("check") == check]


def test_launchd_persistence_audit_discovered():
    mod = _get_module()
    assert mod.name == "launchd_persistence_audit"
    assert mod.category == "security"
    assert Platform.DARWIN in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_launchd_persistence_audit_no_items():
    mod = _get_module()
    with patch.object(Path, "exists", return_value=False):
        result = mod.check(_make_profile())
    assert not result.has_issues


def test_launchd_persistence_audit_known_malware(tmp_path):
    _, result = _check(
        tmp_path,
        {"com.vsearch.helper": {"Label": "com.vsearch.helper", "Program": "/tmp/malware"}},
    )
    found = _by_check(result, "known_malware")
    assert found and found[0].severity == Severity.CRITICAL


def test_launchd_persistence_audit_tmp_stays_critical(tmp_path):
    """Regression: a missing /tmp script is still a true positive. Anyone can create it."""
    _, result = _check(
        tmp_path,
        {
            "com.morgan.bluesky-poster": {
                "Label": "com.morgan.bluesky-poster",
                "Program": "/tmp/morgan-local-post.sh",
                "RunAtLoad": True,
                "StartInterval": 7200,
            }
        },
    )
    found = _by_check(result, "suspicious_path")
    assert len(found) == 1
    assert found[0].severity == Severity.CRITICAL
    assert "any program" in found[0].description
    assert "/tmp" in found[0].description


def test_launchd_persistence_audit_private_tmp_and_shared_critical(tmp_path):
    for i, prog in enumerate(
        ("/private/tmp/x", "/var/tmp/x", "/Users/Shared/x", "/private/var/tmp/x")
    ):
        sub = tmp_path / str(i)
        sub.mkdir()
        _, result = _check(sub, {"com.example.a": {"Label": "com.example.a", "Program": prog}})
        found = _by_check(result, "suspicious_path")
        assert found and found[0].severity == Severity.CRITICAL, prog


def test_launchd_persistence_audit_tmp_in_program_arguments(tmp_path):
    _, result = _check(
        tmp_path,
        {
            "com.example.a": {
                "Label": "com.example.a",
                "ProgramArguments": ["/bin/bash", "/tmp/run.sh"],
            }
        },
    )
    found = _by_check(result, "suspicious_path")
    assert found and found[0].severity == Severity.CRITICAL


def test_launchd_persistence_audit_developer_dirs_not_flagged(tmp_path):
    programs = {
        "a": "/Users/me/.nvm/versions/node/v22.16.0/bin/node",
        "b": "/Users/me/.hermes/hermes-agent/venv/bin/python",
        "c": "/Users/me/src/x/.venv/bin/python",
        "h": "/Users/me/src/x/.venv-hermes/bin/python",
        "d": "/Users/me/.pyenv/shims/python",
        "e": "/Users/me/.bun/bin/bun",
        "f": "/Users/me/.local/bin/tool",
        "g": "/Users/me/.cargo/bin/tool",
    }
    _, result = _check(
        tmp_path,
        {f"com.dev.{k}": {"Label": f"com.dev.{k}", "Program": v} for k, v in programs.items()},
    )
    assert not any(f.severity in (Severity.WARNING, Severity.CRITICAL) for f in result.findings)
    # They stay listed (as info), they are not dropped
    listed = _by_check(result, "developer_tool_path")
    assert len(listed) == len(programs)
    assert all(f.severity == Severity.INFO for f in listed)
    assert all("developer tool folder" in f.title for f in listed)


def test_launchd_persistence_audit_unusual_hidden_dir_is_warning_not_malware(tmp_path):
    _, result = _check(
        tmp_path,
        {"com.example.app": {"Label": "com.example.app", "Program": "/Users/admin/.hidden/thing"}},
    )
    found = _by_check(result, "suspicious_path")
    assert found and found[0].severity == Severity.WARNING
    assert "malware persistence" not in found[0].description


def test_launchd_persistence_audit_keepalive_runatload_existing_program_is_info(tmp_path):
    prog = tmp_path / "svc"
    prog.write_text("x")
    _, result = _check(
        tmp_path,
        {
            "homebrew.mxcl.redis": {
                "Label": "homebrew.mxcl.redis",
                "ProgramArguments": [str(prog), "/opt/homebrew/etc/redis.conf"],
                "KeepAlive": True,
                "RunAtLoad": True,
            }
        },
    )
    assert not _by_check(result, "keepalive_runatload")
    assert not any(f.severity in (Severity.WARNING, Severity.CRITICAL) for f in result.findings)
    assert _by_check(result, "non_apple_info")[0].severity == Severity.INFO


def test_launchd_persistence_audit_keepalive_runatload_missing_program_warns(tmp_path):
    _, result = _check(
        tmp_path,
        {
            "com.example.gone": {
                "Label": "com.example.gone",
                "Program": str(tmp_path / "does-not-exist"),
                "KeepAlive": True,
                "RunAtLoad": True,
            }
        },
    )
    found = _by_check(result, "keepalive_runatload")
    assert found and found[0].severity == Severity.WARNING


def test_launchd_persistence_audit_apple_no_info(tmp_path):
    _, result = _check(
        tmp_path,
        {
            "com.apple.someservice": {
                "Label": "com.apple.someservice",
                "Program": "/System/Library/CoreServices/app",
                "KeepAlive": True,
                "RunAtLoad": True,
            }
        },
    )
    assert not result.has_issues


def test_launchd_persistence_audit_program_arguments_and_quotes(tmp_path):
    _, result = _check(
        tmp_path,
        {
            "com.example.app": {
                "Label": "com.example.app",
                "ProgramArguments": ["/Applications/App.app/Contents/MacOS/app", "-arg1"],
            }
        },
    )
    info = _by_check(result, "non_apple_info")
    assert info and info[0].data["program"] == "/Applications/App.app/Contents/MacOS/app"
    assert '"' not in info[0].data["program"]


def test_launchd_persistence_audit_fix_known_malware(tmp_path):
    mod, check = _check(
        tmp_path,
        {"com.pcv.malware": {"Label": "com.pcv.malware", "Program": "/tmp/malware"}},
    )
    fix = mod.fix(check, Mode.MANUAL)
    assert any("Remove known malware" in a.title for a in fix.actions)
    assert all(a.success for a in fix.actions)


def test_launchd_persistence_audit_fix_suspicious_path(tmp_path):
    mod, check = _check(
        tmp_path,
        {"com.example.app": {"Label": "com.example.app", "Program": "/tmp/badapp"}},
    )
    fix = mod.fix(check, Mode.MANUAL)
    assert any("Remove suspicious" in a.title for a in fix.actions)


def test_launchd_persistence_audit_unreadable_plist(tmp_path):
    (tmp_path / "broken.plist").write_text("not a plist")
    mod = _get_module()
    items = mod._scan_launchd_dir(tmp_path)
    # Unreadable items are still reported, never silently skipped
    assert len(items) == 1 and items[0][0] == "broken" and items[0][1] == ""


# --- identities an attacker controls must not hide anything -------------------


def _severities(result, check=None):
    return [f.severity for f in result.findings if check is None or f.data.get("check") == check]


def test_developer_dir_name_nested_in_hidden_folder_is_still_warned(tmp_path):
    for i, prog in enumerate(
        (
            "/Users/me/.hidden/.nvm/bin/x",
            "/Users/me/.nvm/../.evil/x",
            "/Users/me/.xvenv/bin/x",
            "/Users/me/.nvm-evil/x",
        )
    ):
        sub = tmp_path / str(i)
        sub.mkdir()
        _, result = _check(sub, {"com.a.b": {"Label": "com.a.b", "Program": prog}})
        assert Severity.WARNING in _severities(result, "suspicious_path"), prog


def test_traversal_into_tmp_is_critical(tmp_path):
    sub = tmp_path / "p"
    sub.mkdir()
    _, result = _check(sub, {"com.a.b": {"Label": "com.a.b", "Program": "/Users/me/../../tmp/x"}})
    assert Severity.CRITICAL in _severities(result, "suspicious_path")


@_POSIX_ONLY
def test_symlink_into_tmp_is_critical(tmp_path):
    link = tmp_path / "link"
    link.symlink_to("/private/tmp")
    sub = tmp_path / "p"
    sub.mkdir()
    _, result = _check(sub, {"com.a.b": {"Label": "com.a.b", "Program": str(link / "x")}})
    assert Severity.CRITICAL in _severities(result, "suspicious_path")


def test_tmp_inside_shell_command_is_critical(tmp_path):
    _, result = _check(
        tmp_path,
        {"com.a.b": {"Label": "com.a.b", "ProgramArguments": ["/bin/sh", "-c", "cd /tmp && ./x"]}},
    )
    assert Severity.CRITICAL in _severities(result, "suspicious_path")


def test_apple_looking_label_with_non_system_program_is_still_listed(tmp_path):
    _, result = _check(
        tmp_path,
        {
            "com.apple.evil": {
                "Label": "com.apple.evil",
                "Program": "/Users/me/Library/evil",
                "KeepAlive": True,
                "RunAtLoad": True,
            }
        },
    )
    assert _by_check(result, "non_apple_info")
    assert _by_check(result, "keepalive_runatload")


def test_apple_label_with_tmp_helper_argument_is_not_trusted(tmp_path):
    _, result = _check(
        tmp_path,
        {
            "com.apple.x": {
                "Label": "com.apple.x",
                "ProgramArguments": ["/usr/bin/python3", "/Users/me/Library/evil.py"],
            }
        },
    )
    assert _by_check(result, "non_apple_info")


def test_odd_plist_shapes_are_still_listed(tmp_path):
    _, result = _check(
        tmp_path,
        {
            "com.a.one": {"Label": "com.a.one", "ProgramArguments": "/Users/me/.hidden/x"},
            "com.a.two": {"Label": "com.a.two", "Program": ["/Users/me/.hidden/y"]},
            "com.a.three": {"Label": "com.a.three"},
            "com.a.four": {"Program": "/Users/me/z"},
        },
    )
    labels = {f.data.get("label") for f in result.findings}
    assert {"com.a.one", "com.a.two", "com.a.three", "com.a.four"} <= labels
    hidden = _by_check(result, "suspicious_path")
    assert {f.data["label"] for f in hidden} >= {"com.a.one", "com.a.two"}


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.launchd_persistence_audit.") for c in declared)
