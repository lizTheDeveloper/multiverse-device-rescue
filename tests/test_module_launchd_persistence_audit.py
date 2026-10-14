import plistlib
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


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
    assert not _by_check(result, "suspicious_path")
    assert not any(f.severity in (Severity.WARNING, Severity.CRITICAL) for f in result.findings)


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
    assert mod._scan_launchd_dir(tmp_path) == []


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.launchd_persistence_audit.") for c in declared)
