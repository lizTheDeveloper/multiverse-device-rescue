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
    return next(m for m in modules if m.name == "launch_agent_audit")


def _check(tmp_path, plists):
    """Write real plists to tmp_path (the user LaunchAgents dir) and run check()."""
    mod = _get_module()
    for name, data in plists.items():
        with open(tmp_path / f"{name}.plist", "wb") as f:
            plistlib.dump(data, f)
    real_scan = mod._scan_launch_agents_dir

    def scan(directory):
        if directory == Path.home() / "Library" / "LaunchAgents":
            return real_scan(tmp_path)
        return []

    with patch.object(mod, "_scan_launch_agents_dir", side_effect=scan):
        return mod, mod.check(_make_profile())


def _real_program(tmp_path, name="svc"):
    p = tmp_path / name
    p.write_text("x")
    return str(p)


def test_launch_agent_audit_discovered():
    mod = _get_module()
    assert mod.name == "launch_agent_audit"
    assert mod.category == "security"
    assert Platform.DARWIN in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_launch_agent_audit_healthy(tmp_path):
    prog = _real_program(tmp_path)
    _, result = _check(
        tmp_path,
        {"com.example.app": {"Label": "com.example.app", "ProgramArguments": [prog]}},
    )
    assert result.findings
    assert all(f.severity == Severity.INFO for f in result.findings)


def test_launch_agent_audit_program_arguments_array_no_false_missing(tmp_path):
    """Regression: ProgramArguments must be parsed as an array, not as quoted text."""
    prog = _real_program(tmp_path, "redis-server")
    _, result = _check(
        tmp_path,
        {
            "homebrew.mxcl.redis": {
                "Label": "homebrew.mxcl.redis",
                "ProgramArguments": [prog, "/opt/homebrew/etc/redis.conf"],
                "KeepAlive": True,
                "RunAtLoad": True,
            }
        },
    )
    assert not any(f.data.get("check") == "missing_program" for f in result.findings)
    info = [f for f in result.findings if f.data.get("check") == "agent_info"]
    assert info[0].data["program"] == prog
    assert '"' not in info[0].data["program"]


def test_launch_agent_audit_program_key(tmp_path):
    prog = _real_program(tmp_path)
    _, result = _check(
        tmp_path,
        {"com.example.a": {"Label": "com.example.a", "Program": prog}},
    )
    assert not any(f.data.get("check") == "missing_program" for f in result.findings)


def test_launch_agent_audit_suspicious_tmp_path(tmp_path):
    _, result = _check(
        tmp_path,
        {"com.tmp.app": {"Label": "com.tmp.app", "Program": "/tmp/suspicious.app"}},
    )
    assert any(
        f.severity == Severity.CRITICAL
        and f.data.get("check") == "suspicious_path"
        and "any program" in f.description
        for f in result.findings
    )


def test_launch_agent_audit_suspicious_vartmp_path(tmp_path):
    _, result = _check(
        tmp_path,
        {"com.vartmp.app": {"Label": "com.vartmp.app", "Program": "/var/tmp/malware"}},
    )
    assert any(
        f.severity == Severity.CRITICAL and f.data.get("check") == "suspicious_path"
        for f in result.findings
    )


def test_launch_agent_audit_hidden_directory(tmp_path):
    _, result = _check(
        tmp_path,
        {"com.hidden.app": {"Label": "com.hidden.app", "Program": "/Users/testuser/.hidden/app"}},
    )
    assert any(
        f.severity == Severity.WARNING and "hidden" in f.title.lower()
        for f in result.findings
    )


def test_launch_agent_audit_developer_dirs_not_hidden_flagged(tmp_path):
    plists = {
        "com.dev.nvm": {"Label": "com.dev.nvm", "Program": "/Users/u/.nvm/versions/node/v22/bin/node"},
        "com.dev.venv": {"Label": "com.dev.venv", "Program": "/Users/u/src/x/.venv/bin/python"},
    }
    _, result = _check(tmp_path, plists)
    assert not any(f.data.get("check") == "suspicious_path" for f in result.findings)


def test_launch_agent_audit_missing_program(tmp_path):
    _, result = _check(
        tmp_path,
        {"com.missing.app": {"Label": "com.missing.app", "Program": "/nonexistent/path/app"}},
    )
    assert any(
        f.severity == Severity.WARNING and f.data.get("check") == "missing_program"
        for f in result.findings
    )


def test_launch_agent_audit_obfuscated_names(tmp_path):
    _, result = _check(
        tmp_path,
        {"com.x": {"Label": "com.x", "Program": "/usr/local/x"}},
    )
    assert any(f.data.get("check") == "obfuscated_name" for f in result.findings)


def test_launch_agent_audit_bin_sh_not_obfuscated(tmp_path):
    _, result = _check(
        tmp_path,
        {"com.sh": {"Label": "com.sh", "ProgramArguments": ["/bin/sh", "-c", "true"]}},
    )
    assert not any(f.data.get("check") == "obfuscated_name" for f in result.findings)


def test_launch_agent_audit_too_many_agents_is_info(tmp_path):
    prog = _real_program(tmp_path)
    plists = {
        f"com.agent{i}": {"Label": f"com.agent{i}", "ProgramArguments": [prog]}
        for i in range(25)
    }
    _, result = _check(tmp_path, plists)
    many = [f for f in result.findings if f.data.get("check") == "too_many_agents"]
    assert many and many[0].severity == Severity.INFO
    assert "malware" not in many[0].description.lower()
    assert "adware" not in many[0].description.lower()


def test_launch_agent_audit_fix_is_informational(tmp_path):
    mod, check = _check(
        tmp_path,
        {"com.tmp.app": {"Label": "com.tmp.app", "Program": "/tmp/suspicious.app"}},
    )
    fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert len(fix.actions) > 0


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.launch_agent_audit.") for c in declared)


# --- identities an attacker controls must not hide anything -------------------


def _checks(result, check):
    return [f for f in result.findings if f.data.get("check") == check]


def test_tmp_agent_is_critical(tmp_path):
    _, result = _check(tmp_path, {"com.a.b": {"Label": "com.a.b", "Program": "/tmp/x"}})
    assert any(f.severity == Severity.CRITICAL for f in _checks(result, "suspicious_path"))


def test_developer_tool_folder_is_listed_as_info_not_dropped(tmp_path):
    _, result = _check(
        tmp_path,
        {"com.dev.nvm": {"Label": "com.dev.nvm", "Program": "/Users/u/.nvm/versions/node/v22/bin/node"}},
    )
    listed = _checks(result, "developer_tool_path")
    assert len(listed) == 1
    assert listed[0].severity == Severity.INFO
    assert "developer tool folder" in listed[0].title
    assert not any(f.severity in (Severity.WARNING, Severity.CRITICAL) for f in result.findings
                   if f.data.get("check") == "suspicious_path")


def test_developer_dir_names_cannot_cover_other_hidden_folders(tmp_path):
    for i, prog in enumerate(
        (
            "/Users/me/.hidden/.nvm/bin/x",
            "/Users/me/.nvm/../.evil/x",
            "/Users/me/.xvenv/bin/x",
        )
    ):
        sub = tmp_path / str(i)
        sub.mkdir()
        _, result = _check(sub, {"com.a.b": {"Label": "com.a.b", "Program": prog}})
        assert any(f.severity == Severity.WARNING for f in _checks(result, "suspicious_path")), prog


def test_traversal_symlink_and_shell_string_into_tmp_are_critical(tmp_path):
    link = tmp_path / "link"
    link.symlink_to("/private/tmp")
    cases = [
        {"Program": "/Users/me/../../tmp/x"},
        {"Program": str(link / "x")},
        {"ProgramArguments": ["/bin/sh", "-c", "cd /var/tmp && ./x"]},
    ]
    for i, extra in enumerate(cases):
        sub = tmp_path / f"p{i}"
        sub.mkdir()
        _, result = _check(sub, {"com.a.b": {"Label": "com.a.b", **extra}})
        assert any(f.severity == Severity.CRITICAL for f in _checks(result, "suspicious_path")), extra


def test_short_name_exemption_does_not_cover_user_writable_bin_dirs(tmp_path):
    for i, prog in enumerate(("/usr/local/bin/ab", "/opt/homebrew/bin/ab")):
        sub = tmp_path / str(i)
        sub.mkdir()
        _, result = _check(sub, {"com.a.b": {"Label": "com.a.b", "Program": prog}})
        assert _checks(result, "obfuscated_name"), prog


def test_short_name_exemption_cannot_be_reached_by_traversal(tmp_path):
    _, result = _check(
        tmp_path, {"com.a.b": {"Label": "com.a.b", "Program": "/bin/../Users/me/ab"}}
    )
    assert _checks(result, "obfuscated_name")


def test_odd_plist_shapes_and_unreadable_files_are_still_listed(tmp_path):
    (tmp_path / "broken.plist").write_text("not a plist")
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
    assert {"broken", "com.a.one", "com.a.two", "com.a.three", "com.a.four"} <= labels
    hidden = _checks(result, "suspicious_path")
    assert {f.data["label"] for f in hidden} >= {"com.a.one", "com.a.two"}
