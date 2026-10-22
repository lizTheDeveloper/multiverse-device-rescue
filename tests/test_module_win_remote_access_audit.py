"""win_remote_access_audit: Windows' built-in Remote Desktop only.

Third-party remote-access tools (TeamViewer, AnyDesk, VNC...) are
remote_access_tools' job, so each tool is reported once.
"""

import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.command import CommandResult
from rescue.models import ActionKind, Mode, Platform, ProcessInfo, RiskLevel, Severity, SystemProfile
from rescue.registry import discover_modules


def _make_profile(processes=()):
    return SystemProfile(
        platform=Platform.WIN32, os_name="Windows 11", os_version="10.0.22621", architecture="AMD64",
        cpu_model="test", cpu_cores=8, ram_bytes=16 * 1024**3,
        processes=[ProcessInfo(pid=1, name=n, cpu_percent=0.0, memory_bytes=0, command=n) for n in processes],
    )


def _get_module():
    modules = discover_modules(Path(__file__).parent.parent / "modules")
    return next(m for m in modules if m.name == "win_remote_access_audit")


def _namespace(mod):
    return sys.modules[type(mod).__module__]


def _cmd(stdout="", returncode=0):
    return CommandResult(args=[], returncode=returncode, stdout=stdout, stderr="", timed_out=False,
                         error=None, duration_s=0.0, truncated=False)


def _rdp(value):
    """A fake `run` for the fDenyTSConnections query: 0 (on), 1 (off) or None (unreadable)."""

    def run(args, **kw):
        assert args[:2] == ["reg", "query"] and "fDenyTSConnections" in args
        assert kw.get("timeout")
        if value is None:
            return _cmd("", returncode=1)
        return _cmd(f"\r\nHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\r\n"
                    f"    fDenyTSConnections    REG_DWORD    0x{value}\r\n")

    return run


def _check(value, profile=None):
    mod = _get_module()
    with patch.object(_namespace(mod), "run", side_effect=_rdp(value)):
        return mod.check(profile or _make_profile())


def test_discovered():
    mod = _get_module()
    assert mod.category == "security"
    assert mod.platforms == [Platform.WIN32]
    assert mod.risk_level == RiskLevel.SAFE


def test_win_remote_access_audit_reports_rdp_only():
    result = _check(0, _make_profile(["TeamViewer.exe", "AnyDesk.exe", "winvnc.exe"]))
    assert [f.code for f in result.findings] == ["security.win_remote_access_audit.rdp_enabled"]
    f = result.findings[0]
    assert f.severity == Severity.WARNING
    assert "TeamViewer" not in f.title + f.description


def test_rdp_off_is_info():
    result = _check(1, _make_profile(["TeamViewer.exe"]))
    assert [f.code for f in result.findings] == ["security.win_remote_access_audit.no_tools_found"]
    f = result.findings[0]
    assert f.severity == Severity.INFO
    assert f.title == "RDP is off"


def test_rdp_unreadable_is_not_reported_as_off():
    result = _check(None)
    assert not result.findings
    assert result.error


def test_no_relationship_words():
    import re

    words = re.compile(r"\b(partner\w*|ex|abuser\w*|stalk\w*|spy\w*)\b", re.I)
    for value in (0, 1):
        for f in _check(value).findings:
            assert not words.search(f.title + f.description)


def test_fix_is_guidance():
    mod = _get_module()
    result = _check(0)
    actions = mod.fix(result, Mode.MANUAL).actions
    assert len(actions) == 1
    assert actions[0].kind == ActionKind.GUIDANCE


def test_emitted_codes_are_declared():
    mod = _get_module()
    assert set(mod.emits_codes) == {
        "security.win_remote_access_audit.rdp_enabled",
        "security.win_remote_access_audit.no_tools_found",
    }
