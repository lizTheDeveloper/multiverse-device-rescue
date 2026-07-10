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
    return next(m for m in modules if m.name == "ai_worm_network")


def test_module_discovered():
    mod = _get_module()
    assert mod.name == "ai_worm_network"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.MODERATE


def test_clean_system_no_findings():
    mod = _get_module()
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        with patch.object(Path, "exists", return_value=False):
            result = mod.check(_make_profile())
    assert not result.has_issues


def test_detects_known_malicious_domain_connection():
    """Detect process connecting to known malicious domain."""
    mod = _get_module()

    lsof_output = (
        "COMMAND   PID   USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\n"
        "node    99999   user   10u  IPv4 0x1234 0t0 TCP "
        "192.168.1.1:50000->cdn.cloudfront-js.com:443 (ESTABLISHED)"
    )

    with patch("subprocess.run") as mock_run:
        mock_result = MagicMock()
        mock_result.stdout = lsof_output
        mock_result.returncode = 0

        def side_effect(cmd, **kwargs):
            if cmd[0] == "lsof":
                return mock_result
            return MagicMock(stdout="", returncode=0)

        mock_run.side_effect = side_effect

        with patch.object(Path, "exists", return_value=False):
            result = mod.check(_make_profile())

    domain_findings = [
        f for f in result.findings if f.data.get("check") == "known_malicious_connection"
    ]
    assert len(domain_findings) > 0
    assert domain_findings[0].severity == Severity.CRITICAL
    assert domain_findings[0].data["confidence"] == "high"


def test_detects_stepsecurity_bypass():
    """Detect /etc/hosts entry redirecting agent.stepsecurity.io."""
    mod = _get_module()

    hosts_content = "127.0.0.1 localhost\n127.0.0.1 agent.stepsecurity.io\n"

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        with patch(
            "builtins.open",
            MagicMock(
                return_value=MagicMock(
                    __enter__=MagicMock(
                        return_value=MagicMock(
                            read=MagicMock(return_value=hosts_content)
                        )
                    ),
                    __exit__=MagicMock(return_value=False),
                )
            ),
        ):
            with patch.object(Path, "exists", return_value=True):
                with patch.object(
                    mod,
                    "_check_stepsecurity_bypass",
                    return_value=[{"line": "127.0.0.1 agent.stepsecurity.io"}],
                ):
                    result = mod.check(_make_profile())

    bypass_findings = [
        f for f in result.findings if f.data.get("check") == "stepsecurity_bypass"
    ]
    assert len(bypass_findings) > 0
    assert bypass_findings[0].data["confidence"] == "high"


def test_detects_beaconing_pattern():
    """Detect processes with regular-interval outbound connections."""
    mod = _get_module()

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        with patch.object(Path, "exists", return_value=False):
            with patch.object(
                mod,
                "_check_beaconing",
                return_value=[
                    {
                        "process": "gh-token-monitor",
                        "pid": 12345,
                        "dest": "api.github.com:443",
                        "interval_seconds": 60,
                    }
                ],
            ):
                result = mod.check(_make_profile())

    beacon_findings = [
        f for f in result.findings if f.data.get("check") == "beaconing_detected"
    ]
    assert len(beacon_findings) > 0
    assert beacon_findings[0].data["confidence"] == "medium"


def test_fix_kills_malicious_connection():
    mod = _get_module()
    from rescue.models import CheckResult, Finding

    check = CheckResult(
        module_name="ai_worm_network",
        findings=[
            Finding(
                title="Connection to known C2",
                description="node connecting to malicious domain",
                severity=Severity.CRITICAL,
                category="security",
                data={
                    "check": "known_malicious_connection",
                    "confidence": "high",
                    "pid": 99999,
                    "process": "node",
                },
            ),
        ],
    )

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        with patch("os.kill"):
            fix = mod.fix(check, Mode.MANUAL)

    assert len(fix.actions) > 0
    assert fix.actions[0].success


def test_subprocess_timeout_handled():
    mod = _get_module()
    import subprocess as sp

    with patch("subprocess.run", side_effect=sp.TimeoutExpired("cmd", 5)):
        with patch.object(Path, "exists", return_value=False):
            result = mod.check(_make_profile())
    assert not result.has_issues
