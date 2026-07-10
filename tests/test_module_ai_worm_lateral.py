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
    return next(m for m in modules if m.name == "ai_worm_lateral")


def test_module_discovered():
    mod = _get_module()
    assert mod.name == "ai_worm_lateral"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.MODERATE


def test_clean_system_no_findings():
    mod = _get_module()
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        with patch.object(Path, "exists", return_value=False):
            with patch.object(Path, "is_file", return_value=False):
                result = mod.check(_make_profile())
    assert not result.has_issues


def test_detects_stolen_credential_file():
    """Detect Miasma stolen PAT storage file."""
    mod = _get_module()

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        with patch.object(
            mod,
            "_check_credential_harvesting",
            return_value=[
                {
                    "path": str(Path.home() / ".config/gh-token-monitor/token"),
                    "threat": "miasma",
                    "ioc_match": True,
                }
            ],
        ):
            result = mod.check(_make_profile())

    cred_findings = [
        f
        for f in result.findings
        if f.data.get("check") == "credential_harvesting"
    ]
    assert len(cred_findings) > 0
    assert cred_findings[0].data["confidence"] == "high"


def test_detects_shai_halud_workflow():
    """Detect shai-hulud-workflow.yml in repos."""
    mod = _get_module()

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        with patch.object(Path, "exists", return_value=False):
            with patch.object(
                mod,
                "_check_supply_chain_artifacts",
                return_value=[
                    {
                        "path": "/Users/dev/project/.github/workflows/shai-hulud-workflow.yml",
                        "threat": "shai_hulud",
                        "type": "workflow",
                    }
                ],
            ):
                result = mod.check(_make_profile())

    sc_findings = [
        f
        for f in result.findings
        if f.data.get("check") == "supply_chain_artifact"
    ]
    assert len(sc_findings) > 0
    assert sc_findings[0].severity == Severity.CRITICAL


def test_detects_imds_access():
    """Detect processes querying cloud instance metadata service."""
    mod = _get_module()

    lsof_output = (
        "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"
        "python3 12345 user 10u IPv4 0x1234 0t0 TCP "
        "10.0.0.1:50000->169.254.169.254:80 (ESTABLISHED)"
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
            with patch.object(Path, "is_file", return_value=False):
                result = mod.check(_make_profile())

    imds_findings = [
        f for f in result.findings if f.data.get("check") == "imds_access"
    ]
    assert len(imds_findings) > 0
    assert imds_findings[0].data["confidence"] == "medium"


def test_fix_provides_rotation_guidance():
    mod = _get_module()
    from rescue.models import CheckResult, Finding

    check = CheckResult(
        module_name="ai_worm_lateral",
        findings=[
            Finding(
                title="Stolen credential file",
                description="Miasma PAT storage",
                severity=Severity.CRITICAL,
                category="security",
                data={
                    "check": "credential_harvesting",
                    "confidence": "high",
                    "path": str(
                        Path.home() / ".config/gh-token-monitor/token"
                    ),
                    "threat": "miasma",
                },
            ),
        ],
    )

    with patch("os.remove"):
        fix = mod.fix(check, Mode.MANUAL)

    assert len(fix.actions) > 0
    # Should include guidance about credential rotation
    action_text = " ".join(a.description for a in fix.actions).lower()
    assert "rotat" in action_text or "revok" in action_text


def test_subprocess_timeout_handled():
    mod = _get_module()
    import subprocess as sp

    with patch("subprocess.run", side_effect=sp.TimeoutExpired("cmd", 5)):
        with patch.object(Path, "exists", return_value=False):
            with patch.object(Path, "is_file", return_value=False):
                result = mod.check(_make_profile())
    assert not result.has_issues
