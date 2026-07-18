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
    return next(m for m in modules if m.name == "ai_worm_git_ssh")


def test_module_discovered():
    mod = _get_module()
    assert mod.name == "ai_worm_git_ssh"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.MODERATE
    assert Platform.DARWIN in mod.platforms


def test_clean_system_no_findings():
    mod = _get_module()
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="", returncode=1)
        with patch.object(Path, "exists", return_value=False):
            with patch.object(Path, "is_file", return_value=False):
                result = mod.check(_make_profile())
    assert not result.has_issues


def test_detects_git_hookspath_hijack():
    """Detect when core.hooksPath is set to a non-standard location."""
    mod = _get_module()

    def run_side_effect(cmd, **kwargs):
        mock = MagicMock()
        if "core.hooksPath" in cmd:
            mock.stdout = "/tmp/.hidden/hooks\n"
            mock.returncode = 0
        else:
            mock.stdout = ""
            mock.returncode = 1
        return mock

    with patch("subprocess.run", side_effect=run_side_effect):
        with patch.object(Path, "exists", return_value=False):
            with patch.object(Path, "is_file", return_value=False):
                result = mod.check(_make_profile())

    hookspath_findings = [
        f for f in result.findings if f.data.get("check") == "git_hookspath_hijack"
    ]
    assert len(hookspath_findings) > 0
    assert hookspath_findings[0].severity == Severity.CRITICAL
    assert hookspath_findings[0].data["confidence"] == "high"


def test_detects_git_templatedir_hijack():
    """Detect when init.templateDir is set to a non-standard location."""
    mod = _get_module()

    def run_side_effect(cmd, **kwargs):
        mock = MagicMock()
        if "init.templateDir" in cmd:
            mock.stdout = "/tmp/.hidden/template\n"
            mock.returncode = 0
        else:
            mock.stdout = ""
            mock.returncode = 1
        return mock

    with patch("subprocess.run", side_effect=run_side_effect):
        with patch.object(Path, "exists", return_value=False):
            with patch.object(Path, "is_file", return_value=False):
                result = mod.check(_make_profile())

    template_findings = [
        f for f in result.findings if f.data.get("check") == "git_templatedir_hijack"
    ]
    assert len(template_findings) > 0
    assert template_findings[0].data["confidence"] == "high"


def test_detects_npmrc_git_node_override():
    """Detect .npmrc containing git=node override."""
    mod = _get_module()

    npmrc_content = "git=node\nregistry=https://registry.npmjs.org/\n"

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="", returncode=1)
        with patch.object(Path, "exists", return_value=False):
            with patch.object(Path, "is_file", return_value=False):
                with patch.object(
                    mod,
                    "_check_npmrc_override",
                    return_value=[
                        {
                            "path": str(Path.home() / ".npmrc"),
                            "line": "git=node",
                        }
                    ],
                ):
                    result = mod.check(_make_profile())

    npmrc_findings = [
        f for f in result.findings if f.data.get("check") == "npmrc_git_override"
    ]
    assert len(npmrc_findings) > 0
    assert npmrc_findings[0].data["confidence"] == "high"


def test_detects_rogue_mcp_server():
    """Detect known malicious MCP server names in AI tool configs."""
    mod = _get_module()

    import json

    claude_settings = json.dumps(
        {"mcpServers": {"index_project": {"command": "node", "args": ["evil.js"]}}}
    )

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="", returncode=1)
        with patch.object(Path, "exists", return_value=False):
            with patch.object(Path, "is_file", return_value=False):
                with patch.object(
                    mod,
                    "_check_mcp_configs",
                    return_value=[
                        {
                            "config_path": "~/.claude/settings.json",
                            "server_name": "index_project",
                            "threat": "sandworm_mode",
                        }
                    ],
                ):
                    result = mod.check(_make_profile())

    mcp_findings = [
        f for f in result.findings if f.data.get("check") == "rogue_mcp_server"
    ]
    assert len(mcp_findings) > 0
    assert mcp_findings[0].severity == Severity.CRITICAL
    assert mcp_findings[0].data["confidence"] == "high"


def test_fix_resets_hookspath():
    """fix() should offer to reset core.hooksPath on high-confidence findings."""
    mod = _get_module()
    from rescue.models import CheckResult, Finding

    check = CheckResult(
        module_name="ai_worm_git_ssh",
        findings=[
            Finding(
                title="Git hooksPath hijacked",
                description="core.hooksPath set to /tmp/.hidden/hooks",
                severity=Severity.CRITICAL,
                category="security",
                data={
                    "check": "git_hookspath_hijack",
                    "confidence": "high",
                    "value": "/tmp/.hidden/hooks",
                },
            ),
        ],
    )

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        fix = mod.fix(check, Mode.MANUAL)

    assert len(fix.actions) > 0
    assert fix.actions[0].success


def test_fix_only_acts_on_high_confidence():
    """fix() should skip mutation for findings with confidence != high."""
    mod = _get_module()
    from rescue.models import ActionKind, CheckResult, Finding

    check = CheckResult(
        module_name="ai_worm_git_ssh",
        findings=[
            Finding(
                title="Auto-run task configuration detected",
                description="Heuristic match, not IOC-confirmed",
                severity=Severity.WARNING,
                category="security",
                data={
                    "check": "repo_hook_file",
                    "confidence": "medium",
                    "path": "/tmp/project/.vscode/tasks.json",
                },
            ),
            Finding(
                title="SSH authorized_keys recently modified",
                description="Heuristic mtime-based match",
                severity=Severity.WARNING,
                category="security",
                data={
                    "check": "ssh_authorized_keys_recent",
                    "confidence": "low",
                    "path": str(Path.home() / ".ssh" / "authorized_keys"),
                },
            ),
        ],
    )

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        fix = mod.fix(check, Mode.MANUAL)

    assert len(fix.actions) == 2
    for action in fix.actions:
        assert action.kind == ActionKind.GUIDANCE
        assert not any(
            action.title.lower().startswith(prefix)
            for prefix in ("reset", "remove", "quarantine")
        )
        assert "investigate" in action.title.lower()
    # subprocess.run must never have been called for git config mutation
    mock_run.assert_not_called()


def test_subprocess_timeout_handled():
    mod = _get_module()
    import subprocess as sp

    with patch("subprocess.run", side_effect=sp.TimeoutExpired("cmd", 5)):
        with patch.object(Path, "exists", return_value=False):
            with patch.object(Path, "is_file", return_value=False):
                result = mod.check(_make_profile())
    assert not result.has_issues


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(
        c.startswith("security.ai_worm_git_ssh.") for c in declared
    )
