import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
import plistlib
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


def _make_profile():
    return SystemProfile(
        platform=Platform.DARWIN,
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
    return next(m for m in modules if m.name == "scheduled_tasks_audit")


def _make_plist(label: str, program: str = "", disabled: bool = False) -> dict:
    """Create a minimal plist dict for a launch agent."""
    plist = {
        "Label": label,
        "RunAtLoad": True,
    }
    if program:
        plist["Program"] = program
    if disabled:
        plist["Disabled"] = True
    return plist


def test_scheduled_tasks_audit_discovered():
    """Test that module is discovered and has correct metadata."""
    mod = _get_module()
    assert mod.name == "scheduled_tasks_audit"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.DARWIN in mod.platforms


def test_scheduled_tasks_audit_empty_directories():
    """Test with no launch agents/daemons found."""
    mod = _get_module()

    def mock_glob(pattern):
        return []

    with patch.object(Path, "exists", return_value=False):
        result = mod.check(_make_profile())

    # Should have no findings if no directories exist
    assert not result.has_issues


def test_scheduled_tasks_audit_legitimate_agents():
    """Test with legitimate Apple launch agents."""
    mod = _get_module()

    def mock_scan(directory, agent_type):
        """Mock scan that returns legitimate agents."""
        from rescue.models import Finding
        findings = []
        if "LaunchAgents" in str(directory):
            for label in ["com.apple.Spotlight", "com.google.Chrome.update"]:
                findings.append(
                    Finding(
                        title=f"Launch {agent_type}: {label}",
                        description=f"Launch {agent_type} found: {label}",
                        severity=Severity.INFO,
                        category="security",
                        data={
                            "check": "launch_agent_info",
                            "label": label,
                            "type": agent_type,
                        },
                    )
                )
        return findings

    with patch.object(mod, "_scan_launch_agents", side_effect=mock_scan):
        result = mod.check(_make_profile())

    # Should have no critical issues with legitimate agents
    assert not any(f.severity == Severity.WARNING for f in result.findings)


def test_scheduled_tasks_audit_suspicious_tmp_agent():
    """Test detection of agent running from /tmp."""
    mod = _get_module()

    # Mock Path operations
    user_agents_path = Path.home() / "Library/LaunchAgents"

    def mock_glob(self, pattern):
        if self == user_agents_path:
            return [user_agents_path / "com.malware.suspicious.plist"]
        return []

    def mock_exists(self):
        return str(self) in [
            str(user_agents_path),
            str(Path("/Library/LaunchAgents")),
            str(Path("/Library/LaunchDaemons")),
        ]

    def mock_plist_load(f):
        return _make_plist(
            "com.malware.suspicious",
            program="/tmp/malicious_script.sh"
        )

    with patch.object(Path, "glob", mock_glob):
        with patch.object(Path, "exists", mock_exists):
            with patch("plistlib.load", mock_plist_load):
                with patch("builtins.open", create=True):
                    result = mod.check(_make_profile())

    # Should detect suspicious path
    suspicious = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(suspicious) > 0
    assert any("suspicious" in f.title.lower() for f in suspicious)


def test_scheduled_tasks_audit_disabled_agents_clutter():
    """Test detection of disabled agents (clutter)."""
    mod = _get_module()

    user_agents_path = Path.home() / "Library/LaunchAgents"

    def mock_glob(self, pattern):
        if self == user_agents_path:
            return [user_agents_path / "com.example.disabled.plist"]
        return []

    def mock_exists(self):
        return str(self) in [
            str(user_agents_path),
            str(Path("/Library/LaunchAgents")),
            str(Path("/Library/LaunchDaemons")),
        ]

    def mock_plist_load(f):
        return _make_plist(
            "com.example.disabled",
            program="/Applications/Example.app/Contents/MacOS/Example",
            disabled=True
        )

    with patch.object(Path, "glob", mock_glob):
        with patch.object(Path, "exists", mock_exists):
            with patch("plistlib.load", mock_plist_load):
                with patch("builtins.open", create=True):
                    result = mod.check(_make_profile())

    # Should detect disabled agents
    disabled = [f for f in result.findings if f.data.get("check") == "disabled_launch_agent"]
    assert len(disabled) > 0
    assert disabled[0].severity == Severity.INFO


def test_scheduled_tasks_audit_excessive_agents():
    """Test WARNING when more than 20 user-level agents."""
    mod = _get_module()

    user_agents_path = Path.home() / "Library/LaunchAgents"

    def mock_glob(self, pattern):
        if self == user_agents_path:
            # Return 25 plists
            return [user_agents_path / f"com.example.agent{i}.plist" for i in range(25)]
        return []

    def mock_exists(self):
        return str(self) in [
            str(user_agents_path),
            str(Path("/Library/LaunchAgents")),
            str(Path("/Library/LaunchDaemons")),
        ]

    def mock_plist_load(f):
        # Return a different label for each call
        return _make_plist(f"com.example.agent{id(f)}")

    with patch.object(Path, "glob", mock_glob):
        with patch.object(Path, "exists", mock_exists):
            with patch("plistlib.load", mock_plist_load):
                with patch("builtins.open", create=True):
                    result = mod.check(_make_profile())

    # Should have WARNING about excessive agents
    excessive = [f for f in result.findings if f.data.get("check") == "excessive_user_agents"]
    assert len(excessive) > 0
    assert excessive[0].severity == Severity.WARNING
    assert "25" in excessive[0].description or "excessive" in excessive[0].title.lower()


def test_scheduled_tasks_audit_fix_is_informational():
    """Test that fix() returns informational actions."""
    mod = _get_module()

    # Create mock findings
    findings = [
        mock_finding("suspicious_launch_agent", "com.malware", "suspicious path"),
        mock_finding("disabled_launch_agent", "com.old.app", ""),
    ]

    from rescue.models import CheckResult
    check_result = CheckResult(module_name="scheduled_tasks_audit", findings=findings)

    fix = mod.fix(check_result, Mode.MANUAL)

    # All actions should succeed
    assert fix.all_succeeded
    assert len(fix.actions) == 2
    for action in fix.actions:
        assert action.success
        assert action.risk_level == RiskLevel.SAFE


def test_scheduled_tasks_audit_fix_suspicious_agent():
    """Test fix() response for suspicious agents."""
    mod = _get_module()

    findings = [
        mock_finding("suspicious_launch_agent", "com.malware.bad", "suspicious path: /tmp/evil"),
    ]

    from rescue.models import CheckResult
    check_result = CheckResult(module_name="scheduled_tasks_audit", findings=findings)

    fix = mod.fix(check_result, Mode.MANUAL)

    # Should have action for reviewing suspicious agent
    assert any("review" in a.title.lower() and "suspicious" in a.title.lower() for a in fix.actions)


def test_scheduled_tasks_audit_fix_excessive_agents():
    """Test fix() response for excessive agents."""
    mod = _get_module()

    findings = [
        mock_finding("excessive_user_agents", "", "", extra_data={"count": 25}),
    ]

    from rescue.models import CheckResult
    check_result = CheckResult(module_name="scheduled_tasks_audit", findings=findings)

    fix = mod.fix(check_result, Mode.MANUAL)

    # Should have action for reducing agents
    assert any("reduce" in a.title.lower() or "excessive" in a.title.lower() for a in fix.actions)


def mock_finding(check_type: str, label: str = "", reason: str = "", extra_data: dict = None):
    """Helper to create mock findings."""
    from rescue.models import Finding
    data = {"check": check_type, "label": label, "reason": reason}
    if extra_data:
        data.update(extra_data)
    return Finding(
        title=f"Test finding: {check_type}",
        description="Test description",
        severity=Severity.WARNING if check_type.startswith("suspicious") else Severity.INFO,
        category="security",
        data=data,
    )
