import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
from tempfile import TemporaryDirectory

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
    return next(m for m in modules if m.name == "launch_agent_audit")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_defaults_read_healthy():
    """Normal case: healthy launch agents"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        # Mocking find commands for user and system LaunchAgents
        if "find" in cmd_str and "LaunchAgents" in cmd_str:
            if "/Library/LaunchAgents" in cmd_str and "testuser" in cmd_str:
                # User LaunchAgents directory
                return _make_subprocess_result(
                    "/Users/testuser/Library/LaunchAgents/com.example.app.plist\n"
                    "/Users/testuser/Library/LaunchAgents/com.another.service.plist\n"
                )
            elif "/Library/LaunchAgents" in cmd_str:
                # System LaunchAgents directory
                return _make_subprocess_result(
                    "/Library/LaunchAgents/com.system.app.plist\n"
                )

        # Mocking defaults read commands
        if "defaults read" in cmd_str:
            if "com.example.app" in cmd_str:
                if "Label" in cmd_str:
                    return _make_subprocess_result("com.example.app\n")
                elif "ProgramArguments" in cmd_str:
                    return _make_subprocess_result(
                        "(\n  /usr/local/bin/app,\n  -arg1\n)\n"
                    )
            elif "com.another.service" in cmd_str:
                if "Label" in cmd_str:
                    return _make_subprocess_result("com.another.service\n")
                elif "ProgramArguments" in cmd_str:
                    return _make_subprocess_result(
                        "(\n  /opt/bin/service\n)\n"
                    )
            elif "com.system.app" in cmd_str:
                if "Label" in cmd_str:
                    return _make_subprocess_result("com.system.app\n")
                elif "ProgramArguments" in cmd_str:
                    return _make_subprocess_result(
                        "(\n  /Applications/App.app/Contents/MacOS/App\n)\n"
                    )

        return _make_subprocess_result()
    return fake_run


def _fake_defaults_read_suspicious_paths():
    """Case with suspicious paths: /tmp/, /var/tmp/, hidden dirs, non-existent"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "find" in cmd_str and "LaunchAgents" in cmd_str:
            if "/Library/LaunchAgents" in cmd_str and "testuser" in cmd_str:
                return _make_subprocess_result(
                    "/Users/testuser/Library/LaunchAgents/com.tmp.app.plist\n"
                    "/Users/testuser/Library/LaunchAgents/com.vartmp.app.plist\n"
                    "/Users/testuser/Library/LaunchAgents/com.hidden.app.plist\n"
                    "/Users/testuser/Library/LaunchAgents/com.missing.app.plist\n"
                )
            else:
                return _make_subprocess_result("")

        if "defaults read" in cmd_str:
            if "com.tmp.app" in cmd_str:
                if "Label" in cmd_str:
                    return _make_subprocess_result("com.tmp.app\n")
                elif "ProgramArguments" in cmd_str:
                    return _make_subprocess_result("(\n  /tmp/suspicious.app\n)\n")
            elif "com.vartmp.app" in cmd_str:
                if "Label" in cmd_str:
                    return _make_subprocess_result("com.vartmp.app\n")
                elif "ProgramArguments" in cmd_str:
                    return _make_subprocess_result("(\n  /var/tmp/malware\n)\n")
            elif "com.hidden.app" in cmd_str:
                if "Label" in cmd_str:
                    return _make_subprocess_result("com.hidden.app\n")
                elif "ProgramArguments" in cmd_str:
                    return _make_subprocess_result("(\n  /Users/testuser/.hidden/app\n)\n")
            elif "com.missing.app" in cmd_str:
                if "Label" in cmd_str:
                    return _make_subprocess_result("com.missing.app\n")
                elif "ProgramArguments" in cmd_str:
                    return _make_subprocess_result("(\n  /nonexistent/path/app\n)\n")

        return _make_subprocess_result()
    return fake_run


def _fake_defaults_read_obfuscated_names():
    """Case with obfuscated names"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "find" in cmd_str and "LaunchAgents" in cmd_str:
            if "/Library/LaunchAgents" in cmd_str and "testuser" in cmd_str:
                return _make_subprocess_result(
                    "/Users/testuser/Library/LaunchAgents/com.x.plist\n"
                    "/Users/testuser/Library/LaunchAgents/com.a.plist\n"
                )
            else:
                return _make_subprocess_result("")

        if "defaults read" in cmd_str:
            if "com.x" in cmd_str:
                if "Label" in cmd_str:
                    return _make_subprocess_result("com.x\n")
                elif "ProgramArguments" in cmd_str:
                    return _make_subprocess_result("(\n  /usr/local/bin/x\n)\n")
            elif "com.a" in cmd_str:
                if "Label" in cmd_str:
                    return _make_subprocess_result("com.a\n")
                elif "ProgramArguments" in cmd_str:
                    return _make_subprocess_result("(\n  /usr/local/bin/a\n)\n")

        return _make_subprocess_result()
    return fake_run


def _fake_defaults_read_too_many_agents():
    """Case with more than 20 user agents"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "find" in cmd_str and "LaunchAgents" in cmd_str:
            if "/Library/LaunchAgents" in cmd_str and "testuser" in cmd_str:
                # Return 25 agents
                agents = "\n".join(
                    f"/Users/testuser/Library/LaunchAgents/com.agent{i}.plist"
                    for i in range(25)
                )
                return _make_subprocess_result(agents + "\n")
            else:
                return _make_subprocess_result("")

        if "defaults read" in cmd_str:
            # Extract agent number from plist path
            for i in range(25):
                if f"com.agent{i}" in cmd_str:
                    if "Label" in cmd_str:
                        return _make_subprocess_result(f"com.agent{i}\n")
                    elif "ProgramArguments" in cmd_str:
                        return _make_subprocess_result(
                            f"(\n  /usr/local/bin/agent{i}\n)\n"
                        )

        return _make_subprocess_result()
    return fake_run


def test_launch_agent_audit_discovered():
    mod = _get_module()
    assert mod.name == "launch_agent_audit"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE


def test_launch_agent_audit_healthy():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_defaults_read_healthy()):
        with patch("pathlib.Path.exists", return_value=True):
            with patch("pathlib.Path.home", return_value=Path("/Users/testuser")):
                result = mod.check(_make_profile())
    # Should have INFO findings for each agent, but no WARNINGs/CRITICALs
    assert result.has_issues  # Should have INFO entries for agents
    for finding in result.findings:
        assert finding.severity in [Severity.INFO]


def test_launch_agent_audit_suspicious_tmp_path():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_defaults_read_suspicious_paths()):
        with patch("pathlib.Path.exists", return_value=True):
            with patch("pathlib.Path.home", return_value=Path("/Users/testuser")):
                result = mod.check(_make_profile())
    assert result.has_issues
    # Should have a WARNING for /tmp/ path
    assert any(
        f.severity == Severity.WARNING and "temporary directory" in f.title.lower()
        and f.data.get("check") == "suspicious_path"
        for f in result.findings
    )


def test_launch_agent_audit_suspicious_vartmp_path():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_defaults_read_suspicious_paths()):
        with patch("pathlib.Path.exists", return_value=True):
            with patch("pathlib.Path.home", return_value=Path("/Users/testuser")):
                result = mod.check(_make_profile())
    assert result.has_issues
    # Should have a WARNING for /var/tmp path (covered by temporary directory check)
    assert any(
        f.severity == Severity.WARNING and "temporary directory" in f.title.lower()
        and f.data.get("check") == "suspicious_path"
        for f in result.findings
    )


def test_launch_agent_audit_hidden_directory():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_defaults_read_suspicious_paths()):
        with patch("pathlib.Path.exists", return_value=True):
            with patch("pathlib.Path.home", return_value=Path("/Users/testuser")):
                result = mod.check(_make_profile())
    assert result.has_issues
    # Should have a WARNING for hidden directory
    assert any(
        f.severity == Severity.WARNING and "hidden" in f.title.lower()
        for f in result.findings
    )


def test_launch_agent_audit_missing_program():
    mod = _get_module()

    def path_exists_side_effect(self):
        """Mock exists() to return False only for /nonexistent/path/app"""
        path_str = str(self)
        if "/nonexistent/path/app" in path_str:
            return False
        return True

    with patch("subprocess.run", side_effect=_fake_defaults_read_suspicious_paths()):
        with patch("pathlib.Path.home", return_value=Path("/Users/testuser")):
            with patch("pathlib.Path.exists", path_exists_side_effect):
                result = mod.check(_make_profile())
    assert result.has_issues
    # Should have a WARNING for non-existent program
    assert any(
        f.severity == Severity.WARNING and "does not exist" in f.title.lower()
        and f.data.get("check") == "missing_program"
        for f in result.findings
    )


def test_launch_agent_audit_obfuscated_names():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_defaults_read_obfuscated_names()):
        with patch("pathlib.Path.exists", return_value=True):
            with patch("pathlib.Path.home", return_value=Path("/Users/testuser")):
                result = mod.check(_make_profile())
    assert result.has_issues
    # Should have WARNINGs for obfuscated names
    assert any(
        f.severity == Severity.WARNING and "obfuscated" in f.title.lower()
        for f in result.findings
    )


def test_launch_agent_audit_too_many_agents():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_defaults_read_too_many_agents()):
        with patch("pathlib.Path.exists", return_value=True):
            with patch("pathlib.Path.home", return_value=Path("/Users/testuser")):
                result = mod.check(_make_profile())
    assert result.has_issues
    # Should have a WARNING for too many agents
    assert any(
        f.severity == Severity.WARNING and "unusual" in f.title.lower()
        and f.data.get("check") == "too_many_agents"
        for f in result.findings
    )


def test_launch_agent_audit_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_defaults_read_suspicious_paths()):
        with patch("pathlib.Path.exists", return_value=True):
            with patch("pathlib.Path.home", return_value=Path("/Users/testuser")):
                check = mod.check(_make_profile())
                fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action
    assert len(fix.actions) > 0
